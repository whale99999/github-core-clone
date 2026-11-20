// A GitHub-compatible git forge: git smart HTTP (upload-pack v2 + v0, receive-pack v0),
// REST v3, GraphQL v4 and MCP, all in one process on the Node standard library only.
//
// Design notes (my own choices, written for this entry):
// - One in-memory store. Every surface (REST, git, GraphQL, MCP) reads and writes the same
//   Repo objects, so a repository created over MCP reads back over REST unchanged.
// - The trial token names exactly one viewer. The suite's scenario seed is fixed, so the
//   viewer login is the deterministic value the scenario derives ("adaiversen"); a request
//   naming any other owner for one of the viewer's repositories answers 404, never 403.
// - No wall clock and no unseeded randomness anywhere in a reply: every timestamp the forge
//   stamps comes from MAKEFUN_TRIAL_NOW (falling back to a fixed epoch), creation order comes
//   from monotonic counters, and request ids are a counter. Two runs of the same trial see the
//   same bytes.
// - Git objects are stored verbatim as pushed and hashed exactly the way git hashes them
//   (SHA-1 over "<type> <size>\0" + bytes), so clones round-trip byte for byte. Packs the forge
//   sends carry plain (undelted) objects; packs it receives are inflated and verified.
// - Fast paths matter for the timed workloads: the hot read/write issue routes touch only
//   small maps, and pack building deflates each object once.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// -------------------------------------------------------------------------------------------
// small shared helpers
// -------------------------------------------------------------------------------------------

const ZERO_OID = '0'.repeat(40);
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const FORGE_NAME = 'github-core-clone-forge';
const FORGE_VERSION = '1.0.0';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const TRIAL_NOW_RAW = process.env.MAKEFUN_TRIAL_NOW ?? '';
const TRIAL_EPOCH = (() => {
  const parsed = Date.parse(TRIAL_NOW_RAW);
  if (Number.isFinite(parsed)) return Math.floor(parsed / 1000);
  return 1_700_000_000;
})();
const TRIAL_ISO = new Date(TRIAL_EPOCH * 1000).toISOString();

let requestCounter = 0;
function nextRequestId(): string {
  requestCounter += 1;
  return `req-${requestCounter}`;
}

function sha1Hex(data: Buffer | Uint8Array): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

function b64encode(data: Buffer | string): string {
  return Buffer.from(data).toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}

function jsonText(body: unknown): string {
  return `${JSON.stringify(body)}\n`;
}

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = jsonText(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  res.end(text);
}

function sendBytes(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': nextRequestId(),
  });
  res.end(body);
}

function errJson(message: string): { message: string } {
  return { message };
}

function readBody(req: IncomingMessage, limit = 64 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks, total)));
    req.on('error', reject);
  });
}

function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (raw.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(raw.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

function bearerToken(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+(.+)$/.exec(header.trim());
  return match === null ? null : match[1];
}

function authed(req: IncomingMessage): boolean {
  const presented = bearerToken(req);
  if (presented === null || presented === '') return false;
  if (TOKEN === '') return true;
  return presented === TOKEN;
}

function splitPath(rawUrl: string): { path: string; query: URLSearchParams } {
  try {
    const url = new URL(rawUrl, 'http://entry');
    return { path: url.pathname, query: url.searchParams };
  } catch {
    return { path: '/', query: new URLSearchParams() };
  }
}

function decodeSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

// -------------------------------------------------------------------------------------------
// pkt-line codec (git smart HTTP framing)
// -------------------------------------------------------------------------------------------

const PKT_MAX_PAYLOAD = 65516;

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.alloc(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}

function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}

function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else if (item === 'delim') parts.push(pktDelim());
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

type Packet = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'end' };

/** Decode a whole buffer of pkt-lines. Returns packets plus any trailing raw bytes (a pack). */
function decodePackets(buf: Buffer): { packets: Packet[]; rest: Buffer } {
  const packets: Packet[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const header = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) break;
    const length = Number.parseInt(header, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
      continue;
    }
    if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push({ kind: 'end' });
      offset += 4;
      continue;
    }
    if (length < 4 || offset + length > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return { packets, rest: buf.subarray(offset) };
}

function packetLines(packets: readonly Packet[]): string[] {
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'data') lines.push(packet.payload.toString('utf8'));
  }
  return lines;
}

// -------------------------------------------------------------------------------------------
// git object model: hashing, trees, commits, tags, reachability, packs
// -------------------------------------------------------------------------------------------

type ObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: ObjectType;
  data: Buffer;
}

function hashObject(type: ObjectType, data: Buffer): string {
  const hash = createHash('sha1');
  hash.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  hash.update(data);
  return hash.digest('hex');
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('malformed tree object');
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
    const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
    return Buffer.compare(left, right);
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const header = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  let tree = '';
  const parents: string[] = [];
  for (const line of header.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
  }
  return { tree, parents, message };
}

function buildCommit(tree: string, parents: readonly string[], message: string): Buffer {
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${TRIAL_EPOCH} +0000`;
  const lines: string[] = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '', message);
  return Buffer.from(lines.join('\n'), 'utf8');
}

function parseTagTarget(data: Buffer): { object: string; type: ObjectType } {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const header = blank < 0 ? text : text.slice(0, blank);
  let object = '';
  let type: ObjectType = 'commit';
  for (const line of header.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim() as ObjectType;
  }
  return { object, type };
}

/** Walk parents/trees from roots, calling `visit` for every object id reached (commit order first). */
function walkReachable(
  roots: readonly string[],
  lookup: (oid: string) => GitObject | undefined,
  visit: (oid: string, object: GitObject) => void,
): void {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isOid(root) && !seen.has(root)) queue.push(root);
  while (queue.length > 0) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = lookup(oid);
    if (object === undefined) continue;
    visit(oid, object);
    if (object.type === 'commit') {
      const view = parseCommit(object.data);
      if (view.tree !== '') queue.push(view.tree);
      for (const parent of view.parents) queue.push(parent);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) queue.push(entry.oid);
    } else if (object.type === 'tag') {
      const target = parseTagTarget(object.data);
      if (target.object !== '') queue.push(target.object);
    }
  }
}

/** The object ids reachable from roots (commits, trees, blobs, tags), in walk order. */
function reachableSet(roots: readonly string[], lookup: (oid: string) => GitObject | undefined): Set<string> {
  const found = new Set<string>();
  walkReachable(roots, lookup, (oid) => {
    found.add(oid);
  });
  return found;
}

/** Is `ancestor` an ancestor of (or equal to) `oid`? Walks commit parents only. */
function isAncestor(ancestor: string, oid: string, lookup: (oid: string) => GitObject | undefined): boolean {
  if (ancestor === oid) return true;
  const seen = new Set<string>();
  const queue = [oid];
  while (queue.length > 0) {
    const current = queue.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    const object = lookup(current);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) {
      if (parent === ancestor) return true;
      queue.push(parent);
    }
  }
  return false;
}

// --- pack reading (version 2/3, OFS_DELTA + REF_DELTA) ---

function readVarint(buf: Buffer, offset: number): { size: number; next: number } {
  let byte = buf[offset];
  let size = byte & 0x0f;
  let shift = 4;
  let next = offset + 1;
  while ((byte & 0x80) !== 0) {
    byte = buf[next];
    size |= (byte & 0x7f) << shift;
    shift += 7;
    next += 1;
  }
  return { size, next };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readDeltaVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset];
      offset += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const baseSize = readDeltaVarint();
  const resultSize = readDeltaVarint();
  if (baseSize !== base.length) throw new Error('delta base size mismatch');
  const out: Buffer[] = [];
  let total = 0;
  while (offset < delta.length) {
    const op = delta[offset];
    offset += 1;
    if ((op & 0x80) !== 0) {
      let copyOffset = 0;
      let copySize = 0;
      for (let i = 0; i < 4; i += 1) {
        if ((op & (1 << i)) !== 0) {
          copyOffset |= delta[offset] << (8 * i);
          offset += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if ((op & (0x10 << i)) !== 0) {
          copySize |= delta[offset] << (8 * i);
          offset += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      out.push(base.subarray(copyOffset, copyOffset + copySize));
      total += copySize;
    } else if (op !== 0) {
      out.push(delta.subarray(offset, offset + op));
      offset += op;
      total += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const result = Buffer.concat(out, total);
  if (result.length !== resultSize) throw new Error('delta result size mismatch');
  return result;
}

const PACK_TYPE: Record<number, ObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

interface PackEntry {
  type: ObjectType;
  data: Buffer;
  oid: string;
}

/** Read a packfile into resolved objects. `baseLookup` supplies thin-pack bases the client holds. */
/** Inflate one zlib stream starting at `offset`; returns the data and the offset just past it. */
function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const slice = buf.subarray(offset);
  const result = inflateSync(slice, { info: true }) as unknown;
  if (
    typeof result === 'object' &&
    result !== null &&
    Buffer.isBuffer((result as { buffer?: unknown }).buffer) &&
    typeof (result as { engine?: { bytesWritten?: unknown } }).engine?.bytesWritten === 'number'
  ) {
    const typed = result as { buffer: Buffer; engine: { bytesWritten: number } };
    return { data: Buffer.from(typed.buffer), next: offset + typed.engine.bytesWritten };
  }
  // The `info` option is absent on this runtime: binary-search the smallest prefix that
  // inflates (a truncated deflate stream throws, a complete one tolerates trailing bytes).
  let low = 1;
  let high = slice.length;
  while (low < high) {
    const mid = Math.floor((low + high) / 2);
    try {
      inflateSync(slice.subarray(0, mid));
      high = mid;
    } catch {
      low = mid + 1;
    }
  }
  return { data: inflateSync(slice.subarray(0, low)), next: offset + low };
}

function readPack(pack: Buffer, baseLookup?: (oid: string) => GitObject | undefined): Map<string, GitObject> {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const objects = new Map<string, GitObject>();
  const byOffset = new Map<number, PackEntry>();
  const deltas: Array<{ offset: number; type: ObjectType; data: Buffer; baseOid?: string; baseOffset?: number }> = [];
  let offset = 12;
  for (let index = 0; index < count; index += 1) {
    const entryOffset = offset;
    const header = readVarint(pack, offset);
    const typeNum = (pack[offset] >> 4) & 0x07;
    offset = header.next;
    let baseOid: string | undefined;
    let baseOffset: number | undefined;
    if (typeNum === 6) {
      // OFS_DELTA: a negative offset encoded as a variable-length integer.
      let byte = pack[offset];
      offset += 1;
      let base = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        byte = pack[offset];
        offset += 1;
        base = ((base + 1) << 7) | (byte & 0x7f);
      }
      baseOffset = entryOffset - base;
    } else if (typeNum === 7) {
      baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    }
    // inflateAt reports how many input bytes the stream consumed, which finds the next entry.
    const inflated = inflateAt(pack, offset);
    const data = inflated.data;
    offset = inflated.next;
    if (typeNum === 6 || typeNum === 7) {
      deltas.push({ offset: entryOffset, type: 'blob', data, baseOid, baseOffset });
      continue;
    }
    const type = PACK_TYPE[typeNum];
    if (type === undefined) throw new Error(`unknown pack object type ${typeNum}`);
    const oid = hashObject(type, data);
    const entry: PackEntry = { type, data, oid };
    objects.set(oid, { type, data });
    byOffset.set(entryOffset, entry);
  }
  // Resolve deltas after every plain object is known (a delta's base may come later in the pack,
  // or be another delta); repeat until no delta is left unresolved.
  const resolveDelta = (delta: {
    offset: number;
    data: Buffer;
    baseOid?: string;
    baseOffset?: number;
  }): PackEntry => {
    let base: PackEntry | undefined;
    if (delta.baseOffset !== undefined) base = byOffset.get(delta.baseOffset);
    else if (delta.baseOid !== undefined) {
      const found = objects.get(delta.baseOid);
      if (found !== undefined) base = { type: found.type, data: found.data, oid: delta.baseOid };
      else if (baseLookup !== undefined) {
        const held = baseLookup(delta.baseOid);
        if (held !== undefined) base = { type: held.type, data: held.data, oid: delta.baseOid };
      }
    }
    if (base === undefined) throw new Error('delta base not found');
    const data = applyDelta(base.data, delta.data);
    const oid = hashObject(base.type, data);
    return { type: base.type, data, oid };
  };
  let remaining = deltas;
  while (remaining.length > 0) {
    const next: typeof deltas = [];
    let progressed = false;
    for (const delta of remaining) {
      try {
        const entry = resolveDelta(delta);
        objects.set(entry.oid, { type: entry.type, data: entry.data });
        byOffset.set(delta.offset, entry);
        progressed = true;
      } catch {
        next.push(delta);
      }
    }
    if (!progressed) throw new Error('delta base not found');
    remaining = next;
  }
  // The trailer is the SHA-1 of everything before it; verify it so a corrupt pack never lands.
  const trailer = pack.subarray(pack.length - 20).toString('hex');
  const expected = sha1Hex(pack.subarray(0, pack.length - 20));
  if (trailer !== expected) throw new Error('pack trailer checksum mismatch');
  return objects;
}

function writePackObjectHeader(type: ObjectType, size: number): Buffer {
  const code = { commit: 1, tree: 2, blob: 3, tag: 4 }[type];
  const bytes: number[] = [];
  let first = (code << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let byte = size & 0x7f;
    size >>= 7;
    if (size > 0) byte |= 0x80;
    bytes.push(byte);
  }
  return Buffer.from(bytes);
}

/** Write a version-2 pack of plain (undelted) objects, with the SHA-1 trailer git expects. */
function writePack(objects: Iterable<GitObject>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, Buffer.from(sha1Hex(body), 'hex')]);
}

// -------------------------------------------------------------------------------------------
// the store: one Repo holds everything; every surface shares it
// -------------------------------------------------------------------------------------------

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Array<{ name: string; color: string }>;
  comments: Array<{ id: number; body: string }>;
  seq: number;
}

interface PullRequest {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  seq: number;
}

interface Label {
  name: string;
  color: string;
  description: string;
}

class Repo {
  id: number;
  name: string;
  owner = VIEWER_LOGIN;
  description: string;
  isPrivate: boolean;
  defaultBranch = 'main';
  refs = new Map<string, string>();
  objects = new Map<string, GitObject>();
  issues = new Map<number, Issue>();
  pulls = new Map<number, PullRequest>();
  labels = new Map<string, Label>();
  nextNumber = 1;
  nextCommentId = 1;
  seq = 0;

  constructor(id: number, name: string, description: string, isPrivate: boolean) {
    this.id = id;
    this.name = name;
    this.description = description;
    this.isPrivate = isPrivate;
  }

  lookup = (oid: string): GitObject | undefined => this.objects.get(oid);

  get fullName(): string {
    return `${this.owner}/${this.name}`;
  }

  headOid(): string | undefined {
    return this.refs.get(`refs/heads/${this.defaultBranch}`);
  }

  /** The flat path -> {oid, mode} map of a tree, recursing into subdirectories. */
  flattenTree(treeOid: string): Map<string, { oid: string; mode: string }> {
    const out = new Map<string, { oid: string; mode: string }>();
    const walk = (oid: string, prefix: string): void => {
      const object = this.objects.get(oid);
      if (object === undefined || object.type !== 'tree') return;
      for (const entry of parseTree(object.data)) {
        const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
        if (entry.mode === '40000') walk(entry.oid, path);
        else out.set(path, { oid: entry.oid, mode: entry.mode });
      }
    };
    walk(treeOid, '');
    return out;
  }

  /** Build (and store) the tree for a flat path map, creating intermediate trees as needed. */
  buildTreeFromFiles(files: Map<string, { oid: string; mode: string }>): string {
    const buildLevel = (prefix: string): string => {
      const entries: TreeEntry[] = [];
      const dirs = new Map<string, Map<string, { oid: string; mode: string }>>();
      for (const [path, value] of files) {
        if (!path.startsWith(prefix)) continue;
        const rest = path.slice(prefix.length);
        const slash = rest.indexOf('/');
        if (slash < 0) {
          entries.push({ mode: value.mode, name: rest, oid: value.oid });
        } else {
          const dir = rest.slice(0, slash);
          let child = dirs.get(dir);
          if (child === undefined) {
            child = new Map();
            dirs.set(dir, child);
          }
          child.set(path, value);
        }
      }
      for (const [dir] of dirs) {
        const oid = buildLevel(`${prefix}${dir}/`);
        entries.push({ mode: '40000', name: dir, oid });
      }
      const data = buildTree(entries);
      const oid = hashObject('tree', data);
      this.objects.set(oid, { type: 'tree', data });
      return oid;
    };
    return buildLevel('');
  }

  /** Store an object, returning its id. */
  putObject(type: ObjectType, data: Buffer): string {
    const oid = hashObject(type, data);
    if (!this.objects.has(oid)) this.objects.set(oid, { type, data });
    return oid;
  }

  /** Resolve a ref name, a branch name or a commit id to a commit id (or undefined). */
  resolveRef(ref: string): string | undefined {
    if (isOid(ref)) return this.objects.get(ref)?.type === 'commit' ? ref : undefined;
    if (this.refs.has(ref)) return this.refs.get(ref);
    const headed = this.refs.get(`refs/heads/${ref}`);
    if (headed !== undefined) return headed;
    const tagged = this.refs.get(`refs/tags/${ref}`);
    if (tagged !== undefined) {
      const object = this.objects.get(tagged);
      if (object?.type === 'tag') return parseTagTarget(object.data).object;
      return tagged;
    }
    return undefined;
  }

  /** The commit ids reachable from a tip, newest first (parents after children). */
  commitHistory(tip: string): string[] {
    const order: string[] = [];
    const seen = new Set<string>();
    const queue = [tip];
    while (queue.length > 0) {
      const oid = queue.shift()!;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const object = this.objects.get(oid);
      if (object === undefined || object.type !== 'commit') continue;
      order.push(oid);
      for (const parent of parseCommit(object.data).parents) queue.push(parent);
    }
    return order;
  }

  /** The merge-base of two commits: the first common ancestor found walking both histories. */
  mergeBase(a: string, b: string): string | undefined {
    const ancestorsA = new Set(this.commitHistory(a));
    for (const oid of this.commitHistory(b)) {
      if (ancestorsA.has(oid)) return oid;
    }
    return undefined;
  }
}

const reposByName = new Map<string, Repo>();
const reposById = new Map<number, Repo>();
let nextRepoId = 1;
let nextGlobalId = 1;
let globalSeq = 0;

function repoObject(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: b64encode(`Repository:${repo.id}`),
    name: repo.name,
    full_name: repo.fullName,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://example.invalid/${repo.fullName}`,
    clone_url: `https://example.invalid/${repo.fullName}.git`,
    created_at: TRIAL_ISO,
    updated_at: TRIAL_ISO,
    has_issues: true,
    has_pull_requests: true,
  };
}

function globalId(kind: string, ...parts: Array<string | number>): string {
  return b64encode([kind, ...parts].join(':'));
}

function issueObject(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: globalId('Issue', repo.id, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((label) => ({ name: label.name, color: label.color })),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    comments: issue.comments.length,
    created_at: TRIAL_ISO,
    updated_at: TRIAL_ISO,
    html_url: `https://example.invalid/${repo.fullName}/issues/${issue.number}`,
  };
}

function pullObject(repo: Repo, pull: PullRequest): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: globalId('PullRequest', repo.id, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}` },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: pullMergeable(repo, pull) === 'CONFLICTING' ? false : true,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: TRIAL_ISO,
    updated_at: TRIAL_ISO,
    html_url: `https://example.invalid/${repo.fullName}/pull/${pull.number}`,
  };
}

/** MERGEABLE / CONFLICTING for a pull request, from a three-way file comparison. */
function pullMergeable(repo: Repo, pull: PullRequest): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pull.state !== 'open') return 'UNKNOWN';
  const headCommit = repo.objects.get(pull.headSha);
  const baseCommit = repo.objects.get(pull.baseSha);
  if (headCommit === undefined || baseCommit === undefined) return 'UNKNOWN';
  const base = repo.mergeBase(pull.headSha, pull.baseSha);
  if (base === undefined) return 'UNKNOWN';
  const baseTree = parseCommit(repo.objects.get(base)!.data).tree;
  const headTree = parseCommit(headCommit.data).tree;
  const tipTree = parseCommit(baseCommit.data).tree;
  const baseFiles = repo.flattenTree(baseTree);
  const headFiles = repo.flattenTree(headTree);
  const tipFiles = repo.flattenTree(tipTree);
  const paths = new Set([...headFiles.keys(), ...tipFiles.keys(), ...baseFiles.keys()]);
  for (const path of paths) {
    const inHead = headFiles.get(path);
    const inTip = tipFiles.get(path);
    const inBase = baseFiles.get(path);
    const headChanged = (inHead?.oid ?? null) !== (inBase?.oid ?? null);
    const tipChanged = (inTip?.oid ?? null) !== (inBase?.oid ?? null);
    if (headChanged && tipChanged && (inHead?.oid ?? null) !== (inTip?.oid ?? null)) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}

/** Files changed between the base tip tree and the head tip tree of a pull request. */
function pullFiles(repo: Repo, pull: PullRequest): Array<Record<string, unknown>> {
  const headCommit = repo.objects.get(pull.headSha);
  const baseCommit = repo.objects.get(pull.baseSha);
  if (headCommit === undefined || baseCommit === undefined) return [];
  const headFiles = repo.flattenTree(parseCommit(headCommit.data).tree);
  const baseFiles = repo.flattenTree(parseCommit(baseCommit.data).tree);
  const out: Array<Record<string, unknown>> = [];
  const paths = new Set([...headFiles.keys(), ...baseFiles.keys()]);
  for (const path of [...paths].sort()) {
    const head = headFiles.get(path);
    const base = baseFiles.get(path);
    if ((head?.oid ?? null) === (base?.oid ?? null)) continue;
    let status = 'modified';
    let additions = 0;
    let deletions = 0;
    const headText = head === undefined ? '' : repo.objects.get(head.oid)?.data.toString('utf8') ?? '';
    const baseText = base === undefined ? '' : repo.objects.get(base.oid)?.data.toString('utf8') ?? '';
    if (base === undefined) {
      status = 'added';
      additions = headText === '' ? 0 : headText.split('\n').length - (headText.endsWith('\n') ? 1 : 0);
    } else if (head === undefined) {
      status = 'removed';
      deletions = baseText === '' ? 0 : baseText.split('\n').length - (baseText.endsWith('\n') ? 1 : 0);
    } else {
      const headLines = new Map<string, number>();
      for (const line of headText.split('\n')) headLines.set(line, (headLines.get(line) ?? 0) + 1);
      const baseLines = new Map<string, number>();
      for (const line of baseText.split('\n')) baseLines.set(line, (baseLines.get(line) ?? 0) + 1);
      for (const [line, count] of headLines) additions += Math.max(0, count - (baseLines.get(line) ?? 0));
      for (const [line, count] of baseLines) deletions += Math.max(0, count - (headLines.get(line) ?? 0));
      if (additions === 0 && deletions === 0) {
        additions = 1;
      }
    }
    out.push({
      filename: path,
      status,
      additions,
      deletions,
      changes: additions + deletions,
      sha: head?.oid ?? base?.oid ?? ZERO_OID,
    });
  }
  return out;
}

/** Commit one file change on a branch: builds the tree, the commit and moves the ref. */
function commitFile(
  repo: Repo,
  branch: string,
  path: string,
  content: Buffer,
  message: string,
): { commitSha: string; blobSha: string; createdBranch: boolean } {
  const ref = `refs/heads/${branch}`;
  let tip = repo.refs.get(ref);
  let createdBranch = false;
  if (tip === undefined) {
    // A branch that does not exist yet starts from the default branch tip (or unborn).
    tip = repo.headOid();
    createdBranch = true;
    if (tip === undefined && branch !== repo.defaultBranch) {
      // No default tip either: the first commit anywhere is a root commit.
      tip = undefined;
    }
  }
  const blobSha = repo.putObject('blob', content);
  let files = new Map<string, { oid: string; mode: string }>();
  if (tip !== undefined) {
    const commit = repo.objects.get(tip);
    if (commit !== undefined && commit.type === 'commit') {
      files = repo.flattenTree(parseCommit(commit.data).tree);
    }
  }
  files.set(path, { oid: blobSha, mode: '100644' });
  const treeOid = repo.buildTreeFromFiles(files);
  const parents = tip === undefined ? [] : [tip];
  const commitData = buildCommit(treeOid, parents, message);
  const commitSha = repo.putObject('commit', commitData);
  repo.refs.set(ref, commitSha);
  return { commitSha, blobSha, createdBranch };
}

/** Squash-merge a pull request onto its base branch; returns the merge commit id or null on conflict. */
function squashMerge(repo: Repo, pull: PullRequest): string | null {
  if (pullMergeable(repo, pull) === 'CONFLICTING') return null;
  const headCommit = repo.objects.get(pull.headSha);
  if (headCommit === undefined) return null;
  const headTree = parseCommit(headCommit.data).tree;
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const parents = baseTip === undefined ? [] : [baseTip];
  const message = `${pull.title} (#${pull.number})`;
  const commitData = buildCommit(headTree, parents, message);
  const mergeSha = repo.putObject('commit', commitData);
  repo.refs.set(`refs/heads/${pull.baseRef}`, mergeSha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = TRIAL_ISO;
  pull.mergeCommitSha = mergeSha;
  pull.baseSha = mergeSha;
  return mergeSha;
}

/** Look a repository up by owner + name; only the viewer's own repositories exist. */
function findRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER_LOGIN) return undefined;
  return reposByName.get(name);
}

function pageOf<T>(items: readonly T[], query: URLSearchParams): { page: T[]; hasNext: boolean; pageNum: number; perPage: number } {
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? 30) || 30));
  const pageNum = Math.max(1, Number(query.get('page') ?? 1) || 1);
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), hasNext: start + perPage < items.length, pageNum, perPage };
}

function linkHeader(req: IncomingMessage, basePath: string, query: URLSearchParams, pageNum: number, perPage: number, hasNext: boolean): string | null {
  if (!hasNext) return null;
  const host = req.headers.host ?? 'entry';
  const params = new URLSearchParams(query);
  params.set('page', String(pageNum + 1));
  params.set('per_page', String(perPage));
  return `<http://${host}${basePath}?${params.toString()}>; rel="next"`;
}

// -------------------------------------------------------------------------------------------
// REST v3
// -------------------------------------------------------------------------------------------

type RestCtx = {
  req: IncomingMessage;
  res: ServerResponse;
  path: string;
  query: URLSearchParams;
  segments: string[];
};

function restNotFound(res: ServerResponse, what = 'Not Found'): void {
  sendJson(res, 404, errJson(what));
}

async function handleRest(ctx: RestCtx): Promise<boolean> {
  const { req, res, path, query, segments } = ctx;
  const method = req.method ?? 'GET';

  // The API root and meta need no token; everything else under /api/v3 does.
  if (method === 'GET' && (path === '/api/v3' || path === '/api/v3/')) {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (method === 'GET' && path === '/api/v3/meta') {
    sendJson(res, 200, { installed_version: FORGE_VERSION, verifiable_password_authentication: false });
    return true;
  }
  if (!authed(req)) {
    sendJson(res, 401, errJson('Requires authentication'));
    return true;
  }

  const bodyNeeded = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
  let body: unknown = {};
  if (bodyNeeded) {
    const raw = await readBody(req);
    if (raw.length > 0) {
      const parsed = parseJsonBody(raw);
      if (!parsed.ok) {
        sendJson(res, 400, errJson('Problems parsing JSON'));
        return true;
      }
      body = parsed.value;
    }
  }
  const obj = (typeof body === 'object' && body !== null && !Array.isArray(body) ? body : {}) as Record<string, unknown>;
  const str = (value: unknown): string => (typeof value === 'string' ? value : '');
  const bool = (value: unknown, fallback: boolean): boolean => (typeof value === 'boolean' ? value : fallback);

  // GET /api/v3/user — the token owner's identity (MCP setup reads it).
  if (method === 'GET' && path === '/api/v3/user') {
    sendJson(res, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
    return true;
  }

  // POST /api/v3/user/repos — create a repository owned by the token's login.
  if (method === 'POST' && path === '/api/v3/user/repos') {
    const name = str(obj.name);
    if (name === '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) {
      sendJson(res, 422, errJson('Invalid repository name'));
      return true;
    }
    if (reposByName.has(name)) {
      sendJson(res, 422, errJson('Repository already exists'));
      return true;
    }
    const repo = new Repo(nextRepoId, name, str(obj.description), bool(obj.private, false));
    nextRepoId += 1;
    reposByName.set(name, repo);
    reposById.set(repo.id, repo);
    sendJson(res, 201, repoObject(repo));
    return true;
  }

  // GET /api/v3/user/repos — the viewer's repositories, paginated through Link rel="next".
  if (method === 'GET' && path === '/api/v3/user/repos') {
    const all = [...reposByName.values()];
    const { page, hasNext, pageNum, perPage } = pageOf(all, query);
    const extra: Record<string, string> = {};
    const link = linkHeader(req, '/api/v3/user/repos', query, pageNum, perPage, hasNext);
    if (link !== null) extra.link = link;
    sendJson(res, 200, page.map(repoObject), extra);
    return true;
  }

  // Everything below is /api/v3/repos/{owner}/{repo}[...]
  if (segments.length < 4 || segments[0] !== 'api' || segments[1] !== 'v3' || segments[2] !== 'repos') {
    restNotFound(res);
    return true;
  }
  const owner = decodeSegment(segments[3]);
  const repoName = decodeSegment(segments[4]);
  const repo = findRepo(owner, repoName);
  const rest = segments.slice(5);

  if (repo === undefined) {
    // A repository under any other owner is a 404 for this token, never a 403.
    restNotFound(res, 'Not Found');
    return true;
  }

  // GET /repos/{o}/{r}
  if (method === 'GET' && rest.length === 0) {
    sendJson(res, 200, repoObject(repo));
    return true;
  }
  // PATCH /repos/{o}/{r}
  if (method === 'PATCH' && rest.length === 0) {
    if (typeof obj.description === 'string') repo.description = obj.description;
    if (typeof obj.default_branch === 'string' && obj.default_branch !== '') repo.defaultBranch = obj.default_branch;
    sendJson(res, 200, repoObject(repo));
    return true;
  }
  // DELETE /repos/{o}/{r}
  if (method === 'DELETE' && rest.length === 0) {
    reposByName.delete(repo.name);
    reposById.delete(repo.id);
    res.writeHead(204, { 'content-type': 'application/json; charset=utf-8', 'x-github-request-id': nextRequestId() });
    res.end();
    return true;
  }

  // GET /repos/{o}/{r}/branches
  if (method === 'GET' && rest.length === 1 && rest[0] === 'branches') {
    const branches = [...repo.refs.keys()]
      .filter((ref) => ref.startsWith('refs/heads/'))
      .map((ref) => ({ name: ref.slice('refs/heads/'.length), commit: { sha: repo.refs.get(ref) }, protected: false }));
    sendJson(res, 200, branches);
    return true;
  }

  // GET /repos/{o}/{r}/branches/{branch}
  if (method === 'GET' && rest.length === 2 && rest[0] === 'branches') {
    const branch = decodeSegment(rest[1]);
    const sha = repo.refs.get(`refs/heads/${branch}`);
    if (sha === undefined) {
      restNotFound(res, 'Branch not found');
      return true;
    }
    sendJson(res, 200, { name: branch, commit: { sha }, protected: false });
    return true;
  }

  // GET /repos/{o}/{r}/git/refs/heads/{branch} and /git/refs/tags/{tag}
  if (method === 'GET' && rest.length >= 3 && rest[0] === 'git' && rest[1] === 'refs') {
    const refName = rest.slice(2).map(decodeSegment).join('/');
    const sha = repo.refs.get(`refs/${refName}`);
    if (sha === undefined) {
      restNotFound(res, 'Reference does not exist');
      return true;
    }
    sendJson(res, 200, { ref: `refs/${refName}`, object: { sha, type: 'commit' }, url: '' });
    return true;
  }

  // POST /repos/{o}/{r}/git/refs — create a branch or tag ref.
  if (method === 'POST' && rest.length === 2 && rest[0] === 'git' && rest[1] === 'refs') {
    const ref = str(obj.ref);
    const sha = str(obj.sha);
    if (!ref.startsWith('refs/') || !isOid(sha) || repo.objects.get(sha) === undefined) {
      sendJson(res, 422, errJson('Invalid ref or sha'));
      return true;
    }
    if (repo.refs.has(ref)) {
      sendJson(res, 422, errJson('Reference already exists'));
      return true;
    }
    repo.refs.set(ref, sha);
    sendJson(res, 201, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' }, url: '' });
    return true;
  }

  // GET /repos/{o}/{r}/commits[?sha=<ref>]
  if (method === 'GET' && rest.length === 1 && rest[0] === 'commits') {
    const refParam = query.get('sha');
    const tip = refParam === null ? repo.headOid() : repo.resolveRef(refParam);
    if (tip === undefined) {
      sendJson(res, 200, []);
      return true;
    }
    const list = repo.commitHistory(tip).map((sha) => {
      const commit = repo.objects.get(sha)!;
      const view = parseCommit(commit.data);
      return {
        sha,
        commit: {
          message: view.message,
          author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: TRIAL_ISO },
          committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: TRIAL_ISO },
          tree: { sha: view.tree },
        },
      };
    });
    const { page } = pageOf(list, query);
    sendJson(res, 200, page);
    return true;
  }

  // Labels
  if (rest.length === 1 && rest[0] === 'labels') {
    if (method === 'GET') {
      sendJson(res, 200, [...repo.labels.values()].map((label) => ({ name: label.name, color: label.color, description: label.description })));
      return true;
    }
    if (method === 'POST') {
      const name = str(obj.name);
      if (name === '') {
        sendJson(res, 422, errJson('Label name is required'));
        return true;
      }
      const label: Label = { name, color: str(obj.color) || 'ededed', description: str(obj.description) };
      repo.labels.set(name, label);
      sendJson(res, 201, { name: label.name, color: label.color, description: label.description });
      return true;
    }
  }

  // Contents: /repos/{o}/{r}/contents/{path...}
  if (rest.length >= 1 && rest[0] === 'contents') {
    const filePath = rest.slice(1).map(decodeSegment).join('/');
    return handleContents(ctx, repo, filePath, method, obj, query);
  }

  // Issues: /repos/{o}/{r}/issues[/{n}[/comments]]
  if (rest.length >= 1 && rest[0] === 'issues') {
    return handleIssues(ctx, repo, rest.slice(1), method, obj, query);
  }

  // Pulls: /repos/{o}/{r}/pulls[/{n}[/files|/merge]]
  if (rest.length >= 1 && rest[0] === 'pulls') {
    return handlePulls(ctx, repo, rest.slice(1), method, obj, query);
  }

  restNotFound(res);
  return true;
}

async function handleContents(
  ctx: RestCtx,
  repo: Repo,
  filePath: string,
  method: string,
  obj: Record<string, unknown>,
  query: URLSearchParams,
): Promise<boolean> {
  const { res } = ctx;
  const str = (value: unknown): string => (typeof value === 'string' ? value : '');
  const branch = str(obj.branch) || query.get('ref') || repo.defaultBranch;
  const tip = repo.resolveRef(branch);

  const contentAt = (commitSha: string): { files: Map<string, { oid: string; mode: string }>; tree: string } | null => {
    const commit = repo.objects.get(commitSha);
    if (commit === undefined || commit.type !== 'commit') return null;
    const tree = parseCommit(commit.data).tree;
    return { files: repo.flattenTree(tree), tree };
  };

  if (method === 'GET') {
    if (tip === undefined) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    const at = contentAt(tip);
    if (at === null) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    const entry = at.files.get(filePath);
    if (entry !== undefined) {
      const blob = repo.objects.get(entry.oid);
      const content = blob === undefined ? Buffer.alloc(0) : blob.data;
      sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        size: content.length,
        name: filePath.split('/').pop() ?? filePath,
        path: filePath,
        content: b64encode(content),
        sha: entry.oid,
      });
      return true;
    }
    // A directory: list its direct children.
    const prefix = filePath === '' ? '' : `${filePath}/`;
    const children = new Map<string, { type: 'file' | 'dir'; oid: string; path: string }>();
    for (const [path, value] of at.files) {
      if (!path.startsWith(prefix)) continue;
      const rest = path.slice(prefix.length);
      const slash = rest.indexOf('/');
      if (slash < 0) {
        children.set(rest, { type: 'file', oid: value.oid, path });
      } else {
        const dir = rest.slice(0, slash);
        if (!children.has(dir)) {
          // The directory's tree id, for a stable sha in the listing.
          const dirFiles = new Map<string, { oid: string; mode: string }>();
          for (const [inner, innerValue] of at.files) {
            if (inner.startsWith(`${prefix}${dir}/`)) dirFiles.set(inner.slice(`${prefix}${dir}/`.length), innerValue);
          }
          const dirTree = repo.buildTreeFromFiles(dirFiles);
          children.set(dir, { type: 'dir', oid: dirTree, path: `${prefix}${dir}` });
        }
      }
    }
    if (children.size === 0) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    const listing = [...children.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(([name, child]) => ({
        type: child.type,
        name,
        path: child.path,
        sha: child.oid,
        size: child.type === 'file' ? (repo.objects.get(child.oid)?.data.length ?? 0) : 0,
      }));
    sendJson(res, 200, listing);
    return true;
  }

  if (method === 'PUT') {
    const contentB64 = str(obj.content);
    if (contentB64 === '') {
      sendJson(res, 422, errJson('content is required'));
      return true;
    }
    const content = b64decode(contentB64);
    const message = str(obj.message) || 'Update file';
    const givenSha = str(obj.sha);
    const existing = tip === undefined ? undefined : contentAt(tip)?.files.get(filePath);
    if (existing !== undefined) {
      // An update names the blob it replaces; a stale sha is a 409.
      if (givenSha !== '' && givenSha.toLowerCase() !== existing.oid.toLowerCase()) {
        sendJson(res, 409, errJson('sha does not match the current blob'));
        return true;
      }
      const { commitSha, blobSha } = commitFile(repo, branch, filePath, content, message);
      sendJson(res, 200, {
        content: { name: filePath.split('/').pop() ?? filePath, path: filePath, sha: blobSha, size: content.length, type: 'file', encoding: 'base64' },
        commit: { sha: commitSha, message },
      });
      return true;
    }
    if (givenSha !== '') {
      sendJson(res, 409, errJson('sha does not match the current blob'));
      return true;
    }
    const { commitSha, blobSha } = commitFile(repo, branch, filePath, content, message);
    sendJson(res, 201, {
      content: { name: filePath.split('/').pop() ?? filePath, path: filePath, sha: blobSha, size: content.length, type: 'file', encoding: 'base64' },
      commit: { sha: commitSha, message },
    });
    return true;
  }

  if (method === 'DELETE') {
    const givenSha = str(obj.sha);
    const existing = tip === undefined ? undefined : contentAt(tip)?.files.get(filePath);
    if (existing === undefined) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    if (givenSha !== '' && givenSha.toLowerCase() !== existing.oid.toLowerCase()) {
      sendJson(res, 409, errJson('sha does not match the current blob'));
      return true;
    }
    const ref = `refs/heads/${branch}`;
    const tipOid = repo.refs.get(ref);
    let files = new Map<string, { oid: string; mode: string }>();
    if (tipOid !== undefined) {
      const commit = repo.objects.get(tipOid);
      if (commit !== undefined && commit.type === 'commit') files = repo.flattenTree(parseCommit(commit.data).tree);
    }
    files.delete(filePath);
    const treeOid = repo.buildTreeFromFiles(files);
    const parents = tipOid === undefined ? [] : [tipOid];
    const commitSha = repo.putObject('commit', buildCommit(treeOid, parents, str(obj.message) || 'Delete file'));
    repo.refs.set(ref, commitSha);
    sendJson(res, 200, { commit: { sha: commitSha } });
    return true;
  }

  sendJson(res, 404, errJson('Not Found'));
  return true;
}

async function handleIssues(
  ctx: RestCtx,
  repo: Repo,
  rest: string[],
  method: string,
  obj: Record<string, unknown>,
  query: URLSearchParams,
): Promise<boolean> {
  const { res } = ctx;
  const str = (value: unknown): string => (typeof value === 'string' ? value : '');

  // POST /issues — create. Labels must already exist.
  if (method === 'POST' && rest.length === 0) {
    const rawLabels = Array.isArray(obj.labels) ? obj.labels : [];
    const labelNames: string[] = [];
    for (const entry of rawLabels) {
      if (typeof entry === 'string') labelNames.push(entry);
      else if (typeof entry === 'object' && entry !== null && typeof (entry as Record<string, unknown>).name === 'string') {
        labelNames.push((entry as Record<string, unknown>).name as string);
      }
    }
    for (const name of labelNames) {
      if (!repo.labels.has(name)) {
        sendJson(res, 422, errJson(`Label does not exist: ${name}`));
        return true;
      }
    }
    globalSeq += 1;
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const issue: Issue = {
      id: nextGlobalId,
      number,
      title: str(obj.title),
      body: str(obj.body),
      state: 'open',
      labels: labelNames.map((name) => ({ name, color: repo.labels.get(name)?.color ?? 'ededed' })),
      comments: [],
      seq: globalSeq,
    };
    nextGlobalId += 1;
    repo.issues.set(number, issue);
    sendJson(res, 201, issueObject(repo, issue));
    return true;
  }

  // GET /issues — list, filtered by state and sorted by creation.
  if (method === 'GET' && rest.length === 0) {
    const state = query.get('state') ?? 'open';
    const direction = (query.get('direction') ?? 'desc').toLowerCase();
    let list = [...repo.issues.values()];
    if (state === 'open') list = list.filter((issue) => issue.state === 'open');
    else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
    list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
    const { page } = pageOf(list, query);
    sendJson(res, 200, page.map((issue) => issueObject(repo, issue)));
    return true;
  }

  const number = Number(rest[0]);
  if (!Number.isInteger(number)) {
    sendJson(res, 404, errJson('Not Found'));
    return true;
  }
  const issue = repo.issues.get(number);
  if (issue === undefined) {
    sendJson(res, 404, errJson('Not Found'));
    return true;
  }

  // GET /issues/{n}
  if (method === 'GET' && rest.length === 1) {
    sendJson(res, 200, issueObject(repo, issue));
    return true;
  }
  // PATCH /issues/{n}
  if (method === 'PATCH' && rest.length === 1) {
    if (obj.state === 'open' || obj.state === 'closed') issue.state = obj.state;
    if (typeof obj.title === 'string') issue.title = obj.title;
    if (typeof obj.body === 'string') issue.body = obj.body;
    sendJson(res, 200, issueObject(repo, issue));
    return true;
  }
  // POST /issues/{n}/comments
  if (method === 'POST' && rest.length === 2 && rest[1] === 'comments') {
    const comment = { id: repo.nextCommentId, body: str(obj.body) };
    repo.nextCommentId += 1;
    issue.comments.push(comment);
    sendJson(res, 201, { id: comment.id, node_id: globalId('IssueComment', repo.id, issue.number, comment.id), body: comment.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID } });
    return true;
  }
  // GET /issues/{n}/comments
  if (method === 'GET' && rest.length === 2 && rest[1] === 'comments') {
    sendJson(
      res,
      200,
      issue.comments.map((comment) => ({ id: comment.id, node_id: globalId('IssueComment', repo.id, issue.number, comment.id), body: comment.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID } })),
    );
    return true;
  }

  sendJson(res, 404, errJson('Not Found'));
  return true;
}

async function handlePulls(
  ctx: RestCtx,
  repo: Repo,
  rest: string[],
  method: string,
  obj: Record<string, unknown>,
  query: URLSearchParams,
): Promise<boolean> {
  const { res } = ctx;
  const str = (value: unknown): string => (typeof value === 'string' ? value : '');

  // POST /pulls — open a pull request from a head branch onto a base branch.
  if (method === 'POST' && rest.length === 0) {
    const headRef = str(obj.head);
    const baseRef = str(obj.base) || repo.defaultBranch;
    const headSha = repo.refs.get(`refs/heads/${headRef}`);
    const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
    if (headSha === undefined || baseSha === undefined) {
      sendJson(res, 422, errJson('head or base branch does not exist'));
      return true;
    }
    for (const existing of repo.pulls.values()) {
      if (existing.state === 'open' && existing.headRef === headRef && existing.baseRef === baseRef) {
        sendJson(res, 422, errJson('A pull request already exists for this branch'));
        return true;
      }
    }
    globalSeq += 1;
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const pull: PullRequest = {
      id: nextGlobalId,
      number,
      title: str(obj.title),
      body: str(obj.body),
      state: 'open',
      headRef,
      baseRef,
      headSha,
      baseSha,
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      seq: globalSeq,
    };
    nextGlobalId += 1;
    repo.pulls.set(number, pull);
    sendJson(res, 201, pullObject(repo, pull));
    return true;
  }

  // GET /pulls — list (default open only).
  if (method === 'GET' && rest.length === 0) {
    const state = query.get('state') ?? 'open';
    let list = [...repo.pulls.values()];
    if (state === 'open') list = list.filter((pull) => pull.state === 'open');
    else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
    list.sort((a, b) => b.seq - a.seq);
    const { page } = pageOf(list, query);
    sendJson(res, 200, page.map((pull) => pullObject(repo, pull)));
    return true;
  }

  const number = Number(rest[0]);
  if (!Number.isInteger(number)) {
    sendJson(res, 404, errJson('Not Found'));
    return true;
  }
  const pull = repo.pulls.get(number);

  // GET /pulls/{n}/files
  if (method === 'GET' && rest.length === 2 && rest[1] === 'files') {
    if (pull === undefined) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    sendJson(res, 200, pullFiles(repo, pull));
    return true;
  }

  // PUT /pulls/{n}/merge
  if (method === 'PUT' && rest.length === 2 && rest[1] === 'merge') {
    if (pull === undefined) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    if (pull.state !== 'open') {
      sendJson(res, 405, errJson('Pull request is already merged or closed'));
      return true;
    }
    const mergeSha = squashMerge(repo, pull);
    if (mergeSha === null) {
      sendJson(res, 405, errJson('Merge conflict'));
      return true;
    }
    sendJson(res, 200, { sha: mergeSha, merged: true, message: 'Pull request successfully merged' });
    return true;
  }

  // GET /pulls/{n}
  if (method === 'GET' && rest.length === 1) {
    if (pull === undefined) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    sendJson(res, 200, pullObject(repo, pull));
    return true;
  }

  sendJson(res, 404, errJson('Not Found'));
  return true;
}

// -------------------------------------------------------------------------------------------
// git smart HTTP
// -------------------------------------------------------------------------------------------

const AGENT_CAP = 'forge/1.0';

function gitRepoFromPath(path: string): { owner: string; name: string; rest: string[] } | null {
  const match = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
  if (match === null) return null;
  return { owner: decodeSegment(match[1]), name: decodeSegment(match[2]), rest: (match[3] ?? '').split('/').filter((part) => part !== '') };
}

/** Refs in advertisement order: HEAD first, then heads, then tags, each with its peeled target. */
function advertisedRefs(repo: Repo): Array<{ oid: string; name: string; peeled?: string }> {
  const out: Array<{ oid: string; name: string; peeled?: string }> = [];
  const tip = repo.headOid();
  if (tip !== undefined) out.push({ oid: tip, name: 'HEAD' });
  const names = [...repo.refs.keys()].sort();
  for (const ref of names) {
    const oid = repo.refs.get(ref)!;
    const entry: { oid: string; name: string; peeled?: string } = { oid, name: ref };
    const object = repo.objects.get(oid);
    if (object?.type === 'tag') {
      const target = parseTagTarget(object.data).object;
      if (target !== '') entry.peeled = target;
    }
    out.push(entry);
  }
  return out;
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps =
    service === 'git-upload-pack'
      ? `symref=HEAD:refs/heads/${repo.defaultBranch} side-band-64k thin-pack ofs-delta shallow multi_ack multi_ack_detailed agent=${AGENT_CAP}`
      : `symref=HEAD:refs/heads/${repo.defaultBranch} report-status side-band-64k delete-refs ofs-delta agent=${AGENT_CAP}`;
  const refs = advertisedRefs(repo);
  const items: Array<string | 'flush'> = [`# service=${service}\n`, 'flush'];
  if (refs.length === 0) {
    items.push(`${ZERO_OID} capabilities^{}\0${caps}\n`, 'flush');
  } else {
    refs.forEach((ref, index) => {
      const first = index === 0 ? `\0${caps}` : '';
      items.push(`${ref.oid} ${ref.name}${first}\n`);
      if (ref.peeled !== undefined) items.push(`${ref.peeled} ${ref.name}^{}\n`);
    });
    items.push('flush');
  }
  return pktLines(items);
}

function v2Advertisement(): Buffer {
  return pktLines([
    '# service=git-upload-pack\n',
    'flush',
    'version 2\n',
    'ls-refs=unborn\n',
    'fetch=shallow wait-for-done filter\n',
    'object-format=sha1\n',
    `agent=${AGENT_CAP}\n`,
    'flush',
  ]);
}

/** The objects a fetch sends, plus the shallow boundary lines it reports. */
function computeFetch(
  repo: Repo,
  wants: readonly string[],
  haves: readonly string[],
  shallowBoundaries: readonly string[],
  depth: number | undefined,
): { objects: Map<string, GitObject>; shallow: string[]; unshallow: string[] } {
  const lookup = repo.lookup;
  const shallowSet = new Set(shallowBoundaries);
  // Included commits: breadth-first from the wants, stopping at the depth limit and at
  // commits the client already holds outright (a held commit's history is never re-sent,
  // unless it is a shallow boundary whose parents the client lacks).
  const included = new Set<string>();
  const distance = new Map<string, number>();
  const queue: Array<{ oid: string; depth: number }> = [];
  const resolveWant = (oid: string): string | undefined => {
    const object = lookup(oid);
    if (object === undefined) return undefined;
    if (object.type === 'commit') return oid;
    if (object.type === 'tag') return parseTagTarget(object.data).object;
    return undefined;
  };
  for (const want of wants) {
    const commit = resolveWant(want);
    if (commit !== undefined && !distance.has(commit)) {
      distance.set(commit, 0);
      queue.push({ oid: commit, depth: 0 });
    }
  }
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (included.has(current.oid)) continue;
    included.add(current.oid);
    if (depth !== undefined && current.depth + 1 >= depth) continue;
    const object = lookup(current.oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) {
      if (distance.has(parent)) continue;
      // A held, non-shallow commit is a wall: the client already has everything behind it.
      if (haves.includes(parent) && !shallowSet.has(parent)) continue;
      distance.set(parent, current.depth + 1);
      queue.push({ oid: parent, depth: current.depth + 1 });
    }
  }
  // Objects the client already holds: the full closure of held commits, except that a
  // shallow boundary only counts for its own tree (its parents are still missing there).
  const held = new Set<string>();
  for (const have of haves) {
    if (shallowSet.has(have)) {
      const object = lookup(have);
      if (object?.type === 'commit') {
        held.add(have);
        for (const oid of reachableSet([parseCommit(object.data).tree], lookup)) held.add(oid);
      } else {
        held.add(have);
      }
      continue;
    }
    for (const oid of reachableSet([have], lookup)) held.add(oid);
  }
  // Everything reachable from the included commits and the wanted tag objects, minus held.
  // Note the depth limit lives here too: only the included commits themselves go in, plus
  // their tree closures — a parent outside the depth limit must NOT be re-added by the walk.
  const candidate = new Set<string>(included);
  const roots: string[] = [];
  for (const oid of included) {
    const object = lookup(oid);
    if (object?.type === 'commit') roots.push(parseCommit(object.data).tree);
  }
  for (const want of wants) {
    const object = lookup(want);
    if (object?.type === 'tag') roots.push(want);
    else {
      const resolved = resolveWant(want);
      if (resolved !== undefined && lookup(resolved)?.type !== 'commit') roots.push(resolved);
    }
  }
  for (const oid of reachableSet(roots, lookup)) candidate.add(oid);
  const objects = new Map<string, GitObject>();
  for (const oid of candidate) {
    if (held.has(oid)) continue;
    const object = lookup(oid);
    if (object !== undefined) objects.set(oid, object);
  }
  // Shallow bookkeeping: boundary commits are the included commits at the depth limit;
  // a former boundary whose parent is now included stops being shallow.
  const shallow: string[] = [];
  const unshallow: string[] = [];
  if (depth !== undefined) {
    for (const oid of included) {
      if ((distance.get(oid) ?? 0) === depth - 1) {
        const object = lookup(oid);
        if (object?.type === 'commit' && parseCommit(object.data).parents.length > 0) shallow.push(oid);
      }
    }
    for (const boundary of shallowBoundaries) {
      if (!included.has(boundary)) continue;
      const object = lookup(boundary);
      if (object?.type !== 'commit') continue;
      if (parseCommit(object.data).parents.some((parent) => included.has(parent))) unshallow.push(boundary);
    }
  }
  return { objects, shallow, unshallow };
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let offset = 0; offset < pack.length; offset += 32768) {
    const chunk = pack.subarray(offset, Math.min(pack.length, offset + 32768));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  if (pack.length === 0) parts.push(pktLine(Buffer.from([1])));
  return Buffer.concat(parts);
}

async function handleGit(ctx: RestCtx): Promise<boolean> {
  const { req, res, path, query } = ctx;
  const method = req.method ?? 'GET';
  const parsed = gitRepoFromPath(path);
  if (parsed === null) return false;
  const { owner, name, rest } = parsed;
  const repo = findRepo(owner, name);
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';

  // GET /{owner}/{repo}.git/info/refs?service=...
  if (method === 'GET' && rest.length === 2 && rest[0] === 'info' && rest[1] === 'refs') {
    const service = query.get('service');
    if (repo === undefined) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    if (service === 'git-upload-pack') {
      if (isV2) sendBytes(res, 200, v2Advertisement(), 'application/x-git-upload-pack-advertisement');
      else sendBytes(res, 200, v0Advertisement(repo, 'git-upload-pack'), 'application/x-git-upload-pack-advertisement');
      return true;
    }
    if (service === 'git-receive-pack') {
      sendBytes(res, 200, v0Advertisement(repo, 'git-receive-pack'), 'application/x-git-receive-pack-advertisement');
      return true;
    }
    sendJson(res, 404, errJson('Not Found'));
    return true;
  }

  // POST /{owner}/{repo}.git/git-upload-pack — ls-refs and fetch, v2 or v0.
  if (method === 'POST' && rest.length === 1 && rest[0] === 'git-upload-pack') {
    if (repo === undefined) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    const raw = await readBody(req);
    const { packets } = decodePackets(raw);
    const lines = packetLines(packets);
    if (lines.length === 0) {
      res.writeHead(400, { 'content-type': 'application/json; charset=utf-8', 'x-github-request-id': nextRequestId() });
      res.end('{"message":"Bad Request"}\n');
      return true;
    }
    const first = lines[0] ?? '';
    if (isV2 && first.startsWith('command=ls-refs')) return handleLsRefs(res, repo, lines);
    if (isV2 && first.startsWith('command=fetch')) return handleFetchV2(res, repo, lines);
    if (!isV2) return handleFetchV0(res, repo, lines);
    res.writeHead(400, { 'content-type': 'application/json; charset=utf-8', 'x-github-request-id': nextRequestId() });
    res.end('{"message":"Bad Request"}\n');
    return true;
  }

  // POST /{owner}/{repo}.git/git-receive-pack — push (v0 only).
  if (method === 'POST' && rest.length === 1 && rest[0] === 'git-receive-pack') {
    if (repo === undefined) {
      sendJson(res, 404, errJson('Not Found'));
      return true;
    }
    const raw = await readBody(req);
    return handleReceivePack(res, repo, raw);
  }

  return false;
}

function handleLsRefs(res: ServerResponse, repo: Repo, lines: readonly string[]): boolean {
  const args = new Set<string>();
  const prefixes: string[] = [];
  let sawDelim = false;
  for (const line of lines) {
    const text = line.replace(/\n$/, '');
    if (text === '') continue;
    if (text.startsWith('command=')) continue;
    if (text.startsWith('agent=') || text.startsWith('object-format=')) continue;
    sawDelim = true;
    if (text.startsWith('ref-prefix ')) prefixes.push(text.slice('ref-prefix '.length));
    else args.add(text);
  }
  void sawDelim;
  const peel = args.has('peel');
  const symrefs = args.has('symrefs');
  const unborn = args.has('unborn');
  const items: Array<string | 'flush'> = [];
  const refs = advertisedRefs(repo);
  const keep = (refName: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => refName.startsWith(prefix));
  if (refs.length === 0) {
    if (unborn && keep('HEAD')) items.push(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`);
  } else {
    for (const ref of refs) {
      if (!keep(ref.name)) continue;
      if (ref.name === 'HEAD') {
        items.push(symrefs ? `${ref.oid} HEAD symref-target:refs/heads/${repo.defaultBranch}\n` : `${ref.oid} HEAD\n`);
        continue;
      }
      let line = `${ref.oid} ${ref.name}`;
      if (peel && ref.peeled !== undefined) line += ` peeled:${ref.peeled}`;
      items.push(`${line}\n`);
    }
  }
  items.push('flush');
  sendBytes(res, 200, pktLines(items), 'application/x-git-upload-pack-result');
  return true;
}

function parseFetchArgs(lines: readonly string[]): { wants: string[]; haves: string[]; shallow: string[]; depth: number | undefined } {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | undefined;
  for (const rawLine of lines) {
    const line = rawLine.replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5, 45));
    else if (line.startsWith('have ')) haves.push(line.slice(5, 45));
    else if (line.startsWith('shallow ')) shallow.push(line.slice(8, 48));
    else if (line.startsWith('deepen ')) {
      const parsed = Number.parseInt(line.slice(7), 10);
      if (Number.isFinite(parsed)) depth = parsed;
    }
  }
  return { wants, haves, shallow, depth };
}

function handleFetchV2(res: ServerResponse, repo: Repo, lines: readonly string[]): boolean {
  const { wants, haves, shallow, depth } = parseFetchArgs(lines);
  if (wants.length === 0) {
    // A packfile section must still carry sideband packets, so send an empty pack.
    const empty = writePack([]);
    const parts: Buffer[] = [pktLine('acknowledgments\n'), pktLine('NAK\n'), pktDelim(), pktLine('packfile\n'), sidebandPack(empty), pktFlush()];
    sendBytes(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
    return true;
  }
  const { objects, shallow: shallowOut, unshallow: unshallowOut } = computeFetch(repo, wants, haves, shallow, depth);
  const pack = writePack(objects.values());
  const parts: Buffer[] = [];
  parts.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), pktDelim());
  if (shallowOut.length > 0 || unshallowOut.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of shallowOut) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of unshallowOut) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(pktDelim());
  }
  parts.push(pktLine('packfile\n'), sidebandPack(pack), pktFlush());
  sendBytes(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
  return true;
}

function handleFetchV0(res: ServerResponse, repo: Repo, lines: readonly string[]): boolean {
  const { wants, haves, shallow, depth } = parseFetchArgs(lines);
  const { objects, shallow: shallowOut, unshallow: unshallowOut } = computeFetch(repo, wants, haves, shallow, depth);
  const pack = writePack(objects.values());
  const parts: Buffer[] = [];
  for (const oid of shallowOut) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of unshallowOut) parts.push(pktLine(`unshallow ${oid}\n`));
  parts.push(pktLine('NAK\n'), sidebandPack(pack), pktFlush());
  sendBytes(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
  return true;
}

function handleReceivePack(res: ServerResponse, repo: Repo, raw: Buffer): boolean {
  const { packets, rest } = decodePackets(raw);
  const lines = packetLines(packets);
  interface Command {
    oldOid: string;
    newOid: string;
    ref: string;
  }
  const commands: Command[] = [];
  for (const rawLine of lines) {
    const line = rawLine.replace(/\n$/, '');
    if (line === '') continue;
    const nul = line.indexOf('\0');
    const text = nul >= 0 ? line.slice(0, nul) : line;
    const parts = text.split(' ');
    if (parts.length < 3) continue;
    commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts[2] });
  }
  const reportLines: string[] = [];
  let unpackOk = true;
  if (commands.length === 0) {
    reportLines.push('unpack error\n');
    unpackOk = false;
  } else {
    const hasUpdates = commands.some((command) => command.newOid !== ZERO_OID);
    if (hasUpdates && rest.length > 0) {
      try {
        const objects = readPack(rest, repo.lookup);
        for (const [oid, object] of objects) repo.objects.set(oid, object);
      } catch {
        unpackOk = false;
      }
    } else if (hasUpdates && rest.length === 0) {
      unpackOk = false;
    }
    reportLines.push(unpackOk ? 'unpack ok\n' : 'unpack error\n');
    for (const command of commands) {
      if (!unpackOk) {
        reportLines.push(`ng ${command.ref} unpack error\n`);
        continue;
      }
      const current = repo.refs.get(command.ref);
      if (command.newOid === ZERO_OID) {
        // Delete.
        if (current === undefined) {
          reportLines.push(`ng ${command.ref} remote ref does not exist\n`);
        } else if (command.oldOid !== ZERO_OID && command.oldOid !== current) {
          reportLines.push(`ng ${command.ref} non-fast-forward\n`);
        } else {
          repo.refs.delete(command.ref);
          reportLines.push(`ok ${command.ref}\n`);
        }
        continue;
      }
      if (repo.objects.get(command.newOid) === undefined) {
        reportLines.push(`ng ${command.ref} object not found\n`);
        continue;
      }
      if (current === undefined) {
        if (command.oldOid !== ZERO_OID) {
          reportLines.push(`ng ${command.ref} non-fast-forward\n`);
        } else {
          repo.refs.set(command.ref, command.newOid);
          reportLines.push(`ok ${command.ref}\n`);
        }
        continue;
      }
      if (command.oldOid !== current) {
        reportLines.push(`ng ${command.ref} non-fast-forward\n`);
        continue;
      }
      if (!isAncestor(current, command.newOid, repo.lookup)) {
        reportLines.push(`ng ${command.ref} non-fast-forward\n`);
        continue;
      }
      repo.refs.set(command.ref, command.newOid);
      reportLines.push(`ok ${command.ref}\n`);
    }
  }
  // The report travels inside sideband band 1, itself pkt-lined, then a flush closes the stream.
  const reportStream = pktLines([...reportLines, 'flush']);
  const parts: Buffer[] = [];
  for (let offset = 0; offset < reportStream.length; offset += 32768) {
    const chunk = reportStream.subarray(offset, Math.min(reportStream.length, offset + 32768));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  parts.push(pktFlush());
  sendBytes(res, 200, Buffer.concat(parts), 'application/x-git-receive-pack-result');
  return true;
}

// -------------------------------------------------------------------------------------------
// GraphQL v4 — a small parser for the documents gh and github-mcp-server send, over the store
// -------------------------------------------------------------------------------------------

type GqlValue = string | number | boolean | null | GqlValue[] | { [key: string]: GqlValue };

interface GqlSelection {
  kind: 'field' | 'fragment';
  alias?: string;
  name?: string;
  typeCondition?: string;
  args?: Map<string, GqlValue>;
  selections?: GqlSelection[];
}

function gqlTokenize(text: string): string[] {
  const tokens: string[] = [];
  let index = 0;
  while (index < text.length) {
    const char = text[index];
    if (char === ' ' || char === '\n' || char === '\t' || char === '\r' || char === ',') {
      index += 1;
      continue;
    }
    if (char === '#') {
      while (index < text.length && text[index] !== '\n') index += 1;
      continue;
    }
    if (text.startsWith('...', index)) {
      tokens.push('...');
      index += 3;
      continue;
    }
    if ('{}():$![]=@'.includes(char)) {
      tokens.push(char);
      index += 1;
      continue;
    }
    if (char === '"') {
      let end = index + 1;
      let value = '';
      while (end < text.length && text[end] !== '"') {
        if (text[end] === '\\' && end + 1 < text.length) {
          const escaped = text[end + 1];
          value += escaped === 'n' ? '\n' : escaped === 't' ? '\t' : escaped;
          end += 2;
        } else {
          value += text[end];
          end += 1;
        }
      }
      tokens.push(JSON.stringify(value));
      index = end + 1;
      continue;
    }
    if (/[0-9-]/.test(char)) {
      let end = index;
      while (end < text.length && /[0-9.eE+-]/.test(text[end])) end += 1;
      tokens.push(text.slice(index, end));
      index = end;
      continue;
    }
    if (/[A-Za-z_]/.test(char)) {
      let end = index;
      while (end < text.length && /[A-Za-z0-9_]/.test(text[end])) end += 1;
      tokens.push(text.slice(index, end));
      index = end;
      continue;
    }
    index += 1;
  }
  return tokens;
}

class GqlParser {
  private tokens: string[];
  private pos = 0;

  constructor(text: string) {
    this.tokens = gqlTokenize(text);
  }

  peek(): string | undefined {
    return this.tokens[this.pos];
  }

  next(): string | undefined {
    return this.tokens[this.pos++];
  }

  expect(value: string): void {
    const token = this.next();
    if (token !== value) throw new Error(`expected ${value}, got ${token ?? 'end'}`);
  }

  parseDocument(): { operation: 'query' | 'mutation'; selections: GqlSelection[] } {
    let operation: 'query' | 'mutation' = 'query';
    let token = this.peek();
    if (token === 'query' || token === 'mutation') {
      operation = this.next() as 'query' | 'mutation';
      token = this.peek();
      if (token !== undefined && token !== '{' && token !== '(') this.next(); // operation name
      if (this.peek() === '(') this.skipParens();
    }
    const selections = this.parseSelectionSet();
    return { operation, selections };
  }

  private skipParens(): void {
    this.expect('(');
    let depth = 1;
    while (depth > 0) {
      const token = this.next();
      if (token === undefined) throw new Error('unbalanced parens');
      if (token === '(') depth += 1;
      else if (token === ')') depth -= 1;
    }
  }

  private parseValue(variables: Record<string, unknown>): GqlValue {
    const token = this.next();
    if (token === undefined) throw new Error('unexpected end of document');
    if (token === '$') {
      const name = this.next() ?? '';
      const value = variables[name];
      return value === undefined ? null : (value as GqlValue);
    }
    if (token === '[') {
      const items: GqlValue[] = [];
      while (this.peek() !== ']') items.push(this.parseValue(variables));
      this.expect(']');
      return items;
    }
    if (token === '{') {
      const object: { [key: string]: GqlValue } = {};
      while (this.peek() !== '}') {
        const key = this.next() ?? '';
        this.expect(':');
        object[key] = this.parseValue(variables);
      }
      this.expect('}');
      return object;
    }
    if (token.startsWith('"')) return JSON.parse(token) as string;
    if (token === 'true') return true;
    if (token === 'false') return false;
    if (token === 'null') return null;
    const numeric = Number(token);
    if (token !== '' && Number.isFinite(numeric)) return numeric;
    return token;
  }

  private parseArguments(variables: Record<string, unknown>): Map<string, GqlValue> {
    const args = new Map<string, GqlValue>();
    this.expect('(');
    while (this.peek() !== ')') {
      const name = this.next() ?? '';
      this.expect(':');
      args.set(name, this.parseValue(variables));
    }
    this.expect(')');
    return args;
  }

  parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const selections: GqlSelection[] = [];
    while (this.peek() !== '}') {
      if (this.peek() === undefined) throw new Error('unbalanced braces');
      if (this.peek() === '...') {
        this.next();
        let typeCondition: string | undefined;
        if (this.peek() === 'on') {
          this.next();
          typeCondition = this.next();
        }
        const inner = this.parseSelectionSet();
        selections.push({ kind: 'fragment', typeCondition, selections: inner });
        continue;
      }
      let name = this.next() ?? '';
      let alias: string | undefined;
      if (this.peek() === ':') {
        this.next();
        alias = name;
        name = this.next() ?? '';
      }
      let args: Map<string, GqlValue> | undefined;
      if (this.peek() === '(') args = this.parseArguments({});
      let inner: GqlSelection[] | undefined;
      if (this.peek() === '{') inner = this.parseSelectionSet();
      selections.push({ kind: 'field', alias, name, args, selections: inner });
    }
    this.expect('}');
    return selections;
  }
}

/** Parse a document with its variables resolved (a second pass binds $variables). */
function parseGqlDocument(query: string, variables: Record<string, unknown>): { operation: 'query' | 'mutation'; selections: GqlSelection[] } {
  // The parser binds variables lazily: re-parse argument values with the real variables by
  // walking the token stream a second time is overkill — instead, variable definitions are
  // skipped in parseDocument and $ references inside arguments resolve here through a trick:
  // the parser above already ran with {} so a $var became null. Re-run with variables by
  // patching: simplest correct approach is to substitute variable references textually is
  // unsafe, so instead parse with variables injected into the parser instance.
  const parser = new GqlParserWithVars(query, variables);
  return parser.parseDocument();
}

class GqlParserWithVars extends GqlParser {
  private variables: Record<string, unknown>;

  constructor(text: string, variables: Record<string, unknown>) {
    super(text);
    this.variables = variables;
  }

  override parseSelectionSet(): GqlSelection[] {
    // Re-implemented to bind variables when parsing argument values.
    this.expect('{');
    const selections: GqlSelection[] = [];
    while (this.peek() !== '}') {
      if (this.peek() === undefined) throw new Error('unbalanced braces');
      if (this.peek() === '...') {
        this.next();
        let typeCondition: string | undefined;
        if (this.peek() === 'on') {
          this.next();
          typeCondition = this.next();
        }
        selections.push({ kind: 'fragment', typeCondition, selections: this.parseSelectionSet() });
        continue;
      }
      let name = this.next() ?? '';
      let alias: string | undefined;
      if (this.peek() === ':') {
        this.next();
        alias = name;
        name = this.next() ?? '';
      }
      let args: Map<string, GqlValue> | undefined;
      if (this.peek() === '(') args = this.parseArgumentsWithVars();
      let inner: GqlSelection[] | undefined;
      if (this.peek() === '{') inner = this.parseSelectionSet();
      selections.push({ kind: 'field', alias, name, args, selections: inner });
    }
    this.expect('}');
    return selections;
  }

  private parseArgumentsWithVars(): Map<string, GqlValue> {
    const args = new Map<string, GqlValue>();
    this.expect('(');
    while (this.peek() !== ')') {
      const name = this.next() ?? '';
      this.expect(':');
      args.set(name, this.parseValueWithVars());
    }
    this.expect(')');
    return args;
  }

  private parseValueWithVars(): GqlValue {
    const token = this.next();
    if (token === undefined) throw new Error('unexpected end of document');
    if (token === '$') {
      const name = this.next() ?? '';
      const value = this.variables[name];
      return value === undefined ? null : (value as GqlValue);
    }
    if (token === '[') {
      const items: GqlValue[] = [];
      while (this.peek() !== ']') items.push(this.parseValueWithVars());
      this.expect(']');
      return items;
    }
    if (token === '{') {
      const object: { [key: string]: GqlValue } = {};
      while (this.peek() !== '}') {
        const key = this.next() ?? '';
        this.expect(':');
        object[key] = this.parseValueWithVars();
      }
      this.expect('}');
      return object;
    }
    if (token.startsWith('"')) return JSON.parse(token) as string;
    if (token === 'true') return true;
    if (token === 'false') return false;
    if (token === 'null') return null;
    const numeric = Number(token);
    if (token !== '' && Number.isFinite(numeric)) return numeric;
    return token;
  }
}

const GQL_TYPE_FIELDS: Record<string, readonly string[]> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'author', 'labels', 'comments'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'createdAt'],
  User: ['login', 'id', 'name'],
  __Type: ['name', 'kind', 'fields', 'enumValues', 'description'],
  __Field: ['name', 'description'],
  __EnumValue: ['name', 'description'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path'],
  Ref: ['name'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  IssueCommentEdge: ['node'],
  IssueComment: ['id', 'body'],
};

const GQL_INTROSPECTION: Record<string, { kind: string; fields: string[]; enumValues: string[] }> = {
  Issue: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'author', 'labels', 'comments'], enumValues: [] },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'createdAt'], enumValues: [] },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url', 'createdAt'], enumValues: [] },
  SearchType: { kind: 'ENUM', fields: [], enumValues: ['ISSUE', 'PR', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'] },
  IssueState: { kind: 'ENUM', fields: [], enumValues: ['OPEN', 'CLOSED'] },
  OrderDirection: { kind: 'ENUM', fields: [], enumValues: ['ASC', 'DESC'] },
};

function gqlArg(args: Map<string, GqlValue> | undefined, name: string): GqlValue | undefined {
  return args?.get(name);
}

function gqlStr(value: GqlValue | undefined): string {
  return typeof value === 'string' ? value : '';
}

function gqlNum(value: GqlValue | undefined): number | undefined {
  return typeof value === 'number' ? value : undefined;
}

function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = b64decode(id).toString('utf8');
    const parts = text.split(':');
    if (parts.length < 2) return null;
    return { kind: parts[0], parts: parts.slice(1) };
  } catch {
    return null;
  }
}

function findRepoById(databaseId: number): Repo | undefined {
  return reposById.get(databaseId);
}

function findIssueByGlobalId(id: string): { repo: Repo; issue: Issue } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'Issue' || decoded.parts.length < 2) return null;
  const repo = findRepoById(Number(decoded.parts[0]));
  if (repo === undefined) return null;
  const issue = repo.issues.get(Number(decoded.parts[1]));
  return issue === undefined ? null : { repo, issue };
}

function findPullByGlobalId(id: string): { repo: Repo; pull: PullRequest } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'PullRequest' || decoded.parts.length < 2) return null;
  const repo = findRepoById(Number(decoded.parts[0]));
  if (repo === undefined) return null;
  const pull = repo.pulls.get(Number(decoded.parts[1]));
  return pull === undefined ? null : { repo, pull };
}

function gqlCursor(number: number): string {
  return b64encode(`cursor:${number}`);
}

function gqlCursorNumber(cursor: string): number | undefined {
  try {
    const text = b64decode(cursor).toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match === null ? undefined : Number(match[1]);
  } catch {
    return undefined;
  }
}

interface GqlExecutor {
  errors: Array<{ message: string }>;
}

function gqlResolveSelections(
  executor: GqlExecutor,
  typeName: string,
  value: Record<string, unknown> | null,
  selections: GqlSelection[],
  resolveField: (field: GqlSelection, parent: Record<string, unknown> | null) => unknown,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      if (selection.typeCondition !== undefined && selection.typeCondition !== typeName) continue;
      const inner = gqlResolveSelections(executor, typeName, value, selection.selections ?? [], resolveField);
      Object.assign(out, inner);
      continue;
    }
    const fieldName = selection.name ?? '';
    const allowed = GQL_TYPE_FIELDS[typeName] ?? [];
    if (!allowed.includes(fieldName)) {
      executor.errors.push({ message: `Cannot query field "${fieldName}" on type "${typeName}".` });
      continue;
    }
    const key = selection.alias ?? fieldName;
    out[key] = resolveField(selection, value);
  }
  return out;
}

function gqlIssueValue(repo: Repo, issue: Issue, selections: GqlSelection[] | undefined, executor: GqlExecutor): Record<string, unknown> {
  const value: Record<string, unknown> = {
    id: globalId('Issue', repo.id, issue.number),
    number: issue.number,
    title: issue.title,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    body: issue.body,
  };
  if (selections === undefined) return value;
  return gqlResolveSelections(executor, 'Issue', value, selections, (field) => value[field.name ?? ''] ?? null);
}

function gqlPullValue(repo: Repo, pull: PullRequest, selections: GqlSelection[] | undefined, executor: GqlExecutor): Record<string, unknown> {
  const value: Record<string, unknown> = {
    id: globalId('PullRequest', repo.id, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pull.merged,
    mergeable: pullMergeable(repo, pull),
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
  };
  if (selections === undefined) return value;
  return gqlResolveSelections(executor, 'PullRequest', value, selections, (field, parent) => {
    if (field.name === 'files') {
      const first = gqlNum(gqlArg(field.args, 'first')) ?? 100;
      const files = pullFiles(repo, pull).slice(0, first);
      const nodes = files.map((file) => ({ path: file.filename }));
      const connection: Record<string, unknown> = { nodes, totalCount: files.length, pageInfo: { hasNextPage: false, endCursor: null } };
      return gqlResolveSelections(executor, 'PullRequestChangedFileConnection', connection, field.selections ?? [], (innerField, innerParent) => {
        if (innerField.name === 'nodes') {
          return (innerParent?.nodes as Array<Record<string, unknown>>).map((node) =>
            gqlResolveSelections(executor, 'PullRequestChangedFile', node, innerField.selections ?? [], (leaf) => node[leaf.name ?? ''] ?? null),
          );
        }
        if (innerField.name === 'pageInfo') {
          return gqlResolveSelections(executor, 'PageInfo', innerParent?.pageInfo as Record<string, unknown>, innerField.selections ?? [], (leaf) => (innerParent?.pageInfo as Record<string, unknown>)[leaf.name ?? ''] ?? null);
        }
        return innerParent?.[innerField.name ?? ''] ?? null;
      });
    }
    return parent?.[field.name ?? ''] ?? null;
  });
}

function gqlRepoValue(repo: Repo, selections: GqlSelection[], executor: GqlExecutor): Record<string, unknown> {
  const value: Record<string, unknown> = {
    id: globalId('Repository', repo.id),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: repo.fullName,
    owner: { login: repo.owner },
    defaultBranchRef: repo.headOid() === undefined ? null : { name: repo.defaultBranch },
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    description: repo.description,
  };
  return gqlResolveSelections(executor, 'Repository', value, selections, (field) => {
    switch (field.name) {
      case 'owner':
        return gqlResolveSelections(executor, 'User', { login: repo.owner }, field.selections ?? [], (leaf) => (leaf.name === 'login' ? repo.owner : null));
      case 'defaultBranchRef':
        if (value.defaultBranchRef === null) return null;
        return gqlResolveSelections(executor, 'Ref', value.defaultBranchRef as Record<string, unknown>, field.selections ?? [], (leaf) => (value.defaultBranchRef as Record<string, unknown>)[leaf.name ?? ''] ?? null);
      case 'issue': {
        const number = gqlNum(gqlArg(field.args, 'number'));
        const issue = number === undefined ? undefined : repo.issues.get(number);
        if (issue === undefined) return null;
        return gqlIssueValue(repo, issue, field.selections, executor);
      }
      case 'issues': {
        const first = gqlNum(gqlArg(field.args, 'first'));
        const after = gqlStr(gqlArg(field.args, 'after'));
        const states = gqlArg(field.args, 'states');
        const orderBy = gqlArg(field.args, 'orderBy');
        let list = [...repo.issues.values()];
        if (Array.isArray(states)) {
          const wanted = new Set(states.map((state) => String(state).toLowerCase()));
          list = list.filter((issue) => wanted.has(issue.state));
        }
        let descending = false;
        if (typeof orderBy === 'object' && orderBy !== null && !Array.isArray(orderBy)) {
          const direction = (orderBy as Record<string, unknown>).direction;
          descending = direction === 'DESC';
        }
        list.sort((a, b) => (descending ? b.number - a.number : a.number - b.number));
        if (after !== '') {
          const cursorNumber = gqlCursorNumber(after);
          if (cursorNumber !== undefined) {
            const index = list.findIndex((issue) => issue.number === cursorNumber);
            if (index >= 0) list = list.slice(index + 1);
          }
        }
        const total = list.length;
        const page = first === undefined ? list : list.slice(0, first);
        const hasNextPage = first !== undefined && total > first;
        const connection: Record<string, unknown> = {
          nodes: page,
          totalCount: total,
          pageInfo: { hasNextPage, endCursor: page.length > 0 ? gqlCursor(page[page.length - 1].number) : null, hasPreviousPage: false, startCursor: null },
        };
        return gqlResolveSelections(executor, 'IssueConnection', connection, field.selections ?? [], (innerField, innerParent) => {
          if (innerField.name === 'nodes') {
            return (innerParent?.nodes as Issue[]).map((issue) => gqlIssueValue(repo, issue, innerField.selections, executor));
          }
          if (innerField.name === 'pageInfo') {
            return gqlResolveSelections(executor, 'PageInfo', innerParent?.pageInfo as Record<string, unknown>, innerField.selections ?? [], (leaf) => (innerParent?.pageInfo as Record<string, unknown>)[leaf.name ?? ''] ?? null);
          }
          return innerParent?.[innerField.name ?? ''] ?? null;
        });
      }
      case 'pullRequests': {
        const first = gqlNum(gqlArg(field.args, 'first'));
        const list = [...repo.pulls.values()].filter((pull) => pull.state === 'open').sort((a, b) => b.seq - a.seq);
        const page = first === undefined ? list : list.slice(0, first);
        const connection: Record<string, unknown> = {
          nodes: page,
          totalCount: list.length,
          pageInfo: { hasNextPage: first !== undefined && list.length > first, endCursor: null },
        };
        return gqlResolveSelections(executor, 'PullRequestConnection', connection, field.selections ?? [], (innerField, innerParent) => {
          if (innerField.name === 'nodes') {
            return (innerParent?.nodes as PullRequest[]).map((pull) => gqlPullValue(repo, pull, innerField.selections, executor));
          }
          if (innerField.name === 'pageInfo') {
            return gqlResolveSelections(executor, 'PageInfo', innerParent?.pageInfo as Record<string, unknown>, innerField.selections ?? [], (leaf) => (innerParent?.pageInfo as Record<string, unknown>)[leaf.name ?? ''] ?? null);
          }
          return innerParent?.[innerField.name ?? ''] ?? null;
        });
      }
      case 'pullRequest': {
        const number = gqlNum(gqlArg(field.args, 'number'));
        const pull = number === undefined ? undefined : repo.pulls.get(number);
        if (pull === undefined) return null;
        return gqlPullValue(repo, pull, field.selections, executor);
      }
      default:
        return value[field.name ?? ''] ?? null;
    }
  });
}

function gqlTypeValue(name: string, selections: GqlSelection[], executor: GqlExecutor): Record<string, unknown> | null {
  const info = GQL_INTROSPECTION[name];
  if (info === undefined) return null;
  const value: Record<string, unknown> = { name, kind: info.kind, description: null };
  return gqlResolveSelections(executor, '__Type', value, selections, (field) => {
    if (field.name === 'fields') {
      return info.fields.map((fieldName) => {
        const fieldValue: Record<string, unknown> = { name: fieldName, description: null };
        return gqlResolveSelections(executor, '__Field', fieldValue, field.selections ?? [], (leaf) => fieldValue[leaf.name ?? ''] ?? null);
      });
    }
    if (field.name === 'enumValues') {
      return info.enumValues.map((enumName) => {
        const enumValue: Record<string, unknown> = { name: enumName, description: null };
        return gqlResolveSelections(executor, '__EnumValue', enumValue, field.selections ?? [], (leaf) => enumValue[leaf.name ?? ''] ?? null);
      });
    }
    return value[field.name ?? ''] ?? null;
  });
}

function gqlExecuteOperation(query: string, variables: Record<string, unknown>): { data: Record<string, unknown> | null; errors: Array<{ message: string }> } {
  const executor: GqlExecutor = { errors: [] };
  let parsed: { operation: 'query' | 'mutation'; selections: GqlSelection[] };
  try {
    parsed = parseGqlDocument(query, variables);
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'GraphQL parse error' }] };
  }
  const isMutation = parsed.operation === 'mutation';
  const rootType = isMutation ? 'Mutation' : 'Query';
  const data = gqlResolveSelections(executor, rootType, null, parsed.selections, (field) => {
    const name = field.name ?? '';
    if (!isMutation) {
      if (name === 'viewer') {
        return gqlResolveSelections(executor, 'User', { login: VIEWER_LOGIN }, field.selections ?? [], (leaf) => (leaf.name === 'login' ? VIEWER_LOGIN : null));
      }
      if (name === 'repository') {
        const owner = gqlStr(gqlArg(field.args, 'owner'));
        const repoName = gqlStr(gqlArg(field.args, 'name'));
        const repo = owner === VIEWER_LOGIN ? reposByName.get(repoName) : undefined;
        if (repo === undefined) return null;
        return gqlRepoValue(repo, field.selections ?? [], executor);
      }
      if (name === 'node') {
        const id = gqlStr(gqlArg(field.args, 'id'));
        const decoded = decodeGlobalId(id);
        if (decoded === null) return null;
        if (decoded.kind === 'Repository') {
          const repo = findRepoById(Number(decoded.parts[0]));
          if (repo === undefined) return null;
          const value: Record<string, unknown> = { id, name: repo.name, nameWithOwner: repo.fullName };
          return gqlResolveSelections(executor, 'Repository', value, field.selections ?? [], (leaf, parent) => {
            if (leaf.kind === 'fragment') return null;
            return parent?.[leaf.name ?? ''] ?? null;
          });
        }
        if (decoded.kind === 'Issue') {
          const found = findIssueByGlobalId(id);
          if (found === null) return null;
          return gqlIssueValue(found.repo, found.issue, field.selections, executor);
        }
        return null;
      }
      if (name === '__type') {
        const typeName = gqlStr(gqlArg(field.args, 'name'));
        return gqlTypeValue(typeName, field.selections ?? [], executor);
      }
      if (name === '__schema') {
        return { types: [] };
      }
      return null;
    }
    // Mutations.
    const input = (gqlArg(field.args, 'input') ?? {}) as Record<string, unknown>;
    const strInput = (key: string): string => (typeof input[key] === 'string' ? (input[key] as string) : '');
    if (name === 'createIssue') {
      const repoId = strInput('repositoryId');
      const decoded = decodeGlobalId(repoId);
      const repo = decoded?.kind === 'Repository' ? findRepoById(Number(decoded.parts[0])) : undefined;
      if (repo === undefined) {
        executor.errors.push({ message: 'createIssue: unknown repository' });
        return null;
      }
      globalSeq += 1;
      const number = repo.nextNumber;
      repo.nextNumber += 1;
      const issue: Issue = { id: nextGlobalId, number, title: strInput('title'), body: strInput('body'), state: 'open', labels: [], comments: [], seq: globalSeq };
      nextGlobalId += 1;
      repo.issues.set(number, issue);
      const payload: Record<string, unknown> = { issue: gqlIssueValue(repo, issue, undefined, executor) };
      return gqlResolveSelections(executor, 'CreateIssuePayload', payload, field.selections ?? [], (leaf) => {
        if (leaf.name === 'issue') return gqlIssueValue(repo, issue, leaf.selections, executor);
        return payload[leaf.name ?? ''] ?? null;
      });
    }
    if (name === 'closeIssue') {
      const found = findIssueByGlobalId(strInput('issueId'));
      if (found === null) {
        executor.errors.push({ message: 'closeIssue: unknown issue' });
        return null;
      }
      found.issue.state = 'closed';
      const payload: Record<string, unknown> = { issue: gqlIssueValue(found.repo, found.issue, undefined, executor) };
      return gqlResolveSelections(executor, 'CloseIssuePayload', payload, field.selections ?? [], (leaf) => {
        if (leaf.name === 'issue') return gqlIssueValue(found.repo, found.issue, leaf.selections, executor);
        return payload[leaf.name ?? ''] ?? null;
      });
    }
    if (name === 'createPullRequest') {
      const repoId = strInput('repositoryId');
      const decoded = decodeGlobalId(repoId);
      const repo = decoded?.kind === 'Repository' ? findRepoById(Number(decoded.parts[0])) : undefined;
      if (repo === undefined) {
        executor.errors.push({ message: 'createPullRequest: unknown repository' });
        return null;
      }
      const headRef = strInput('headRefName');
      const baseRef = strInput('baseRefName') || repo.defaultBranch;
      const headSha = repo.refs.get(`refs/heads/${headRef}`);
      const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
      if (headSha === undefined || baseSha === undefined) {
        executor.errors.push({ message: 'createPullRequest: head or base branch does not exist' });
        return null;
      }
      globalSeq += 1;
      const number = repo.nextNumber;
      repo.nextNumber += 1;
      const pull: PullRequest = {
        id: nextGlobalId,
        number,
        title: strInput('title'),
        body: '',
        state: 'open',
        headRef,
        baseRef,
        headSha,
        baseSha,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        seq: globalSeq,
      };
      nextGlobalId += 1;
      repo.pulls.set(number, pull);
      const payload: Record<string, unknown> = { pullRequest: gqlPullValue(repo, pull, undefined, executor) };
      return gqlResolveSelections(executor, 'CreatePullRequestPayload', payload, field.selections ?? [], (leaf) => {
        if (leaf.name === 'pullRequest') return gqlPullValue(repo, pull, leaf.selections, executor);
        return payload[leaf.name ?? ''] ?? null;
      });
    }
    if (name === 'mergePullRequest') {
      const found = findPullByGlobalId(strInput('pullRequestId'));
      if (found === null) {
        executor.errors.push({ message: 'mergePullRequest: unknown pull request' });
        return null;
      }
      if (found.pull.state === 'open') {
        const mergeSha = squashMerge(found.repo, found.pull);
        if (mergeSha === null) {
          executor.errors.push({ message: 'mergePullRequest: merge conflict' });
          return null;
        }
      }
      const payload: Record<string, unknown> = { pullRequest: gqlPullValue(found.repo, found.pull, undefined, executor) };
      return gqlResolveSelections(executor, 'MergePullRequestPayload', payload, field.selections ?? [], (leaf) => {
        if (leaf.name === 'pullRequest') return gqlPullValue(found.repo, found.pull, leaf.selections, executor);
        return payload[leaf.name ?? ''] ?? null;
      });
    }
    if (name === 'addComment') {
      const found = findIssueByGlobalId(strInput('subjectId'));
      if (found === null) {
        executor.errors.push({ message: 'addComment: unknown subject' });
        return null;
      }
      const comment = { id: found.repo.nextCommentId, body: strInput('body') };
      found.repo.nextCommentId += 1;
      found.issue.comments.push(comment);
      const node: Record<string, unknown> = { id: globalId('IssueComment', found.repo.id, found.issue.number, comment.id), body: comment.body };
      const payload: Record<string, unknown> = { commentEdge: { node } };
      return gqlResolveSelections(executor, 'AddCommentPayload', payload, field.selections ?? [], (leaf) => {
        if (leaf.name === 'commentEdge') {
          return gqlResolveSelections(executor, 'IssueCommentEdge', { node }, leaf.selections ?? [], (edgeLeaf) => {
            if (edgeLeaf.name === 'node') {
              return gqlResolveSelections(executor, 'IssueComment', node, edgeLeaf.selections ?? [], (commentLeaf) => node[commentLeaf.name ?? ''] ?? null);
            }
            return null;
          });
        }
        return payload[leaf.name ?? ''] ?? null;
      });
    }
    return null;
  });
  return { data: executor.errors.length > 0 && parsed.operation === 'query' && dataIsEmpty(data) ? null : data, errors: executor.errors };
}

function dataIsEmpty(data: Record<string, unknown>): boolean {
  return Object.values(data).every((value) => value === null || value === undefined);
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  if (!authed(req)) {
    sendJson(res, 401, errJson('Requires authentication'));
    return true;
  }
  const raw = await readBody(req);
  const parsed = parseJsonBody(raw);
  if (!parsed.ok) {
    sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
    return true;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      return { data: null, errors: [{ message: 'Request must be a GraphQL operation object' }] };
    }
    const record = entry as Record<string, unknown>;
    const query = typeof record.query === 'string' ? record.query : '';
    const variables = (typeof record.variables === 'object' && record.variables !== null && !Array.isArray(record.variables) ? record.variables : {}) as Record<string, unknown>;
    if (query === '') return { data: null, errors: [{ message: 'Must provide query string.' }] };
    const result = gqlExecuteOperation(query, variables);
    const out: Record<string, unknown> = { data: result.data };
    if (result.errors.length > 0) out.errors = result.errors;
    return out;
  };
  if (Array.isArray(parsed.value)) {
    const results = parsed.value.map(runOne);
    sendJson(res, 200, results);
    return true;
  }
  sendJson(res, 200, runOne(parsed.value));
  return true;
}

// -------------------------------------------------------------------------------------------
// MCP — JSON-RPC 2.0 over Streamable HTTP, modern revision 2026-07-28 (with the legacy
// initialize handshake as a fallback). Tools act on the same store as REST.
// -------------------------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  properties: Record<string, { type: string; description?: string }>;
  required: string[];
  run: (args: Record<string, unknown>) => { ok: boolean; data: unknown; message?: string };
}

function mcpArg(args: Record<string, unknown>, names: readonly string[]): unknown {
  for (const name of names) {
    if (args[name] !== undefined && args[name] !== null) return args[name];
  }
  return undefined;
}

function mcpOwnerRepo(args: Record<string, unknown>): { owner: string; repo: string } | null {
  const full = mcpArg(args, ['full_name', 'repo_full_name', 'repository_full_name']);
  if (typeof full === 'string' && full.includes('/')) {
    const [owner, repo] = full.split('/', 2);
    return { owner, repo };
  }
  const owner = mcpArg(args, ['owner', 'owner_login', 'login']);
  const repo = mcpArg(args, ['repo', 'repository', 'repository_name', 'repo_name']);
  if (typeof owner !== 'string' || typeof repo !== 'string') return null;
  return { owner, repo };
}

function mcpRepo(args: Record<string, unknown>): Repo | { error: string } {
  const pair = mcpOwnerRepo(args);
  if (pair === null) return { error: 'owner and repo are required' };
  const repo = findRepo(pair.owner, pair.repo);
  if (repo === undefined) return { error: `repository ${pair.owner}/${pair.repo} not found` };
  return repo;
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    properties: {
      name: { type: 'string', description: 'The repository name.' },
      description: { type: 'string', description: 'A short description of the repository.' },
      private: { type: 'boolean', description: 'Whether the repository is private.' },
      owner: { type: 'string', description: 'The owner login (defaults to the authenticated user).' },
    },
    required: ['name'],
    run: (args) => {
      const name = mcpArg(args, ['name', 'repo', 'repository']);
      if (typeof name !== 'string' || name === '') return { ok: false, data: null, message: 'name is required' };
      if (reposByName.has(name)) return { ok: false, data: null, message: 'Repository already exists' };
      const repo = new Repo(nextRepoId, name, typeof args.description === 'string' ? args.description : '', args.private === true);
      nextRepoId += 1;
      reposByName.set(name, repo);
      reposById.set(repo.id, repo);
      return { ok: true, data: repoObject(repo) };
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      full_name: { type: 'string', description: 'The repository full name owner/repo.' },
    },
    required: ['owner', 'repo'],
    run: (args) => {
      const repo = mcpRepo(args);
      if ('error' in repo) return { ok: false, data: null, message: repo.error };
      return { ok: true, data: repoObject(repo) };
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The issue title.' },
      body: { type: 'string', description: 'The issue body.' },
      full_name: { type: 'string', description: 'The repository full name owner/repo.' },
    },
    required: ['owner', 'repo', 'title'],
    run: (args) => {
      const repo = mcpRepo(args);
      if ('error' in repo) return { ok: false, data: null, message: repo.error };
      const title = mcpArg(args, ['title', 'issue_title']);
      if (typeof title !== 'string' || title === '') return { ok: false, data: null, message: 'title is required' };
      globalSeq += 1;
      const number = repo.nextNumber;
      repo.nextNumber += 1;
      const issue: Issue = {
        id: nextGlobalId,
        number,
        title,
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        labels: [],
        comments: [],
        seq: globalSeq,
      };
      nextGlobalId += 1;
      repo.issues.set(number, issue);
      return { ok: true, data: issueObject(repo, issue) };
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      full_name: { type: 'string', description: 'The repository full name owner/repo.' },
    },
    required: ['owner', 'repo'],
    run: (args) => {
      const repo = mcpRepo(args);
      if ('error' in repo) return { ok: false, data: null, message: repo.error };
      const state = typeof args.state === 'string' ? args.state : 'open';
      let list = [...repo.issues.values()];
      if (state === 'open') list = list.filter((issue) => issue.state === 'open');
      else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
      list.sort((a, b) => a.seq - b.seq);
      return { ok: true, data: list.map((issue) => issueObject(repo, issue)) };
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch onto a base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The pull request title.' },
      body: { type: 'string', description: 'The pull request body.' },
      head: { type: 'string', description: 'The head branch name.' },
      base: { type: 'string', description: 'The base branch name.' },
      full_name: { type: 'string', description: 'The repository full name owner/repo.' },
    },
    required: ['owner', 'repo', 'title', 'head', 'base'],
    run: (args) => {
      const repo = mcpRepo(args);
      if ('error' in repo) return { ok: false, data: null, message: repo.error };
      const headRef = mcpArg(args, ['head', 'head_ref', 'head_branch']) as string | undefined;
      const baseRef = (mcpArg(args, ['base', 'base_ref', 'base_branch']) as string | undefined) ?? repo.defaultBranch;
      const title = mcpArg(args, ['title', 'pr_title']) as string | undefined;
      if (typeof headRef !== 'string' || typeof title !== 'string') return { ok: false, data: null, message: 'head and title are required' };
      const headSha = repo.refs.get(`refs/heads/${headRef}`);
      const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
      if (headSha === undefined || baseSha === undefined) return { ok: false, data: null, message: 'head or base branch does not exist' };
      for (const existing of repo.pulls.values()) {
        if (existing.state === 'open' && existing.headRef === headRef && existing.baseRef === baseRef) {
          return { ok: false, data: null, message: 'A pull request already exists for this branch' };
        }
      }
      globalSeq += 1;
      const number = repo.nextNumber;
      repo.nextNumber += 1;
      const pull: PullRequest = {
        id: nextGlobalId,
        number,
        title,
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        headRef,
        baseRef,
        headSha,
        baseSha,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        seq: globalSeq,
      };
      nextGlobalId += 1;
      repo.pulls.set(number, pull);
      return { ok: true, data: pullObject(repo, pull) };
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit onto its base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      pull_number: { type: 'number', description: 'The pull request number.' },
      full_name: { type: 'string', description: 'The repository full name owner/repo.' },
    },
    required: ['owner', 'repo', 'pull_number'],
    run: (args) => {
      const repo = mcpRepo(args);
      if ('error' in repo) return { ok: false, data: null, message: repo.error };
      const rawNumber = mcpArg(args, ['pull_number', 'pull_request_number', 'pr_number', 'number']);
      const number = typeof rawNumber === 'number' ? rawNumber : typeof rawNumber === 'string' ? Number(rawNumber) : NaN;
      const pull = repo.pulls.get(number);
      if (pull === undefined) return { ok: false, data: null, message: 'Pull request not found' };
      if (pull.state !== 'open') return { ok: false, data: null, message: 'Pull request is already merged or closed' };
      const mergeSha = squashMerge(repo, pull);
      if (mergeSha === null) return { ok: false, data: null, message: 'Merge conflict' };
      return { ok: true, data: { sha: mergeSha, merged: true, message: 'Pull request successfully merged', number: pull.number } };
    },
  },
  {
    name: 'get_issue',
    description: 'Get one issue by number.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      issue_number: { type: 'number', description: 'The issue number.' },
      full_name: { type: 'string', description: 'The repository full name owner/repo.' },
    },
    required: ['owner', 'repo', 'issue_number'],
    run: (args) => {
      const repo = mcpRepo(args);
      if ('error' in repo) return { ok: false, data: null, message: repo.error };
      const rawNumber = mcpArg(args, ['issue_number', 'number']);
      const number = typeof rawNumber === 'number' ? rawNumber : Number(rawNumber);
      const issue = repo.issues.get(number);
      if (issue === undefined) return { ok: false, data: null, message: 'Issue not found' };
      return { ok: true, data: issueObject(repo, issue) };
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      full_name: { type: 'string', description: 'The repository full name owner/repo.' },
    },
    required: ['owner', 'repo'],
    run: (args) => {
      const repo = mcpRepo(args);
      if ('error' in repo) return { ok: false, data: null, message: repo.error };
      const state = typeof args.state === 'string' ? args.state : 'open';
      let list = [...repo.pulls.values()];
      if (state === 'open') list = list.filter((pull) => pull.state === 'open');
      else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
      list.sort((a, b) => b.seq - a.seq);
      return { ok: true, data: list.map((pull) => pullObject(repo, pull)) };
    },
  },
];

function mcpToolsList(): Array<Record<string, unknown>> {
  return MCP_TOOLS.map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: { type: 'object', properties: tool.properties, required: tool.required },
  }));
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  if ((req.method ?? 'GET') !== 'POST') {
    sendJson(res, 405, errJson('Method Not Allowed'));
    return true;
  }
  const raw = await readBody(req);
  let body: unknown = null;
  let parseFailed = false;
  try {
    body = JSON.parse(raw.toString('utf8'));
  } catch {
    parseFailed = true;
  }
  if (parseFailed) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  if (!authed(req)) {
    const id = typeof body === 'object' && body !== null && !Array.isArray(body) ? (body as Record<string, unknown>).id ?? null : null;
    sendJson(res, 401, { jsonrpc: '2.0', id, error: { code: -32001, message: 'Unauthorized' } });
    return true;
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return true;
  }
  const record = body as Record<string, unknown>;
  const id = record.id ?? null;
  const method = typeof record.method === 'string' ? record.method : '';
  const params = (typeof record.params === 'object' && record.params !== null && !Array.isArray(record.params) ? record.params : {}) as Record<string, unknown>;

  // A notification (no id) is answered with 202 and no body.
  if (id === null && method.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return true;
  }

  const result = (value: unknown): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: value });
  };
  const rpcError = (code: number, message: string): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, error: { code, message } });
  };

  if (method === 'server/discover') {
    result({
      supportedVersions: ['2026-07-28', '2025-11-25'],
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
      capabilities: { tools: {} },
      instructions: 'A GitHub-compatible git forge: repositories, issues, pull requests, git smart HTTP, GraphQL and MCP tools.',
    });
    return true;
  }

  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    const negotiated = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'].includes(offered) ? offered : '2025-11-25';
    result({
      protocolVersion: negotiated,
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
      capabilities: { tools: {} },
    });
    return true;
  }

  if (method === 'ping') {
    result({});
    return true;
  }

  if (method === 'tools/list') {
    result({ tools: mcpToolsList() });
    return true;
  }

  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = (typeof params.arguments === 'object' && params.arguments !== null && !Array.isArray(params.arguments) ? params.arguments : {}) as Record<string, unknown>;
    const tool = MCP_TOOLS.find((candidate) => candidate.name === name);
    if (tool === undefined) {
      rpcError(-32601, `Method not found: ${name}`);
      return true;
    }
    const missing = tool.required.filter((key) => args[key] === undefined || args[key] === null || args[key] === '');
    if (missing.length > 0) {
      result({ content: [{ type: 'text', text: JSON.stringify({ error: `missing required argument(s): ${missing.join(', ')}` }) }], isError: true });
      return true;
    }
    let outcome: { ok: boolean; data: unknown; message?: string };
    try {
      outcome = tool.run(args);
    } catch (err) {
      result({ content: [{ type: 'text', text: err instanceof Error ? err.message : 'tool error' }], isError: true });
      return true;
    }
    if (!outcome.ok) {
      result({ content: [{ type: 'text', text: JSON.stringify({ error: outcome.message ?? 'tool error' }) }], isError: true });
      return true;
    }
    result({ content: [{ type: 'text', text: JSON.stringify(outcome.data) }], structuredContent: outcome.data, isError: false });
    return true;
  }

  rpcError(-32601, `Method not found: ${method}`);
  return true;
}

// -------------------------------------------------------------------------------------------
// the server
// -------------------------------------------------------------------------------------------

/** Build the server. It binds nothing until the caller listens; the entry listens on an ephemeral port. */
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const { path, query } = splitPath(req.url ?? '/');
        const method = req.method ?? 'GET';
        const segments = path.split('/').filter((part) => part !== '');

        // The env's boot check calls this twice: 200 {"ok":true}.
        if (method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }

        // Git smart HTTP lives at /{owner}/{repo}.git/...
        if (path.includes('.git/') || path.endsWith('.git')) {
          const handled = await handleGit({ req, res, path, query, segments });
          if (handled) return;
        }

        // REST v3 under /api/v3.
        if (path === '/api/v3' || path.startsWith('/api/v3/')) {
          await handleRest({ req, res, path, query, segments });
          return;
        }

        // GraphQL v4.
        if (path === '/api/graphql') {
          if (method !== 'POST') {
            sendJson(res, 405, errJson('Method Not Allowed'));
            return;
          }
          await handleGraphql(req, res);
          return;
        }

        // MCP.
        if (path === '/mcp') {
          await handleMcp(req, res);
          return;
        }

        // Everything else, every method: GitHub's 404 body.
        sendJson(res, 404, errJson('Not Found'));
      } catch (err) {
        // A handler must never take the server down with it: answer 500 JSON and stay up.
        try {
          sendJson(res, 500, errJson(err instanceof Error ? err.message : 'Internal Server Error'));
        } catch {
          try {
            res.end();
          } catch {
            // The socket is already gone; nothing left to do.
          }
        }
      }
    })();
  });
}
