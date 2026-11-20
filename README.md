# github-core-clone

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/whale99999/github-core-clone/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/whale99999/github-core-clone/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A from-scratch, Node 22 stdlib-only GitHub-compatible git forge in a single process: smart HTTP git (upload-pack v2/v0 and receive-pack), a REST v3 API, GraphQL v4, and an MCP server, all sharing one in-memory store so a repository created over one surface reads back identically over the others. Git objects are stored verbatim and hashed exactly the way git hashes them, so clones round-trip byte for byte, and every timestamp comes from the trial clock rather than the wall clock, so two runs of the same trial see the same bytes. Grade-local: 814/1000, with all 120/120 checks passing.

## Run it

```sh
node --experimental-strip-types main.ts
```

---

<sub>Entered on [make.fun](https://make.fun/?ref=881py9z1&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
