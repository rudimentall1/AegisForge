# Project Context — my-project

## Purpose and status

This directory is an isolated bootstrap scaffold requested inside [rudimentall1/AegisForge](https://github.com/rudimentall1/AegisForge). It is **not** the AegisForge product runtime and currently provides no user-facing capability.

The repository audit confirms that AegisForge already has a substantial Python implementation for agent orchestration, task queueing, Research Case binding, bounded execution, evidence capture, verification, and EVM Key Forensics. Do not recreate those capabilities here.

No separate product problem, domain ownership, public API, or integration contract has been approved for `my-project/`. Keep it deliberately inert until a concrete purpose and acceptance contract are agreed.

## Parent repository facts

- Product focus: AegisForge — EVM Key Forensics.
- Main implementation language: Python.
- Runtime entrypoints include `aegisforge.py`, `run.py`, and `agents/worker.py`.
- Agent implementations live under `agents/`; orchestration lives under `orchestrator/`.
- Shared task, Research Case, capability, execution, evidence, verification, and recovery components live under `shared/`.
- EVM Key Forensics tools and fixtures live under `tools/evm_key_forensics/` and `tests/`.
- Main persistence is SQLite through the shared queue/ledger components.
- Root dependencies are pinned in `../requirements.txt`; this Node package does not contribute to that Python dependency set.
- Canonical project direction: `../docs/MASTER_CONTEXT.md`.
- Architecture: `../docs/ARCHITECTURE.md`.
- Product acceptance: `../docs/PRODUCT-READINESS.md`.

These are repository-structure observations, not a claim that the full product workflow is release-ready.

## Current technical baseline

- Runtime/tooling: Node.js ECMAScript modules.
- Package manager: npm.
- Third-party dependencies: none.
- `package.json` is private and contains only `test` and `check` scripts.
- `src/index.js` exports static scaffold metadata only.
- `tests/index.test.js` checks that metadata export.
- The root GitHub Actions workflow runs this package's syntax check and tests on Node.js 24.
- The Node 24 syntax and test commands passed in GitHub Actions run `45770823759` on candidate commit `4bd34c0790835ca0d4829e8b07888459e47da438`; subsequent changes to this package have been documentation-only.
- Node.js 24 is the selected CI major version; no other Node versions are currently supported.

## Integration boundary

There is no integration with the parent Python runtime, task queue, Research Case registry, execution gate, sandbox, or evidence ledger. Do not add one by importing parent internals or creating a parallel implementation. An integration requires a documented interface, threat model, ownership boundary, and end-to-end tests.

## Directory map

```text
my-project/
├── AGENTS.md
├── PROJECT_CONTEXT.md
├── TASKS.md
├── DECISIONS.md
├── README.md
├── .gitignore
├── package.json
├── src/
│   └── index.js
└── tests/
    └── index.test.js
```

## Server inspection — 2026-11-26

- The connected Linux host `Gensyn2.play2go.cloud` reports Node.js `v24.18.0`, npm `11.16.0`, and system Python `3.10.12`.
- The host checkout at `/root/AegisForge` is on `feat/persist-local-experiment-evidence-main` at `c69dbcc5142c98d38fcc01ebf721a77ce4e282db`, not on current `main`. It has two untracked inspection files (`dump.txt` and `tree.txt`). These files and the checkout were left untouched.
- A separate clean worktree was created from fetched `origin/main` at `da91e18a69a1bc455f53b0ea4dc0ea53bb3ce261` for this documentation update.
- No AegisForge, Foundry, Anvil, or Firecracker process was observed on the host during inspection. This is a point-in-time process observation, not proof that no scheduled or remote execution exists.
- The isolated scaffold was checked on the host: `npm run check` passed; `npm test` passed (1 test, 0 failures, 0 skipped).
- No AegisForge service was deployed, started, restarted, or modified during this inspection.

## Verified status

- [x] Requested directory and documentation scaffold exists on this PR branch.
- [x] Mandatory working rules exist at repository root and in this directory.
- [x] Minimal private Node ESM package exists without third-party dependencies.
- [x] Source entrypoint and native Node test are present.
- [x] Run `npm test` in Node.js 24 CI (historical scaffold run `45770823759`; current parent main CI `45771692353` also passed).
- [x] Run `npm run check` in Node.js 24 CI (historical scaffold run `45770823759`; current parent main CI `45771692353` also passed).
- [x] Run `npm run check` on Gensyn2 host with Node.js `v24.18.0` (2026-11-26).
- [x] Run `npm test` on Gensyn2 host (1 passed, 0 failed, 0 skipped; 2026-11-26).
- [x] Select Node.js 24 as the CI runtime baseline.
- [ ] Define the product problem, domain ownership, API, and acceptance criteria.
- [ ] Decide whether integration is justified; do not assume that it is.

## Source of truth

The parent product's current direction and verified implementation status are maintained in `../docs/MASTER_CONTEXT.md`. This file describes only the current state and boundary of `my-project/`.
