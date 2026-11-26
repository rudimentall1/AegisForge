# Tasks — my-project

This ledger describes only work inside the isolated `my-project/` scaffold. Keep it synchronized with implementation and observed verification evidence.

## Bootstrap

- [x] Add the requested directory structure.
- [x] Add mandatory repository and subproject agent working rules.
- [x] Record the parent AegisForge architecture and non-duplication boundary.
- [x] Add a minimal private Node.js ESM package without third-party dependencies.
- [x] Add a minimal source entrypoint and native Node test.

## Verification — current

- [x] Run `npm test` in Node.js 24 CI — run `45770823759` passed.
- [x] Run `npm run check` in Node.js 24 CI — run `45770823759` passed.
- [x] Add a separate CI job for the scaffold on Node.js 24.
- [x] Observe passing Node 24 syntax-check and test jobs on candidate commit `4bd34c0790835ca0d4829e8b07888459e47da438`; later changes to the scaffold were documentation-only.
- [x] Recheck parent main after PR #213 merge at `da91e18a69a1bc455f53b0ea4dc0ea53bb3ce261`; post-merge CI run `45771692353` passed the Node.js 24 job.
- [x] Run `npm run check` on Gensyn2 (`Node v24.18.0`) — passed, 2026-11-26.
- [x] Run `npm test` on Gensyn2 — 1 passed, 0 failed, 0 skipped, 2026-11-26.
- [x] Inspect the host process list for AegisForge/Foundry/Anvil/Firecracker — none observed at inspection time.
- [x] Preserve the existing stale feature checkout and its untracked `dump.txt`/`tree.txt`; use a separate clean main worktree for this update.

## Product definition — intentionally blocked

- [ ] Define the concrete user problem this directory owns.
- [ ] Define inputs, outputs, trust boundaries, and acceptance criteria.
- [ ] Confirm that the capability is not already implemented by the parent Python runtime.
- [ ] Decide whether integration with the parent Research Case/evidence workflow is necessary.
- [ ] Record an accepted design in `DECISIONS.md` before implementing behavior.

## Parent repository audit findings

- [x] Confirmed the parent product is AegisForge — EVM Key Forensics, implemented primarily in Python.
- [x] Confirmed existing agent, orchestration, queue, Research Case, execution, sandbox, evidence, and verification modules.
- [x] Confirmed that no parent integration is present in this scaffold.
- [ ] Do not treat the parent repository's overall release readiness as satisfied; see `../docs/PRODUCT-READINESS.md`.
- [x] Recorded that the server checkout is an older feature branch; used a separate clean worktree from current `main` for this update.

## Completion policy

Do not mark a task complete because code was drafted or a command was proposed. Mark verification tasks complete only after observing their actual result. Product implementation remains blocked until a distinct problem and architecture are approved.
