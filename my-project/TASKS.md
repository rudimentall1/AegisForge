# Tasks — my-project

This ledger describes only work inside the isolated `my-project/` scaffold. Keep it synchronized with implementation and observed verification evidence.

## Bootstrap

- [x] Add the requested directory structure.
- [x] Add mandatory repository and subproject agent working rules.
- [x] Record the parent AegisForge architecture and non-duplication boundary.
- [x] Add a minimal private Node.js ESM package without third-party dependencies.
- [x] Add a minimal source entrypoint and native Node test.

## Verification — pending

- [ ] Run `npm test` in a real Node.js environment and record the exact result.
- [ ] Run `npm run check` in a real Node.js environment and record the exact result.
- [ ] Decide whether this package merits its own CI job after its purpose and supported Node LTS version are approved.

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

## Completion policy

Do not mark a task complete because code was drafted or a command was proposed. Mark verification tasks complete only after observing their actual result. Product implementation remains blocked until a distinct problem and architecture are approved.
