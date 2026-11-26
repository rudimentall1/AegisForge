# my-project

An isolated Node.js scaffold inside [AegisForge](https://github.com/rudimentall1/AegisForge).

**Status: scaffold only.** This directory does not implement EVM Key Forensics, agent orchestration, contract scanning, evidence verification, or any other user-facing product capability. The parent repository already owns those Python capabilities. No separate product scope or integration contract has been approved.

## Why it is isolated

The repository's primary runtime is Python. A second Node runtime is not justified for the existing AegisForge workflow, so this package remains dependency-free and disconnected. Do not move parent functionality into this directory or create duplicate queues, agents, evidence stores, or security gates.

## Requirements

- Node.js with ECMAScript module support.
- npm (bundled with Node.js).

No third-party packages are declared.

## Commands

```bash
npm test
npm run check
```

- `npm test` runs the built-in Node.js test runner.
- `npm run check` performs a syntax check on `src/index.js`.

These commands passed in the root GitHub Actions Node.js 24 job (run `45770823759`, candidate commit `4bd34c0790835ca0d4829e8b07888459e47da438`).

## Structure

- `AGENTS.md` — mandatory subproject workflow, in addition to root `AGENTS.md`.
- `PROJECT_CONTEXT.md` — verified scope, architecture boundary, and status.
- `TASKS.md` — task ledger and outstanding verification.
- `DECISIONS.md` — accepted and deferred architecture decisions.
- `src/` — currently only the scaffold entrypoint.
- `tests/` — currently only the scaffold metadata test.

Read both agent instruction files before making changes. Do not add product behavior until the user problem, ownership boundary, API, and acceptance criteria are explicitly approved.
