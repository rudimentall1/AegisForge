# my-project

An isolated subproject scaffold inside [AegisForge](https://github.com/rudimentall1/AegisForge).

**Current status:** bootstrap only. This directory does not yet implement a user-facing product capability and is not integrated with the parent Python agent runtime.

## Requirements

- Node.js with ECMAScript module support.
- npm (bundled with Node.js).

No third-party packages are required by the initial scaffold.

## Commands

```bash
npm test
npm run check
```

- `npm test` runs the native Node.js test runner.
- `npm run check` performs a syntax check on the source entrypoint.

These commands are defined in `package.json`; they have not been executed as part of the initial GitHub-only scaffold change.

## Structure

- `AGENTS.md` — mandatory contributor/agent workflow.
- `PROJECT_CONTEXT.md` — verified project context and current status.
- `TASKS.md` — task ledger and outstanding verification.
- `DECISIONS.md` — accepted architecture decisions.
- `src/` — implementation.
- `tests/` — automated tests.

Read `AGENTS.md` before making changes. Product scope and parent integration remain undecided; do not infer them from the folder name.
