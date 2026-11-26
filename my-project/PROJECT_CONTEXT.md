# Project Context — my-project

## Purpose

This file is the durable context entrypoint for work inside `my-project/`. Keep it factual and update it when the project structure, architecture, dependencies, or implementation status changes.

## Parent repository

- Repository: [rudimentall1/AegisForge](https://github.com/rudimentall1/AegisForge)
- Product: AegisForge — EVM Key Forensics.
- Parent implementation is primarily Python; its pinned dependencies are listed in the repository-root `requirements.txt`.
- The parent README describes a research workflow based on registered research cases, bounded experiments, evidence capture, and independent verification.
- Parent architecture and release acceptance are documented in `../docs/ARCHITECTURE.md` and `../docs/PRODUCT-READINESS.md`.

## Scope of this directory

- `my-project/` is a newly introduced, isolated subproject scaffold.
- It has its own package manifest, source directory, and test directory.
- No integration with the parent Python runtime, task queue, research-case store, or evidence ledger is established by this scaffold.
- The exact product responsibilities and integration contract for this subproject have not yet been approved. Do not invent them.

## Initial technical baseline

- Runtime/tooling: Node.js with native ECMAScript modules and the built-in Node test runner.
- Third-party runtime dependencies: none declared in the initial scaffold.
- Package is private and is not intended for publication.
- `src/index.js` exports only minimal package metadata; it is a scaffold marker, not product functionality.
- `tests/index.test.js` checks that minimal export.
- Node version compatibility has not yet been verified in CI. Select and pin a supported Node LTS version before adding runtime-dependent functionality.

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

## Verified status

- [x] Initial directory and documentation scaffold added.
- [x] Minimal Node ESM package manifest added.
- [x] Minimal source entrypoint and test added.
- [ ] Local Node test execution — not yet run in this GitHub-only change.
- [ ] CI workflow for this subproject.
- [ ] Product scope and parent-integration contract.
- [ ] Node LTS version policy.

## Working rules

Follow `AGENTS.md`. Before implementation, inspect the current code and documentation. Keep assumptions labelled, update docs with significant changes, and verify documentation before closing each task.
