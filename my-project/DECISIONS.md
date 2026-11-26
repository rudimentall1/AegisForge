# Architecture Decisions — my-project

Record decisions that constrain implementation. Do not convert tentative ideas into accepted architecture.

## ADR-001 — Isolated subproject scaffold

- **Status:** Accepted
- **Date:** 2026-11-26
- **Context:** AegisForge is an existing Python research and evidence platform. A new `my-project/` directory was requested with its own `package.json`, `src/`, and `tests/`. The intended product scope of this subdirectory was not specified.
- **Decision:** Create a minimal, private Node.js ECMAScript-module scaffold using only built-in Node functionality. Keep it isolated from the parent Python runtime until a concrete integration contract is approved.
- **Consequences:** The scaffold can evolve independently without introducing dependencies into the parent application. It does not yet provide product functionality or imply that Node.js is the final technology choice for all future components.
- **Alternatives considered:** Adding a framework or third-party dependencies immediately was rejected because there is no approved product scope or demonstrated need for them.

## ADR-002 — Documentation and verification are mandatory

- **Status:** Accepted
- **Date:** 2026-11-26
- **Decision:** The rules in `AGENTS.md` are mandatory. Significant code changes and their documentation must be committed together. Documentation must be checked against implementation and actual verification results before a task is declared complete.
- **Consequences:** A change is not complete when code alone is written; its tests, documentation, and recorded status must agree.
