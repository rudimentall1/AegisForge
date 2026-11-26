# Architecture Decisions — my-project

Record decisions that constrain implementation. Do not convert tentative ideas into accepted architecture.

## ADR-001 — Keep the requested scaffold isolated

- **Status:** Accepted
- **Date:** 2026-11-26
- **Context:** The parent AegisForge repository is a substantial Python security-research platform. It already contains agent roles, orchestration, a task queue, Research Case contracts, execution controls, sandboxing, evidence ledgers, verification, and EVM Key Forensics tooling. The intended separate product scope for `my-project/` has not been specified.
- **Decision:** Keep the requested private Node.js ESM scaffold minimal and isolated. Do not duplicate parent capabilities or add a second runtime to the production path without a concrete requirement.
- **Consequences:** The directory is not currently a product component and must not be described as an implemented capability. Its only behavior is static package metadata.
- **Alternatives considered:** Rewriting existing Python capabilities in Node or adding a framework was rejected because no distinct user problem or technical need has been demonstrated.

## ADR-002 — Documentation and verification are mandatory

- **Status:** Accepted
- **Date:** 2026-11-26
- **Decision:** Repository-root `AGENTS.md` and this directory's `AGENTS.md` define mandatory working rules. Significant implementation changes and their documentation/tests must be committed in the same change set. Documentation must be checked against implementation and actual verification output before completion.
- **Consequences:** A task is not complete when code alone is written; tests, documentation, and recorded status must agree.

## ADR-003 — Product scope and parent integration remain unapproved

- **Status:** Deferred
- **Date:** 2026-11-26
- **Context:** The repository audit found existing parent components that overlap with likely security-research and agent-platform responsibilities.
- **Decision:** Do not assign `my-project/` ownership of EVM Key Forensics, on-chain discovery, worker orchestration, evidence storage, or verification until a distinct unmet need and explicit integration contract are approved.
- **Consequences:** No production feature work or parent integration should begin based only on the directory name or scaffold structure.
