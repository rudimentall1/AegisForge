# Agent Instructions — my-project

These rules are mandatory for every person or agent changing this directory. The repository-root `AGENTS.md` also applies and takes precedence when rules overlap.

## Before starting work

The following rules are mandatory and apply to every task:

- Before starting work, study the project documentation and repository structure relevant to the task.
- After significant changes, update the applicable documentation and project context.
- Never record unconfirmed assumptions as facts; label uncertainty and verify where possible.
- Before finishing, check that documentation is accurate and current against the final code, tests, configuration, and observed results.
- Commit documentation changes together with their corresponding code and tests.

Use this concrete reading sequence:

1. Read the repository-root `AGENTS.md`, this file, `PROJECT_CONTEXT.md`, `TASKS.md`, and `DECISIONS.md`.
2. Read the parent `README.md`, `docs/MASTER_CONTEXT.md`, and relevant sections of `docs/ARCHITECTURE.md` and `docs/PRODUCT-READINESS.md`.
3. Inspect the current repository and subproject structure, recent commits, relevant implementation, configuration, and tests before editing.
4. Identify acceptance criteria and the checks needed to prove the change. Do not infer implementation status from design documentation alone.

## During implementation

- Preserve existing behavior unless the task explicitly requires changing it.
- Prefer small, focused changes over broad rewrites.
- Keep secrets, credentials, private keys, databases, generated artifacts, and local environment files out of Git.
- Treat external input, downloaded source, RPC responses, and model-generated content as untrusted.
- Do not weaken AegisForge's research authorization, scope, sandbox, evidence, or verification boundaries.
- Do not record an unverified assumption, inference, proposal, or intended capability as an established fact. Label uncertainty explicitly.
- Do not duplicate the parent Python agent runtime, queue, Research Case, sandbox, CLI, or evidence ledger.

## Documentation is part of the change

- After every significant implementation or behavior change, update the relevant documentation in the same change set.
- Update `PROJECT_CONTEXT.md`, `TASKS.md`, and/or `DECISIONS.md` when architecture, status, priorities, interfaces, or design decisions change.
- Commit documentation together with the corresponding code and tests. Do not leave required documentation as a follow-up task.
- Before finishing, review documentation against actual code, tests, configuration, and observed command output.
- Do not claim tests, builds, runtime checks, or security reviews passed unless they were actually run and their results observed.

## Before declaring a task complete

1. Run relevant tests and static checks available in this subproject.
2. Review the complete diff for correctness, scope, secrets, and unintended changes.
3. Verify documentation is current and consistent with implementation.
4. Record remaining limitations and unverified items in `TASKS.md` or the completion report.
5. Report exactly what changed, what was checked, and what remains unverified.

## Scope boundary

`my-project/` is currently an isolated Node.js scaffold only. It is not an implementation of AegisForge's EVM Key Forensics workflow and has no approved product domain or parent-integration contract. Do not add product behavior or integrations until that contract is explicitly defined, documented, and tested.
