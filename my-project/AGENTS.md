# Agent Instructions — my-project

These rules are mandatory for every person or agent changing this directory.

## Before starting work

1. Read this file, `PROJECT_CONTEXT.md`, `TASKS.md`, and `DECISIONS.md`.
2. Read the relevant documentation and inspect the current directory structure before editing.
3. Inspect the implementation and tests that the requested change touches. Do not assume the repository or this subproject has the architecture you expect.
4. Identify the acceptance criteria and the checks needed to prove the change.

## During implementation

- Preserve existing behavior unless the task explicitly requires changing it.
- Prefer small, focused changes over broad rewrites.
- Keep secrets, credentials, private keys, databases, generated artifacts, and local environment files out of Git.
- Treat external input and model-generated content as untrusted.
- Do not weaken AegisForge's research authorization, sandbox, evidence, or verification boundaries.
- Do not record an unverified assumption, inference, proposal, or intended capability as an established fact. Label uncertainty explicitly.

## Documentation is part of the change

- After every significant implementation or behavior change, update the relevant documentation in the same change set.
- Update `PROJECT_CONTEXT.md`, `TASKS.md`, and/or `DECISIONS.md` when architecture, status, priorities, interfaces, or design decisions change.
- Commit documentation together with the corresponding code and tests. Do not leave required documentation as a follow-up task.
- Before finishing, review the documentation against the actual code, tests, configuration, and command output. Correct stale or unsupported statements.
- Do not claim tests, builds, runtime checks, or security reviews passed unless they were actually run and their results observed.

## Before declaring a task complete

1. Run the relevant tests and static checks available in this subproject.
2. Review the complete diff for correctness, scope, secrets, and unintended changes.
3. Verify that documentation is current and consistent with the implementation.
4. Record remaining limitations and unverified items in `TASKS.md` or the completion report.
5. Report exactly what changed, what was checked, and what remains unverified.

## Scope boundary

`my-project/` is a subproject inside AegisForge. Do not duplicate or silently replace the parent repository's Python agent runtime, research-case contract, queue, evidence ledger, sandbox, or CLI. Any integration with parent components must be explicit, documented, and tested.
