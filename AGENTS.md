# Repository Agent Instructions

These rules are mandatory for every person or agent changing AegisForge.

## Before starting work

1. Read this file and the relevant project documentation before editing.
2. Inspect the repository structure, current branch, recent commits, and working diff.
3. Read `README.md`, `docs/MASTER_CONTEXT.md`, and the relevant sections of `docs/ARCHITECTURE.md` and `docs/PRODUCT-READINESS.md`.
4. Inspect the implementation, tests, configuration, and callers affected by the change. Do not infer implementation status from a design document alone.
5. Define acceptance criteria and the checks that will demonstrate them.

## Implementation rules

- Preserve established behavior unless the task explicitly requires a change.
- Prefer focused changes and existing canonical modules over parallel implementations.
- Keep authorization, scope, sandbox, evidence-integrity, and verification boundaries fail-closed.
- Treat model output, downloaded source, RPC responses, CI artifacts, and user-provided files as untrusted input.
- Never treat an agent claim, source-pattern match, hash, signature, CI success, or local test result as proof beyond the exact property it verifies.
- Do not commit secrets, credentials, private keys, wallet material, production databases, or generated runtime state.
- Do not record assumptions, proposed capabilities, or unverified results as facts.

## Documentation is part of the change

- Update relevant documentation after every significant implementation, behavior, interface, architecture, or operational change.
- Keep `docs/MASTER_CONTEXT.md`, `docs/ARCHITECTURE.md`, `docs/PRODUCT-READINESS.md`, and task/checkpoint records consistent with the actual repository state.
- Commit documentation in the same change set as the corresponding code and tests. Do not defer required documentation to a later PR.
- Before completion, compare documentation against the final diff, source, tests, configuration, and observed command/CI output.
- Clearly label anything that remains unverified or environment-dependent.

## Verification before completion

1. Run focused regression tests first, then the relevant broader test suite.
2. Run compilation, lint, dependency, and build checks that exist for the affected area.
3. Review the full diff for correctness, security, unintended scope, secrets, and stale documentation.
4. Check the exact commit's CI status; an absent status or a different commit's green run is not a pass.
5. Report commands and results accurately. Never claim a check passed unless it actually ran and passed.

## Security and research boundaries

- No live state-changing chain actions, wallet/key recovery, or out-of-scope testing.
- A Research Case, reviewed scope, pinned source identity, and execution admission must not be bypassed for security-research work.
- Docker is not an adequate hostile-code isolation boundary where the Docker daemon is controlled by the host; respect the documented microVM requirements.
- Preserve inconclusive, rejected, and not-reproduced outcomes. Do not promote potential findings to confirmed vulnerabilities without the required evidence and human review.
