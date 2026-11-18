# AegisForge — EVM Key Forensics

**Reproducible security research for EVM systems. Evidence before conclusions.**

AegisForge is an early-stage security research toolkit for turning authorized vulnerability hypotheses into reproducible experiments and independently checkable evidence. It combines an existing Python agent/orchestration codebase with an EVM forensic evidence workflow.

It is not an autonomous exploit bot, a scanner that promises findings, or a report generator that treats model output as proof. Its purpose is to reduce the work required to investigate, reproduce, challenge, and document a security claim — including a clear rejected or inconclusive result.

## Why it exists

Security research often leaves evidence scattered across source links, repository revisions, test scripts, traces, environment assumptions, and reports. Reviewers then have to reconstruct the work before they can evaluate the conclusion. LLMs can accelerate navigation and hypothesis generation, but plausible reasoning is not proof.

AegisForge is being built around a controlled research loop:

1. **Define the case.** Record the target, immutable source revision, bounty scope, hypothesis, attacker capability, expected invariant, and falsification criteria.
2. **Plan bounded work.** Break the case into tasks with explicit acceptance and stop conditions.
3. **Run reproducible experiments.** Execute deterministic tests in a pinned, permitted environment.
4. **Challenge the hypothesis.** Try counterexamples, safe control cases, mitigations, and alternative explanations.
5. **Establish impact.** Connect behavior to an in-scope security consequence rather than relying on a suspicious code difference.
6. **Package evidence.** Preserve tool versions, commands, logs, outputs, hashes, limitations, and machine-readable conclusions.
7. **Verify independently.** Allow another reviewer to check what the evidence actually establishes without trusting the author's narrative.

## Product focus: EVM Key Forensics

The immediate goal is to ship a reliable forensic workflow, not to keep expanding bounty hunts. Active SSV Network vulnerability research is paused while the product is completed.

The first release should take a pinned public source revision and a falsifiable forensic question through source analysis, a bounded local or synthetic experiment, validation, and export of a portable evidence bundle. Another engineer should be able to inspect the bundle and understand exactly what was and was not established.

The existing Profanity work is currently a benchmark and synthetic demonstration, not proof that the historical implementation has been reproduced and not evidence about any individual wallet. The product must preserve that distinction in code, tests, reports, and documentation.

The release acceptance checklist is [docs/PRODUCT-READINESS.md](docs/PRODUCT-READINESS.md). The MVP is not release-ready until its blockers are verified against the exact candidate commit. The command-line workflow for creating cases and submitting bound forensic tasks is documented in [docs/RESEARCH-CASE-CLI.md](docs/RESEARCH-CASE-CLI.md).

## Sandbox isolation levels

AegisForge distinguishes analysis-only work from bounded execution. These modes are not equivalent security guarantees:

- `none`: analysis only. The requested code is not executed.
- `process`: a subprocess launched inside `source_root`, with POSIX `RLIMIT_AS`, `RLIMIT_CPU`, and `RLIMIT_NPROC` limits and bounded stdout/stderr capture. This is **process isolation plus resource limits**, not a filesystem, syscall, or network sandbox.
- `container`: Docker with `--network=none`, read-only root filesystem and source mount, dropped Linux capabilities, a non-root user, memory/CPU limits, and a bounded temporary filesystem. No seccomp profile is configured in v1; this is **not a complete seccomp sandbox**. The `python:3.12-slim` image must already be available to Docker, because network access is disabled for the container.

The runner never uses `shell=True`. Output is retained only up to `max_output_bytes` per stream; results contain SHA-256 digests and truncation flags, not raw output. A timeout kills the launched process group and raises `SandboxError`. Do not treat either execution mode as sufficient isolation for hostile workloads without additional platform-level controls.

## Disclosure Timeline

Each configured research round has a default **90-day disclosure deadline** from its recorded start time. A round may set a different `disclosure_deadline_days` value in its immutable `RoundSpec`, subject to the global 7–180 day range and technique-specific limits. AegisForge records the round ID, technique, start time, current deadline, status, completion time, verdict, and any extension metadata in `round_transparency`.

Round statuses have explicit lifecycle meanings:

- `OPEN`: the round is in progress and has not been extended.
- `EXTENDED`: a human approved the round's single permitted extension and the disclosure deadline was shifted.
- `COMPLETED`: the round is finished and its verdict is recorded.

An extension can be granted **only once per round and only by human decision**. The extension operation is a review-gated action; repeating it or attempting it on an `EXTENDED` or `COMPLETED` round is a no-op. Both `OPEN` and `EXTENDED` rounds are checked against their current deadline. An overdue round creates or prioritizes a human review with reason `deadline_exceeded:<round_id>`; this is a review trigger, not an automatic-publication timer. AegisForge does not automatically publish a vulnerability, contact a target, or promote an agent claim to `CONFIRMED`.

Public-safe timeline metadata can be queried with:

```bash
aegisforge tasks case rounds --public <case_id>
```

The command returns only round identifiers, techniques, timestamps, status, and verdict metadata; it does not expose hypotheses, private evidence, or reproduction details.

## What exists today

- A Python agent and orchestration codebase with task queueing and research roles.
- Evidence-ledger and evidence-manifest components, plus EVM Key Forensics tooling and GitHub Actions checks.
- Source-pinning and artifact-verification work that explicitly distinguishes object/hash checks from stronger provenance claims.
- A proposed architecture describing the target workflow and its trust boundaries.
- A first-class immutable `ResearchCase` contract persisted in the SQLite-backed queue, with CLI commands to register and inspect cases.
- Worker-side fail-closed validation for forensic roles, automatic case-ID inheritance for child tasks, and evidence observations that inherit the task's case ID.
- Security-boundary tests covering missing scope, mutable source references, mismatched case IDs, prohibited execution modes, queue persistence, and case-linked evidence.

**Integration boundary:** `source_researcher`, `crypto_analyst`, and `lab_runner` now fail closed at the worker boundary when a task has no registered `research_case_id`. Child tasks inherit the parent's case identity unless an explicit ID is supplied, and mismatched or invalid case bindings are blocked before agent execution. Generic non-forensic roles retain compatibility with legacy tasks. The CLI now supports case registration and case-bound forensic task submission. The full end-to-end run-to-evidence workflow and independent portable-bundle verifier still require release-level validation.

## What is not established

- No SSV vulnerability is currently claimed as confirmed.
- Historical vulnerability reproduction is not established by the current EVM forensic evidence workflow.
- Source-to-binary provenance is not established merely by hashes, reproducible builds on one runner, or a GitHub Actions attestation.
- Independent review remains pending unless a specific evidence artifact says otherwise.
- A green CI run establishes only that the checks that ran passed; it does not prove a security conclusion.
- Dedicated Immunefi and Hackathon Hunter integrations are not complete product capabilities.
- Commercial product-market fit and recurring revenue are hypotheses to validate, not established facts.

## Architecture and agent roles

The long-term design is documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), with a comparison of the original agent plan to the current implementation in [docs/LEGACY-AGENT-PLAN-STATUS.md](docs/LEGACY-AGENT-PLAN-STATUS.md).

The intended responsibilities are:

- **Hunters:** discover candidate repositories, bounty programs, scope changes, and research opportunities.
- **Analyst:** propose a falsifiable hypothesis and define attacker capability, preconditions, invariant, and impact.
- **Planner/orchestrator:** create bounded tasks, manage dependencies and retries, and preserve case identity.
- **Executor:** run only permitted deterministic tools in an approved environment.
- **Controller/verifier:** challenge the claim and check test outputs, scope, impact, and evidence completeness.
- **Evidence pipeline:** preserve the research record and produce a result such as `CONFIRMED`, `REJECTED`, `INCONCLUSIVE`, or `OUT_OF_SCOPE`.

These are responsibilities, not a requirement to create one LLM per role. LLMs may assist analysis and test design, but deterministic checks must enforce execution boundaries and result-promotion rules. Agreement between models is not independent verification.

## Safety and trust principles

- **Evidence over confidence:** model output alone can never confirm a vulnerability.
- **Falsification first:** actively search for counterexamples and alternative explanations.
- **Immutable inputs:** require a full source commit SHA and record scope evidence for a research case.
- **Fail closed:** missing scope evidence, unpinned source, mismatched case identity, or prohibited execution mode must block execution.
- **Bounded execution:** prefer local tests, authorized forks, and testnets; no live-mainnet execution mode is provided by the initial case contract.
- **Honest conclusions:** preserve inconclusive and rejected results instead of forcing a finding.
- **No invented provenance:** state only what each verifier actually checks.
- **Human accountability:** the researcher remains responsible for authorization, scope, impact, and disclosure.

## Roadmap

### Phase 1 — Trusted research loop

- Complete review and CI verification of the initial research-case contract and scope gate.
- Extend mandatory case binding to legacy entrypoints and relevant execution paths without breaking existing task workflows.
- Carry immutable target revision and scope digest into experiment records and exported evidence manifests.
- Add end-to-end tests proving unauthorized or unbound research execution is blocked at the actual execution boundary.
- Run one authorized, independently reproducible case study — whether it confirms or rejects the hypothesis.

### Phase 2 — Research workbench

- Add reusable EVM state-transition and invariant-test templates.
- Improve revision comparison and regression triage.
- Standardize evidence manifests and independent reproduction commands.
- Benchmark research quality before splitting agents into Solidity, DeFi, NFT, or other specializations.

### Phase 3 — Research infrastructure

- Add a dedicated Immunefi program/scope watcher that creates candidate cases but cannot authorize execution by itself.
- Support multiple protocols and team review workflows.
- Consider a separate hackathon/opportunity discovery workflow without coupling it to bounty execution.
- Evaluate paid team workspaces and evidence retention only after repeated use and willingness to pay are demonstrated.

## Product and business hypothesis

The initial target users are independent smart-contract security researchers and small audit teams who spend substantial time reproducing and documenting findings. The first potential paid value is not “AI finds every bug”; it is less effort to build a defensible research case and less reviewer time spent reconstructing it.

Possible future models include team workspaces, private research history, and evidence-retention workflows. These are hypotheses to validate with users, not current revenue or proven product-market fit.

## What success means

For the first EVM Key Forensics release, an independent reviewer can validate the pinned source and portable evidence bundle, rerun the documented checks, distinguish synthetic results from historical reproduction, and reach the same conclusion without trusting the author or an LLM. Release readiness is tracked in [docs/PRODUCT-READINESS.md](docs/PRODUCT-READINESS.md).

The long-term asset is not the number of agents. It is the verification tooling, reproducible research history, and workflow quality accumulated across investigations.

## Repository

- Source: https://github.com/rudimentall1/AegisForge
- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Original-plan implementation map: [docs/LEGACY-AGENT-PLAN-STATUS.md](docs/LEGACY-AGENT-PLAN-STATUS.md)
- SSV Network Bug Bounty: https://immunefi.com/bug-bounty/ssvnetwork/information/
- SSV Network scope: https://immunefi.com/bug-bounty/ssvnetwork/scope/

**Rule:** no code difference becomes a vulnerability until a reproducible test connects it to an in-scope security impact.
