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

## First proving ground: SSV Network

The first active research target is the [SSV Network Bug Bounty on Immunefi](https://immunefi.com/bug-bounty/ssvnetwork/information/), subject to its current [program scope](https://immunefi.com/bug-bounty/ssvnetwork/scope/).

The investigation has examined differences involving operator migration and effective-balance accounting across source revisions. **No eligible exploit path with demonstrated impact has been established.** These observations are research leads, not a bounty finding. A report is justified only if a reproducible test demonstrates an in-scope security impact.

A hypothesis should be rejected or stopped when evidence shows expected behavior, an existing mitigation, out-of-scope conditions, or no meaningful impact.

## What exists today

- A Python agent and orchestration codebase with task queueing and research roles.
- Evidence-ledger and evidence-manifest components, plus EVM Key Forensics tooling and GitHub Actions checks.
- Source-pinning and artifact-verification work that explicitly distinguishes object/hash checks from stronger provenance claims.
- A proposed architecture describing the target workflow and its trust boundaries.
- A first-class `ResearchCase` contract and fail-closed validation tests are being introduced on the `feat/research-case-scope-gate` branch.

The new case contract is an initial boundary component. It is **not yet fully wired through every queue, worker, executor, and evidence path**. Do not treat the overall case/scope gate as complete until those integrations and CI checks are verified.

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

- Finalize the research-case schema and fail-closed scope gate.
- Bind queue tasks, workers, execution records, and evidence to a case ID.
- Preserve immutable target revision and scope digest throughout the lifecycle.
- Add tests for missing scope, mutable source references, mismatched case IDs, and prohibited execution modes.
- Run CI and complete one authorized, independently reproducible case study — whether it confirms or rejects the hypothesis.

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

AegisForge succeeds when an independent reviewer can reconstruct the pinned environment, rerun the relevant checks, understand the attack preconditions and impact, and reach the same conclusion from the evidence — without needing to trust the author's reputation or an LLM's explanation.

The long-term asset is not the number of agents. It is the verification tooling, reproducible research history, and workflow quality accumulated across investigations.

## Repository

- Source: https://github.com/rudimentall1/AegisForge
- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Original-plan implementation map: [docs/LEGACY-AGENT-PLAN-STATUS.md](docs/LEGACY-AGENT-PLAN-STATUS.md)
- SSV Network Bug Bounty: https://immunefi.com/bug-bounty/ssvnetwork/information/
- SSV Network scope: https://immunefi.com/bug-bounty/ssvnetwork/scope/

**Rule:** no code difference becomes a vulnerability until a reproducible test connects it to an in-scope security impact.
