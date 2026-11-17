# Legacy Agent Plan: Implementation Status

**Reviewed against:** `main` repository tree and source files  
**Purpose:** map the original MASTER AGENT diagram to the implementation that exists today. This is a source review, not a claim that the full test suite was run.

## Executive finding

The original idea is still visible in AegisForge, but it has evolved into a more general agent orchestration and evidence system. Several agent roles and verification mechanisms exist. The original diagram is **not yet implemented end-to-end**: the clearest gap is a first-class research case that binds target identity, authorization/scope, pinned source revision, hypothesis, experiment, and evidence across the whole task lifecycle.

Do not add more agent roles before closing that control-plane gap.

## Mapping: old plan to current repository

| Original component | Current code evidence | Assessment |
|---|---|---|
| MASTER AGENT / planner | `orchestrator/master.py`, `agents/master/agent.py`, `shared/queue.py` | Partial. Planning, queueing, deduplication, bounded retries and evidence-quality heuristics exist. This does not itself establish that a security result is correct. |
| GitHub Hunter | `agents/researcher/agent.py`, `shared/github_client.py`, `agents/opportunity_hunter/agent.py` | Partial. Repository discovery and opportunity triage exist. Popularity and keyword scores are discovery signals, not proof of a security issue or buyer demand. |
| Immunefi Hunter | No dedicated Immunefi-specific agent was identified in the current agent registry/tree reviewed. | Missing as a distinct integration. Program discovery, scope parsing, version tracking and scope-change alerts should not be assumed to exist. |
| Hackathon Hunter | No dedicated hackathon agent was identified in the current agent registry/tree reviewed. | Missing as a distinct integration. Keep this separate from the security research path unless a concrete shared interface is defined. |
| Solidity / DeFi / NFT auditors | `agents/analyst/agent.py`, `agents/security_checker/agent.py`, `agents/developer/agent.py`, `agents/lab_runner/agent.py`, plus source and crypto researchers | Partial and cross-domain. Roles exist, but separate names or prompts do not prove domain-specific audit coverage. There is no basis here to claim dedicated, mature Solidity/DeFi/NFT auditors. |
| Analyst | `agents/analyst/agent.py` | Present as an agent role. Output remains a hypothesis or analysis until independently verified. |
| Planner | `orchestrator/master.py` and master agent | Present, with bounded orchestration controls. Planner scores and model-generated plans are routing inputs, not proof. |
| Executor | `agents/worker.py`, `shared/execution_gate.py`, capability policy/grants, executor registry and outcome verifiers | Present as a controlled execution path. Keep execution permissions narrower than research permissions. |
| Controller / verification | `agents/validator/agent.py`, deterministic tests, artifact verifiers, source-pin checks and CI workflows | Partial. Several checks exist, but the validator still must not be treated as an oracle; evidence-origin independence and historical reproduction can correctly remain inconclusive. |
| Evidence / report | `shared/evidence_ledger.py`, `shared/evidence_manifest.py`, `shared/experiment_dossier.py`, `shared/proof_bundle.py`, EVM Key Forensics tools and workflows | Substantial foundation. Hashes, manifests and CI establish only the properties their checks actually verify. They do not alone prove exploitability or source-to-binary provenance. |
| Case and scope gate | Architecture specifies it, but no single first-class case/scope object was identified in the CLI/queue entry path reviewed. | Highest-priority gap. A task can be queued by role and description without a mandatory, structured case that carries scope and immutable target identity through all stages. |

## Four-role LLM loop: recommended interpretation

The four roles should be **responsibilities**, not four LLMs that trust one another:

1. **Analyst:** proposes a falsifiable hypothesis and states attacker capability, preconditions, invariant and expected impact.
2. **Planner:** turns it into bounded tasks with explicit acceptance and stop conditions.
3. **Executor:** runs only permitted deterministic tools in the pinned environment.
4. **Controller:** attempts to disprove the claim, checks evidence and reports a state such as `CONFIRMED`, `REJECTED`, `INCONCLUSIVE` or `OUT_OF_SCOPE`.

The controller should combine LLM critique with deterministic gates. An LLM's agreement with another LLM is not independent verification.

## Recommended build order

### P0 — Research Case and Scope Gate

Introduce a structured case contract that binds:
- case ID and lifecycle status;
- target repository, immutable commit/tag and relevant contracts;
- authorization/scope URL plus a recorded scope snapshot or digest and review date;
- hypothesis, attacker capabilities, preconditions, invariant and falsification criteria;
- permitted execution mode and explicit prohibited actions;
- task IDs, experiment records, evidence manifest and final decision.

Every security-research task should carry a case ID. Missing scope or unpinned target must block execution rather than silently fall back to a general task.

### P1 — Verification contract

Define machine-checkable promotion rules so agent output cannot become a finding merely because a task completed. Require reproducible evidence, counter-tests, demonstrated impact and scope eligibility. Keep `INCONCLUSIVE` as a valid terminal result.

### P2 — Hunter integrations

Only after P0/P1: add a dedicated Immunefi program/scope watcher. It should create candidate cases, not authorize testing by itself. A hackathon hunter is a separate product-discovery workflow and should not be coupled to bounty execution.

### P3 — Domain specialization

Split Solidity/DeFi/NFT agents only when benchmark results show that specialized tools or context improve precision. Do not multiply agent classes just to mirror the old diagram.

## Current proving ground

Keep the immediate research target as SSV Network Bug Bounty. The observed operator-migration/effective-balance difference remains a lead, not a confirmed vulnerability. The next research action must be a reproducible, scope-eligible test of a specific asset-impact path or an explicit rejection of the hypothesis.

## Acceptance criteria for P0

- Case creation fails closed when target revision or scope evidence is missing.
- Task submission references an existing case; workers reject mismatched or unapproved case/task bindings.
- Scope and source revision are preserved in the experiment/evidence output.
- A task cannot mark a case `CONFIRMED` by writing free-form LLM text.
- Tests cover missing scope, mutable branch-only targets, mismatched case IDs, prohibited execution modes, and a valid local/test-environment case.
- Existing non-security research workflows remain compatible or are explicitly migrated.

## Source landmarks reviewed

- `orchestrator/master.py`
- `agents/worker.py`
- `agents/researcher/agent.py`
- `agents/opportunity_hunter/agent.py`
- `agents/analyst/agent.py`
- `agents/validator/agent.py`
- `shared/queue.py`
- `shared/evidence_ledger.py`
- `shared/result_codec.py`
- `aegisforge.py`
- `docs/ARCHITECTURE.md`
- `docs/EVM-KEY-FORENSICS.md`
- `docs/evm-key-forensics-source-provenance.md`
