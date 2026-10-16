# AegisForge Architecture

**Status:** target architecture and implementation map, not a claim that every component is implemented.
**Product:** AegisForge — EVM Key Forensics
**Principle:** evidence before conclusions.

## 1. Mission and product boundary

AegisForge is intended to become a reproducible security-research and forensic evidence platform. It should help a researcher move from an authorized target and a falsifiable hypothesis to a repeatable experiment, impact analysis, and evidence package that an independent reviewer can verify.

It is not intended to be:
- An autonomous exploit bot that attacks live systems.
- A scanner that treats every suspicious pattern as a vulnerability.
- A report generator that converts model output into a security claim.
- A CI badge or attestation presented as proof that a finding is true.

The first release target is the EVM Key Forensics workflow: pinned public source, structured hypothesis, bounded local or synthetic experiment, independent validation, and portable evidence export. Active SSV bounty hunting is paused until this product workflow is release-candidate ready. Broader smart-contract investigations should follow only after the forensic evidence loop is dependable.

## 2. System architecture at a glance

The architecture is organized around a controlled research pipeline:

```text
Researcher / CLI / CI
        |
        v
Research Case & Scope Gate
        |
        v
Planner / Orchestrator ---- Task Queue & State Store
        |
        +---- Research Agents (hypothesis, source, protocol, crypto)
        |
        v
Target Adapter & Pinned Environment
        |
        v
Experiment Runner (Foundry / scripts / deterministic checks)
        |
        v
Independent Counter-tests & Impact Analysis
        |
        v
Evidence Ledger + Artifact Manifest
        |
        v
Verifier / Reproduction Runner
        |
        v
Research Result: CONFIRMED | REJECTED | INCONCLUSIVE | OUT_OF_SCOPE
```

AI proposes and helps investigate. Deterministic tools execute tests. The verifier checks artifacts and claims. Human researchers remain responsible for authorization, scope, disclosure, and final interpretation.

## 3. Architectural layers

### 3.1 Researcher interface and entrypoints

**Purpose:** accept research goals, show task status, run verification commands, and export evidence.

**Current code landmarks:** `aegisforge.py`, `run.py`, CLI/task interfaces.

**Target responsibilities:**
- Start a case from a target repository, exact revision, scope reference, and research question.
- Inspect queued/running/completed/failed tasks.
- Show the difference between agent output and verified result.
- Run local/CI verification and export a portable evidence bundle.
- Never imply that a task completed successfully merely because an agent returned text.

### 3.2 Case and scope gate

**Purpose:** define the permitted boundary before research begins.

**Target case record:**
- Unique case ID and creation time.
- Target protocol/repository, commit or immutable tag, contracts and chain where relevant.
- Bug bounty scope and version/date reviewed.
- Attacker capability and explicit preconditions.
- Assets and security properties at risk.
- Allowed testing environment and excluded actions.
- Hypothesis, expected invariant, and falsification conditions.

**Status:** the initial implementation is present on `main`. `shared/research_case.py` defines an immutable case contract with pinned source commit, scope URL/digest/review date, hypothesis, attacker capability, invariant, falsification criteria, execution mode, and case status. `shared/queue.py` persists registered cases, rejects conflicting reuse of a case ID, binds explicitly case-linked tasks, and returns the case ID to workers. `agents/worker.py` validates case-linked tasks before normal task processing. `shared/evidence_ledger.py` attaches the queue task's case ID to evidence observations, with a migration for existing SQLite databases. Tests cover these boundaries.

**Important limit:** this is not universal enforcement yet. Legacy tasks without `research_case_id` can still use the old path, and case identity is not yet proven to flow into every executor record, experiment dossier, or exported evidence manifest. The next milestone is mandatory case binding at all research entrypoints and execution boundaries, followed by end-to-end tests.

No live transaction, state-changing external action, or out-of-scope target should be tested automatically. Default to local forks, testnets, or other explicitly authorized environments.

### 3.3 Planner and orchestration layer

**Purpose:** decompose a research goal into bounded tasks, assign work, manage retries, and stop when evidence stops improving.

**Current code landmarks:** `orchestrator/master.py`, `shared/queue.py`, `shared/result_codec.py`, `shared/evidence_ledger.py`, `shared/intelligence_quality.py`.

**Target responsibilities:**
- Create a task graph with explicit dependencies and acceptance criteria.
- Deduplicate equivalent work and cap retries, task counts, time, and resource usage.
- Keep task state separate from research conclusions.
- Require verification before promoting an agent result to a finding.
- Stop or branch when tests falsify a hypothesis, the target is out of scope, or repeated work produces no new evidence.

**Design constraint:** orchestration scores and information-gain heuristics are routing signals, not proof of correctness or vulnerability severity.

### 3.4 Agent layer

**Current code landmarks:** the `agents/` tree includes master, researcher, analyst, source-researcher, crypto-analyst, developer, checker/security-checker, validator, lab-runner, opportunity-hunter, and worker modules.

**Target role separation:**
- **Researcher:** gathers context and proposes hypotheses.
- **Source researcher:** maps source paths, versions, and relevant changes.
- **Analyst:** reasons about invariants, trust boundaries, and attack preconditions.
- **Crypto analyst:** reviews cryptographic assumptions and historical key-generation claims.
- **Developer/test designer:** drafts minimal deterministic tests or PoCs.
- **Lab runner:** executes approved experiments in bounded environments.
- **Security checker:** challenges assumptions, identifies counterexamples, and checks impact.
- **Validator:** checks the completeness and consistency of structured results and evidence.
- **Planner/master:** coordinates tasks but cannot unilaterally mark a vulnerability confirmed.

Agent names in code do not automatically mean every role has the target responsibilities or reliable quality today. Agent output is untrusted input until independently checked.

### 3.5 Target adapters and source intelligence

**Purpose:** normalize source retrieval and environment setup while preserving exact target identity.

**Target responsibilities:**
- Pin Git repository, commit SHA/tag, submodules, dependency lockfiles, compiler/tool versions, and configuration.
- Record source provenance and fail closed when the requested revision cannot be verified.
- Provide adapters for EVM repositories, Foundry projects, RPC/fork configuration, and later other target types.
- Compare revisions and surface changed code without treating a diff as a vulnerability.
- Cache source artifacts by immutable identity, not only mutable branch names.

**Current status:** repository research and source-pinning/evidence workflows exist in the project. Full target-adapter interfaces and consistent enforcement across all research agents remain future work.

### 3.6 Experiment and execution layer

**Purpose:** turn a hypothesis into a reproducible test.

**Target responsibilities:**
- Generate or use a minimal Foundry test, invariant harness, scripted state-transition experiment, or deterministic reproduction.
- Execute in an isolated, resource-bounded runner.
- Record exact command, environment, dependency versions, exit code, stdout/stderr, test result, and timeout/resource limits.
- Support counter-tests: expected-safe control case, boundary values, alternative sequence, and regression checks.
- Keep live-chain interaction disabled by default; require explicit authorization and safe test mode.

**Acceptance rule:** compilation is not reproduction. A passing test only establishes the behavior asserted by that test. The test must connect attacker capability and preconditions to an in-scope security impact.

### 3.7 Hypothesis, invariant, and impact model

Each hypothesis should be a structured record rather than free-form prose.

Minimum fields:
- Claim and affected component.
- Source revision and relevant source locations.
- Attacker capability.
- Preconditions and transaction/state sequence.
- Expected invariant or security property.
- Reproduction procedure.
- Counter-test and alternative explanations.
- Impact path, affected assets/users, and severity rationale.
- Scope status and disclosure constraints.
- Current conclusion and evidence references.

A code difference, unusual state, test failure, or static-analysis warning is a lead. It becomes a finding only when the causal path and impact are demonstrated.

### 3.8 Evidence ledger and artifact package

**Current code landmarks:** `shared/evidence_ledger.py` and the EVM Key Forensics documentation/workflows under `docs/` and `.github/workflows/`.

**Target evidence package should include:**
- Case ID, target revision, scope reference, and hypothesis ID.
- Immutable manifest with hashes of included files.
- Toolchain and dependency identity.
- Reproduction command and environment.
- Raw logs, traces, test outputs, and relevant diffs.
- Counter-test results and independent verification status.
- Machine-readable conclusion, limitations, and known missing evidence.
- Provenance statements whose wording matches what was actually verified.

Hashes make artifacts tamper-evident only relative to a trusted recorded digest. A GitHub Actions attestation can identify a workflow-produced artifact under its stated claims; it does not by itself prove that source produced a binary, that the experiment is valid, or that a vulnerability exists.

### 3.9 Independent verifier and reproduction runner

**Purpose:** enable a reviewer to verify the evidence package without trusting the agent that generated it.

**Target responsibilities:**
- Validate schema, manifest, file hashes, paths, size limits, and archive safety.
- Check that target and toolchain identities match the case record.
- Re-run the documented experiment in a clean runner where practical.
- Compare expected outputs and report missing, inconsistent, or unverified claims.
- Emit a clear verification report with individual checks and limitations.
- Fail closed on malformed or ambiguous evidence.

Verification levels must be explicit:
1. **Package integrity checked:** files match the manifest.
2. **Workflow provenance checked:** a specific attestation verifies under its trust model.
3. **Experiment rerun:** the documented experiment reruns successfully.
4. **Independent source review:** a reviewer confirms the causal reasoning.
5. **Finding independently reproduced:** the attack path and impact are reproduced.
These levels are not interchangeable.

### 3.10 Persistence and data model

**Current code landmarks:** `shared/queue.py` and the existing SQLite-backed task/evidence workflow.

**Target logical entities:**
- ResearchCase
- TargetRevision
- ScopeSnapshot
- Hypothesis
- Task and TaskDependency
- ExperimentRun
- EvidenceArtifact
- VerificationCheck
- Finding
- ReviewerDecision
- AuditEvent

The initial implementation can remain SQLite-first. A server/team deployment may later use PostgreSQL and object storage, but only when concurrent users, retention, and access-control requirements justify the complexity. Evidence files should be content-addressed and linked from durable metadata.

### 3.11 Security, policy, and isolation

Security is a cross-cutting control plane, not just another agent.

Required controls:
- Explicit authorization and scope checks.
- No private keys, seed phrases, or production secrets in prompts, logs, or artifacts.
- Sandboxed execution with CPU, memory, time, filesystem, and network limits.
- No unreviewed shell commands or autonomous transactions against live systems.
- Secret redaction and safe handling of RPC credentials.
- Dependency and artifact integrity checks.
- Audit trail for who initiated a case, changed scope, ran tests, and approved publication.
- Human approval for external disclosure or any action with external side effects.

### 3.12 CI and delivery layer

**Current code landmarks:** `.github/workflows/ci.yml` and `.github/workflows/evm-key-forensics-probe.yml`.

CI should validate code and evidence tooling, not manufacture a positive research conclusion.

Target gates:
- Unit and integration tests.
- Static checks and schema validation.
- Reproducibility smoke tests.
- Negative tests for corrupt or malicious evidence bundles.
- Clean-runner verification.
- Artifact manifest/hash checks.
- Explicitly reported skips and limitations.
- No secret-dependent or network-dependent test treated as passing when it was skipped.

### 3.13 External integrations

Initial integrations:
- GitHub for source revisions, PRs, workflows, and immutable references.
- Foundry for EVM test execution.
- CI runners for repeatable verification.
- Optional model providers for agent reasoning.

Later integrations may include audit-team issue trackers, private source hosting, and additional analysis engines. Integrations must be replaceable and must not be allowed to override the evidence verifier's conclusion.

## 4. Data flow and trust boundaries

1. A researcher creates a case and declares authorization, target revision, and scope.
2. The scope gate validates required fields and refuses unsafe or ambiguous execution.
3. The planner creates bounded tasks and records dependencies.
4. Agents gather source context and propose falsifiable hypotheses.
5. A human or explicit policy approves an experiment plan.
6. The runner executes against the pinned local/fork/test environment.
7. Counter-tests and impact analysis attempt to falsify the hypothesis.
8. Evidence is recorded with hashes, environment, logs, and limitations.
9. A separate verifier checks the package and, when feasible, reruns the experiment.
10. The case receives one of the allowed conclusions; a human approves any disclosure.

Trust boundaries include model output to executable command, repository content to analysis prompts, source identity to built artifacts, runner to evidence package, and evidence package to final report. Treat repository text, model output, RPC responses, and test artifacts as untrusted data.

## 5. Result states

Use distinct conclusions:
- **CONFIRMED:** the in-scope attack path and security impact are reproduced and evidence requirements are met.
- **REJECTED:** a specific hypothesis was falsified by documented counter-evidence.
- **INCONCLUSIVE:** evidence is insufficient, reproduction is unstable, or a key precondition is unverified.
- **OUT_OF_SCOPE:** the behavior does not meet the target program's current scope or rules.
- **NOT_REPRODUCED:** the attempt did not reproduce the claim; this does not necessarily prove the claim false.

A tool error, missing dependency, timeout, skipped test, or failed environment setup must not be silently converted into REJECTED or CONFIRMED.

## 6. Implementation map: current vs target

| Area | Current evidence in repository | Target state |
|---|---|---|
| CLI and entrypoints | `aegisforge.py`, `run.py` | Case-oriented research and verification commands |
| Orchestration | `orchestrator/master.py` | Bounded task graph with case/scope enforcement |
| Agents | Multiple role modules under `agents/` | Clear role contracts; suggestions separated from verified results |
| Queue and persistence | Shared queue and SQLite-oriented workflow | Versioned case/evidence schema and migrations |
| EVM forensics | EVM Key Forensics tools/docs and probe workflow; SSV Network is the first active bounty target | End-to-end authorized reproduction pipeline with case-bound experiments and independently reproducible evidence |
| Evidence | Evidence ledger and artifact/attestation docs | Portable schema-versioned bundle with explicit verification levels |
| Independent verification | Verifier and CI checks exist in part | Clean-runner replay and end-to-end acceptance tests |
| Scope/policy gate | Initial `ResearchCase` contract; SQLite case registry; case-bound queue tasks; worker validation and case-linked evidence observations on `feat/research-case-scope-gate`. Legacy tasks can still bypass case binding. | Required before every research experiment, with the case identity carried through executor records and exported evidence |
| User/team interface | Primarily CLI/automation today | Researcher workflow first; team UI/API only after validated demand |
| Commercial deployment | Not established | Private team workspace and evidence retention after customer validation |

This map is deliberately conservative. Before claiming a target row is implemented, link it to code and tests that demonstrate the behavior.

## 7. Roadmap

### Phase 1 — Reliable research loop
- Review and verify the initial case schema, queue binding, worker gate, and case-linked evidence migration.
- Make case binding mandatory at research entrypoints and execution boundaries, including legacy paths that currently accept unbound tasks.
- Carry case ID, pinned target commit, and scope digest into experiment records and exported evidence manifests.
- Make one authorized SSV investigation reproducible end to end, including counter-tests, impact analysis, and explicit negative/inconclusive outcomes.
- Verify an evidence bundle on a clean runner and document one complete case study, whether it confirms or rejects a hypothesis.

### Phase 2 — Reusable EVM research workbench
- Reusable Foundry templates for state transitions, invariants, and differential testing.
- Target-revision comparison and regression capture.
- Stable evidence-bundle schema and command-line verifier.
- Better task deduplication, experiment caching, and resource budgets.
- Measure how much reviewer/researcher time the workflow actually saves.

### Phase 3 — Team product
- Private case workspaces and role-based access.
- Review and approval workflow.
- Artifact retention and auditable history.
- Integrations requested by paying audit teams.
- Hosted offering only after security, isolation, and customer demand are validated.

### Phase 4 — Extend beyond EVM
Add another domain only when the same evidence model can pin inputs, reproduce behavior, challenge a hypothesis, and support independent verification. Historical key-generation research and cryptographic provenance are candidate specializations, not a reason to dilute the initial EVM workflow.

## 8. Initial customer and business model

**First customer hypothesis:** independent smart-contract security researchers and small audit teams that repeatedly build PoCs and evidence packages for complex findings.

**Initial value proposition:** reduce time to a reviewer-ready, reproducible finding and make it easier to distinguish a real exploit from a plausible but false lead.

Potential pricing hypotheses:
- Individual paid tier for private research cases and repeatable evidence tooling.
- Team subscription for collaboration, review, private artifacts, and retention.
- Enterprise deployment for private repositories, access controls, and internal audit trails.

Do not build billing or a broad SaaS control plane before interviews validate the workflow pain, current alternatives, budget owner, and willingness to pay.

## 9. Product success criteria

AegisForge is making progress when:
- A clean runner can reproduce the same documented result from pinned inputs.
- A reviewer can inspect the chain from attacker capability to impact.
- Negative results are recorded and prevent repeated wasted work.
- The verifier detects tampered, incomplete, or contradictory bundles.
- AI-generated claims cannot bypass deterministic verification gates.
- A real researcher or audit team chooses to use the workflow again.
- Time-to-reproduce and review effort improve measurably.

The long-term moat is not the number of agents. It is the quality of the evidence model, reliable verification, accumulated reproducible research cases, and integration into security teams' workflows.

## 10. Current SSV case boundary

The SSV Network Immunefi program is the first active research target. Each hypothesis must reference the exact scope and source revision used. Differences between a tagged release and a moving branch are leads only. Do not submit a report unless an authorized, reproducible path demonstrates in-scope security impact.

The current investigation of operator migration/effective-balance accounting has not established a confirmed exploit path. Preserve that status until a test proves otherwise.

## 11. Architecture decisions to keep explicit

- **Modular monolith before microservices:** the current team size does not justify distributed service complexity.
- **SQLite first:** keep local research reproducible; move to PostgreSQL only when concurrent team use requires it.
- **CLI/CI first:** prove the research loop before building a dashboard.
- **AI as assistant, deterministic tools as verifier:** no model confidence score can certify a finding.
- **Evidence bundle as a first-class artifact:** results should be portable and independently inspectable.
- **No token, chain, or blockchain layer without a specific requirement:** on-chain evidence anchoring is optional and must solve a demonstrated trust problem; hashes and signed manifests can be sufficient for early iterations.
- **Security and scope before autonomy:** agents must not gain authority to perform external actions merely because they can plan them.

## References

- [AegisForge README](../README.md)
- [EVM Key Forensics overview](EVM-KEY-FORENSICS.md)
- [Source provenance notes](evm-key-forensics-source-provenance.md)
- [SSV Network Bug Bounty](https://immunefi.com/bug-bounty/ssvnetwork/information/)
- [SSV Network scope](https://immunefi.com/bug-bounty/ssvnetwork/scope/)
