# AegisForge — EVM Key Forensics

**Reproducible security research for EVM systems. Evidence before conclusions.**

AegisForge is being built as a security-research and forensic platform that helps researchers investigate EVM systems, test vulnerability hypotheses, and produce evidence that another person can independently reproduce and verify.

It is not an autonomous exploit bot, a vulnerability scanner that promises findings, or a report generator that turns suspicious code into a claim. Its job is to shorten the path from a security hypothesis to a defensible result — including a clear **not reproduced** or **inconclusive** outcome when the evidence does not support a finding.

## Why this exists

Smart-contract security work often produces fragmented evidence: source links, fork-specific code, test scripts, traces, environment assumptions, screenshots, and reports that are difficult for another researcher to reproduce. AI can accelerate investigation, but plausible analysis is not proof. Build and CI success are not proof of a vulnerability either.

AegisForge aims to make the research chain explicit:

1. **Pin the target** — record the repository, commit/tag, scope, and relevant environment.
2. **Form a falsifiable hypothesis** — identify the trust boundary, attacker capability, expected invariant, and possible impact.
3. **Reproduce the behavior** — run a bounded, deterministic test or proof of concept against the pinned target.
4. **Try to disprove it** — test alternative explanations, controls, mitigations, and counterexamples.
5. **Calculate impact** — connect the behavior to a concrete security consequence, not just a code difference.
6. **Package evidence** — preserve commands, versions, logs, test results, hashes, and limitations.
7. **Verify independently** — let another person validate the evidence without trusting the researcher's narrative.

## Current mission: SSV Network Bug Bounty

The first active research target is the [SSV Network program on Immunefi](https://immunefi.com/bug-bounty/ssvnetwork/information/), using the program's current scope and the relevant source revision.

This is a research target, not a claim that a vulnerability has been found. The current investigation has identified differences in operator migration and effective-balance accounting between source revisions. So far, no eligible exploit path with demonstrated impact has been established. Those observations must not be presented as a bounty finding unless a reproducible test proves the impact and the program scope permits the report.

Research should stop pursuing a hypothesis when tests show that the behavior is expected, already mitigated, out of scope, or lacks meaningful impact.

## Product direction

The long-term goal is a **forensic evidence pipeline for security research**, starting with EVM protocols and expanding only when the same verification model works in other environments.

Potential capabilities, introduced incrementally:

- Target and source-revision pinning.
- Hypothesis tracking with explicit attacker capabilities, preconditions, and impact.
- Reproducible Foundry and other test-runner execution.
- Differential analysis across commits and releases.
- Invariant and state-transition testing.
- Evidence bundles with manifests, hashes, logs, and machine-readable conclusions.
- Independent verification tooling that checks the bundle rather than trusting its author.
- AI agents for code navigation, hypothesis generation, test design, and triage, with deterministic checks separating suggestions from verified results.
- Research history that records failed hypotheses and why they were rejected.

These are roadmap directions, not claims that all capabilities are implemented today.

## Design principles

- **Evidence over confidence:** no vulnerability claim without a reproducible path to impact.
- **Falsification first:** actively seek counterexamples to the hypothesis.
- **Pinned inputs:** record exact source revision, toolchain, dependencies, configuration, and commands.
- **Honest conclusions:** distinguish confirmed, not reproduced, inconclusive, and out-of-scope results.
- **Independent verification:** make it possible to check artifacts without trusting the generating agent.
- **Human accountability:** AI can assist research; researchers remain responsible for authorization, scope, impact, and disclosure.
- **Safe and authorized testing:** test only systems and environments for which testing is authorized; do not use the project to steal assets or access systems without permission.
- **No invented provenance:** a hash or CI attestation proves only what its verified chain actually establishes. It does not, by itself, prove that source code produced a binary or that a vulnerability exists.

## Current status

AegisForge already has a Python agent/orchestration codebase and an EVM Key Forensics evidence workflow with CI checks and artifact-verification work. This is an early-stage research tool, not yet a proven commercial platform.

Known limitations in the current evidence workflow include:

- Historical vulnerability reproduction is not established.
- Source-to-binary provenance is not established.
- Independent review remains pending unless a specific artifact says otherwise.
- Successful CI runs validate the checks that ran; they do not establish that the research conclusion is correct.

Use the evidence artifact and its machine-readable conclusion for the status of an individual run. Do not infer a confirmed finding from a green workflow alone.

## Roadmap

### Phase 1 — Trustworthy research loop
- Make target revision and bounty scope explicit for every investigation.
- Build a repeatable path from hypothesis to test, counter-test, impact analysis, and evidence bundle.
- Ensure a clean runner can validate the evidence bundle and report exactly what is and is not proven.
- Complete one well-documented, authorized case study, whether the result is a confirmed finding or a rigorously rejected hypothesis.

### Phase 2 — Research workbench
- Add reusable EVM state-transition and invariant-test templates.
- Compare target revisions and track regressions.
- Standardize machine-readable findings and evidence manifests.
- Reduce manual work without allowing AI-generated hypotheses to become findings automatically.

### Phase 3 — Research infrastructure
- Support multiple protocols and research teams.
- Add review workflows, reproducibility status, and tamper-evident research history.
- Evaluate hosted and team offerings only after researchers demonstrate repeated use and willingness to pay.

## Business hypothesis

The initial user is a security researcher or small audit team that loses time reproducing, validating, and documenting complex findings. The first potential paid value is not “AI finds every bug”; it is **less time spent building a reproducible case and less reviewer effort spent reconstructing it**.

Possible future models include paid team workflows, private research workspaces, and enterprise evidence retention. These are hypotheses to validate with users, not an established revenue stream.

## What success means

AegisForge succeeds when an independent reviewer can take a research bundle, reconstruct the environment, rerun the relevant checks, understand the attack preconditions and impact, and reach the same conclusion — without needing to trust the author's reputation or the AI's explanation.

The long-term asset is not a collection of agents. It is a growing body of reproducible security knowledge, verification tooling, and research workflows that become more useful with each investigation.

## Architecture

The full system design, trust boundaries, module map, current-vs-target implementation status, evidence model, and roadmap are documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The architecture document distinguishes implemented code from planned capabilities.

## Repository

- Source: https://github.com/rudimentall1/AegisForge
- SSV Network Bug Bounty: https://immunefi.com/bug-bounty/ssvnetwork/information/
- SSV Network scope: https://immunefi.com/bug-bounty/ssvnetwork/scope/

**Current rule:** no code difference becomes a vulnerability until a reproducible test connects it to an in-scope security impact.
