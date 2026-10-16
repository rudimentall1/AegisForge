# AegisForge — Master Context

**Canonical project context.** Update this file when product direction, verified implementation status, or priorities change. Architecture and research-track documents should link here and must not maintain conflicting priorities.

## Product direction

AegisForge is a reproducible security-research and forensic evidence platform. Its primary workflow binds an authorized target and immutable source revision to a falsifiable hypothesis, controlled experiment, counter-tests, evidence artifacts, and an independently reviewable conclusion.

**EVM Key Forensics is a core research direction, not a disposable experiment or a separate competing product.** The first active bounty target is SSV Network. Historical EVM key-generation research, including the Profanity benchmark, remains a separate forensic track.

## Decisions

1. Evidence takes precedence over agent confidence, source-pattern matches, and CI success.
2. AI agents propose and investigate hypotheses. Deterministic tests and independent review establish what the evidence supports.
3. Research Case is the shared control-plane contract for target identity, scope, hypothesis, execution mode, and evidence linkage.
4. Existing agent roles should be reused. Do not add new agents or duplicate evidence systems before validating a concrete gap.
5. SQLite remains the initial persistence layer until concurrency or customer requirements justify a change.
6. Preserve explicit outcomes: `CONFIRMED`, `REJECTED`, `INCONCLUSIVE`, `OUT_OF_SCOPE`, and `NOT_REPRODUCED`.
7. Never claim a vulnerability, source-to-binary provenance, or individual-wallet exposure without the corresponding reproducible evidence.
8. Capability and execution controls are supporting infrastructure for controlled experiments, not the product's primary positioning.
9. No live state-changing actions or testing outside explicitly authorized scope. Prefer pinned local forks, testnets, or bounded environments.

## Current implementation (verify against main before relying on it)

- ResearchCase contract and SQLite registry exist in the main-branch implementation reviewed in `docs/ARCHITECTURE.md`.
- Case-linked queue tasks are validated by Worker.
- Evidence observations can carry a case ID.
- Git-object source-pin verification and EVM Key Forensics evidence tooling exist.
- Historical source-classification benchmarks and regression tests exist.
- Evidence ledger, experiment dossier, proof/evidence manifest tooling, and CI workflows exist.
- Documentation describes architecture, evidence limitations, and the legacy agent plan.

These statements describe implementation components, not proof that the full end-to-end research workflow is complete.

## Known gaps

- Legacy tasks without `research_case_id` can bypass the Research Case gate.
- Case identity is not yet guaranteed across every executor record, experiment dossier, and exported evidence manifest.
- The independent human source-review record is a procedure/template, not proof that independent review has occurred.
- The Profanity benchmark is not a historical runtime reproduction.
- The SSV investigation has no confirmed eligible vulnerability established by the evidence reviewed so far.
- Main-branch CI status must be checked explicitly; an empty status response is not a passing result.
- Research Case must be mandatory at all security-research entrypoints and execution boundaries.
- Evidence replay must be validated from pinned inputs in a clean environment before calling a case independently reproducible.

## Open pull requests and consolidation

At the last repository review on 2026-10-15, the following PRs were open and must be reviewed against current `main` before merging:

- [#33 — Document independent human review gate for EVM source evidence](https://github.com/rudimentall1/AegisForge/pull/33)
- [#34 — Add regression tests for EVM forensics evidence boundaries](https://github.com/rudimentall1/AegisForge/pull/34)
- [#35 — Add negative controls to EVM source-classification benchmark](https://github.com/rudimentall1/AegisForge/pull/35)
- [#37 — Add regression tests for EVM source-body extraction](https://github.com/rudimentall1/AegisForge/pull/37)
- [#38 — Add adversarial negative controls for source classification](https://github.com/rudimentall1/AegisForge/pull/38)
- [#39 — Align benchmark with explicit negative source context](https://github.com/rudimentall1/AegisForge/pull/39)
- [#40 — Add pinned source excerpt integrity records](https://github.com/rudimentall1/AegisForge/pull/40)

PRs #35, #38, and #39 overlap in source classification and negative controls. Reconcile them into one implementation path. PRs #33 and #34 provide review-gate documentation and evidence-boundary regression tests; check for overlap with the newer evidence tooling. PR #40 adds source-coordinate integrity records and must be checked for schema compatibility with the existing evidence manifest.

Branch existence or PR mergeability alone does not mean a change is validated. Inspect diffs, run tests against current main, and merge only after conflicts/duplication are resolved. Check CI status explicitly for the current base/head commits.

Other branches also exist for Research Case scope enforcement, executor identity, signed intents, technical evidence gates, recovery, discovery pagination, and query focus. Inspect them for useful non-duplicated work only after the immediate PR consolidation and Research Case binding requirements are addressed.

## Priority order

1. Reconcile overlapping open PRs and update documentation to reflect current main.
2. Make Research Case binding mandatory across security-research entrypoints and execution boundaries without silently breaking unrelated workflows.
3. Propagate case ID, pinned target revision, and scope digest through experiment records and evidence manifests.
4. Run one authorized SSV case end to end, including counter-tests, impact analysis, and explicit inconclusive outcomes where necessary.
5. Validate evidence replay in a clean environment and document exactly what was independently verified.
6. Only then expand integrations, agent specializations, or hosted/team-product functionality.

## SSV research boundary

SSV Network is the first active bounty target. Scope was rechecked on 2026-10-16; Immunefi lists the program scope as last updated 2026-09-13. The pinned research source is `ssvlabs/ssv-network@9bb7b21d4432f34f623bed3e0bb3fa77f1e5d2b9` (`mainnet-v2.0.0`). Re-pin and re-check the scope before each new case or submission. Differences between a tagged release and a moving branch are leads only.

**Bounty exclusion rule:** Immunefi's current program terms state that vulnerabilities identified in prior audits and issues documented on `docs.ssv.network` or in any branch of the specified repository are ineligible. The published known-issues list already covers effective-balance root drift and liquidation, removed-operator fee-index accounting, permissionless dust-deposit stale-cluster reverts, theoretical `uint64` accounting overflow, liquidator-liveness assumptions, validator-capacity griefing during migration/reactivation, and operator-fee rounding. Do not recycle these as new findings without a demonstrably distinct, unlisted root cause and impact. Testing must remain on local forks; the program prohibits mainnet and public-testnet testing.

The operator-migration/effective-balance accounting lead has not established a confirmed exploit path. Preserve that status until a test proves otherwise. Use explicit `INCONCLUSIVE` or `NOT_REPRODUCED` results when evidence is insufficient. Do not submit a report unless an authorized, reproducible path demonstrates in-scope security impact.

## Product and commercial hypothesis

The first plausible users are independent smart-contract security researchers and small audit teams that repeatedly build PoCs and evidence packages. The value hypothesis is reducing time to a reviewer-ready, reproducible finding and helping distinguish a real exploit from a plausible false lead.

Potential later models: individual paid tooling, team subscriptions for collaboration/review/private artifacts, and enterprise deployment. Do not build billing or a broad SaaS control plane before interviews validate workflow pain, alternatives, budget owner, and willingness to pay.

## Success criteria

- A clean runner reproduces the documented result from pinned inputs.
- A reviewer can inspect the chain from attacker capability to impact.
- Negative results are recorded and prevent repeated wasted work.
- The verifier detects tampered, incomplete, or contradictory evidence bundles.
- AI-generated claims cannot bypass deterministic verification gates.
- A real researcher or audit team returns to the workflow.
- Time-to-reproduce and review effort improve measurably.

The long-term moat is not the number of agents. It is the evidence model, reliable verification, accumulated reproducible research cases, and integration into security teams' workflows.

## Source of truth and linked implementation docs

- [Architecture](ARCHITECTURE.md)
- [Legacy agent plan status](LEGACY-AGENT-PLAN-STATUS.md)
- [EVM Key Forensics](EVM-KEY-FORENSICS.md)
- [Source provenance notes](evm-key-forensics-source-provenance.md)
- [SSV Network Bug Bounty](https://immunefi.com/bug-bounty/ssvnetwork/information/)
- [SSV Network scope](https://immunefi.com/bug-bounty/ssvnetwork/scope/)
