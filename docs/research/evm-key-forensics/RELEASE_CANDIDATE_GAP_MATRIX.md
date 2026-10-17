# EVM Key Forensics — Release-Candidate Gap Matrix

**Baseline:** `main` after PR #186 (`e054bce04eaa5480b986ec5c2ea16d6d5580882f`) (2026-10-17).  
**Status:** engineering checklist, not a release approval. No row below should be treated as complete merely because a related unit test passes.

The source of truth for release criteria remains [PRODUCT-READINESS.md](../../../PRODUCT-READINESS.md). This matrix maps those criteria to concrete code and the next acceptance evidence so work can be closed end to end rather than through disconnected hardening changes.

## Current evidence and gaps

| Gate | Existing implementation/evidence | Remaining acceptance work | Status |
|---|---|---|---|
| Immutable research case | `shared/research_case.py`, `shared/queue.py`; case contract includes pinned commit, scope digest, hypothesis, invariant and falsification criteria | Acceptance-test the full supported CLI path, including case registration and failure on missing/mismatched binding | Partial |
| Case/round lineage | `shared/queue.py` inherits case/round identity from a parent and rejects conflicting round overrides; `tests/test_case_rounds.py` covers inheritance and mismatch; portable bundle checks task/evidence case, role and round consistency | PR #179 adds a synthetic integration test covering a failed child task, retry, preserved case/round IDs, successful result, and Evidence Ledger observation; still add full supported CLI acceptance across lifecycle states | Partial |
| Operator-controlled lifecycle | Explicit `new-round --confirm-new-round` CLI and read-only case diagnostics are on `main`; round creation is guarded against duplicate active rounds | PR #187 adds fail-closed guards and tests for unresolved failed tasks and open human review; remaining work is full supported CLI acceptance across all lifecycle states | Partial |
| Pinned source evidence | `tools/evm_key_forensics/build_source_evidence_report.py` pins the two historical upstream revisions and expected Git object identities | PR #176 binds the report digest to the combined evidence index; PR #182 enforces a strict semantic schema for pinned source claims; PR #183 rejects promoted GitHub-attestation claims. Define an explicit cross-artifact relationship contract; do not equate the registered case target commit with the Profanity benchmark commits unless repository and exact commit identity match | Partial |
| Isolated experiment | `tools/evm_key_forensics/profanity_seed_environment_probe.cpp` is a bounded synthetic environment diagnostic | Keep its output explicitly synthetic; define and test the acceptance contract for any future historical-runtime reproduction separately | Partial |
| Independent complete-evidence verification | `tools/evm_key_forensics/verify_complete_evidence.py` checks archive safety, exact schemas, hashes and cross-artifact links | PR #176 closes report-digest equality between probe metadata and combined index; PR #182 validates source-report semantics and PR #183 constrains attestation wording. PR #185 adds semantic links from the combined index to the source report ID, experiment ID, and both pinned upstream commits, with mismatch tests. PR #186 documents the identity boundary: contextual Profanity benchmark commits must not be conflated with an unrelated registered case target. Machine-verifiable case-to-evidence relationship remains open | Partial |
| Portable case bundle | `shared/research_case_bundle.py` exports deterministic ZIP evidence and verifies it without SQLite; v2 adds a deterministic Merkle root while preserving v1 verification; report explicitly says `UNSIGNED_INTEGRITY_ONLY` | Prove clean-checkout CLI use and document exact output/exit-code examples; add a verifier for a declared case-to-source-report relationship that distinguishes exact target-revision evidence from contextual benchmark evidence | Partial |
| Tamper rejection | Tests cover archive path safety, hash integrity, unknown fields, orphaned observations, task-parent graphs, role/round lineage, and a mutation that recomputes entry hashes, Merkle root, and bundle digest | PR #172 rejects a rehashed task-binding/source-commit mismatch; PR #176 binds the source-report digest into the combined index; PR #182 validates source-report semantics; PR #183 rejects promoted attestation claims. PR #185 adds source-report semantic linkage in the complete-evidence index; PR #186 documents the distinction between case target identity and contextual benchmark identity. Machine-verifiable cross-artifact case linkage remains open. The Merkle root is not an authenticity anchor because the bundle is unsigned and all digests can be recomputed by an editor | Partial |
| Honest conclusions | Probe/source-report verifiers explicitly avoid claiming historical exploit reproduction, entropy proof or wallet exposure | End-to-end test that synthetic output cannot upgrade the case verdict; keep `INCONCLUSIVE` until historical runtime evidence actually meets the declared criteria | Partial |
| Clean-machine reproduction | README documents probe, combined evidence, lab artifact and research-case verification commands | Validate the full supported path from a clean checkout and a separate machine with no SQLite database or hidden workflow artifacts | Not yet demonstrated |
| Release-candidate gate | `docs/PRODUCT-READINESS.md` defines blockers and exit rule | Link passing exact-commit CI, sample bundle, expected verifier output and independent reviewer evidence before marking any blocker complete | Open |

## Required end-to-end acceptance run

Run only after the implementation gaps above are closed. Use public/pinned source and synthetic or otherwise explicitly authorized local fixtures; do not interact with live wallets or recover keys.

1. Register a case containing the exact target commit, scope reference/digest, hypothesis, expected invariant and falsification criteria.
2. Start exactly one explicitly confirmed bounded case round.
3. Verify that root and child tasks preserve case and round IDs and that conflicting overrides are rejected.
4. Produce source evidence for the pinned revision and a separate bounded experiment artifact. Treat the Profanity source report as a contextual benchmark unless the registered case targets the same repository and exact pinned revision; never copy its commit identity into an unrelated case.
5. Export a case bundle and the combined evidence package.
6. Copy the packages to a clean environment without the original database and verify them offline.
7. Mutate each cross-artifact identity in turn, recompute unsigned manifests, and confirm that semantic verification still rejects the package.
8. Confirm that the final machine-readable result distinguishes source-pattern evidence, synthetic demonstration, historical reproduction and wallet exposure. The latter two remain unestablished unless their own criteria are met.
9. Record exact commit SHA, commands, CI URLs, output summaries and unresolved risks here and in the release checklist.

## Current exact-commit CI evidence

PR #179 (`51d8b3185ce8c4069e73e7f8f07283ae45172389`) passed [AegisForge CI run 39026468766](https://github.com/rudimentall1/AegisForge/actions/runs/39026468766), including the new synthetic failed-task retry/lineage integration test, then merged as `47d746cd173c8bdb0aff5a89eaf0d9d8545ba7d3`. PR #176 (`049bca4d94be975f6cfe649f34edb997fddf0512`) passed both `EVM Key Forensics Probe` run [39026209088](https://github.com/rudimentall1/AegisForge/actions/runs/39026209088) and `AegisForge CI` run [39026209125](https://github.com/rudimentall1/AegisForge/actions/runs/39026209125), then merged as `3d48541399c94eaacf5fa23303e87c71361e2caf`. The probe run compiled the synthetic diagnostic twice, compared a separate-runner rebuild, generated/validated pinned source evidence, and verified portable probe evidence. These results validate the tooling path only; they do not reproduce the historical Profanity runtime or establish wallet exposure.

## Merge hygiene

The explicit round-creation CLI and read-only lifecycle diagnostics are already on `main`; open PRs #153 and #156 are stale duplicates and must not be merged as-is. PR #138 still contains the child-task round-inheritance change and must be reapplied/reviewed against current `main`, then tested on its exact head before merging. PR #166's Merkle structure is merged, but it is deliberately treated as deterministic structure only, not as a trusted signature or authenticity anchor.

## Non-negotiable release boundary

A green build, deterministic synthetic probe, source-pattern match, artifact hash or GitHub attestation does not establish historical exploitability or exposure of any individual wallet. The historical Profanity reproduction conclusion remains `INCONCLUSIVE` until the historical code path is actually exercised under a documented, reproducible and independently verifiable experiment.


## Additional source-report hardening

PR #182 (`fix: enforce strict semantic source report schema`) adds strict validation for pinned source revisions, expected evidence class, conservative conclusion, comparison consistency, interpretation, limitations, and optional reproducibility fields. PR #183 (`fix: constrain source report attestation wording`) rejects a report that describes a separate GitHub workflow check as authentication of source claims. These controls constrain accepted claims; they do not authenticate an unsigned report or establish historical runtime behavior. The source-report-to-case identity link remains open.
