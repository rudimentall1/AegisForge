# EVM Key Forensics — Release-Candidate Gap Matrix

**Baseline:** `main` at `4ca18f2557595d18e2b9561f0b37b988e7184ed4` (2026-10-17).  
**Status:** engineering checklist, not a release approval. No row below should be treated as complete merely because a related unit test passes.

The source of truth for release criteria remains [PRODUCT-READINESS.md](../../../PRODUCT-READINESS.md). This matrix maps those criteria to concrete code and the next acceptance evidence so work can be closed end to end rather than through disconnected hardening changes.

## Current evidence and gaps

| Gate | Existing implementation/evidence | Remaining acceptance work | Status |
|---|---|---|---|
| Immutable research case | `shared/research_case.py`, `shared/queue.py`; case contract includes pinned commit, scope digest, hypothesis, invariant and falsification criteria | Demonstrate the supported CLI path from case registration to a single bounded round, with IDs preserved without manual copying | Partial |
| Case/round lineage | `shared/case_rounds.py`; case bundle now checks task/evidence case, role and round consistency | Propagate round identity into every child task and execution/evidence path; verify this against current `main` after stale PR conflicts are resolved | Partial |
| Operator-controlled lifecycle | Explicit round-start API exists; proposed CLI and read-only diagnostic changes remain in open PRs | Reconcile open PRs with current `main`, then test idle, active, blocked, terminal and failed states through the actual CLI | Partial |
| Pinned source evidence | `tools/evm_key_forensics/build_source_evidence_report.py` pins the two historical upstream revisions and expected Git object identities | Verify that the source report identity is bound to the same case and carried into the exported case/evidence package, not just a separate workflow artifact | Partial |
| Isolated experiment | `tools/evm_key_forensics/profanity_seed_environment_probe.cpp` is a bounded synthetic environment diagnostic | Keep its output explicitly synthetic; define and test the acceptance contract for any future historical-runtime reproduction separately | Partial |
| Independent complete-evidence verification | `tools/evm_key_forensics/verify_complete_evidence.py` checks archive safety, exact schemas, hashes and cross-artifact links | Add adversarial cross-artifact tests for mismatched case ID, round ID, source commit and report-to-index identity wherever those fields are present | Partial |
| Portable case bundle | `shared/research_case_bundle.py` exports deterministic ZIP evidence and verifies it without SQLite | Prove clean-checkout CLI use and document exact output/exit-code examples; ensure the same source revision and scope identity are carried into the bundle schema | Partial |
| Tamper rejection | Tests cover archive path safety, hash integrity, unknown fields, orphaned observations, task-parent graphs, role and round lineage | Maintain mutation tests that recompute unsigned manifests so rejection depends on semantic validation, not merely a stale digest | Partial |
| Honest conclusions | Probe/source-report verifiers explicitly avoid claiming historical exploit reproduction, entropy proof or wallet exposure | End-to-end test that synthetic output cannot upgrade the case verdict; keep `INCONCLUSIVE` until historical runtime evidence actually meets the declared criteria | Partial |
| Clean-machine reproduction | README documents probe, combined evidence, lab artifact and research-case verification commands | Validate the full supported path from a clean checkout and a separate machine with no SQLite database or hidden workflow artifacts | Not yet demonstrated |
| Release-candidate gate | `docs/PRODUCT-READINESS.md` defines blockers and exit rule | Link passing exact-commit CI, sample bundle, expected verifier output and independent reviewer evidence before marking any blocker complete | Open |

## Required end-to-end acceptance run

Run only after the implementation gaps above are closed. Use public/pinned source and synthetic or otherwise explicitly authorized local fixtures; do not interact with live wallets or recover keys.

1. Register a case containing the exact target commit, scope reference/digest, hypothesis, expected invariant and falsification criteria.
2. Start exactly one explicitly confirmed bounded case round.
3. Verify that root and child tasks preserve case and round IDs and that conflicting overrides are rejected.
4. Produce source evidence for the pinned revision and a separate bounded experiment artifact.
5. Export a case bundle and the combined evidence package.
6. Copy the packages to a clean environment without the original database and verify them offline.
7. Mutate each cross-artifact identity in turn, recompute unsigned manifests, and confirm that semantic verification still rejects the package.
8. Confirm that the final machine-readable result distinguishes source-pattern evidence, synthetic demonstration, historical reproduction and wallet exposure. The latter two remain unestablished unless their own criteria are met.
9. Record exact commit SHA, commands, CI URLs, output summaries and unresolved risks here and in the release checklist.

## Merge hygiene

Open PRs related to case-round propagation, explicit round creation and lifecycle diagnostics were found to be based on older `main` commits. PR #138 encountered merge conflicts when a merge was attempted. Do not bypass those conflicts or merge stale snapshots blindly. Rebase/reapply the minimal intended changes on current `main`, then require CI on the resulting exact head before merging.

## Non-negotiable release boundary

A green build, deterministic synthetic probe, source-pattern match, artifact hash or GitHub attestation does not establish historical exploitability or exposure of any individual wallet. The historical Profanity reproduction conclusion remains `INCONCLUSIVE` until the historical code path is actually exercised under a documented, reproducible and independently verifiable experiment.
