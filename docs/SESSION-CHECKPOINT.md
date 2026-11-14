# Session Checkpoint — AegisForge

**Updated:** 2026-11-14  
**Repository:** https://github.com/rudimentall1/AegisForge  
**Working branch:** `feat/persist-local-experiment-evidence-main`  
**Latest implementation commit:** `020f60323e32202a8eae2357514198ddc057fbba`  
**PR:** [#196](https://github.com/rudimentall1/AegisForge/pull/196) — OPEN, DRAFT, not merged  
**Release gate:** [Issue #158](https://github.com/rudimentall1/AegisForge/issues/158) — OPEN

## 1. Where we stopped (verified repository state)

- PR #196 currently has 239 commits, 45 changed files, +10,012/-138 lines. Current head: `a7c7c318f4d5fe2baf2d80f195c0a8a5608d1f5e`; base is `main` at `0adfc88c41e8c48c8ed25f2b25ef8db67cab5370`.
- PR remains OPEN and DRAFT. Latest observed PR metadata reports `mergeable: true`; this is not approval to merge. Keep Draft until release gate #158 is satisfied.
- Workflow run #1615 / ID `43597955894` on the previous checkpoint head `33eb493b554752eca43b92f795d3dd980c0dc2ba` completed **SUCCESS**. This supersedes the older observed run #1614 failure for that earlier head, but does not prove the release acceptance contract or close issue #158. The latest docs-only commits still need their own CI result.
- Issue #158 remains open. Its acceptance contract still requires one clean-runner, local-only path from immutable Research Case registration through bounded experiment, evidence export, independent verification, adversarial rejection tests, and honest machine-readable statuses.
- `docs/SESSION-CHECKPOINT.md` is maintained on this PR branch as the handoff record.
- `README.md`, `docs/ARCHITECTURE.md`, and `docs/PRODUCT-READINESS.md` all explicitly say release readiness and commercial fit are not established.
- Current Python requirements are small (requests, python-dotenv, cryptography, pydantic). No confirmed Slither or Echidna integration was found in the files reviewed. Foundry appears in the target architecture, not as proof of a completed end-to-end adapter.

## 2. What has already been built (do not rewrite)

PR #196 has substantial evidence infrastructure:
- persisted local experiment records with task/case/round identity checks and bounded artifact storage;
- planned RoundSpec identity kept distinct from runtime round IDs;
- Research Case bundle schema v3 with offline identity checks;
- deterministic experiment ZIP export and offline artifact/hash/path/size verification;
- paired control/counter-test binding;
- fixed repository-owned synthetic fixture subprocess with output/time/resource limits;
- combined evidence packages and detached Ed25519 attestations;
- trusted-key verification, freshness checks, and durable SQLite replay protection;
- adversarial tests for identity substitution, altered case digests, tampering, archive abuse, incomplete signatures, and replay.

These mechanisms establish specific package/record/signature properties only. They do **not** establish runner honesty, a security sandbox for arbitrary target code, historical vulnerability reproduction, or a confirmed finding. Synthetic outcomes stay `INCONCLUSIVE`.

## 3. Product direction

Build **AegisForge as a reproducible smart-contract security research and evidence workbench**, not another AI scanner or autonomous exploit bot.

Core value:
1. Take an authorized, pinned EVM repository and a falsifiable security question.
2. Run mature deterministic security tools through bounded adapters.
3. Preserve raw outputs, tool versions, exact commands, inputs, exit codes and artifact hashes.
4. Correlate findings and counter-tests without allowing an LLM to confirm them.
5. Export a portable evidence package that another engineer can verify independently.

Sell saved researcher/reviewer time and defensible evidence, not access to free scanners. First commercial target: a boutique smart-contract audit team or independent researcher willing to run a paid pilot. No billing system, hosted SaaS, dashboard, token, or blockchain layer until a real buyer validates the workflow.

## 4. What we reuse, and from whom

**Our foundation — keep and extend, do not replace:**
- AegisForge existing Python agent/orchestration code, Research Case and scope gate, SQLite queue, Evidence Ledger, package verifier and CLI.
- Preserve existing authorship and project history. No rewrite of the core.

**External engines to integrate as separate, replaceable tools (not copy into our codebase):**
- [Foundry](https://github.com/foundry-rs/foundry) by the Foundry project: Solidity build/test execution, local EVM and reproducible test runs. First integration candidate.
- [Slither](https://github.com/crytic/slither) by Trail of Bits/Crytic: Solidity static analysis. Invoke as a pinned external executable and preserve its raw output. Verify current license and distribution obligations before packaging or modifying it.
- [Echidna](https://github.com/crytic/echidna) by Trail of Bits/Crytic: property-based fuzzing and invariant testing. Add only after the Foundry + Slither slice works.

**Not selected for the MVP:**
- Do not adopt Certora, Sherlock, Olympix, AuditAgent or other commercial/closed products as code dependencies without a clearly licensed public source and explicit rights.
- Do not add generic pentest agents, Nuclei, MCP wrappers, LangGraph, extra LLM agents, or another database merely to increase feature count.
- No code from candidate upstream projects has been copied or integrated as of this checkpoint. Attribution, exact version pinning, license review, NOTICE files and dependency inventory are required before any reuse/distribution.

**External AI/API security lab reviewed:** [Parakh-Shinde/AegisForge](https://github.com/Parakh-Shinde/AegisForge) is an unrelated Apache-2.0 project with synthetic AI/API scenarios, deterministic tenant-authorization simulation, telemetry correlation, evaluation and report provenance. It is NOT part of our codebase. Its documented untouched holdout v2 metrics are weak (F1 0.1333, recall 0.0833); later adapted regression metrics must not be presented as independent validation. Keep it separate and do not let it delay the EVM MVP. Detailed assessment and reuse conditions: `docs/EXTERNAL-COMPONENT-EVALUATION-AI-API-LAB.md`. Both projects share the AegisForge name; preserve clear attribution and avoid implying affiliation.

## 5. Immediate execution order

1. Refresh CI on the current PR head and inspect whether the release-gate acceptance contract is actually exercised. The observed successful run #1615 is not sufficient by itself. Keep PR Draft and issue #158 open.
2. Close the release-critical gap with a truthful clean-checkout acceptance path. Do not relabel process limits as a security sandbox. If hosted CI cannot provide the required namespace capability, use a supported runner/isolated environment or mark that acceptance as NOT_RUN; do not fake a pass.
3. Once the case-to-bundle workflow is reproducible, add **one** vertical slice: pinned Solidity target → Foundry build/test → Slither static analysis → raw outputs and tool metadata recorded in the existing evidence model → offline bundle verification.
4. Pin tool versions, record installation provenance and licenses. Keep tools as subprocess/container adapters; never execute commands taken from an evidence bundle.
5. Add Echidna only after the first slice is independently reproducible.
6. Put the workflow in front of 2–3 audit researchers. Measure setup time, time saved, false-positive review effort and whether they will pay for a pilot.

## 6. Explicit non-goals until the above is proven

- No new agent farm or broad OWNERA merge.
- No SSV bounty hunting restart before the product release gate passes.
- No historical Profanity/key-generation claim based on synthetic fixtures.
- No arbitrary untrusted-code execution through the current fixed-fixture subprocess.
- No dashboard, SaaS billing, multi-tenant cloud, PostgreSQL migration, token or on-chain anchoring.
- No mass feature expansion or commit-count target.

## 7. Definition of the next meaningful result

A clean checkout can run one pinned, authorized Solidity case using Foundry and Slither, retain raw and attributable evidence, export a portable bundle, and have a second environment verify it. Every stage reports PASS/FAIL/INCONCLUSIVE/NOT_RUN honestly. Then a researcher outside the project can reproduce and review the result.

**Current status:** substantial evidence foundation exists; release gate is not passed; commercial demand is not validated; Foundry/Slither/Echidna integrations are plans, not completed capabilities.


## 8. Latest execution note — 2026-11-14

- Re-read PR #196 metadata and the checkpoint from the working branch. PR is open, Draft, and currently reported mergeable.
- Added `docs/EXTERNAL-COMPONENT-EVALUATION-AI-API-LAB.md` with upstream ownership, Apache-2.0 reuse conditions, candidate modules, limitations, weak holdout metrics, and the decision to keep the repositories separate.
- No external code was copied. No runtime integration was claimed. Next engineering work remains the release-gate acceptance path, then the Foundry + Slither vertical slice.


## 9. Bubblewrap acceptance and evidence integration — 2026-11-14

- GitHub Actions run #1615 / ID `43597955894` completed SUCCESS on the PR merge ref based on head `33eb493b554752eca43b92f795d3dd980c0dc2ba`.
- Its Bubblewrap acceptance step completed successfully. Downloaded and inspected artifact `aegisforge-bubblewrap-acceptance-43597955894-1`: report status PASS; Bubblewrap 0.11.1; both `control` and `countertest` PASS; network namespace, read-only system tree, and private temporary write checks all true. The report explicitly says target code was not executed and vulnerability reproduction was not established.
- Added `tests/test_bubblewrap_fixture_evidence_e2e.py`. It exercises the isolated Bubblewrap fixture outputs through the existing Research Case → bounded round/tasks → Evidence Ledger → portable experiment bundles → paired semantic assessment path. It asserts the network/filesystem checks and keeps vulnerability status INCONCLUSIVE.
- The new test commit is `020f60323e32202a8eae2357514198ddc057fbba`. No workflow run is currently returned for this exact commit, so this new test is **not yet CI-verified**. Do not describe it as passing.
- This closes the previous Bubblewrap-hosted-runner blocker for the fixed synthetic fixture only. It does NOT close issue #158: arbitrary target execution remains unsupported; the isolated runner intentionally executes only the repository-owned fixture. The next boundary is a separately reviewed, pinned-target adapter with a real isolation contract, followed by the Foundry + Slither vertical slice. Do not loosen the fixture-only runner into a general command runner.


## 10. Current-head CI verification — 2026-11-14 (supersedes stale notes above)

- Current PR #196 head: `926111d52aae23a0d2b593f10be5f5acf2e0bc20`; current PR metadata: OPEN, DRAFT, `mergeable: true`, 243 commits, 46 changed files, +10,202/-138. Mergeability is not release approval.
- Workflow run #1621 / ID `43599145979` was returned for this exact head and completed SUCCESS. Its sole job completed successfully.
- Retrieved job log confirms: **1,795 passed, 4 warnings, 30 subtests passed**. The run includes the Bubblewrap fixture acceptance step, which also completed successfully.
- Therefore `tests/test_bubblewrap_fixture_evidence_e2e.py` is now CI-verified on the current PR head. This supersedes the earlier note saying no current-head CI result was available.
- The CI pass validates the implemented synthetic fixture-to-ledger-to-bundle-to-paired-assessment path. It does not demonstrate execution of pinned target code, vulnerability reproduction, or the full #158 acceptance contract.
- Issue #158 remains OPEN. PR #196 remains DRAFT. Do not merge or close the gate based solely on this CI result.
- Next engineering priority: design and review the pinned-target execution boundary before implementing an adapter. It must bind execution to the immutable Research Case target commit and scope; pin toolchain versions; deny network by default; constrain filesystem, CPU, memory, wall time and output; reject bundle-supplied commands; capture raw outputs and exit status; and fail closed when isolation is unavailable. The existing fixture-only runner must remain fixture-only.
