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


## 11. Pinned-target execution design — 2026-11-14

- Added `docs/PINNED-TARGET-EXECUTION-ADAPTER-DESIGN.md` in commit `3123a58be58fe38e40123d5dca8a65f73a094767`.
- The document defines immutable case admission, exact source materialization, fixed Foundry/Slither adapters, executor request schema, isolation/resource controls, evidence lifecycle, result semantics, staged acceptance, and unresolved deployment/toolchain decisions.
- Critical security decision: do not treat same-kernel Bubblewrap as a sufficient hostile-repository boundary. Public/untrusted target code requires a disposable isolated VM/microVM with no host credentials or shared writable mounts. Bubblewrap remains limited to the existing fixed synthetic fixture and lower-assurance local use only if explicitly approved.
- No arbitrary target execution code was added. This is deliberate: the available repository state does not yet establish a safe VM backend or pinned toolchain profile. Implementing a shell wrapper before resolving that boundary would create a dangerous false sense of security.
- Next: choose and verify the disposable execution backend and exact Foundry/Slither versions, then implement Stage A typed admission and negative tests before any target process can start.

## 9. Target-execution admission gate — 2026-11-14

- Added `shared/target_execution_admission.py` and `tests/test_target_execution_admission.py`.
- The gate accepts only a typed task ID plus a fixed adapter-profile enum. It does not accept caller-supplied case JSON, target URL/commit, argv, environment variables, or scripts.
- It resolves the target exclusively from `TaskQueue.get_research_case()`, then checks the registered task is a running `lab_runner`, the case is runnable and LOCAL, the runtime round exists and is RUNNING, the root task belongs to the same case/round, and any planned RoundSpec matches both the case and round registry.
- The gate returns `execution_assurance=NOT_RUN`. It does not spawn a process, fetch source, or provide isolation. It is not a sandbox and does not close issue #158.
- This deliberately reuses the existing SQLite Research Case registry in `shared/queue.py`; no parallel registry was introduced.
- Commits: `db2272b` (admission module), `40b2774` (tests), `06c611c` (remove unused import).
- Validation status: no workflow run was returned for HEAD `06c611c` at checkpoint time. The new tests and latest branch state are **not yet CI-verified**. Do not describe this gate as validated until a run for the exact HEAD passes.
- Next: verify the exact-head CI result; repair any failures; then implement the source-revision resolver as a separate non-executing step. Do not add a process launcher until an ephemeral VM/microVM execution backend and pinned toolchain are selected.

## 10. Admission gate CI correction — 2026-11-14

- CI run #1628 on HEAD `4c3781f` exposed two failures in the new admission tests; the rest of the suite passed: 1,799 passed, 2 failed, 4 warnings, 30 subtests passed.
- Failure 1 was a test asserting object identity for a deserialized RoundSpec. Corrected to value equality.
- Failure 2 showed the gate reported role mismatch before task lifecycle mismatch. Reordered checks so non-running tasks fail first, then role is checked. This is deterministic fail-closed behavior and matches the intended admission contract.
- Fix commits: `15b4b85`, `560ee20`.
- These fixes have not yet been confirmed by CI on the exact latest HEAD. Continue from the latest PR head and verify the workflow result before adding source acquisition.


## 12. Exact-head CI and source-acquisition security review — 2026-11-14

- Refreshed PR #196: OPEN, DRAFT, mergeable; current head `a0f6d136987dbaa7ee3a7ba13de027708709ad89`; 253 commits, 49 changed files, +10,750/-138. Keep Draft; do not merge.
- CI run #1629 completed SUCCESS on code-fix head `560ee2033c76826bd094a7ee2725f3a5f612b93b`. CI run #1630 / ID `43601010509` completed SUCCESS for the current checkpoint head `a0f6d136987dbaa7ee3a7ba13de027708709ad89`.
- Retrieved #1630 job log: **1,801 passed, 4 warnings, 30 subtests passed**. Compile, whitespace, EVM Key Forensics evidence steps, and Bubblewrap fixture acceptance also completed successfully. The four pytest warnings include duplicate ZIP member-name warnings in adversarial package tests; they are not silently treated as a clean warning-free run.
- Re-read `shared/target_execution_admission.py`, `shared/research_case.py`, `shared/queue.py`, tests, README, architecture and pinned-target adapter design.
- New security finding before source acquisition: ResearchCase accepts either `owner/repo` or an arbitrary absolute HTTPS URL. The admission gate validates task/case/round bindings and LOCAL mode, but it does not apply a trusted repository allowlist or canonical GitHub-host policy. A source fetcher must not consume this field directly as a clone URL; doing so could create an arbitrary-remote/SSRF boundary.
- Do not implement `git clone` or source materialization yet. First define a server-side trusted repository policy (canonical host + owner/repo allowlist), ensure it is enforced against the immutable registered case before any network access, and test rejection of alternate hosts, credentials in URLs, ports, redirects, path tricks, mutable refs, and non-full SHAs. Existing cases/tests currently use identifiers such as `owner/repository`; preserve compatibility at the ResearchCase contract layer unless a reviewed migration is explicitly approved.
- Once repository authorization is in place, source acquisition must be non-executing: resolve exact full SHA, fetch without hooks, no recursive submodules by default, verify commit and tree identity, create a read-only source artifact, compute a content digest, and record provenance. No Foundry/Slither process launch until the disposable VM/microVM backend and pinned toolchain decisions are resolved.
- Issue #158 remains OPEN. The green CI verifies implemented tests and fixed-fixture acceptance only; it does not prove pinned-target execution, historical vulnerability reproduction, or release readiness.


## 13. Trusted target repository policy — 2026-11-14

- Added `shared/repository_policy.py` and `tests/test_repository_policy.py`.
- Added a server-side allowlist loaded from `AEGISFORGE_ALLOWED_TARGET_REPOSITORIES`. Unset/empty configuration denies all repositories; no wildcard or caller-provided policy exists.
- Accepted identities are limited to `owner/repo` and canonical `https://github.com/owner/repo[.git]`. Reject alternate hosts, non-HTTPS, credentials, explicit ports, query/fragment, nested paths, trailing slash, percent-encoding, backslashes, control characters and malformed path segments.
- Added `authorize_admitted_target_source()`: source acquisition must provide a registry-resolved `AdmittedTarget`, then authorize the immutable ResearchCase repository against the server-owned allowlist before any network access. It returns the canonical GitHub clone URL only after authorization.
- Updated `docs/PINNED-TARGET-EXECUTION-ADAPTER-DESIGN.md` to make this policy mandatory and to require redirects be disabled or each redirect target be revalidated.
- Files are committed in PR #196. Current implementation head before this checkpoint update: `7f9c550dcfdc3ee29aaf957a468a5000a19a0ae3`. No CI result has yet been returned for these policy changes; do not claim tests pass until the exact-head workflow completes.
- Important limitation: this is an authorization/parser boundary, not a source fetcher. No network request, checkout, redirect handling, commit resolution, or source digest is implemented yet. The next step is run CI, fix any failures, then build a non-executing source materializer that consumes only this authorized result and verifies the full commit SHA and tree identity.
- PR #196 remains OPEN and DRAFT. Issue #158 remains OPEN. The source policy is intentionally separate from the legacy ResearchCase schema so existing registered cases remain compatible.


## 14. Repository policy compile correction — 2026-11-14

- CI run #1638 / ID `43601989735` failed at the Python compile step before pytest. The cause was literal backslash-n characters accidentally inserted into two import statements while editing through the GitHub contents API; this was caught by the compile gate, not hidden.
- Corrected both imports and added the missing explicit rejection for passing a single string/bytes object as the allowlist iterable.
- Fix commits: `b76aeb0` (policy module) and `ae11ebe` (test imports).
- CI run #1639 / ID `43602043973` is running on the corrected HEAD `ae11ebe2706f159d1e6433367f59b31c2b21b408`. No pytest result is available yet. Do not claim the repository policy tests pass until this run completes.
- The policy code is now syntactically clean on direct file inspection; exact-head CI remains the authority.


## 15. Source archive extraction prototype — 2026-11-14

- CI run #1639 / ID `43602043973` completed SUCCESS on code head `ae11ebe2706f159d1e6433367f59b31c2b21b408`: **1,832 passed, 4 warnings, 30 subtests passed**. Python compilation, whitespace, EVM Key Forensics evidence generation, and Bubblewrap fixture acceptance passed. The four pytest warnings remain visible (duplicate ZIP member names in adversarial tests).
- Added `shared/source_archive.py` and `tests/test_source_archive.py` to PR #196. The helper performs bounded, non-executing extraction of an already-fetched tar.gz archive; it rejects traversal, multiple roots, duplicate paths, file/directory collisions, links, special files, and oversized archives, and cleans partial output on failure.
- The helper deliberately performs no network access and does not establish that archive bytes correspond to a Git commit. The future resolver must first fetch GitHub commit metadata for the exact 40-character SHA, verify the returned commit SHA and tree SHA, then fetch the archive pinned to that SHA. Redirect policy and response-size enforcement must be implemented before enabling HTTP.
- No target code is executed. No Foundry/Slither process launcher is added. A disposable VM/microVM and pinned toolchain remain unresolved.
- New extraction tests and implementation are committed after run #1639 and therefore are **not yet CI-verified**. Trigger and inspect a fresh workflow for the latest branch head.
- PR #196 remains OPEN, DRAFT, and mergeable. Issue #158 remains OPEN.


## 16. Pinned commit and Git tree verification prototype — 2026-11-14

- Exact-head CI for `3ef07ba8a0143a6006c214651c97b1e37087139e`, run #1646 / ID `43602474301`, completed SUCCESS: **1,844 passed, 4 warnings, 30 subtests passed**. Bubblewrap fixture acceptance and evidence artifact upload also passed.
- Added commit metadata validation: require requested full 40-character SHA, returned SHA equality, and valid root tree SHA.
- Added Git blob/tree object ID calculation for extracted regular files and executable-bit semantics, plus fail-closed comparison against the pinned root tree SHA.
- Added combined extract-and-verify entry point. It removes extracted content if the computed Git tree does not match the pinned metadata.
- New tests cover metadata mismatch, empty Git tree known vector, content/mode changes, symlink rejection, successful pinned extraction, tree mismatch cleanup, and rejection before writing when commit SHA mismatches.
- The latest implementation/tests/docs are newer than run #1646 and therefore not yet CI-verified. A new exact-head CI result is required.
- No network downloader, redirect handling, or immutable source store has been added. No target code is executed. Symlinks, special files, and gitlinks/submodules are intentionally rejected pending a safe, verifiable design.
- PR #196 remains OPEN and DRAFT; issue #158 remains OPEN.


## 17. Git tree hash regression and correction — 2026-11-14

- Latest code implementation head: `79c04db3bb9848c8039d8add11bd89ba599b3895`. This checkpoint update is commit `3ecf6c091c424e56eda6d98f6bc8a9f8f49fe102`, now the PR #196 head. PR remains OPEN and DRAFT; base is `main`. Current PR metadata reports `mergeable: true`. Do not merge.
- Exact-head CI run #1655 / ID `43603314753` on prior head `536ee0100c5e9c0bc5780570be1f69930ea89431` failed in pytest: **1,855 passed, 1 failed**. The failing case was the empty-directory branch in `compute_git_tree_sha()`; it treated the recursively returned complete Git tree object as though it were only a tree payload, producing an incorrect nested tree object hash. Other workflow stages, including Bubblewrap fixture acceptance, completed successfully.
- Fixed `shared/source_archive.py`: recursive directory hashing now recognizes the canonical empty tree object (`tree 0\\0`) and omits empty directories, while hashes non-empty child tree objects directly. This preserves Git's rule that empty directories are not represented in Git trees.
- Fix commit: `79c04db3bb9848c8039d8add11bd89ba599b3895`.
- Exact-head CI run #1656 / ID `43603669224` was created for code head `79c04db3bb9848c8039d8add11bd89ba599b3895`. At last inspection its job was still `in_progress` during dependency installation; no pytest result or final conclusion was available. The fix is therefore **not yet CI-verified**. The later checkpoint-only commit `3ecf6c0` has no workflow run returned (documentation-only change). Recheck run #1656 before further implementation.
- The source archive layer now includes bounded tar.gz extraction, full commit/tree metadata validation, Git SHA-1 blob/tree reconstruction (including executable mode), and fail-closed archive-to-pinned-tree comparison with cleanup on mismatch. It remains a local helper only: it accepts archive bytes and metadata supplied by its caller and performs no network access.
- Outstanding limitations remain: no HTTP source downloader, redirect validation, streamed response-size enforcement, immutable source storage, or independent acquisition provenance. Symlinks, hardlinks, special files and gitlinks/submodules are rejected. No target code execution or process launcher has been added.
- Next action: inspect CI #1656 to completion. If green, record the exact pytest count and Bubblewrap result, then review source archive edge cases and design the trusted, bounded HTTP resolver separately. If red, fix only the demonstrated failure and rerun exact-head CI.
- Issue #158 remains OPEN. PR #196 remains DRAFT. This prototype does not close the release gate or establish arbitrary target execution safety.


## 18. Pinned source tree fix — exact-head CI passed — 2026-11-15

- CI run #1656 / ID `43603669224` completed SUCCESS for implementation commit `79c04db3bb9848c8039d8add11bd89ba599b3895`.
- Retrieved job log confirms: **1,856 passed, 4 warnings, 30 subtests passed**. Python compilation, whitespace checks, EVM Key Forensics evidence steps, and Bubblewrap fixture acceptance all completed successfully. Bubblewrap acceptance report status was PASS and the report artifact uploaded successfully.
- This verifies the empty-directory/Git tree hashing correction described in section 17. The four pytest warnings remain present and visible; they include duplicate ZIP member-name warnings in adversarial evidence-package tests. Do not describe the run as warning-free.
- The workflow ran against code commit `79c04db`; subsequent checkpoint-only commits `3ecf6c0` and `8918d80` change documentation, not implementation. CI #1656 is the relevant exact-code-head validation.
- PR #196 remains OPEN and DRAFT; latest observed PR head is checkpoint commit `8918d80e3a41e8d24d28d2cddc22664344ae8da3`, and GitHub reports `mergeable: true`. Issue #158 remains OPEN.
- Next: review source archive and repository-policy boundaries together before adding network acquisition. Any resolver must enforce the server-side repository allowlist, bind requests to the immutable full commit SHA, disable/revalidate redirects, enforce streamed response and extraction limits, verify commit metadata and reconstructed Git tree, and clean up on every failure. Keep acquisition non-executing. Do not launch Foundry/Slither or arbitrary target code until the isolated VM/microVM backend and pinned toolchain are selected.
- This CI pass does not prove source acquisition, target execution safety, vulnerability reproduction, or full #158 release acceptance.


## 19. Git-native tree hash oracle test — 2026-11-15

- Added `test_git_tree_sha_matches_git_for_mixed_names_modes_and_nested_directories` to `tests/test_source_archive.py`.
- The test creates a controlled source tree containing a nested directory, a filename that exercises Git's file-vs-directory sort ordering (`a.c` vs `a/`), a Unicode filename, and an executable file. It computes the implementation hash, stages an equivalent tree in a separate temporary Git repository, and compares against Git's own `git write-tree` result.
- The test skips only if the Git executable is unavailable. It executes no target repository code and uses only a temporary test fixture.
- Commit: `ae8d32c5bb8096690d79f891e73b9a2b3de50581`.
- PR #196 remains OPEN and DRAFT; current head is this test commit. GitHub Actions run #1660 / ID `43676151759` is running for this exact head; at last inspection its job was in progress during checkout. The new oracle test is **not yet CI-verified**.
- A documentation-only checkpoint commit `4cb28096b74d835325791ab19468c04c8eaa824c` also triggered run #1659; run #1660 is the relevant code/test validation.
- Next: inspect run #1660 to completion. If the Git oracle test fails, fix the tree serialization against Git's observed behavior before any network source resolver is implemented. If green, proceed with a separately tested, non-executing bounded source resolver design; do not add target execution.


## 20. Git-native source tree oracle CI passed — 2026-11-15

- CI run #1660 / ID `43676151759` completed SUCCESS for test commit `ae8d32c5bb8096690d79f891e73b9a2b3de50581`.
- Exact pytest result: **1,857 passed, 4 warnings, 30 subtests passed** in 29.99s.
- The new `test_git_tree_sha_matches_git_for_mixed_names_modes_and_nested_directories` passed. It compared the implementation against Git's own `git write-tree` for nested directories, file/directory ordering, Unicode filenames and executable mode.
- Bubblewrap fixture acceptance: **PASS**; acceptance JSON artifact uploaded successfully (artifact ID `14146457921`). Compilation, deterministic C++ diagnostic build, source pin comparison, portable evidence assembly/verification, invalid sample-count rejection and Python compilation all passed.
- Four pytest warnings remain, including intentional duplicate ZIP member names exercised by adversarial evidence-package tests. The workflow also emitted GitHub Actions Node.js 20 deprecation warnings; neither is a test failure, but both should be tracked separately.
- Code head validated: `ae8d32c5bb8096690d79f891e73b9a2b3de50581`. PR #196 remains DRAFT and must not be merged. Issue #158 remains OPEN.
- The Git tree hash implementation now has both known-vector coverage and an independent Git CLI oracle test. This is sufficient to move to the next isolated source-acquisition design step; it is not proof of acquisition provenance or execution safety.
- Next implementation boundary: build a bounded, non-executing GitHub source resolver that accepts only configured repository identities and a full immutable commit SHA; validates commit metadata and root tree; obtains the archive for that exact SHA; enforces HTTPS/redirect policy and streamed byte limits; passes bytes into the existing archive extractor/tree verifier; and removes partial artifacts on all failures. No arbitrary URL fetch, no target code execution, no dependency installation, no submodules/symlinks, and no process launcher.


## 21. Bounded GitHub source acquisition and archive-bomb defenses — 2026-11-15

- Added `shared/github_source_resolver.py` and `tests/test_github_source_resolver.py`. The resolver accepts an already admitted target and an explicit server-owned repository allowlist; it does not accept caller-provided URLs, owner/repository names, commit refs, or archive locations.
- Acquisition order: authorize admitted case against allowlist; require full registered commit SHA; request GitHub commit metadata; validate returned SHA and root tree; request archive using that exact SHA; enforce response byte limits; run bounded extraction; recompute Git tree and require exact root-tree match.
- HTTP transport uses HTTPS only, fixed GitHub API/codeload host allowlist, rejects credentials/ports/host aliases in redirect destinations, limits redirect count to three, and applies a bounded socket timeout. No credentials are sent. Current implementation therefore supports public GitHub repositories only; private-repository authentication and rate-limit/backoff handling are not implemented.
- Added a decompression boundary in `shared/source_archive.py`: gzip data is inflated to a temporary file under `max_tar_uncompressed_bytes` before tar parsing. Tar members are iterated and counted incrementally rather than loaded wholesale through `getmembers()`. This prevents unbounded gzip expansion and caps tar metadata accumulation before extraction.
- Added adversarial tests for non-allowlisted repository denial before network access, wrong commit metadata before archive request, redirect URL policy, streamed archive size without Content-Length, gzip expansion bombs, and excessive TAR member metadata.
- CI run #1668 / ID `43676729620` passed for exact latest code/test head `4582afd6b41805278b07e3d6041acf0a05de26db`: **1,869 passed, 4 warnings, 30 subtests passed**. Bubblewrap fixture acceptance: **PASS**, report artifact uploaded (ID `14146820186`). Python compilation, source evidence workflow and whitespace checks passed.
- The four pytest warnings remain from intentionally duplicated ZIP member names in adversarial evidence-package tests. GitHub Actions also emits Node.js 20 deprecation warnings for existing workflow actions; neither is a test failure.
- PR #196 remains OPEN and DRAFT; do not merge. Issue #158 remains OPEN.
- Explicit limitations: resolver is not wired into a worker/executor or persistent immutable source store; no private-repo auth, API rate-limit retry, independent repository provenance, total wall-clock transfer deadline, submodule/symlink support, or target execution. GitHub TLS/API plus Git object consistency is not independent provenance. No source code is executed.
- Next: add resolver integration only at the existing admitted-target boundary after reviewing the destination ownership/lifecycle and immutable storage contract. Keep it non-executing. Do not implement process launchers or alter Agent B-owned orchestration/CLI paths. Release gate #158 remains blocked by attestation trust, case-binding entrypoints, operator lifecycle, and isolated reproduction requirements.
