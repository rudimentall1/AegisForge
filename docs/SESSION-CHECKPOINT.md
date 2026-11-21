# Session Checkpoint — AegisForge

**Updated:** 2026-11-15
**Repository:** https://github.com/rudimentall1/AegisForge  
**Working branch:** `feat/persist-local-experiment-evidence-main`  
**Latest implementation commit:** `9189d21ae56514ca1757fd4c2f4b4e2097870cc0`  
**PR:** [#196](https://github.com/rudimentall1/AegisForge/pull/196) — OPEN, DRAFT, not merged  
**Release gate:** [Issue #158](https://github.com/rudimentall1/AegisForge/issues/158) — OPEN

## 1. Where we stopped (verified repository state)

- PR #196 currently has 319 commits, 57 changed files; latest PR head: `ba8a145720b5dfd7752ec85b7fac1b3a19fa72bb` (checkpoint-only commit); latest implementation/test head: `9189d21ae56514ca1757fd4c2f4b4e2097870cc0`; base: `0adfc88c41e8c48c8ed25f2b25ef8db67cab5370`.
- PR remains OPEN and DRAFT. Latest observed PR metadata reports `mergeable: true`; this is not approval to merge. Keep Draft until release gate #158 is satisfied.
- Historical CI run #1615 is retained below for chronology; current code verification is CI #1680 / ID `43677460311` (see section 22). The latest checkpoint-only commit `b4f070b...` has no workflow run returned yet.
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


## 7. Update — 2026-11-15: pinned GitHub source acquisition

- CI run #1670 / ID `43676846682` passed on head `c912fdeab3ab8acc16ae10c34cdb2e003032c5bd`: **1,869 tests passed, 4 warnings, 30 subtests passed**. Bubblewrap fixture acceptance passed for both fixed fixture modes. This is not a release-gate pass.
- Added `shared/github_source_fetch.py` as a separate acquisition-only adapter. It requests commit metadata for a full immutable SHA, validates the resolved commit and root tree SHA, fetches the tarball for that exact SHA, bounds response sizes and timeouts, restricts HTTPS redirects to GitHub API/codeload hosts, and sends no authorization header or ambient credentials.
- The fetched archive is passed to the existing non-executing extractor and accepted only when the computed Git tree SHA matches the commit API's tree SHA. The adapter does not execute source, install dependencies, or connect to the experiment runner.
- Added `tests/test_github_source_fetch.py` for successful pinned acquisition, wrong commit rejection before archive download, duplicate JSON key rejection, redirect allowlisting, response-size limits, exact SHA URLs, and absence of Authorization headers.
- Documented the acquisition boundary in `docs/local-experiment-evidence.md`. The clean-checkout test command now includes source archive and source fetch tests.
- Current head: `c23528119c5f0ce3372bc7a2d98b165ec147de12`. CI run #1677 / ID `43677232465` is **in progress**; latest observed job ID `132699935186`. Do not claim the new source fetcher is CI-verified until this run completes.
- PR #196 remains OPEN and DRAFT, not merged. Keep it Draft. Issue #158 remains OPEN.
- Next: inspect run #1677 and logs. If green, review the source fetcher's redirect/response/error behavior and only then decide whether to expose a CLI or integrate source acquisition into a higher-level workflow. Do not execute downloaded target code. Continue to treat GitHub metadata/archive agreement as consistency, not independent provenance.

## 22. Pinned GitHub source fetcher hardening — 2026-11-15

- Latest implementation commit: `d571f2911706c98052ed5a686407ed8155a0c7c1`.
- Hardened `shared/github_source_fetch.py`: validate all caller-supplied fetch limits before network access; reject boolean values as numeric limits; require timeout to be a finite positive number; require metadata/archive byte caps to be positive integers.
- Added regression coverage for NaN/Infinity/bool timeout values, boolean and invalid byte limits, redirects using non-standard ports or URL userinfo, non-HTTPS redirects, and oversized declared Content-Length.
- GitHub Actions run #1680 / ID `43677460311` completed **SUCCESS** for this code head. Job `132700618281`: **1,878 passed, 4 warnings, 30 subtests passed** in 35.67s. Python compilation and whitespace checks passed; EVM Key Forensics evidence artifact uploaded; Bubblewrap fixture acceptance returned **PASS** and its report artifact uploaded.
- Four pytest warnings are intentional duplicate ZIP-member warnings from adversarial archive tests. GitHub Actions emitted Node.js 20 deprecation warnings for existing workflow actions; neither caused failure.
- CI checked the PR merge ref `0a408c77c707bb6ceaca5e1e6f9d420b1d74bacf`, which contains head `d571f291...` merged with base `0adfc88...`. The PR head itself is `d571f291...`.
- PR #196 remains OPEN, DRAFT, not merged; current metadata reports 308 commits, 57 changed files, +12,785/-138, mergeable true. Keep Draft.
- Issue #158 remains OPEN. The source fetcher remains acquisition-only and is not wired into a runner. GitHub API metadata/archive tree agreement is consistency checking, not independent provenance. No arbitrary target code execution is enabled.
- Next engineering focus: review the existing admitted-target and immutable source-storage boundaries, then build only the missing local-only acceptance path required by #158. Do not modify protected attestation files, reserved workflows, or Agent B-owned orchestration/CLI paths. Do not add a process launcher before a reviewed VM/microVM isolation contract and pinned toolchain exist.

## 23. Full isolated fixture-to-dossier path and archive budget hardening — 2026-11-15

- Extended `tests/test_bubblewrap_fixture_evidence_e2e.py`: the actual Bubblewrap-isolated control and counter-test now flow through Research Case registration, one bounded runtime round, distinct bound tasks, raw output persistence in Evidence Ledger, individual experiment bundle export/verification, Research Case dossier export/verification, and a combined portable evidence package.
- The combined package is checked for matching case identity, both task IDs, runtime round and planned round. It explicitly reports unsigned integrity only, no attestation present, no authenticated execution truth, and no confirmed vulnerability.
- CI run #1683 / ID `43677676345` exposed one incorrect test expectation: the verifier reports `attestation_verification_status=NOT_PRESENT` when no attestation exists. Corrected the expectation; no production-code defect was involved in that failure.
- Security review found that `SourceArchiveLimits` accepted booleans, floats, NaN and Infinity. In particular, NaN comparisons could bypass the tar expansion and file-count budgets. Added `validate_source_archive_limits()` to require all four resource caps to be strict positive integers (bool excluded), and call it both in the extractor and before the GitHub fetcher opens a network connection.
- Added adversarial tests for every archive limit with boolean, zero, negative, fractional, NaN and Infinity values, plus fetcher tests proving malformed archive limits are rejected before network opener construction.
- Latest CI run #1690 / ID `43677792881` completed **SUCCESS** on exact PR head `9189d21ae56514ca1757fd4c2f4b4e2097870cc0`: **1,907 passed, 4 warnings, 30 subtests passed** in 31.85s. Python compilation, whitespace checks, EVM Key Forensics evidence workflow and Bubblewrap fixture acceptance all passed. Bubblewrap acceptance report status: **PASS**.
- Four pytest warnings remain intentional duplicate ZIP-member warnings from adversarial archive tests. Existing GitHub Actions Node.js deprecation warnings are external to the Python test suite.
- PR #196 remains OPEN, DRAFT, not merged; GitHub currently reports mergeable true. Issue #158 remains OPEN.
- Remaining boundary: this proves the fixed repository-owned synthetic fixture path and portable evidence integrity. It does not execute arbitrary target code, prove runner honesty, establish independent provenance, or satisfy all #158 release blockers. Do not turn the fixture backend into a generic command runner. Continue with separately reviewed isolation/toolchain design and the outstanding Agent B-owned case-entrypoint/operator lifecycle blockers without editing their files.



## 24. Resolver hardening, exact-head CI, and sandbox boundary review — 2026-11-15

- PR #196 head at review: `a484c0dfc67eaea0169f06cf066165d94fd3fee9`; PR remains OPEN, DRAFT, not merged. Release gate #158 remains OPEN.
- Added resolver-side validation of source archive limits before the first network request. Invalid booleans, floats, NaN, Infinity, and out-of-range values fail closed as `source_archive_limits_invalid`.
- Added duplicate-key rejection for GitHub commit metadata JSON in `shared/github_source_resolver.py`; duplicate metadata keys fail before archive retrieval as `github_commit_metadata_duplicate_key`.
- Added negative tests proving malformed limits do not trigger network access and duplicate metadata keys block archive fetch.
- CI run #1696 / ID `43678177553` completed SUCCESS on PR merge ref `a82170ec6a750f88fba3eb0e1a0ad1bdb01d3eaf`, containing PR head `a484c0d...`. Job ID `132702810909`: **1,913 passed, 4 warnings, 30 subtests passed**; Python compilation, whitespace check, EVM Key Forensics evidence steps, and Bubblewrap fixture acceptance all passed. Bubblewrap report status: PASS.
- The four pytest warnings are duplicate ZIP member-name warnings intentionally triggered by adversarial tests. They are not runtime failures.
- Re-reviewed `shared/sandbox.py` and `tests/test_sandbox.py`. This generic helper is not evidence of a hostile-code sandbox. The process backend has no filesystem or network isolation; POSIX resource limits do not establish isolation, and `RLIMIT_NPROC` is not a reliable process-count boundary when the service runs as root. The Docker backend has no explicit seccomp profile, no PID limit, no `no-new-privileges`, and uses floating image tag `python:3.12-slim`. These are known limitations, not acceptable controls for arbitrary public repositories.
- No arbitrary target runner is authorized by this review. Keep the existing fixed-fixture-only execution path. Do not route untrusted repository content or dossier-provided argv through `run_in_sandbox`.
- Next: inspect all call sites and the pinned-target adapter design; decide and document the actual disposable VM/microVM backend and pinned toolchain. Only then implement a narrow fixed-profile adapter with fail-closed admission and adversarial tests. Keep PR Draft and do not close #158 until the full acceptance contract is met.


## 25. Existing Docker reproduction prototype review — 2026-11-15

- Audited `shared/reproduction_runner.py`, `shared/reproduction_contract.py`, `tests/test_reproduction_runner.py`, `shared/target_execution_admission.py`, and the main runtime entrypoints (`agents/lab_runner`, `agents/worker.py`, `orchestrator/master.py`).
- The repository already contains a standalone Docker reproduction prototype. It requires a digest-qualified local image (`--pull=never`), refuses root host identity, copies and verifies pinned Git worktree blobs, mounts source read-only, disables network/IPC, drops capabilities, sets no-new-privileges, PID/CPU/memory/swap/output limits, uses a minimal environment, verifies exact output paths/digests, and requires cleanup for success.
- This is stronger than `shared/sandbox.py`, but it is still Docker on the host kernel. Existing tests mock Docker/Git; they do not prove actual isolation or resistance to container/kernel escape.
- The reproduction contract accepts arbitrary argv and declared environment values and is not bound to persisted Research Case/task/runtime-round/planned-round state. The separate target admission gate is not wired into the runner in the reviewed runtime entrypoints. Do not expose this as a public runner or wire it into workers/API/CLI.
- Updated `docs/PINNED-TARGET-EXECUTION-ADAPTER-DESIGN.md` in commit `df4c813aa60d963a6f296a608a28ceb29694e675` to accurately distinguish the existing prototype from an approved execution boundary and to record the missing admission, fixed-profile, and VM/microVM requirements.
- Next engineering step is not another generic subprocess wrapper. First establish a disposable VM/microVM backend that can be provisioned and verified on the actual deployment runner; then connect persisted admission and fixed server-owned tool profiles. Until then, only repository-owned synthetic fixtures may execute. Issue #158 stays OPEN; PR #196 stays DRAFT.


## 26. Hostile execution backend decision — 2026-11-15

- Added `docs/EXECUTION-BACKEND-DECISION.md` in commit `2e86d8c8c98a68c2aba31e7d4511d32bf17c2119`.
- Decision: Firecracker on a dedicated Linux KVM host is the first production microVM candidate, but it is NOT approved until the actual host proves CPU virtualization, usable `/dev/kvm`, jailer startup, and adversarial host/network isolation.
- Kata Containers is deferred because it also requires bare metal/nested virtualization and adds a CRI/containerd operational stack not justified by the current single-host MVP.
- gVisor systrap is documented as a possible lower-assurance internal tier where KVM is unavailable. It is explicitly not equivalent to a VM/microVM and does not close the hostile-public-repository release gate.
- GitHub-hosted `ubuntu-latest` is not assumed to expose KVM merely because it is itself a VM. The workflow specification does not guarantee nested virtualization; do not modify protected CI workflows for speculative probing.
- The new decision document includes a read-only host capability probe and ten mandatory microVM acceptance conditions. No kernel modules, permissions, packages, services, or workflows were changed.
- The execution pipeline remains intentionally unconnected: persisted admission gate exists, Docker reproduction prototype remains opt-in, and only the repository-owned synthetic fixture is approved for execution.
- Latest documentation commit is `2e86d8c8c98a68c2aba31e7d4511d32bf17c2119`. CI for this documentation-only commit has not yet been observed. PR #196 remains DRAFT; issues #158, #80, #88, #116, #118, #100, and #67 remain OPEN. No merge or release-gate closure.


## 27. Real EVM target intake vertical slice — 2026-11-21

- Opened Draft PR #208: `feat/onchain-contract-intake` → `feat/first-foundry-exploit-benchmark`.
- Current PR head at checkpoint update: `80faa4c60fa06e68dfd3cfb55c369d7821556c89`. PR remains OPEN and DRAFT; do not merge into #207/base branch automatically.
- Added `scam_intelligence/contract_intake.py`: bounded Blockscout v2 verified-contract pagination, minimum transaction-count filter, address validation, multi-file and Standard JSON source normalization, source SHA-256, compiler/ABI/proxy metadata, source-size and path-traversal checks, and per-target rejection reporting.
- Initial explorer instances documented: Ethereum (`eth.blockscout.com`, chain 1), Base (`base.blockscout.com`, chain 8453), Arbitrum One (`arbitrum.blockscout.com`, chain 42161).
- Added independent configured-RPC attestation: chain ID check, block number/hash capture, and runtime-code hash. Hardened the code read to use EIP-1898 `blockHash` with `requireCanonical: true`, rather than querying by block number only; this prevents silently reading code from a replacement block after a reorg. The returned block number is also checked against the requested height.
- Added `tests/test_contract_intake.py` with 10 test functions covering pagination/filtering, source normalization, unverified/empty source, malformed addresses, path traversal, Standard JSON, chain mismatch, empty runtime code, pinned-block attestation, and the combined intake path. These tests are authored but **not yet executed**.
- Added `docs/ONCHAIN-CONTRACT-INTAKE.md` describing usage and trust boundaries.
- Latest observed Actions run for this PR (run ID `44888335495`, triggered on test/code head `aafad2b818cf16204051432afb788ad39dc9095e`) failed before any job steps: runner ID 0, empty runner name, `steps=[]`. This is a GitHub runner assignment/infrastructure failure; it is neither a test failure nor a passing test result. The later documentation-only head `80faa4c...` has not been validated by CI.
- Important limitation: this is acquisition only. It is not wired into Worker/ResearchCase/queue/SecurityChecker/LabRunner, does not recursively acquire proxy implementations, and does not prove explorer source corresponds to deployed bytecode. No autonomous vulnerability discovery claim is justified yet.
- Next: implement a persisted, immutable target/source record that binds chain ID, address, pinned block hash, runtime-code hash, source digest, compiler metadata, and acquisition provider; then connect it to the existing admitted ResearchCase/Worker handoff without putting source bytes into the small capability-intent field. Preserve existing execution admission: downloaded source remains non-executable until the approved microVM/fixed-profile gate is satisfied. After integration, run focused tests locally/CI and perform one real read-only intake against Base or Arbitrum using configured RPC credentials; do not claim a vulnerability was found until the complete agent-to-evidence path produces independently validated evidence.


### Integration boundary clarification (same milestone)

- Inspected `shared/research_case.py`, `shared/queue.py`, `shared/target_execution_admission.py`, `shared/source_record_verifier.py`, `shared/evidence_ledger.py`, and `agents/worker.py`.
- Confirmed `ResearchCase` is Git-source-centric: it requires `target_repository` plus a full 40-character `target_commit`, while the pinned source/execution admission path resolves Git worktrees. It has no first-class `chain_id`, contract address, block hash, runtime-code hash, or explorer source bundle fields.
- Therefore the Blockscout intake result cannot safely be converted into a current `ResearchCase` by inventing a Git commit or overloading `capability_intent`. The latter is explicitly capped at 8 KiB and is not a source/artifact store.
- Correct next design: add a distinct immutable `OnchainTargetRecord`/store in the existing SQLite database, with source bytes persisted separately from queue payloads and content-addressed by source digest. It must bind chain ID, normalized contract address, canonical block number/hash, runtime bytecode hash, source digest, provider, compiler metadata, and proxy metadata. Then extend the case/worker handoff through an explicit target-type binding rather than weakening Git-based ResearchCase invariants or execution admission.


## 28. Immutable on-chain target persistence — 2026-11-21

- Added `shared/onchain_target_store.py` with `OnchainTargetRecord` and insert-only `OnchainTargetStore`, using the existing SQLite connection but keeping full source bundles outside queue task/capability payloads.
- The record binds chain ID, normalized contract address, block number/hash, runtime-code SHA-256, source-file map/source SHA-256, source provider, compiler version, contract name, proxy type, and implementation addresses. `target_id` is a deterministic SHA-256 over the identity metadata.
- Source bundles are bounded to 4 MiB and 500 files; paths reject traversal, absolute paths, backslashes and NUL. Source mapping is read-only after record construction. A conflicting record for the same chain/address/block hash is rejected; exact duplicate insertion is idempotent.
- Added `put_intake_item()` to validate agreement among Blockscout candidate, acquired source, and RPC deployment attestation before persistence. Chain IDs and contract addresses must agree; deployment must be positively attested.
- Added `tests/test_onchain_target_store.py` for validation, source digest mismatch, immutable mapping, insert/retrieve, idempotency, conflicting snapshots, new block snapshots, and intake-to-store binding.
- Updated `docs/ONCHAIN-CONTRACT-INTAKE.md` with the store integration example and explicit statement that Worker/ResearchCase integration is still missing.
- Current branch includes the above changes; latest Actions run observed before these later commits (`44888508243`) again failed before steps with `runner_id=0` and no assigned runner. No tests have executed in CI. Do not mark this milestone test-passing.
- Next: add an explicit on-chain target binding to the case/queue model without weakening Git-based ResearchCase invariants, then add a narrow Worker handoff that loads the persisted target by ID. Do not start target code execution; source must remain inert until the existing admission and approved microVM/fixed-profile controls authorize it.



## 29. Worker handoff boundary review — 2026-11-21

- Re-read the live branch implementations of `shared/research_case.py`, `shared/queue.py`, `shared/target_execution_admission.py`, `agents/worker.py`, and `shared/onchain_target_store.py`.
- Confirmed the existing extension points:
  - `TaskQueue.register_research_case()/get_research_case()` persist and resolve only the Git-centric `ResearchCase` contract.
  - `TaskQueue.add()` inherits and enforces `research_case_id`, `round_id`, and `round_spec_id` across parent/child tasks. `capability_intent` is deliberately capped at 8 KiB.
  - `Worker.run_once()` claims the task, resolves its ResearchCase and planned RoundSpec, calls `validate_worker_case_binding()`, then constructs the common `Task.payload` and dispatches through `TechniqueRegistry`.
  - `validate_worker_case_binding()` requires a ResearchCase for `source_researcher`, `crypto_analyst`, and `lab_runner`; simply attaching an on-chain target ID would still be rejected or, if bypassed, would weaken a security boundary.
  - `admit_target_execution()` independently resolves only Git ResearchCase + runtime round state and must remain Git-specific. It must not be tricked into accepting an on-chain target as a fake repository/commit.
- Therefore the correct integration is a distinct typed `OnchainResearchCase` registry and task binding, not optional EVM fields bolted onto `ResearchCase`. The on-chain case must bind an immutable `target_id` plus explicit authorization/scope evidence and a reviewed scope digest; public visibility or verified source alone is not authorization to perform security testing.
- Worker should resolve the on-chain case and `OnchainTargetRecord` from the same SQLite database and expose a typed, read-only target context in `Task.payload`. Source bytes must be loaded from `OnchainTargetStore`, never copied into queue descriptions, capability intent, or task result metadata.
- First integration stage should permit non-executing source research only. It must not route on-chain cases into the Git-only `target_execution_admission`, Foundry runner, or arbitrary subprocess. A separate on-chain execution admission contract is required before any fork/harness execution.
- No production code was changed in this review. No target source was executed and no vulnerability finding was claimed.
- Committed the integration boundary to `docs/ONCHAIN-CONTRACT-INTAKE.md` in `06808eb0bc42bb8c7114ed255e19a526f80d6b45`; checkpoint review itself was committed in `329500c4f0a996153e3e3397c79f20080b081524`. This is documentation/design progress only; no tests were run and no CI result is claimed for these commits.
- Next implementation slice: TDD for immutable `OnchainResearchCase` validation/registration, mutually exclusive Git/on-chain task bindings with parent inheritance, and Worker target resolution tests. Only after those pass should agent dispatch be enabled.


## 30. On-chain source-research Worker path — 2026-11-21

- Implemented `shared/onchain_research_case.py`: frozen typed case contract binds immutable target ID, HTTPS scope URL, scope SHA-256/review date, authorization reference, falsifiable hypothesis, invariant, falsification criteria, and a restricted source-only technique set. Added canonical digest binding and tamper verification.
- Extended `TaskQueue` with `onchain_research_cases` registry, `onchain_case_id` queue migration, target-backed registration, target lookup, mutual exclusion from Git ResearchCase, parent/child inheritance, and case mismatch rejection. `source_researcher`, `crypto_analyst`, and `security_checker` are allowed; `lab_runner` remains Git-only.
- Extended Worker claim resolution to load the registered on-chain case and immutable target record. It passes typed target context to agents and sets role-scoped offline capability intents. Git case validation and Git target admission remain unchanged.
- Added a working non-executing agent chain: `source_researcher` performs bounded lexical triage over stored Solidity source; `crypto_analyst` converts signals into falsifiable, unconfirmed hypotheses; `security_checker` independently applies its existing source-pattern rules to the full persisted source bundle. Worker automatically enqueues the next agent as a child task; the case binding is inherited.
- Extended EvidenceLedger observation lineage to store `COALESCE(research_case_id, onchain_case_id)`, so on-chain agent evidence is case-bound.
- Added `scripts/aegisforge_onchain_research.py`: explicit single-address CLI; it fetches verified source, obtains RPC deployment attestation, persists the immutable target, registers the case, and queues the first source-research task. It deliberately does not crawl arbitrary chain contracts into a bug-bounty scope.
- Added 18 test functions in `tests/test_onchain_research_case.py` and `tests/test_onchain_source_pipeline.py` for case validation, tamper detection, queue registration/claim/inheritance, role separation, evidence lineage, source triage, hypothesis generation, SecurityChecker review, and offline capability policy. Combined with 22 earlier intake/store test functions, this PR adds 40 test functions total.
- Verification: CI run `44889956828` on an intermediate commit failed with no job steps; rerunning job `136803413922` also failed before steps were reported. The latest PR head at checkpoint time is `ee65eff40454e5dfb8e8ddd455a9e81208d9370f`; no CI run was returned for that exact head. No test suite has been executed. Do not claim passing tests.
- PR #208 remains Draft and its description now documents the implementation and verification limits.
- Current limitation: the on-chain path now ingests and triages real authorized source, creates candidate hypotheses, and produces independent potential-risk pattern reviews. It does not yet prove a vulnerability or run exploit reproduction. Next engineering priority is a bounded source-level reasoning stage that traces each candidate through modifiers, call graph, state writes, and access control, followed by authorized fork execution admission only after a separate scope gate exists.


- Follow-up verification update: the latest tested commit before this checkpoint note was `f59ef81fec28e205bd03ab5e125ec964c5f1e87d`. Actions run `44890185757` failed with job `136804103973` reporting `steps=[]`; a rerun created job `136804181500` and failed the same way with no steps. This is runner/job initialization failure evidence, not a test failure and not a pass. No Python tests executed.


- Final Worker provenance addition: every successful on-chain agent result now carries `onchain_research_case_binding` with the immutable case digest. Latest observed CI run `44890248965` and rerun job `136804362034` again failed with `steps=[]`; no test code ran. Current implementation commit: `93fb52b2fa8e4ee04916c19205f3b53385ac16c0`.

---

# Current checkpoint — PR #208 on-chain source reasoning

**Updated:** 2026-11-21  
**Repository:** `rudimentall1/AegisForge`  
**Working branch:** `feat/onchain-contract-intake`  
**Latest code/test head before this checkpoint update:** `d45d09a511ae790104839d348569e18c19677a85`  
**PR:** [#208](https://github.com/rudimentall1/AegisForge/pull/208), OPEN, DRAFT, not merged.

## Implemented in this continuation

- Added `shared/solidity_source_analysis.py`, a bounded Solidity source structural pass.
- Inventories function bodies, modifiers, visibility and mutability.
- Builds conservative same-file call edges only where the callee name is unambiguous.
- Records external-call and state-write candidate sites with exact file/line/excerpt evidence.
- Detects syntactic authorization signals from modifier names and common inline sender/owner checks.
- Fails closed on unterminated comments/strings and unbalanced source/function braces.
- `SourceResearcher` now attaches structural analysis to the on-chain source result.
- `CryptoAnalyst` emits function-level `NEEDS_DEEPER_ANALYSIS` hypotheses and bounded call paths from public/external entrypoints to relevant internal functions.
- `SecurityChecker` independently recomputes structural analysis from the immutable target source bundle and records operation-site evidence.
- Added `tests/test_solidity_source_analysis.py` and expanded `tests/test_onchain_source_pipeline.py` to assert function inventory, call edges, operation line references, function hypotheses, independent recomputation, and malformed-source handling.
- Updated `docs/ONCHAIN-CONTRACT-INTAKE.md` with current implementation and limitations.

## Verification — NOT PASSED

- Added `workflow_dispatch` to `.github/workflows/ci.yml` so the current draft branch can be manually validated from the GitHub Actions UI.
- The last known GitHub Actions run `44890299159` completed with failure and job `136806540311` reported `steps: null`. No test step was executed.
- The latest PR head includes the manual `workflow_dispatch` trigger, but the latest run still failed before step initialization. A local checkout attempt was unavailable because this runtime could not resolve `github.com`.
- 47 test functions are present across the intake/store, on-chain case/pipeline, and structural-analysis test files, but they have **not** been executed. Do not describe the implementation as tested or passing.
- PR #208 remains Draft. Do not merge.

## Current technical limits

This is not a Solidity compiler AST, Slither, formal control-flow analysis, or bytecode-equivalence proof. Overloads, cross-file/inherited dispatch, assembly semantics, storage aliasing, proxy context, and compiler transformations are unresolved. State-write and authorization signals are syntactic candidates only. No deployed contract code is executed; no fork or transaction is started; no vulnerability is confirmed.

## Next actions

1. Restore a working CI execution path and run the focused tests, then the full suite.
2. Fix all actual test failures before extending the analyzer.
3. Add compiler-backed AST/source-map ingestion (prefer pinned solc standard JSON output where compiler version and input are available); retain the current bounded parser only as fallback/triage.
4. Extend call-graph analysis with overload-aware function identity and cross-file/import resolution.
5. Only then design a separate authorization/admission gate for fixed-block Anvil fork reproduction. Never route on-chain cases into the existing Git Foundry path by default.



---

## Continuation checkpoint — Standard JSON intake regression and focused CI

**Updated:** 2026-11-21  
**Working branch:** `feat/onchain-contract-intake`  
**Latest observed branch commit:** `bde0c7c9f0eb387d6e59f7a19828a952d7b15951`  
**PR:** [#208](https://github.com/rudimentall1/AegisForge/pull/208), OPEN, DRAFT, not merged.

### Regression found and fixed

- Found a concrete bug in `BlockscoutContractIntake._normalize_sources`: when Blockscout returned Standard JSON as a JSON-encoded string, the code parsed it into a dict but never entered the dict extraction branch. This left the source file map empty and caused valid Standard JSON contracts to be rejected as `contract_source_empty`.
- Added a regression test first in `tests/test_onchain_standard_json_provenance.py`.
- Fixed the normalizer to process the parsed dict after string decoding.
- The regression test now asserts that the Solidity source path and content are extracted from a string-encoded Standard JSON payload.

### Focused CI

- Initially added a standalone workflow, then removed it after noticing it would not be present on the PR base branch and therefore could not reliably trigger for this pull request.
- Added a separate `onchain-source-tests` job to the existing `.github/workflows/ci.yml`, which already exists on the PR base. It uses `ubuntu-24.04`, Python 3.10, compileall, and the four focused on-chain pytest files.
- The new job has not yet produced a confirmed run. Do not treat the workflow edit as verification.

### Current verification

- Standard JSON provenance test file now contains 9 test functions.
- Total authored test functions in the previously reported relevant suites: 56.
- No test has yet been executed successfully in this environment.
- The broad CI still cannot provide a usable job log or step list. The latest observed failure is infrastructure/job initialization, not an observed pytest failure.

### Next actions

1. Obtain a real run of the focused workflow and inspect its job steps/logs.
2. Fix any failures it actually reports; then run the complete repository suite.
3. Continue with pinned solc compiler AST and source maps only after the source intake and persistence tests are green.


### CI wiring correction

The standalone on-chain workflow was removed because a workflow introduced only on the PR head is not a reliable pull-request trigger when it is absent from the base branch. The focused test job now lives in the existing `.github/workflows/ci.yml` instead. This avoids creating a workflow that appears configured but never runs for PR #208.


## Latest verification update — focused job also blocked before steps

- PR head after the Standard JSON fix, focused CI job, and checkpoint update: `6865f49b09d47dc9ddb4085982521fbf76233f60`.
- Workflow run: `44892786010`.
- Both jobs (`136812006792` broad CI and `136812006657` focused on-chain job) failed before step initialization with `steps: null`.
- Retried the focused job; retry job `136812049679` also completed as failure with `steps: []`.
- No checkout, dependency install, compileall, or pytest step executed. This is still a GitHub Actions runner/job initialization failure, not a reported test failure and not a pass.
- Standard JSON string regression is fixed in source and covered by a test, but that test remains unexecuted.
- Do not begin compiler-AST implementation until this focused suite has an actual execution result. Do not merge PR #208.


## 31. On-chain worker orchestration verified — 2026-11-21

**Current implementation branch:** `fix/onchain-security-checker-offline`  
**Current implementation head:** `ce372f57fb18e1e4457fbb34904f4f734c03c8e4`  
**PR:** [#210](https://github.com/rudimentall1/AegisForge/pull/210), OPEN, DRAFT, not merged; based on `feat/onchain-contract-intake`.

### CI verification

- CI run #2435 / `44897880430` passed on the earlier compatibility-fix head: 2,046 passed, 2 skipped, 4 warnings, 30 subtests.
- Added a real SQLite-backed Worker integration test at `tests/test_worker_onchain_pipeline.py`. It runs the actual `SourceResearcher`, `CryptoAnalyst`, and `SecurityChecker` agents in sequence through `Worker.run_once()`.
- The test verifies parent/child task linkage, propagation of the immutable on-chain case ID and digest, independent structural review, and that no `lab_runner` task is created. It also fails if the on-chain SecurityChecker initializes the GitHub client.
- Tightened the on-chain SecurityChecker capability intent to `requires_filesystem=False`; all three source-analysis roles remain offline and read-only.
- Added the integration test to the existing focused CI job.
- Exact-head CI run #2439 / `44898342309` completed SUCCESS on `ce372f57fb18e1e4457fbb34904f4f734c03c8e4`.
- Focused on-chain job: **40 passed**.
- Full Python/EVM suite: **2,047 passed, 2 skipped, 4 warnings, 30 subtests passed**.
- PR #210 description updated with the exact verification results. Keep it Draft; do not merge without explicit approval.

### Verified architecture state

The non-executing on-chain path now runs end-to-end through:
`persisted OnchainTargetRecord → registered OnchainResearchCase → source_researcher → crypto_analyst → security_checker → case-bound SQLite results`.

The Git ResearchCase execution admission remains separate. On-chain source agents do not use GitHub, RPC, shell, LabRunner, or target execution. The worker integration test uses a synthetic local Solidity fixture and SQLite; it is not a live-chain test and does not prove a deployed-contract vulnerability.

### Remaining hard boundary — exploit reproduction

- Current on-chain agents produce lexical/structural leads and `POTENTIAL_RISK` patterns only. They do not confirm vulnerabilities.
- Blockscout's verified-source label plus RPC-pinned runtime-code hash does **not** prove source-to-bytecode equivalence. The intake stores source and runtime hashes independently.
- PR #207 already contains a case-bound Foundry runner and a real-EVM positive/negative reentrancy benchmark, but its `admit_target_execution()` resolves only Git `ResearchCase` records and pinned Git checkouts.
- Do not route `OnchainResearchCase` into the Git-only admission path or weaken that path. Current on-chain case validation allows only `source_pattern` and `crypto_primitive_analysis`; the queue deliberately rejects on-chain `lab_runner` tasks.
- Next engineering slice: design a separate typed `OnchainExecutionAdmission` that resolves only a persisted on-chain case/target, enforces a fresh reviewed scope and explicit authorization, pins the block hash, and refuses execution until compiler-backed source/runtime equivalence is established or the result is explicitly labelled source-only. Then reuse the existing fixed-profile Foundry runner with positive and negative controls in the isolated environment. Preserve `NOT_RUN`, `INCONCLUSIVE`, and `SOURCE_ONLY` states; a passing local harness alone must not mark a deployed vulnerability confirmed.

### Do not claim

- No live contract has been autonomously discovered and proven vulnerable by this pipeline.
- No source-to-runtime equivalence has been established.
- No on-chain exploit or transaction has been executed.
- No PR has been merged.
