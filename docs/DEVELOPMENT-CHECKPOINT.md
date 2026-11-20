# AegisForge Development Checkpoint

Updated: 2026-11-20

## Active workstream

- Repository: `rudimentall1/AegisForge`
- Pull request: [#206](https://github.com/rudimentall1/AegisForge/pull/206)
- Head branch: `feat/anvil-fork-research-engine`
- Base branch: `feat/aegisforge-working-state-2026-11-18`
- Required PR state: **Draft, open, not merged**
- Current focus: evidence-grade isolation for the disposable Anvil fork runtime.

## Current implementation state

1. Hash-pinned EVM fork snapshots bind chain ID, exact block number/hash, contract address, and runtime bytecode hash.
2. RPC Gateway and Adapter provide a constrained read-only upstream RPC path.
3. Compose topology places Gateway on internal + egress networks; Adapter and Anvil are attached only to the internal network.
4. Compose resolver and validator check effective static configuration without starting containers.
5. Runtime evidence collector inspects Docker containers, network attachments, hardening settings, and nftables table presence.
6. The collector deliberately reports only `RUNTIME_OBSERVATIONS_VALIDATED`. It does **not** prove packet flow and keeps `runtime_isolation_verified=false`, `dynamic_verified=false`, and `confirmed=false`.
7. A namespace-level nftables packet-path test checks approved HTTPS, denied IP/port traffic, and internal RPC behavior.
8. A disposable Docker Compose integration test checks real network membership, Gateway default route, internal RPC paths, and egress isolation.

## Latest change in this checkpoint

The Docker Compose integration test now:
- creates the networks and containers before starting services;
- installs the dedicated egress firewall before the dual-homed Gateway is started (only in the explicitly enabled GitHub-hosted-runner test mode);
- starts the stack after the firewall is installed;
- checks that Adapter and Anvil have no default route and cannot establish an external connection.

This ordering matches the documented deployment safety sequence and closes the test's previous firewall-installation timing gap.

## Verification status

- No VPS or production host has been used.
- No production assets, wallets, or live transactions are involved.
- The new Docker integration assertions have **not** been confirmed by a successful workflow run yet.
- Previous workflow attempts on earlier commits reported failure, but GitHub returned jobs with `steps: null` and no usable logs. Their underlying failure cause is unknown; do not infer that the new tests failed.
- Do not describe synthetic fixtures, static Compose validation, Docker inspect output, or namespace tests as a completed production E2E validation.
- Do not promote any finding to dynamically verified or confirmed based on these artifacts.

## Safety invariants

- Keep PR #206 Draft, open, and unmerged.
- Do not change the PR base branch.
- Do not run Docker/Compose or firewall commands on a VPS or production machine.
- Do not modify protected doctrine or policy files without explicit authorization.
- Keep the networkless sandbox behavior unchanged.
- Keep `dynamic_verified=false` and `confirmed=false` until finding-specific fork execution evidence is validated by the SecurityChecker pipeline.
- Never claim that firewall isolation is verified from the presence of an nftables table alone.

## Next steps

1. Inspect the CI run triggered by the latest test change; obtain real step output before diagnosing failures.
2. If the Docker integration job passes, retain its evidence and extend the runtime receipt to bind the observed packet-path probe to the exact container IDs, network IDs, firewall ruleset identity, and runtime session.
3. If it fails, isolate the failing command/assertion from logs and add a focused regression test before changing implementation.
4. Add explicit packet-path probes for the Gateway's approved and denied egress, and for Adapter/Anvil external egress, only inside the disposable GitHub-hosted environment.
5. Only after evidence is complete should a separate design step consider a distinct `RUNTIME_ISOLATION_VERIFIED` state. Do not infer or set it now.

## Checkpoint discipline

Update this file after each substantive repository change or verification milestone. Record the exact head commit, workflow run IDs/conclusions, and any unverified assumptions. Keep facts, hypotheses, and next actions separate.


## Latest review update — 2026-11-20

Implementation commit: `de54875db60d92aefcf75645e4cfc37915abad5c`.

A review of the Docker runtime test found that its Anvil probes invoked Python inside the official Foundry container, although that image is not guaranteed to include Python. The test now uses the Foundry container's Bash TCP device for Anvil-to-Adapter and Anvil-to-external connection probes, and checks the Anvil route table with `awk`. Python probes remain limited to the Python sidecar. This removes an invalid test-environment assumption; it is not yet a passing runtime result.

Workflow observations:
- Runs `44710108854` (Foundry runner integration) and `44710108982` (AegisForge CI), triggered by an earlier test commit, both concluded `failure`.
- The jobs endpoint returned no step summaries; the dedicated step endpoint returned empty arrays, and the log download returned `BlobNotFound`.
- These failures cannot be attributed to a specific test or command. No blind rerun was started.
- No workflow result has yet been observed for implementation commit `de54875...`.

The test now installs the firewall after Compose creates the network/containers but before `compose up` starts the Gateway. The integration test still needs a successful GitHub-hosted Docker run before its packet-path assertions can be treated as verified.


## CI refresh — 2026-11-20

The implementation commit `de54875db60d92aefcf75645e4cfc37915abad5c` produced:
- Foundry runner integration run `44710310036`: `failure`.
- AegisForge CI run `44710309999`: `failure`.

The checkpoint-document commit `6621ad264b21ee6499dfaff94990805f7dd5daf3` produced:
- Foundry runner integration run `44710338021`: `failure`.
- AegisForge CI run `44710338004`: `failure`.

For these attempts, GitHub again returned empty job-step summaries; log downloads returned `BlobNotFound`. The combined commit status endpoint also returned no status entries. The failure cause remains **unknown**. No test-level diagnosis is supported, and no rerun was initiated.

Latest known repository facts at this checkpoint:
- PR #206 remains listed as open; its description still identifies it as a Draft PR.
- The PR comparison is 237 commits ahead and 0 behind its base, with 34 changed files.
- The protected doctrine files checked in this cycle are not among the changed files.
- The implementation changes remain unverified by an accessible successful CI result.


## Foundry probe portability correction — 2026-11-20

Implementation commit: `e9f83ac670002e530581fc47f54aa420e3ad4e2d`.

A second review removed the Bash dependency as well as the Python dependency from the Foundry runtime checks. The Anvil container's route table is now read with `cat /proc/net/route` and parsed by the host-side pytest process. The test no longer assumes Bash, Python, curl, or netcat exists in the official Foundry image. The Adapter sidecar retains Python-based route and failed-connect checks. The namespace-level packet-path test remains responsible for the Anvil-to-Adapter TCP probe.

This is a test portability correction only. It does not establish a passing Docker run or promote the runtime evidence state. The Docker runtime integration still requires a successful GitHub-hosted workflow result.


## Latest CI observation — 2026-11-20

Implementation commit `e9f83ac670002e530581fc47f54aa420e3ad4e2d` produced:
- Foundry runner integration run `44710514921`: `failure`.
- AegisForge CI run `44710514942`: `failure`.

The integration job again has `steps: null`; the dedicated step endpoint returned no usable step details, and downloading the job log returned `BlobNotFound`. The failure remains undiagnosed. The checkpoint-only commit `5aa9bf49fc73e4459927bdcb6d20359ede695c81` has no associated workflow runs in the commit-runs response at the time of this update.

Do not claim that the probe portability correction fixed CI. The next engineering action is to obtain usable Actions logs or reproduce the failing workflow in an authorized disposable CI environment; do not repeatedly rerun jobs whose logs are unavailable.


## Anvil + Adapter container-level isolation probes — 2026-11-20

Implementation commit: `e53a2c7074d45ce8c61657497484869353b6ed0e`.

The Compose integration test fixture explicitly replaces the Anvil service image with the same digest-pinned Python sidecar image used for the test Adapter. The previous test did not take advantage of that fixture contract: it checked Anvil's route table but performed an external failed-connect probe only from Adapter, and it did not exercise Anvil-to-Adapter TCP in the real Docker topology.

The test now performs, from the Anvil container namespace:
- a real TCP connection to `anvil-rpc-adapter:8546`;
- a default-route absence assertion;
- a real failed TCP connection attempt to `8.8.8.8:443`.

The Adapter retains its real Gateway TCP connection, default-route assertion, and failed external connection probe. These are integration-test assertions only; they do not imply a successful run. The fixture contract was checked in the repository: Anvil is overridden to the digest-pinned Python image, so these probes do not depend on Python being present in the production Foundry image.

CI status for this new implementation commit is pending observation. No test was run locally or on a server. No runtime state was promoted.


## Packet Path Evidence Receipt — schema and validator stage — 2026-11-20

Test contract commit: `d94a493b083868358e18c16005632ca353c1332d`.
Validator implementation commit: `cf46f255fe0ea756c6e8a030c4f9a4b4f22e9197`.
Validator hardening commits: `ebfeacdacc2e7b2e34ba8b4b0406e092947daa73` and `bf6ce37ae45c02bd12e45a14973fdfef3749f3c0`.

Added:
- `tests/test_packet_path_evidence.py`: receipt contract tests for exact service/probe inventory, UUID session identity, commit/run binding, container/network IDs, firewall ruleset digest, positive nftables counter deltas, and required probe outcomes.
- `agents/security_checker/packet_path_evidence.py`: fail-closed validator for the disposable Docker packet-path receipt.
- The validator binds evidence to the expected Git commit, GitHub Actions run ID, and run attempt.
- The validator requires distinct full container/network IDs, a SHA-256 ruleset identity, increasing allow/drop counters, and all six required probe observations.
- The report is explicitly limited to `PACKET_PATH_RECEIPT_VALIDATED`; it always keeps `runtime_isolation_verified=false`, `dynamic_verified=false`, and `confirmed=false`.

Important scope limitation:
- This is the receipt schema and validation layer only. The Docker integration test does not yet emit this receipt, the workflow does not yet upload it, and no receipt has been observed from a real CI run.
- The tests were authored and committed but have not been executed in this environment. No passing test or CI result is claimed.
- This receipt is not yet connected to a finding-specific Anvil fork execution and cannot promote a vulnerability finding.

CI observations:
- The latest observed runs associated with the earlier checkpoint commit `e994b4da7aa82d83009b177c04485d17144596fe` were AegisForge CI run `44712559237` and Foundry runner integration run `44712559105`; both concluded `failure`.
- Their job summaries exposed `steps: null` and no usable log URL. The failure cause remains unknown and is not attributed to the new receipt code.
- No workflow runs were returned for the latest validator hardening commit `bf6ce37ae45c02bd12e45a14973fdfef3749f3c0` at checkpoint time. No blind rerun was started.

Repository state at this checkpoint:
- PR #206 remains open; its description identifies it as a Draft PR. Do not merge or change its base.
- Head branch: `feat/anvil-fork-research-engine`.
- Base branch: `feat/aegisforge-working-state-2026-11-18`.
- Compare: 247 commits ahead, 0 behind, 36 changed files.
- No protected doctrine/policy file was changed in this stage.
- No VPS, production host, wallet, or live asset was used.

Next implementation stage:
1. Instrument the disposable Docker Compose test to capture the runtime session ID, actual container IDs, Docker network IDs, canonical nftables ruleset SHA-256, counter snapshots, and probe outcomes.
2. Ensure receipt values are captured from observed runtime state only; do not synthesize successful results.
3. Write the receipt to a temporary CI artifact path and upload it only from the disposable GitHub-hosted integration job.
4. Add a test that validates the generated artifact against `GITHUB_SHA`, `GITHUB_RUN_ID`, and `GITHUB_RUN_ATTEMPT`.
5. Keep all finding/runtime promotion flags false until a separate finding-specific evidence design is implemented and verified.


## Receipt contract test alignment — 2026-11-20

Test correction commit: `4d5ebc69bcfdea62db9cab63edcb31d923fd910d`.

The missing-session-field test now expects the schema-level rejection emitted by the validator (the required-field inventory is checked before UUID semantics). This aligns the test with the fail-closed validation order; no production behavior or security state changed.

Latest repository check:
- PR #206 is still open; its PR description still identifies it as Draft.
- Branch comparison: 249 commits ahead, 0 behind, 36 changed files.
- No workflow runs were returned for commit `4d5ebc69bcfdea62db9cab63edcb31d923fd910d` at the time of this check.
- The receipt tests remain unexecuted here. No green CI result is claimed.
- No protected doctrine/policy files were changed.


## Disposable Docker Packet Path Receipt — runtime emission and CI artifact wiring — 2026-11-20

Implementation commits:
- Dynamic Compose project binding in the receipt validator: `49453c9d60d0cdca14537d058a5dafe0deec9b95`, `1e8a675645bbc78dd9a385fb1d5f9b14bf4853f1`, `c1b9f333ee7e5acded40442a9349e51782b2a208`.
- Runtime packet-path receipt capture: `370055fcfdf2f64a6ce9b159b300c346f2bfbfcb`, `4697d40fb47b761dc0e08460fe4ba06b7a465a83`, `294e910bb118e8c2934fd311a74daf28c8adc697`, `d86de207e44d76bc69a6b6e46d68027489128698`.
- Validator/test contract refinements: `8de5d300a04e94c7e09fda75830ef731421420b8`, `2ca905f4d9d6901352fbf5bd269ee387ef77f4ef`, `da7c626ab88dd6db062bf84c11ecd7c107291bef`.
- CI artifact and workflow path/test wiring: `7f9f12c5d88975ce99f69305bdca762adfc3b8b6`, `22db9a743003c0de667b01eea095f33eeae3ee0d`.

The disposable Docker Compose integration test now, when and only when `AEGISFORGE_DOCKER_FIREWALL_RUNTIME=1` on a GitHub-hosted runner:
- captures the unique Compose project name and actual full container/network IDs;
- computes a canonical SHA-256 digest of the live nftables JSON ruleset with volatile counter expressions excluded (counter values are recorded separately);
- records before/after packet counters for the approved Gateway allow rule and unapproved Gateway drop rule;
- records observed TCP outcomes for approved Gateway egress, denied Gateway egress, Adapter-to-Gateway, Anvil-to-Adapter, and external egress attempts from Adapter and Anvil;
- records observed default-route absence and Docker internal-only network membership for Adapter and Anvil;
- binds the JSON receipt to `GITHUB_SHA`, `GITHUB_RUN_ID`, and `GITHUB_RUN_ATTEMPT`;
- validates the receipt in the same test process and writes it to the configured runner-temp path only after all required assertions pass.

The validator binds network names to the actual unique Compose project name, rather than assuming a fixed project name. This matches the disposable integration test's per-run Compose namespace.

The Foundry integration workflow now:
- includes the packet receipt validator and tests in path filters and the focused test command;
- configures a runner-temp receipt path for the Docker integration step;
- uploads the receipt as a 14-day Actions artifact when one exists. The upload step is `always()` so a receipt created before a later test/job failure is still retained; missing receipts are ignored rather than fabricated.

Evidence limitations:
- No receipt has yet been emitted by a successful GitHub-hosted Docker run.
- The runtime receipt is created only after all Docker and nftables assertions succeed. A failed or skipped integration test produces no receipt.
- Approved egress records both whether the TCP handshake connected and whether the specific nftables allow counter increased. A successful handshake is not required because the test target is an external IP without a guaranteed listener.
- Denied egress requires both a failed TCP connection and a positive nftables drop-counter delta.
- The receipt validator checks structure and CI bindings; it does not independently re-run probes or establish finding-specific exploit validation.
- The receipt does not promote `runtime_isolation_verified`, `dynamic_verified`, or `confirmed`; all remain false.
- Tests have not been executed in this authoring environment. No green CI result is claimed.

CI observations:
- Earlier checkpoint commit `a8d5b516ce0d8f4e223b376b4424b2ce3a333d0a` produced Foundry integration run `44714787040` and AegisForge CI run `44714787046`; both concluded `failure`.
- The Foundry job endpoint returned `steps: null` and no log URL. The failure cause is unknown and is not attributed to the receipt changes.
- Receipt implementation commit `d86de207e44d76bc69a6b6e46d68027489128698` produced Foundry integration run `44716547824` and AegisForge CI run `44716547873`; both concluded `failure`.
- Both job summaries returned `steps: null`; both job-log downloads returned `BlobNotFound`. The artifact listing for Foundry run `44716547824` was empty. The failure cause and whether the test reached receipt emission are unknown.
- No blind rerun was started.

Repository state:
- PR #206 remains open and Draft; not merged.
- Head: `feat/anvil-fork-research-engine`; latest implementation commit `d86de207e44d76bc69a6b6e46d68027489128698`; latest checkpoint commit `2323bf104f2650a044966d498883b00466edfec6`.
- Base: `feat/aegisforge-working-state-2026-11-18`.
- Compare: 265 commits ahead, 0 behind, 36 changed files.
- Protected doctrine/policy files remain untouched.
- No VPS, production host, wallet, live transaction, or production asset was used.

Next steps:
1. Obtain a new CI result for the receipt-emission commit and inspect real job logs/artifact metadata.
2. If the Docker job succeeds, download/inspect the Actions receipt and independently validate its commit/run binding, IDs, ruleset digest, counter deltas, and probe outcomes.
3. If the job fails, use actual step logs to isolate the failing assertion; do not diagnose from a missing artifact alone.
4. Only after the receipt has been observed and independently reviewed should we design any integration into the finding-specific SecurityChecker evidence chain. Do not change confirmation flags in this stage.


## TCP probe source and receipt serialization correction — 2026-11-20

Regression-test commit: `ae0118eecefd0f0f725297567d24d13fa9a5db7e`.
Implementation commit: `c14a2f680c2d6ba513ceb746a146905dae889944`.

Static review of the newly added Docker packet-path receipt code found a concrete source-generation defect:
- The TCP probe passed to `docker exec ... python -c` contained escaped backslash-n sequences rather than actual line breaks. The in-container Python interpreter would receive invalid source instead of the intended multi-line probe.
- The receipt writer likewise appended a literal backslash-n sequence instead of a newline character.

Correction:
- Added `_docker_tcp_probe_script()` as a dedicated source builder.
- Added a regression test that compiles the generated probe source, so malformed Python source is rejected before any Docker integration test is attempted.
- Replaced the escaped sequence with real newline escapes in the Python string literals.
- Corrected receipt serialization to end with an actual newline.

Verification:
- The generated probe source was independently compiled with Python in this authoring session: compilation succeeded and the source contains the expected line breaks.
- The repository pytest regression test has **not** been executed here. No test pass or Docker runtime pass is claimed.
- No successful workflow run or receipt artifact has been observed for commit `c14a2f680c2d6ba513ceb746a146905dae889944` at checkpoint time.
- Latest known CI runs on the preceding head `01efad6b40ba3b0ed049429c5611a6c335f6c8ae`: Foundry integration `44716836713` and AegisForge CI `44716836727`, both `failure`; both job summaries had `steps: null`. Their failure cause remains unknown.

Repository state:
- PR #206 remains open, Draft, and unmerged.
- Base remains `feat/aegisforge-working-state-2026-11-18`.
- Latest head: `c14a2f680c2d6ba513ceb746a146905dae889944`.
- The two commits in this correction stage put the branch 268 commits ahead and 0 behind the base.
- No protected doctrine/policy files were changed.
- No VPS, production host, wallet, or live asset was used.

Next steps:
1. Inspect CI runs for the corrected head and obtain step logs if GitHub exposes them.
2. Run the focused regression and packet receipt tests in CI; do not infer success from source inspection.
3. If Docker integration succeeds, inspect the uploaded receipt and independently validate its bindings and observed packet counters.
4. Keep `runtime_isolation_verified`, `dynamic_verified`, and `confirmed` false until the separate evidence chain is independently established.

## CI failure refresh and SecurityChecker integration boundary — 2026-11-20

Repository state:
- PR #206 remains open, Draft, and unmerged.
- Head branch: `feat/anvil-fork-research-engine`.
- Head SHA at review: `38a0a69f5d33a504113253906daec2de22474cc9`.
- Base remains `feat/aegisforge-working-state-2026-11-18`.
- PR metadata reports 269 commits ahead, 0 behind, and 36 changed files.
- No protected doctrine/policy files were changed.

CI observation for the current head:
- Foundry runner integration run `44717347331`: completed with `failure`; job `136224007235`.
- AegisForge CI run `44717347308`: completed with `failure`; job `136224006955`.
- Both jobs endpoints returned job summaries without usable step details; the dedicated step endpoints returned empty arrays.
- Both log downloads returned GitHub `BlobNotFound`.
- Both run artifact listings were empty. No packet-path receipt artifact is available.
- The failure cause, failing step, and whether the Docker test reached receipt emission remain unknown. No blind rerun was started; no test pass is claimed.

SecurityChecker integration audit:
- `agents/security_checker/anvil_fork_runner.py` contains a synthetic, networkless Anvil/Foundry smoke runner. Its result explicitly remains synthetic and keeps `dynamic_verified=false` and `confirmed=false`.
- `agents/security_checker/fork_runtime_orchestrator.py` validates a fork plan and Compose topology and returns a preparation-only object; it does not start the runtime.
- `agents/security_checker/packet_path_evidence.py` validates the disposable Docker packet-path receipt against a commit SHA, GitHub run ID, and attempt. It validates structure/bindings only and does not establish a finding-specific exploit.
- `agents/security_checker/agent.py` still invokes `_run_foundry_fork_validation` for findings, but that method unconditionally returns `SKIPPED` with reason `isolated_fork_runner_not_configured`. The message is now stale: runner/preparation components exist, but there is no finding-specific execution-and-evidence binding path connected to SecurityChecker.
- Do not simply invoke the synthetic smoke runner for production findings: it deploys a synthetic target and proves runner mechanics, not exploitability of a repository finding.
- Do not connect the packet-path receipt to finding promotion. It proves only the declared disposable CI network probes and remains a separate infrastructure-evidence class.

Next engineering sequence:
1. Obtain accessible CI step logs or reproduce the failing workflow in an authorized disposable CI environment; do not infer the cause from missing artifacts.
2. Correct the SecurityChecker skip reason and add regression coverage before any runner integration, so API/status output accurately distinguishes “runner unavailable” from “finding-specific validation not implemented.” Keep all confirmation flags false.
3. Design a separate finding-specific execution contract: immutable source/snapshot binding, normalized finding identity, exact fork block/hash, exploit preconditions, bounded test payload, isolated runtime identity, execution transcript, and independent result validation.
4. Only after that contract has tests and real evidence should SecurityChecker consume the result. A generic Anvil smoke pass or packet-path receipt must never confirm a finding.

No VPS, production host, real wallet, live transaction, or production asset was used.

## SecurityChecker validation status clarification — 2026-11-20

Implementation commits:
- Regression contract first: `4d4c47113c214f02927bfd926be03254dcb2fa62`.
- Minimal implementation: `da622f5ce85b7e74e8f59f1c52ec979edec29ce4`.

Change:
- `dynamic_validation_status` now reports `FINDING_SPECIFIC_VALIDATION_NOT_IMPLEMENTED` when findings require dynamic validation.
- Per-finding results remain `SKIPPED`, but the reason now accurately reports `finding_specific_execution_not_integrated`.
- The required next step is `implement_finding_specific_fork_execution`.
- Low-severity findings remain outside this dynamic-validation result list, as before.
- `dynamic_verified=false` and `confirmed=false` remain unchanged.

Why this matters:
- The synthetic networkless Anvil smoke runner exists, and the runtime orchestrator can prepare/validate a Compose plan, but neither executes a finding-specific exploit test.
- The old reason `isolated_fork_runner_not_configured` incorrectly implied that no runner component existed. The new status distinguishes available infrastructure components from the missing finding-specific execution/evidence integration.
- No synthetic smoke result or packet-path receipt is promoted into finding confirmation.

Verification:
- Re-fetched both changed source/test files from the branch and statically checked the new status, reason, next-step field, regression assertions, and absence of the stale reason.
- The pytest regression test was not executed in this session. No test pass is claimed.
- CI has not yet been assessed for the new implementation commit at checkpoint time.

Next:
1. Obtain a usable focused-test CI result; if logs are unavailable, do not infer a cause or blindly rerun.
2. Specify and test a finding-specific execution contract bound to immutable source, normalized finding identity, pinned chain/block hash, exploit preconditions, bounded test payload, runtime identity, transcript, and independent validation.
3. Keep all runtime and finding confirmation flags false until real finding-specific evidence is independently verified.

PR #206 remains Draft, open, and unmerged. Base branch unchanged. No protected doctrine/policy files were modified. No VPS or production environment was used.


## Finding-specific execution request contract — 2026-11-20

Implementation commits:
- Request contract regression tests first: `b14bd07c7251bdbbb67ea42e8d08d9875c5e6b5f`.
- Contract implementation: `191698b979b1f4a968007b23929af0179878ba7e`.
- Malformed-type validation hardening: `6a467d84f06fe5384900bbcfdbe20c9b6021326b`.

Added:
- `tests/test_finding_execution_contract.py`: deterministic identity, snapshot/plan binding, exploit-test allowlist, bounded preconditions, and confirmation-flag tamper tests.
- `agents/security_checker/finding_execution_contract.py`: pure request builder/validator. It introduces no runtime execution, shell invocation, RPC call, or transaction submission.
- Stable `finding_id` is derived from repository, commit SHA, source-tree digest, detector ID, source location, and target contract address.
- Request binds to the existing validated fork plan and snapshot digest, including source chain, fork chain, exact block number/hash, contract address, and runtime bytecode digest.
- Exploit artifacts are restricted to repository-owned `tests/fork_exploits/<slug>.t.sol` paths and a SHA-256 digest. Arbitrary paths, shell commands, and caller-selected runtime endpoints are not part of the contract.
- Preconditions use a small typed vocabulary with strict value bounds and a maximum of 16 entries.
- Execution policy caps timeout at 300 seconds and steps at 100,000; external network access and external transactions are explicitly disabled.
- Validation recomputes the complete request and rejects unknown fields, changed bindings, policy overrides, or promotion of `dynamic_verified`/`confirmed`.

Scope and limitations:
- This is a request-contract layer only. It does not prove that the referenced source tree or test artifact bytes were fetched and hashed by a trusted runner; the caller-supplied digests must be bound to a later immutable checkout/artifact verification stage.
- It does not execute the allowlisted Foundry test, collect an execution transcript, authenticate runtime provenance, or independently validate exploit results.
- It is not connected to SecurityChecker's finding pipeline yet.
- No status can be promoted: `dynamic_verified=false` and `confirmed=false` remain invariant.
- The new pytest tests were authored before implementation, but were not executed in this environment. No test pass is claimed.
- No Docker runtime, real RPC provider, wallet, live transaction, VPS, or production asset was used.

CI observation:
- Current pre-change head `986aa71c27baabf442583c2af1a966fc484bd50a` produced Foundry integration run `44721873135` and AegisForge CI run `44721873143`; both concluded `failure`.
- Job summaries returned `steps: null`; step endpoints returned empty arrays; log downloads returned `BlobNotFound`. The failure cause remains unknown. No blind rerun was started.
- CI for the new contract commits has not yet been assessed.

Repository state at checkpoint:
- PR #206 remains open, Draft, and unmerged.
- Head branch: `feat/anvil-fork-research-engine`.
- Base remains `feat/aegisforge-working-state-2026-11-18`.
- Protected doctrine/policy files were not modified.

Next:
1. Add a separately validated execution-receipt contract bound to the request digest, observed runtime identity, workflow provenance, test artifact digest, and transcript digest.
2. Require an independent validator observation; do not accept self-asserted result fields as proof.
3. Verify source-tree and exploit-test bytes against the immutable commit before runtime execution.
4. Only then design the narrow runner adapter and SecurityChecker consumption path. Keep all confirmation flags false until actual finding-specific execution and independent evidence validation exist.
