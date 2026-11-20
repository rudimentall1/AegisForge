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
