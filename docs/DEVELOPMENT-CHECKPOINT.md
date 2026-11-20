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
