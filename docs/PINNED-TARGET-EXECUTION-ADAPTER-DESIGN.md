# Pinned-target execution adapter — design decision

**Status:** proposed; not implemented  
**Date:** 2026-11-14  
**Parent:** PR #196 / release gate #158  
**Decision owner:** AegisForge maintainers

## 1. Purpose

Add a separately reviewable execution boundary for an explicitly authorized, immutable EVM Research Case. The adapter must run a fixed set of security tools against the exact case-pinned source revision, capture attributable raw evidence, and persist it through the existing local-experiment model.

This is not permission to run arbitrary commands from a case, agent, repository file, or evidence bundle.

## 2. Non-goals

- General-purpose shell, terminal, CI runner, or remote code execution API.
- Automatic execution of bundle-provided `argv`, scripts, Makefiles, package hooks, or agent-generated commands.
- Live-chain transactions, wallet access, production RPC credentials, or deployment.
- Automatic vulnerability confirmation from tool exit codes or static-analysis findings.
- Installing dependencies from the target repository during the experiment.
- Treating Bubblewrap alone as a hostile-code security boundary on a shared production host.

## 3. Trust boundaries and threat model

Treat all target repository files, Solidity tests, Foundry configuration, remappings, dependency metadata, compiler inputs, tool output, and model-generated hypotheses as untrusted.

The runner must assume a target can attempt to:
- read host files or environment secrets;
- access the network or local metadata services;
- write outside its workspace;
- exhaust CPU, memory, disk, process count, file descriptors, or output storage;
- exploit the compiler, test runner, native dependencies, or kernel;
- falsify its own logs or produce misleading test outcomes.

A process sandbox is not a complete defense against kernel or hypervisor vulnerabilities. The production trust boundary for hostile public repositories should be a disposable, isolated VM/microVM with no host credentials and no shared writable mounts. A same-kernel Bubblewrap profile may be used only for local development or explicitly lower-assurance execution and must be labelled accordingly. Do not market it as equivalent to a VM boundary.

## 4. Immutable case admission

Before provisioning an executor, validate the registered Research Case from the authoritative case store, not from caller-supplied JSON:

1. Case status is READY and authorization/scope fields are complete.
2. Repository identity matches a strict `owner/repo` allowlist and the case's immutable target.
3. Target commit is a full 40-character Git SHA and resolves to a commit in the selected repository.
4. Scope digest and reviewed date match the registered case.
5. Execution mode explicitly permits local isolated EVM analysis.
6. The selected experiment is bound to the case ID, runtime round ID, planned RoundSpec ID, and task ID.
7. No secrets, private keys, wallet files, or production RPC credentials are made available to the executor.

Fail closed on missing or inconsistent identity. Do not silently substitute the default branch, a tag, or a newer commit.

## 5. Source materialization

- Fetch source outside the execution boundary using a read-only source acquisition component.
- Resolve and verify the exact requested commit SHA before materialization.
- Materialize a clean checkout or archive for that commit; do not execute repository hooks during acquisition.
- Disable submodule recursion by default. If a case explicitly requires submodules, pin each submodule URL and commit in the case manifest and validate before fetching.
- Do not run `npm install`, `forge install`, package lifecycle scripts, or any dependency resolver against the public network inside the runner.
- Record repository URL, commit SHA, tree SHA, submodule policy, source archive digest, and acquisition timestamp.
- Mount source read-only in the executor. Use a separate bounded writable output directory.

## 6. Fixed tool adapters

The first supported profile is intentionally narrow:

### Foundry adapter

- Invoke only a configured, pinned `forge` executable with a fixed argument template.
- First command: `forge test --offline --no-auto-detect` (confirm exact CLI support against the pinned Foundry release before implementation).
- Run from the pinned project root with a generated, controlled Foundry configuration overlay.
- Force `ffi = false`; deny filesystem permissions by default; disable RPC endpoints and fork URLs; do not load secrets from `.env`.
- Do not allow target configuration to override executor-owned security settings.
- Do not run `forge script`, `forge deploy`, `cast send`, or arbitrary user-supplied scripts.
- If the repository needs unavailable dependencies or compiler downloads, return `NOT_RUN` with a precise reason. Never enable network as an automatic fallback.

### Slither adapter

- Invoke only a configured, pinned `slither` executable with a fixed argument template.
- Pin and record Slither, Python runtime, solc, and relevant dependency versions.
- Use a pre-provisioned compiler/toolchain image. No runtime package installation.
- Capture Slither JSON output and stderr as raw artifacts. Preserve detector IDs, source locations, and tool version; do not convert warnings into confirmed findings.
- Treat parser/compiler failure as `FAIL` or `NOT_RUN`, not as a clean scan.

Tool versions and image digests must be explicit configuration, not floating `latest` tags. Verify current tool CLI flags and licenses before implementation and distribution.

## 7. Executor contract

The executor accepts a typed request, not a command string:

- `case_id`
- `round_id`
- `round_spec_id`
- `task_id`
- `target_repository`
- `target_commit`
- `adapter_id` from a fixed enum
- `profile_id` from a fixed enum
- bounded timeout and resource profile selected from server-side policy

The executor must not accept arbitrary `argv`, shell fragments, executable paths, environment variables, mount paths, or network settings from the request.

Enforced controls:
- no network namespace connectivity, including loopback unless explicitly required by a reviewed profile;
- no host filesystem mounts other than immutable runtime/toolchain inputs;
- source mounted read-only;
- output mounted as a separate bounded writable volume;
- no inherited environment; explicit minimal allowlist;
- no credentials or host sockets;
- CPU, memory, process-count, file-size, disk, wall-clock, and open-file limits;
- bounded stdout/stderr and total artifact size;
- process-group termination on timeout;
- deterministic cleanup of executor and scratch storage;
- fixed working directory and fixed executable paths;
- explicit toolchain and image digest recorded in the experiment.

If a required control cannot be established and verified, execution is rejected before target code starts.

## 8. Evidence lifecycle

For each adapter invocation, record through the existing `build_experiment_record` and `EvidenceLedger.record_local_experiment` path:

- case, runtime round, planned round, task, repository and full commit identity;
- source tree/archive digest;
- adapter ID and fixed profile ID;
- exact executable version and immutable toolchain/image digest;
- fixed effective argument vector (metadata only);
- normalized, non-secret environment description;
- raw input, stdout, stderr, exit code and timeout state;
- resource policy and observed resource usage where available;
- explicit execution assurance level and any unavailable controls.

The bundle verifier should verify bytes and identity. It must not infer that the tool was honest, the source was safe, or a vulnerability exists.

Suggested execution assurance labels:
- `NOT_RUN`: admission or provisioning failed; target code did not start.
- `LOCAL_BWRAP_LIMITED`: same-kernel Bubblewrap profile, only for explicitly approved lower-assurance use.
- `EPHEMERAL_VM`: disposable VM boundary with verified policy.
- `INDEPENDENT_RERUN`: a second clean environment reproduced the same experiment.

These labels describe execution environment only. They are separate from experiment result and vulnerability conclusion.

## 9. Result semantics

- Foundry test process exit 0 means the configured test command completed successfully. It does not prove the case hypothesis.
- Foundry test failure may be a test failure, compilation failure, environment failure, or a real counterexample; preserve structured output and classify only after parsing and review.
- Slither findings are leads with tool/version/detector provenance, not confirmed vulnerabilities.
- Missing compiler/dependency, unsupported project layout, timeout, denied operation, or isolation failure must remain explicit `NOT_RUN`, `FAIL`, or `INCONCLUSIVE` states as appropriate.
- Only a separately reviewed causal reproduction and impact analysis may promote a hypothesis to `CONFIRMED`.

## 10. Implementation sequence and acceptance

### Stage A — contract and negative tests

- Define typed request/profile schemas and immutable case admission.
- Unit-test malformed IDs, mutable refs, missing scope, mismatched commits, unknown adapters/profiles, oversized limits, injected argv/env/mounts, and secret-bearing environment.
- Prove that no child process is started when admission fails.

### Stage B — executor prototype

- Implement the disposable execution boundary before invoking Foundry or Slither.
- Test network denial, host-file denial, read-only source, writable bounded output, resource caps, timeout kill, output caps, and cleanup using benign adversarial fixtures.
- Record actual enforcement checks and fail closed if any check is unavailable.
- Security review the executor independently before enabling target repositories.

### Stage C — one Foundry vertical slice

- Use a small, repository-owned, pinned Solidity fixture with no external dependencies.
- Run build/test offline in the executor.
- Persist raw outputs and metadata using the existing evidence path.
- Export and verify the bundle from a second clean environment.

### Stage D — Slither

- Add Slither as a separate adapter after Foundry acceptance.
- Pin toolchain and detector configuration.
- Preserve raw JSON and stderr; add parser tests and explicit no-finding vs execution-failure semantics.

### Stage E — customer validation

- Demonstrate the workflow to 2–3 boutique audit teams.
- Measure setup time, reproducibility time, review time, and false-positive triage effort.
- Do not build hosted multi-tenancy or billing until a buyer confirms the pain and budget.

## 11. Explicit release-gate mapping

This design addresses only part of issue #158. It does not close the gate until a clean checkout can execute a case-pinned target in a genuinely isolated environment, export the complete dossier, independently verify it, and pass the required adversarial failure tests.

The existing fixed-fixture Bubblewrap runner remains unchanged and fixture-only. Do not generalize it into an arbitrary command runner.

## 12. Open decisions before code

1. Which disposable VM/microVM backend is available in the target deployment and CI environment?
2. What exact pinned Foundry and Slither versions will be supported first?
3. Which Solidity project layouts are in the first supported profile?
4. What dependency vendoring policy will be used for offline runs?
5. What is the maximum per-case CPU, memory, disk, runtime, and artifact budget?

Until these are answered, a production-capable hostile-repository runner must not be implemented or advertised.


## 13. Non-executing archive extraction prototype — 2026-11-14

Implemented `shared/source_archive.py` as a pure local extraction boundary. It accepts bounded archive bytes and a server-selected destination; it performs no HTTP requests and executes no repository content.

- Enforces compressed-byte, uncompressed-byte, and regular-file limits.
- Requires one archive root; rejects absolute paths, traversal components, backslashes, NULs, duplicate paths, file/directory collisions, and multiple roots.
- Rejects symlinks, hardlinks, devices, FIFOs, sparse entries, and all non-regular non-directory members.
- Writes files with exclusive creation and no-follow where supported. Archive ownership, timestamps, and permission bits are not preserved; files receive restrictive local modes.
- Removes a partially created destination if extraction fails.
- The caller must resolve the full commit SHA and Git tree through GitHub metadata before fetching the corresponding pinned archive. This module does not prove that archive bytes correspond to a commit; that verification remains a required upstream step.
- This is not yet a source downloader, commit resolver, tree verifier, immutable artifact store, or execution sandbox. The destination parent must be server-owned and not writable by untrusted tasks.
- Tests are added in `tests/test_source_archive.py`. Await exact-head CI before treating this implementation as validated.
