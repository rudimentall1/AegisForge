# Pinned-target execution adapter — design decision

**Status:** proposed; standalone Docker reproduction prototype exists but is not accepted as the production execution boundary  
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


## 14. Pinned commit and Git tree verification — 2026-11-14

The source archive helper now includes a fail-closed verification path:

1. Require a full 40-character commit SHA supplied by the server-side admitted case.
2. Validate the GitHub commit API response: returned commit SHA must exactly match the requested SHA, and its root tree SHA must be a valid full Git object ID.
3. Extract the already-fetched tar.gz using the bounded non-executing extractor.
4. Recompute Git blob and tree object IDs from extracted regular files, including executable-bit semantics.
5. Require the computed root tree SHA to equal the pinned commit's root tree SHA. On mismatch, delete the extracted destination and fail.

The combined entry point is `extract_and_verify_pinned_github_source_archive()`. It accepts archive bytes and commit metadata; it does not fetch either. The caller must obtain metadata from the GitHub API and request the archive using the exact pinned SHA, never a branch or tag.

Important compatibility boundary: this extractor rejects symlinks, hardlinks, special files, and gitlinks/submodules. Such repositories fail closed rather than being silently altered. Supporting these requires a separately designed representation and verification path; do not weaken the rejection policy.

This still is not an HTTP downloader or a full source-acquisition service. Redirect validation, response streaming limits, API rate handling, immutable storage, and independent provenance recording remain unimplemented. No target code is executed.


## 15. Bounded allowlisted GitHub source resolver — 2026-11-15

A non-executing acquisition prototype now exists in `shared/github_source_resolver.py`.

### Enforced boundary

- Input is an `AdmittedTarget` resolved from persisted case/task/round state, plus a server-owned repository allowlist and a server-selected destination.
- Repository identity is re-authorized before network access. Empty allowlist denies all.
- Only a full immutable commit SHA from the admitted Research Case is accepted.
- Commit metadata is requested first. The returned commit SHA and root tree SHA are validated before requesting the archive.
- Archive request is constructed from the canonical allowlisted owner/repository and the exact commit SHA. No branch/tag, user URL, task URL, or agent-supplied archive location is accepted.
- HTTPS only. Redirects are limited to `api.github.com` and `codeload.github.com`, with a maximum of three. Credentials, explicit ports, and host aliases are rejected.
- Metadata and archive responses are streamed under byte limits. The resolver uses a bounded socket timeout.
- Gzip expansion is bounded into a temporary file before TAR parsing. TAR member metadata is counted incrementally. Existing path, file-count, regular-file, and payload-size restrictions still apply.
- Extracted Git blob/tree identities must reproduce the commit API root tree SHA. Any mismatch fails closed and partial extraction is removed.
- No target file is executed, no dependency is installed, and no process is spawned.

### Current limitations and non-claims

- Public GitHub repositories only; private-repository credentials are not supported.
- No API rate-limit backoff/retry, immutable artifact store, or independent provenance source.
- Socket timeout is not a strict end-to-end wall-clock deadline for a slow-drip response.
- Symlinks, hardlinks, gitlinks/submodules and special files remain unsupported and are rejected.
- Resolver is not yet wired into a worker/executor lifecycle. Destination parent ownership and immutable storage policy must be defined before integration.
- A matching Git tree proves consistency with the tree SHA returned by GitHub over TLS; it does not independently establish repository ownership, publisher identity, workflow provenance, or source trust.
- This acquisition prototype does not authorize execution. The VM/microVM execution boundary and pinned toolchain remain unresolved.

Exact-head CI for the current resolver and archive defenses: 1,869 tests passed, 4 warnings, 30 subtests passed; Bubblewrap fixture acceptance PASS (2026-11-15, CI run #1668). This is unit/CI validation only, not full issue #158 acceptance.


## 16. Review of the existing Docker reproduction prototype — 2026-11-15

The branch contains `shared/reproduction_contract.py` and `shared/reproduction_runner.py`. This is a real, explicitly invoked Docker prototype, not merely a design sketch. It must not be confused with the fixed Bubblewrap fixture runner or treated as an accepted hostile-repository executor.

### What the prototype already enforces

- Requires a locally available image referenced by a SHA-256 digest and uses `--pull=never`.
- Refuses execution when Docker is unavailable, when the host identity is root, or when POSIX UID/GID support is unavailable.
- Copies the pinned Git worktree into a temporary workspace and checks file blobs against the requested commit tree.
- Mounts source read-only; disables network and IPC; uses a read-only container root, drops capabilities, enables `no-new-privileges`, sets PID, CPU, memory, memory+swap, and output tmpfs limits.
- Does not inherit the host process environment; passes only contract-declared environment values.
- Collects outputs only after a confirmed container stop, validates exact output paths and SHA-256 digests, and requires container cleanup to succeed for a successful result.
- Does not change the finding verdict; its result is an execution result only.

### Why it is not yet an approved target runner

1. The contract accepts arbitrary argv and environment values (with sensitive variable names blocked). That is acceptable only as a low-level prototype input, not as the product API. The public execution API must accept a server-authorized task ID plus a fixed adapter/profile enum; it must construct argv and environment internally.
2. The contract does not bind itself to the authoritative Research Case store, task ID, runtime round ID, or planned RoundSpec ID. The separate admission gate exists, but the reviewed runtime entrypoints do not wire that gate into this runner.
3. Docker shares the host kernel. Default Docker seccomp behavior and these container flags are useful defense-in-depth, but they do not meet the design requirement for a disposable VM/microVM boundary against hostile public repositories.
4. The runner verifies a digest-form image reference syntactically and relies on Docker's digest-qualified image resolution with `--pull=never`; it does not independently attest the daemon/runtime or host configuration.
5. The current tests mock Docker and Git. They validate command construction and state handling, not actual host/network isolation or resistance to a kernel/container escape.

### Decision

- Keep this prototype isolated and explicitly opt-in. Do not wire it into the worker, API, orchestrator, or public CLI.
- Do not execute target repositories through `shared.sandbox.run_in_sandbox`; its process mode is not a security boundary and its Docker mode is weaker than this prototype.
- Before enabling any untrusted target execution: integrate persisted case/task/round admission, replace arbitrary request-supplied argv/env with fixed server-owned adapter profiles, select and verify a disposable VM/microVM backend, and add real adversarial host-isolation acceptance on the deployment runner.
- Until those conditions pass, the supported execution path remains the repository-owned synthetic fixture. Issue #158 remains OPEN.

## 17. Firecracker backend decision and host preflight — 2026-11-22

### Decision

Select **Firecracker microVM + its matching Jailer** as the first production-boundary candidate for hostile public Solidity harnesses. Do not treat the current Docker runner as an equivalent fallback.

Rationale:
- Firecracker provides a KVM-backed guest-kernel boundary; its own threat model treats guest vCPU code as malicious and layers host-side seccomp, cgroups, namespaces and privilege dropping around the VMM.
- Production guidance requires using the matching Jailer (or an equally restrictive process boundary), retaining Firecracker's default seccomp filters, and keeping host/guest kernels and host microcode patched.
- The microVM must have no network interface for this profile. Source and toolchain inputs are immutable/read-only; output is a separately bounded artifact channel. Do not expose host sockets, credentials, Docker socket, production RPC, wallets, or host writable paths.
- Firecracker's Jailer setup is a privileged host operation. Keep that privilege in a dedicated, narrowly scoped host service; do not run the API, Worker, model agents, or task-provided code as root.

Primary upstream references:
- Firecracker getting started / KVM and Jailer requirements: https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md
- Production host setup and Jailer/seccomp/cgroup guidance: https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md
- Firecracker threat model and sandboxing design: https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md
- Firecracker release policy: https://github.com/firecracker-microvm/firecracker/blob/main/docs/RELEASE_POLICY.md

### Deployment consequence

Do not rely on GitHub-hosted Actions as the Firecracker execution host. GitHub documents nested virtualization as technically possible but unsupported and without stability or compatibility guarantees: https://docs.github.com/en/actions/concepts/runners/github-hosted-runners#nested-virtualization. Use CI for deterministic unit/contract tests; require a separately managed Linux KVM host (prefer dedicated bare metal or a cloud metal instance) for real microVM acceptance. A failed or unavailable KVM preflight must return NOT_RUN; never fall back to Docker or process isolation.

### Initial version candidate

At this checkpoint the upstream release policy lists Firecracker v1.18.0 as the current supported release (released 2026-11-09, support window ending 2027-05-09). Treat 1.18.0 only as the initial evaluation candidate. Before enabling execution, pin and independently verify the exact Firecracker and matching Jailer release artifact digests, guest kernel digest, and rootfs digest; confirm the release is still supported at deployment time. Do not pin floating tags or infer artifact integrity from a version string.

### Host preflight implementation

Added:
- `shared/onchain_firecracker_host.py`
- `tests/test_onchain_firecracker_host.py`

The preflight is deliberately non-executing. It checks Linux architecture, root privilege required for the Jailer setup phase, accessible character-device `/dev/kvm`, cgroup v2 CPU/memory/pids controllers, executable Firecracker/Jailer artifacts, and exact SHA-256 matches for both binaries, guest kernel and rootfs. It returns READY/NOT_READY with named checks and a deterministic profile digest.

A READY report means only that these host prerequisites and local artifact hashes match the operator-supplied profile. It does **not** prove Firecracker was securely launched, guest network is disabled, mounts are read-only, guest agent is trustworthy, cleanup works, or hostile code is contained. No VM or harness is started by this module.

### Required before runner implementation

1. Obtain and verify official Firecracker v1.18.0 release artifacts and matching Jailer; record release provenance and SHA-256 values.
2. Build a minimal guest kernel/rootfs with only the fixed Foundry runner and required offline toolchain. Pin both image digests.
3. Implement a dedicated privileged Jailer service with a narrow typed API; no user-controlled paths, argv, environment, kernel args, drives, or network configuration.
4. Prove guest network absence, no host credentials/sockets, read-only source/toolchain, bounded output drive, CPU/memory/pids/disk/time limits, timeout kill, and destruction of VM plus scratch storage.
5. Run adversarial acceptance on the actual dedicated KVM host. CI mocks alone do not satisfy this gate.
6. Only then connect the existing typed on-chain admission and round store to the VM adapter, with a signed/verified guest execution receipt and independent result verification.

Until these gates pass, the on-chain execution round remains NOT_RUN and the dedicated runner remains unavailable. The existing Docker Foundry prototype stays isolated and is not used for arbitrary public targets.
