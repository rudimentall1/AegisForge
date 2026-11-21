# Case-bound Foundry execution

A planned Foundry round is selected only from a registered ResearchCase and its
persisted RoundSpec. The worker does not accept arbitrary target URLs, source
paths, compiler versions, or harness code at execution time.

## RoundSpec inputs

A Foundry `runtime_probe` round declares:

- `target_source_paths`: repository-root-relative Solidity files at the exact pinned commit.
  Include every imported project dependency needed by the test.
- `foundry_source_root`: repository-relative directory containing those source
  files; defaults to `src`. For the in-repository benchmark this is
  `benchmark/src`.
- `test_harness_source`: the complete, immutable Solidity test harness stored in
  the ResearchCase round contract.
- `solc_version`: an exact semantic version such as `0.8.24`.
- `foundry_image`: a digest-pinned image such as
  `ghcr.io/foundry-rs/foundry@sha256:<64 lowercase hex>`.
- `positive_control_test` and `negative_control_test`: distinct Solidity test
  function names (without parentheses) that the runner must observe as
  successful in Foundry's JSON output.

The harness, compiler version, image digest, and both control identities are
included in the ResearchCase binding digest. A round cannot invoke Foundry without both
named controls. A passing execution is downgraded to
`CONTROL_COVERAGE_INVALID` if either declared test is absent or did not pass.
The source loader reads each declared file from the Git object database after
checking the checkout's `origin` and exact `HEAD` SHA. It rejects mutable
worktree substitutions, symlinks, non-blob entries, unsafe paths, and source
sets larger than 4 MiB. The scope gate validates the reviewed scope envelope
and review date; it does not fetch or interpret the external scope page. A
reviewer must ensure every declared source path is actually in scope before
marking the ResearchCase ready.

The Foundry adapter creates a disposable project with `src/` as its source
root. Every declared repository path must be beneath `foundry_source_root`;
the prefix is stripped and the remaining relative path is copied into the
generated `src/` directory. Harness imports should therefore use paths such as
`../src/Vault.sol` or `../src/contracts/Vault.sol`. This initial adapter
does not install arbitrary Foundry libraries or resolve network dependencies;
all required Solidity sources must be declared and compile within this generated
layout. It does not import the target repository's original `foundry.toml`;
optimizer, EVM-version, and other project-specific compiler settings are not
reproduced yet.

## Worker configuration

Set these on the LabRunner host:

- `AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED=1`: explicit operator opt-in required by
  the capability policy before LabRunner may access the Docker daemon. Docker
  group membership is effectively host-root; use a dedicated worker host and
  do not expose this permission to general-purpose agents.
- `AEGISFORGE_TARGET_CHECKOUT_ROOT`: local checkout of the target repository.
  It must have the registered GitHub origin and be checked out at the case's
  exact 40-character commit SHA.
- The exact `foundry_image` digest declared in the immutable RoundSpec must be
  preloaded in Docker. The runner uses `--pull=never`, so it never downloads an
  image during an experiment. The digest pins the image bytes, but this
  adapter does not verify registry publisher signatures or attestations.
- `AEGISFORGE_SOLC_BINARY`: optional explicit executable path to the exact
  `solc` binary. Otherwise the adapter looks for the version through
  `solc-select`.
- `AEGISFORGE_AUTO_INSTALL_SOLC=1`: optional opt-in to install a missing compiler
  through `solc-select`. It is disabled by default.

The configured `solc` binary is executed on the LabRunner host for a version
probe before it is copied into the disposable project. Treat this as an
operator-managed trusted binary: its SHA-256 is recorded, but publisher
provenance is not independently verified by this adapter.

## Execution and evidence semantics

The Docker invocation disables networking, mounts the generated project
read-only, uses a read-only container root, drops Linux capabilities, enables
`no-new-privileges`, limits processes, memory, CPU, file descriptors, output,
and runtime, and retains Docker's default seccomp profile. This is a bounded
container boundary, not a guarantee against kernel or Docker-runtime escapes.

The runner records Foundry's machine-readable test result, exact command,
compiler version and digest, harness digest, pinned source digests, and bounded
stdout/stderr. The Worker persists those artifacts through the existing local
experiment evidence ledger.

**A passing test is an execution observation, not a confirmed vulnerability.**
The adapter always sets `dynamic_verified=false` and
`vulnerability_confirmed=false`. Confirmation still requires independent review,
a meaningful positive exploit control, a negative/safe control, and validation
of the observed impact. Missing Docker, compiler, image, or checkout configuration
must produce an explicit not-run/unavailable result rather than a synthetic pass.


## Opt-in Worker-to-Evidence end-to-end test

`tests/test_foundry_worker_e2e.py` uses the repository's vulnerable/safe
reentrancy benchmark and exercises the real Worker, capability policy, pinned
Git source loader, Docker Foundry runner, and Evidence Ledger. It is skipped by
default. On a dedicated host with Docker access, a preloaded image digest, and
the trusted solc binary configured, run:

```bash
AEGISFORGE_FOUNDRY_WORKER_E2E=1 \
AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED=1 \
AEGISFORGE_FOUNDRY_E2E_IMAGE='ghcr.io/foundry-rs/foundry@sha256:<64 lowercase hex>' \
AEGISFORGE_SOLC_BINARY=/absolute/path/to/solc \
pytest -q tests/test_foundry_worker_e2e.py
```

The test does not contact a remote target or send transactions. It creates a
temporary local Git repository containing the benchmark source and runs the
two declared controls inside the isolated container.
