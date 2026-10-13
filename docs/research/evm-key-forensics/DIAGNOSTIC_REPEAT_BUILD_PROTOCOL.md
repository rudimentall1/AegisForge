# Diagnostic binary repeat-build protocol

The Probe and main CI workflows now compile the synthetic `std::random_device` diagnostic twice from the same checked-out source, using the same compiler invocation and flags. Both binary files are included in the evidence directory. The offline verifier checks each file hash and requires byte-for-byte identity.

## What a passing result means

A pass shows that two builds in the same workflow runner, with the same installed compiler and flags, produced identical bytes. It is a useful determinism check and can detect unexpected differences between repeated invocations.

## What it does not mean

This is not yet a fully reproducible build claim. The two builds share one runner, one installed toolchain, and one workspace checkout. It does not independently establish:

- identical output from a separately provisioned clean environment;
- a cryptographically pinned compiler/toolchain image;
- a verified mapping from the historical Profanity source to the diagnostic binary;
- historical Profanity behavior, exploitability, or wallet exposure.

The artifact records the compiler version and flags. The current workflow installs `g++` from the runner's package repositories and uses `ubuntu-latest`, so the environment is not yet pinned by an immutable image digest.

## Next gate

Before using the term reproducible build without qualification, add a second isolated job with a pinned toolchain image or package snapshot. Have that job build from the same source commit and compare the resulting binary SHA-256 against the first job. Preserve both build attestations and environment manifests. If toolchains differ, record the mismatch and investigate rather than normalizing or ignoring it.

The research conclusion remains `INCONCLUSIVE`. The diagnostic is synthetic and does not execute historical Profanity code.
