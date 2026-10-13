# Probe source-to-binary linkage: reproducibility gate

## Scope

This gate links the synthetic diagnostic probe source checked out by a GitHub Actions run to the binary produced from that source. It is deliberately limited to `tools/evm_key_forensics/profanity_seed_environment_probe.cpp`. It does not compile, patch, or execute the historical Profanity application.

## Checks

The workflow performs these checks:

1. Two builds on the first runner must produce the same SHA-256 digest.
2. A second, independent GitHub-hosted runner checks out the workflow revision, verifies that its source file has the same SHA-256 digest as the reference source, rebuilds with the same declared compiler flags, and compares the resulting binary digest to the first runner's reference binary.

The compile flags are `-std=c++11 -O2 -Wall -Wextra -Werror -pedantic`. For the independent rebuild run documented below, the runner was Ubuntu 24.04.5 on the `ubuntu-24.04` image and reported `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`. The compiler is installed from the runner's Ubuntu package repositories. Because the runner image and package repository are not pinned by immutable digest and exact package version, this is a cross-runner reproducibility check, not a fully hermetic or long-term reproducible build.

## Recorded run

The independent clean-runner job completed successfully for PR #32 on 2026-10-13.

- Workflow run: [38367194061](https://github.com/rudimentall1/AegisForge/actions/runs/38367194061)
- Independent rebuild job: [115195176208](https://github.com/rudimentall1/AegisForge/actions/runs/38367194061/job/115195176208)
- Source SHA-256 on reference artifact: `60611d0f287aee085afab07b3bb5f3747fb3c4ef70d5e2f238594885affdfffa`
- Source SHA-256 in independent checkout: `60611d0f287aee085afab07b3bb5f3747fb3c4ef70d5e2f238594885affdfffa`
- Reference binary SHA-256: `c8abed601e5c34fd2db77b3b02140381114366550a44ee55c687e43bcd43e274`
- Independent rebuild SHA-256: `c8abed601e5c34fd2db77b3b02140381114366550a44ee55c687e43bcd43e274`
- Downloaded reference artifact SHA-256: `96be4719c21d9048961d56524a88371c934e0637b746e422f455a34053ec40d9`

The job log reports that the independent rebuild matched byte-for-byte. These values are transcribed from the GitHub Actions log; they are not a substitute for independently downloading and re-hashing the artifacts.

## Acceptance criteria and remaining evidence gap

- [x] Reference source digest equals the source digest in the independent checkout.
- [x] The same-runner build check passed.
- [x] The independent-runner build matches the reference binary byte-for-byte.
- [x] Compiler version and compile flags are recorded here.
- [x] The independent runner's compiler version, runner details, source digest, binary digests, and comparison result are persisted in the separate `independent-rebuild-report.json` artifact.
- [ ] The GitHub Actions provenance attestation for the evidence ZIP must be verified with the command in [ARTIFACT_ATTESTATION.md](ARTIFACT_ATTESTATION.md). The attestation job's success alone is not independent verification.

A mismatch is a failed gate. Do not silently accept it or overwrite the reference binary. Record compiler versions, runner details, and digests before diagnosing the difference.

## What a pass means

A pass supports the claim that this diagnostic binary can be rebuilt from the recorded probe source under the tested GitHub Actions environments. It improves source-to-binary traceability for the probe itself.

A pass does **not** establish that the historical Profanity binary was built from either pinned source revision, reproduce historical runtime behavior, prove weak entropy, or establish that any wallet was exposed. The historical vulnerability conclusion remains `INCONCLUSIVE`; historical source-to-binary linkage remains `NOT_ESTABLISHED`.
