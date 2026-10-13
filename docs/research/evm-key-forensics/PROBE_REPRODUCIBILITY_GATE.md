# Probe source-to-binary linkage: reproducibility gate

## Scope

This gate links the synthetic diagnostic probe source checked out by a GitHub Actions run to the binary produced from that source. It is deliberately limited to `tools/evm_key_forensics/profanity_seed_environment_probe.cpp`. It does not compile, patch, or execute the historical Profanity application.

## Checks

The workflow performs two separate checks:

1. Two builds on the first runner must produce the same SHA-256 digest.
2. A second, independent GitHub-hosted runner checks out the same workflow revision, verifies that its source file has the same SHA-256 digest as the reference source, rebuilds with the same declared compiler flags, and compares the resulting binary digest to the first runner's reference binary.

The compile flags are `-std=c++11 -O2 -Wall -Wextra -Werror -pedantic`. Both jobs currently install `g++` from the runner's Ubuntu package repositories. The compiler version is printed in each job log. Because the runner image and package repository are not pinned by immutable digest and exact package version, this is a cross-runner reproducibility check, not a fully hermetic or long-term reproducible build.

## Acceptance criteria

- The source digest from the reference artifact equals the source digest in the second checkout.
- The two same-runner builds match byte-for-byte.
- The second-runner build matches the reference binary byte-for-byte.
- The evidence metadata records the source and binary digests, compiler version, flags, and the scope of the first-runner repeat build.
- The GitHub Actions provenance attestation for the evidence ZIP is verified separately with the command in [ARTIFACT_ATTESTATION.md](ARTIFACT_ATTESTATION.md).

A mismatch is a failed gate. Do not silently accept it or overwrite the reference binary. Record compiler versions, runner details, and digests before diagnosing the difference.

## What a pass means

A pass supports the claim that this diagnostic binary can be rebuilt from the recorded probe source under the tested GitHub Actions environments. It improves source-to-binary traceability for the probe itself.

A pass does **not** establish that the historical Profanity binary was built from either pinned source revision, reproduce historical runtime behavior, prove weak entropy, or establish that any wallet was exposed. The historical vulnerability conclusion remains `INCONCLUSIVE`; historical source-to-binary linkage remains `NOT_ESTABLISHED`.

## Status

The workflow gate has been added. Its status is pending until the new `independent-clean-runner-rebuild` job completes successfully on the current branch head. A workflow definition or a successful first-runner build alone is not evidence that the independent rebuild passed.
