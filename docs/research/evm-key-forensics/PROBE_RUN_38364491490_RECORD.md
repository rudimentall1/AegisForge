# EVM Key Forensics Probe Run Record

## Run identity

- Workflow: EVM Key Forensics Probe
- GitHub Actions run: 38364491490
- Tested commit: `6fa2430a6a48cced7ac2c2a47edca3fc6e9bbc96`
- Artifact: `evm-key-forensics-probe-38364491490-1`
- Artifact SHA-256: `f27bbe7964695d2acc3fc677de6f206e3599a79fe344eee567427de49c3c3e71`
- Artifact digest was independently recomputed from the downloaded ZIP and matched the digest reported by GitHub.

## Independently checked artifact contents

The ZIP contains `probe-run-metadata.json`, `probe-output.json`, `probe-source.cpp`, `probe-binary`, and `source-evidence-report.json`.

Recomputed SHA-256 values for the source, binary, probe output, and source-evidence report match the corresponding values in `probe-run-metadata.json`.

The source-evidence report records:

- Both pinned source revisions passed the configured source-pattern check.
- The extracted `createSeed()` body fingerprints match across the two revisions.
- Whole-file SHA-256 and Git blob SHA-1 values differ across revisions.
- Overall conclusion remains `INCONCLUSIVE`.
- Independent review remains `PENDING`.
- Source-to-binary provenance remains `NOT_ESTABLISHED`.
- Historical Profanity code was not executed, and no wallet material was used.

The runtime diagnostic requested 64 `std::random_device` samples and observed 64 distinct values in this runner environment. The artifact explicitly states that these observations are not proof of entropy. They do not establish historical behavior, exploitability, or vulnerability of any address.

## Interpretation

This run provides a reproducible integrity check for the artifact and its internally recorded files, plus source-pattern comparison output. It does not authenticate the workflow producer, independently prove that the pinned source files were extracted correctly, or establish a source-to-binary chain of custody. Matching function-body hashes are a useful cross-revision observation, not proof that the implementation is exploitable or that the post-disclosure release was remediated.

## Next acceptance gate

A reviewer working from a clean directory should independently retrieve both pinned upstream revisions, verify the expected Git blob IDs, inspect the exact function boundaries and body, recompute the fingerprints without relying on the project checker, and record the commands, environment, results, and reviewer identity in `INDEPENDENT_SOURCE_REVIEW_WORKSHEET.md`. Until that review is actually completed, the status must remain `PENDING` and the research conclusion must remain `INCONCLUSIVE`.
