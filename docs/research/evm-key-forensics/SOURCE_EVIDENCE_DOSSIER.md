# EVM Key Forensics: Source evidence dossier

The machine-readable evidence register is [SOURCE_EVIDENCE_DOSSIER.json](./SOURCE_EVIDENCE_DOSSIER.json).

It records the two immutable upstream source revisions, expected Git blob identifiers, claim boundaries, verifier contract, and current experiment status. The JSON file is a review index, not a signed attestation and not proof that an external runner produced the evidence.

## Current interpretation

- The checker can establish that a local file matches a pinned Git blob and that its source pattern matches the reviewed structure.
- It does not establish the identity of the person or process that collected the file.
- It does not establish that a compiled binary came from the reviewed source.
- It does not measure the effective entropy of a specific runtime.
- It does not reproduce a historical wallet-key vulnerability.

## How to verify

For each revision, independently retrieve `Dispatcher.cpp` from the immutable URL in the dossier, then run the checker with the matching revision role:

```bash
python tools/evm_key_forensics/check_historical_source_pattern.py /path/to/Dispatcher.cpp --revision pre-disclosure --pretty
python tools/evm_key_forensics/check_historical_source_pattern.py /path/to/Dispatcher.cpp --revision post-disclosure --pretty
```

The CLI accepts only the exact pinned Git blob for the selected role. A result of `SOURCE_PATTERN_MATCHED` is source-level evidence only. A mismatch or ambiguous structure must remain `INCONCLUSIVE`.

## Trust boundary

Git blob IDs and SHA-256 digests support content-integrity checks. They do not authenticate the collector, the execution environment, or the truth of a report. The dossier is intentionally unsigned. Independent runner attestation and source-to-binary provenance remain unimplemented.

## Current conclusion

`SOURCE_REVIEW_ONLY`; historical code was not executed; no wallet material was used; historical vulnerability reproduction remains **not established**. Independent review is pending.
