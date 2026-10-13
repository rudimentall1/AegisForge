# Source provenance in EVM Key Forensics

The provenance record schema is at `tools/evm_key_forensics/source-provenance.schema.json`.

## Keep four questions separate

1. **Content integrity**: did a bounded re-fetch return bytes with the recorded SHA-256?
2. **Publisher identity**: is there evidence that the claimed publisher controls the publishing identity or signing key?
3. **Origin and derivation**: is this a primary publication, or does it rely on another source?
4. **Evidence independence**: does the evidence actually come from a separately verified origin?

A passing content hash answers only the first question. Different URLs and different hashes do not establish publisher identity or independent origin.

## Conservative interpretation

- Missing provenance is `UNKNOWN` or `NOT_ESTABLISHED`, never an implicit pass.
- A publisher name, domain, origin URL, or verification status supplied by the source record is a claim, not proof.
- A `verification_evidence_ref` is only a pointer. A verifier must inspect the referenced evidence and record who performed the check, how, and when.
- `PRIMARY_ORIGIN_VERIFIED` must not be assigned solely because a page calls itself a primary source.
- If a secondary article cites an advisory, record the advisory in `derived_from_source_ids`. Count the underlying origin once for a claim unless a separate origin is established.
- Conflicting provenance claims require human review. Do not resolve them by counting sources.
- A schema-valid record is not a verified record. JSON Schema checks structure, not truth or authenticity.

## Independence rule

An origin may be treated as independent only after an explicit review establishes distinct origins and records the evidence used. A different URL, a different SHA-256, a different byline, or a self-declared publisher field is insufficient by itself.

Until a verifier and evidence-review path is implemented, the validator deliberately reports `source_origin_independence_established: false` and blocks `READY_FOR_HUMAN_REVIEW`. This is a conservative limitation, not a finding that the sources are definitely dependent.

## Scope and limitations

This schema is a data contract for future provenance assessment. It does not perform DNS/domain-control checks, validate publisher signing keys, authenticate a verifier, resolve citations automatically, or establish a trust registry. Those checks need separate implementations and tests before the record can influence readiness.


## Signed reviewer attestations

The validator can verify a detached Ed25519 reviewer attestation. This adds signer authentication and tamper detection to a review record; it does **not** prove that the reviewer's conclusions are true or that the evidence reference was inspected correctly.

The operator provisions the trust root outside the dossier through `AEGISFORGE_PROVENANCE_TRUSTED_PUBLIC_KEYS`. Its value is a JSON object mapping stable key IDs to base64-encoded raw 32-byte Ed25519 public keys. Duplicate JSON keys, malformed base64, and keys of the wrong length fail closed. Never populate this trust store from a source dossier or from the attestation itself.

Each source may include a `provenance_attestation` object:

- `key_id`: an ID present in the operator trust store.
- `payload`: a JSON object containing `attestation_version` (`evm-provenance-attestation-v1`), matching `source_id`, publisher and origin statuses, `canonical_origin_ref`, independence status and basis, `evidence_ref`, `reviewed_by`, and `reviewed_at`.
- `signature`: base64-encoded Ed25519 signature over the UTF-8 bytes of the payload serialized as JSON with sorted keys, compact separators, and `ensure_ascii=False`.

The validator checks the signature against the operator-configured key, enforces allowed status values, and rejects a source-ID mismatch. It records the result as `SIGNATURE_VERIFIED`; unknown keys, malformed payloads, and signature mismatches are rejected. The public key proves only that the holder of the configured private key signed those exact bytes.

A valid attestation is not yet enough to remove the dossier-wide source-independence blocker. The current implementation does not fetch or adjudicate the referenced evidence, verify publisher domain control, or establish that all relevant sources have distinct origins. `source_origin_independence_established` therefore remains false until a separate evidence-review procedure can justify that conclusion. The attestation check must not be described as independent evidence verification.
