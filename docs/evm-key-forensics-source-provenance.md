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
