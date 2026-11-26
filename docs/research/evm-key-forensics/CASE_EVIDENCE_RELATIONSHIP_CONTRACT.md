# Research Case to Evidence Relationship Contract

**Status:** proposed contract for implementation and acceptance tests; not a release approval.  
**Scope:** EVM Key Forensics source reports, registered Research Cases, portable case bundles, and combined complete-evidence packages.

## Problem

The current evidence pipeline validates several local relationships: a case bundle binds task and evidence records to a case, the combined evidence index binds the pinned Profanity source report identity and digest, and the source report pins two upstream revisions. These checks do not yet define one explicit, machine-verifiable relationship between a registered Research Case and every source report included in its evidence package.

The historical Profanity source report is a contextual benchmark by default. Its repository and commits must not be copied into an unrelated case's `target_repository` or `target_commit`.

## Relationship types

Every source report attached to a case must declare exactly one relationship type:

- `EXACT_TARGET_REVISION`: the source report describes the same repository and exact immutable commit as the registered case target.
- `CONTEXTUAL_BENCHMARK`: the report is supporting or comparative evidence from another repository or revision. It may inform the hypothesis but does not satisfy the case's target-source evidence requirement.

Unknown, omitted, mixed, or contradictory relationship types must be rejected.

## Required relationship record

The implementation should introduce a strict versioned record with these semantic fields:

- `schema_version`: integer version, rejecting booleans and unsupported versions.
- `case_id`: exact registered case identifier.
- `case_contract_sha256`: SHA-256 of the canonical immutable case contract, excluding mutable lifecycle status.
- `relationship_type`: one of the two values above.
- `report_id` and `experiment_id`: exact identities declared by the validated source report.
- `source_repository`: canonical repository identity associated with that report.
- `source_commit`: full immutable commit SHA associated with the report.
- `source_report_sha256`: digest of the exact source-report bytes included in the package.

The relation record is a consistency claim, not a signature. It must be validated against the actual case record and report content, not trusted as a self-authenticating assertion.

## Validation rules

1. Validate the registered case and source report against their existing strict schemas before checking their relationship.
2. Compute the immutable case contract digest from the canonical case representation using a documented canonicalization function. Do not include mutable status, queue counters, or timestamps that change during lifecycle transitions.
3. Recompute the source report digest from the exact included bytes and compare it with the relation record and combined evidence index.
4. For `EXACT_TARGET_REVISION`, require normalized repository identity and exact full commit equality with `target_repository` and `target_commit`. A source report that only references the same project name is insufficient.
5. For `CONTEXTUAL_BENCHMARK`, preserve the report's own repository and pinned commit identities separately. Do not treat it as proof that the registered target revision was inspected.
6. The historical Profanity comparison report must declare `CONTEXTUAL_BENCHMARK` unless the registered case explicitly targets the Profanity repository at the exact revision represented by that report. Because the report compares two revisions, implementation must define which revision is the subject of any exact-target relation; absent a single unambiguous subject revision, it remains contextual.
7. Case ID, immutable case digest, report ID, experiment ID, repository, commit, relationship type, and report digest must agree across the case bundle, relationship record, source report, and combined evidence index wherever those artifacts duplicate the fields.
8. Reject missing fields, unknown fields, duplicate JSON keys, malformed digests, partial commit identifiers, contradictory identities, and implicit defaults.
9. Recompute all ordinary archive digests and Merkle values as usual, but do not treat them as authenticity anchors. An editor can recompute unsigned hashes; semantic mismatch checks must still reject the altered package.
10. Preserve the existing conservative conclusion boundary. A valid relationship establishes identity consistency only; it does not prove source-to-binary provenance, runtime reproduction, exploitability, entropy properties, or wallet exposure.

## Required adversarial acceptance tests

Use synthetic fixtures only. For each mutation, recompute the bundle's unsigned entry hashes, Merkle root, and outer digest before verification, so the test exercises semantic checks rather than ordinary hash failures.

- Change `case_id` in one artifact while leaving the registered case unchanged.
- Change the immutable case contract digest.
- Change `target_commit` while keeping the source report pinned to its original revision.
- Change `source_repository` to a different repository.
- Change `relationship_type` from contextual to exact-target without satisfying repository and commit equality.
- Change report or experiment identity while keeping the source report bytes unchanged.
- Replace source report bytes and recompute its digest, but preserve a contradictory relation record.
- Remove the relationship record or add an unknown field.
- Confirm that a contextual benchmark is accepted as context but cannot satisfy an exact-target source-evidence requirement.
- Confirm that none of these changes can promote a synthetic result or source-pattern match to historical reproduction or `CONFIRMED`.

## Offline verification and compatibility

The verifier must work from exported artifacts alone, without the original SQLite database. The case bundle's existing v1/v2 compatibility must remain intact unless a separately reviewed schema migration explicitly changes it. New relationship data should be versioned and rejected closed when unsupported; it must not silently reinterpret old bundles as having an exact-target relationship.

## Release gate

This contract is implemented only when tests exercise the actual export and verifier path on a clean environment, including the rehashed adversarial mutations above. Documentation alone does not close the release blocker. Until then, the case-to-evidence relationship remains an open release-candidate gap.
