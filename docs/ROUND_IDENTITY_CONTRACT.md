# Canonical Research Case Round Identity Contract

Status: proposed implementation contract for RC gate #158. This document does not change runtime behavior or authorize a database migration.

## Identity domains

A planned research step and an execution are different entities.

- `RoundSpec.round_id` in the current schema is the legacy name for a stable planned-step identifier. The canonical name is `round_spec_id`.
- Runtime `round_id` is a unique identifier for one execution created by `start_case_round`. It is never compared directly with a planned-step identifier.
- `case_id` identifies the immutable research case. The case contract digest binds the target repository/revision, scope, hypothesis, attacker capability, expected invariant, falsification criteria, rounds, and execution mode.

No identity may be inferred from task descriptions, timestamps, ordering, or matching UUID text.

## Runtime registry

The authoritative runtime record must contain exactly the versioned fields defined by its schema, including:

- `case_id`
- `round_id` (runtime execution ID)
- `round_number`
- `round_spec_id` (nullable only for explicitly classified legacy/unplanned runs)
- `root_task_id`
- `status`
- `created_at` and, when applicable, terminal timestamp

The registry enforces uniqueness of runtime `round_id`, uniqueness of `(case_id, round_number)`, and uniqueness of a root task assignment. A root task must belong to the same case and runtime round as its registry record.

## Portable dossier and offline verification

The versioned dossier exports a canonical `rounds.json` snapshot (or a versioned equivalent). Export reads registry and queue data from one consistent, read-only SQLite snapshot. Verification must not require access to the original database.

The verifier fails closed if any required binding is missing or inconsistent:

1. Every exported round belongs to the dossier's registered case and its immutable contract digest.
2. A non-legacy `round_spec_id` resolves to exactly one declared RoundSpec.
3. The registered root task exists and matches the registry's case and runtime round.
4. Every child task, evidence observation, and experiment output included in the round matches the same `case_id` and runtime `round_id`.
5. Parent/child task edges stay within the same case and round; cycles and dangling parents are rejected.
6. Duplicate runtime IDs, duplicate case round numbers, unknown fields, malformed records, missing registry rows, and cross-round swaps are rejected.
7. Rebuilding hashes or a Merkle root after tampering does not make a semantically inconsistent dossier valid.

## Legacy compatibility

Legacy data remains inspectable for diagnostics under its explicitly versioned legacy rules. It must not be represented as satisfying the new bounded-round RC contract.

A null `round_spec_id` is allowed only when the run is explicitly marked legacy/unplanned and the case has no bounded plan requirement. If a case declares planned rounds, missing runtime registry or plan binding blocks RC eligibility. Do not rewrite historical runtime IDs in place.

## Evidence and result semantics

Structural consistency and package integrity do not establish authenticity, source-to-binary provenance, runtime behavior, exploitability, entropy quality, or wallet exposure. Signature validity, artifact integrity, reproduction, and human vulnerability confirmation remain separate outcomes.

Missing scope, mismatched revisions, missing artifacts, failed tests, timeouts, malformed evidence, or failed identity bindings must never produce `CONFIRMED`. No live-network actions, private keys, seed phrases, secrets, or bundle-controlled host execution are permitted.

## Required adversarial and end-to-end tests

- Valid planned run round-trips through export and verifies in a clean process using only the dossier.
- Missing registry record, unknown plan ID, missing root, wrong case/round root, duplicate IDs, and duplicate round numbers fail closed.
- Child task, evidence observation, or experiment swapped across rounds fails even after manifest hashes are recomputed.
- A planned case with missing runtime/plan binding cannot satisfy the RC gate.
- Legacy/unplanned evidence remains explicitly labelled and cannot satisfy bounded-run acceptance.
- Missing artifacts, invalid paths, malformed schemas, and tampering produce machine-readable failure states, never `CONFIRMED`.

## Implementation order and safety boundary

1. Add explicit model fields and compatibility tests.
2. Update the runtime registry/start API and task/evidence propagation.
3. Version the portable bundle, exporter, and offline verifier together.
4. Add synthetic end-to-end and adversarial tests.
5. Run CI and keep the release candidate blocked until issue #158 acceptance criteria are met.

This is a contract-first change. It does not authorize a production migration, deployment, live-chain activity, or merging a PR with unresolved review findings. PR #175 remains Draft until the complete path is implemented and verified.
