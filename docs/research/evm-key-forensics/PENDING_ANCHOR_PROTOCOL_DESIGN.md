# Pending-first protocol for externally anchored replay registration

Status: design proposal. Not implemented. The current strict adapter remains fail-closed but is not crash-atomic across SQLite and the external anchor.

## Problem

`verify_and_record_attestation_anchored()` currently calls `verify_and_record_attestation()`, which commits the accepted row, journal event, journal state, and evidence in one SQLite transaction. Only after that commit does the adapter attempt external compare-and-set (CAS). If CAS fails, local accepted state is ahead of the external anchor. Strict calls then stop, but the system needs operator reconciliation.

A process-local mutex is insufficient: separate processes and hosts do not share it. A distributed lock alone also does not remove the crash window between SQLite commit and external CAS.

## Required invariant

An attestation is externally accepted only when its exact candidate journal head is confirmed by the authoritative external anchor. A pending record must never reserve an accepted run ID or nonce, and it must never be returned to a caller as accepted.

The anchor remains authoritative for the accepted sequence and head. SQLite is durable local evidence and a recovery aid, not authority to advance the anchor by itself.

## Proposed state machine

- `PREPARED`: signature, trusted key, dossier binding, provider, run ID, nonce, and receipt digest are validated. A pending candidate and its canonical evidence are durably stored, but no accepted row or accepted journal head is advanced.
- `ANCHORED`: external CAS has atomically moved from the exact prior `(sequence, head)` to the candidate `(sequence + 1, candidate_head)`. The candidate head is derived from canonical event fields and includes the signed receipt digest.
- `FINALIZED`: SQLite has atomically converted the pending candidate into accepted replay reservation, journal event, journal state, and evidence. Only this state can return success to the caller.
- `CONFLICT`: CAS did not succeed because another writer advanced the anchor. The pending candidate is not accepted. It remains diagnostic evidence and may be discarded only through an explicit safe cleanup path.

## Write protocol

1. Validate the signed attestation before creating any state.
2. Read and validate the external anchor.
3. In a short `BEGIN IMMEDIATE` transaction, verify local accepted state exactly matches that anchor, validate journal integrity, reject already accepted run IDs/nonces, calculate the candidate event/head, and persist a pending record containing canonical dossier/envelope, key ID, receipt digest, expected prior anchor, and candidate event fields. Do not insert into accepted tables yet.
4. Attempt external CAS from the exact prior anchor to the candidate sequence/head. The anchor store must provide linearizable CAS.
5. If CAS returns conflict, mark the pending item conflicted where safe and return an error. Do not change accepted local state. If the CAS outcome is ambiguous because the store call timed out, reread the authoritative anchor: exact candidate means continue finalization; exact prior means retry CAS only if the store contract guarantees the original call did not succeed; any other state requires fail-closed reconciliation.
6. If the anchor confirms the candidate, finalize in a SQLite transaction. Revalidate the pending record, recompute its candidate hash, re-verify the signed evidence with the caller's trusted keys, verify the current accepted head equals the candidate's recorded prior head or is already finalized at this exact candidate, then atomically insert accepted reservation, journal row, journal state, evidence, and mark pending finalized.
7. Return success only after finalization commits and the external anchor is confirmed to match the returned head.

## Crash recovery rules

- Crash before pending commit: no accepted state changed; retry from the authoritative anchor.
- Crash after pending commit but before CAS: compare anchor with recorded prior and candidate. If prior still matches, retry CAS under normal validation. If another head is present, do not accept the pending candidate.
- Crash after successful CAS but before local finalization: if anchor exactly matches the pending candidate, re-verify signed evidence and finalize locally. Never compute a replacement candidate from the local journal and advance the anchor based only on SQLite data.
- Crash during local finalization: SQLite atomicity must leave either all finalization writes committed or none. Recovery repeats the exact-candidate check and finalization idempotently.
- CAS timeout with unknown outcome: reread anchor. Exact candidate permits evidence verification and finalization; exact prior permits a retry only under a documented idempotent/linearizable CAS contract; a different anchor is a conflict requiring review.
- Pending evidence that fails signature, key pinning, canonical binding, or candidate hash checks must not be finalized, even if local metadata claims it was anchored. Raise an integrity incident for operator review; never silently advance the anchor.

## Concurrency

Two writers may prepare different candidates for the same prior anchor. The external CAS chooses at most one winner. The loser remains pending/conflicted and is not accepted. A retry by the losing writer must start from the newly authoritative anchor and recompute a fresh candidate; it must not reuse the stale candidate. Database uniqueness constraints still protect accepted run IDs and nonces.

The implementation must not depend on a process-local lock for correctness. Optional distributed serialization can reduce conflicts but is not the source of truth.

## Anchor contract

The existing anchor fields `(provider_id, sequence, head_sha256)` are sufficient only if `head_sha256` cryptographically commits to the complete canonical event, including provider ID, sequence, previous head, run ID, nonce, and signed receipt digest. The CAS operation must be linearizable and compare both expected sequence and expected head. The service must expose authoritative reads and document timeout/unknown-outcome semantics.

The external anchor must remain outside the SQLite database and its backup/restore domain. Genesis provisioning must be explicit per provider.

## Acceptance tests required before enabling this protocol

1. Invalid signature creates neither pending nor accepted state.
2. Pending commit followed by CAS conflict never creates accepted rows or advances local accepted head.
3. Crash/failure after pending commit but before CAS is recoverable without accepting unanchored data.
4. Crash/failure after CAS but before finalization is recoverable from the exact pending candidate and valid signed evidence.
5. Finalization transaction failure leaves no partial accepted state and can be retried idempotently.
6. Two concurrent writers sharing one prior anchor produce exactly one accepted candidate; the loser is not accepted.
7. Same run ID or nonce cannot be accepted twice after retries or recovery.
8. Tampered pending evidence, candidate fields, or receipt digest cannot be finalized.
9. Anchor read failure, malformed anchor, ambiguous CAS result, and unrelated anchor advancement fail closed.
10. Reopening the database after each injected crash point produces the same decision as uninterrupted execution.
11. Existing recovery planner continues to reject a local suffix not covered by the authoritative anchor.
12. Full test suite and `git diff --check` pass.

## Migration and rollout

Do not silently change the existing adapter in place without a schema version and compatibility tests. Introduce pending state through an explicit schema migration. Existing local suffixes created by the old protocol must remain quarantined for operator review; do not auto-promote or auto-delete them. Keep `qualification=NOT_ESTABLISHED` until independent fault-injection testing and an actual external anchor implementation are reviewed.

## Non-goals

This design does not claim that SQLite is tamper-proof, that a local operator cannot replace trusted public keys, or that the external anchor can verify the runner's business logic. It addresses ordering, crash recovery, and accepted-state semantics across two independent persistence systems. The lab remains synthetic; no live wallet key recovery or scanning is part of this work.