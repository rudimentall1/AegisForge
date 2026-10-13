# Replay anchor consistency semantics

Status: proposed protocol decision for review. No production qualification implied.

## Decision

Treat a candidate as **historically anchored** once the authoritative anchor has confirmed the exact `(provider_id, sequence, head_sha256)` tuple. Do not promise that the candidate remains the current anchor head until the caller receives its response.

A monotonic anchor is expected to advance. Requiring a candidate to remain the latest head through the entire local SQLite commit would require a reservation/lease or a single serialized authority service. A second read cannot guarantee that property.

## Why this is the least misleading contract

There are two distinct claims:

- **Historically anchored:** the authority accepted this exact candidate at its sequence and head.
- **Current head:** the authority currently reports this exact sequence and head.

The first is a durable statement about an event in the anchor's history, assuming the anchor's monotonicity and rollback controls hold. The second is a point-in-time observation and may cease to be true as soon as another valid writer advances the anchor.

The API must not conflate these claims. A later valid anchor advancement must not retroactively invalidate a candidate that was already anchored, nor may it authorize an unrelated local candidate.

## Required protocol contract

1. Candidate identity binds provider, sequence, previous head, run ID, nonce, receipt digest, and signed evidence.
2. A successful compare-and-set is accepted only if the exact candidate tuple can be authoritatively confirmed. An ambiguous transport outcome remains pending until reconciliation.
3. Local acceptance is committed only after the exact candidate is confirmed as historically anchored.
4. The local transaction must enforce unique `(provider_id, run_id)` and `(provider_id, nonce)` constraints, or equivalent serialization, so concurrent writers cannot accept duplicates.
5. If another writer advances the anchor after the candidate was confirmed, return metadata that says `HISTORICALLY_ANCHORED`; do not say `CURRENT_EXTERNAL_HEAD_CONFIRMED`.
6. A recovery operation may finalize only a candidate whose signature, evidence binding, sequence, predecessor, and candidate head are recomputed and whose exact tuple is confirmed by the authoritative anchor.
7. If the external anchor is ahead but the local journal is behind, do not synthesize missing entries, truncate a suffix, or advance the anchor automatically. Reconciliation must identify the exact intervening evidence.
8. If two candidates compete from the same predecessor, at most one may win that anchor sequence. The loser remains pending/conflicted and requires reconciliation; it must not be silently rebased and republished.

## Implementation status on the research branch

- **Implemented:** accepted replay rows enforce `PRIMARY KEY (provider_id, run_id)` and `UNIQUE (provider_id, nonce)`; journal and evidence tables enforce the same provider-scoped uniqueness.
- **Implemented:** anchored finalization passes its expected prior journal tuple into `verify_and_record_attestation`. The tuple is checked inside the same `BEGIN IMMEDIATE` transaction as the append.
- **Implemented:** accepted replay row, journal event, journal head, evidence, and pending `FINALIZED` status now commit in one SQLite transaction on the normal finalization path.
- **Implemented:** a failure while updating the pending status rolls back the accepted row and journal/evidence in the same transaction. Non-unique SQLite integrity failures are no longer mislabeled as replay duplicates.
- **Implemented:** result metadata uses `HISTORICALLY_ANCHORED_CANDIDATE_HEAD_CONFIRMED`, not a claim that the candidate is still the current external head.
- **Verified in GitHub Actions:** deterministic tests cover an external anchor advance after candidate confirmation, a local writer interleaving between preflight and append, and rollback when the pending-status update fails.
- **Verified in GitHub Actions:** a concurrent duplicate-submission test uses two worker threads, each opening its own SQLite connection, and asserts that exactly one copy is accepted with one journal event and one evidence row.
- **Verified in GitHub Actions:** recovery explicitly tests an anchor at N+1 with local state at N and asserts the planner fails closed without changing accepted rows, journal, state, or evidence.
- **Verified in GitHub Actions:** when an injected SQLite trigger blocks the atomic `FINALIZED` update after the external anchor advances, recovery succeeds after the trigger is removed. A second recovery leaves the accepted row, journal event, evidence row, and final status unchanged.
- **Still open:** operator-run reconciliation and independent-anchor rollback controls remain outside this prototype.
- The latest full CI run for commit `4dbd0260edb0f5497f502b5c0ce973ef3c1f5ba1` passed **746 tests in 16.67 seconds**. The EVM Key Forensics Probe also completed successfully. Keep `qualification=NOT_ESTABLISHED`; passing tests do not replace independent-anchor rollback controls or operational fault-injection testing.

## Explicit limitation

This contract depends on the anchor service's promised monotonic history. The reference SQLite service cannot detect a privileged operator restoring an old database snapshot. A separate witness, append-only external log, or non-rollbackable storage is required to cover that threat.
