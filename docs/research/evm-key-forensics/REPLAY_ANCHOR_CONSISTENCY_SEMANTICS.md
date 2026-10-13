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

## Implementation work required before adopting this contract

- Inspect the SQLite schema and ensure database-enforced uniqueness for provider-scoped run IDs and nonces.
- Ensure the finalizer's accepted row, journal event, journal head, and pending status are updated in one SQLite transaction where possible.
- Add a deterministic race test that advances the anchor after candidate confirmation but before the local commit. Under this contract, the candidate may be accepted as historically anchored, but its result must not claim that it is still the current external head.
- Add concurrent independent-connection tests for duplicate nonce and duplicate run ID.
- Add a reconciliation test for anchor sequence N+1 while local state remains at N.
- Keep `qualification=NOT_ESTABLISHED` until independent-anchor rollback controls and operational fault-injection testing are complete.

## Explicit limitation

This contract depends on the anchor service's promised monotonic history. The reference SQLite service cannot detect a privileged operator restoring an old database snapshot. A separate witness, append-only external log, or non-rollbackable storage is required to cover that threat.
