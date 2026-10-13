# Independent Anchor Witness: Design and Acceptance Criteria

Status: DESIGN ONLY
Qualification: NOT_ESTABLISHED

## Problem

The local SQLite hash chain can detect many inconsistent edits, and the pending replay protocol compares its local head with an external anchor. Neither property proves freshness if an attacker can restore both the local database and the anchor service to a mutually consistent older snapshot.

A hash chain proves internal linkage. It does not prove that no newer head existed elsewhere.

## Threat model

The design must distinguish these cases:

1. Local database rollback while the external anchor remains current.
2. External anchor rollback while the local database remains current.
3. Coordinated rollback of both the local database and the anchor.
4. Witness unavailable, stale, equivocal, or returning malformed data.
5. Legitimate anchor advancement concurrent with a local operation.

The current prototype has checks for some mismatched-state cases. Case 3 is not solved by the current local database plus anchor pair.

## Proposed witness contract

Introduce an independent append-only witness only after selecting a deployment model. For each accepted provider head, the witness record should bind:

- protocol/schema version;
- provider ID;
- monotonically increasing sequence;
- previous head hash;
- new head hash;
- a unique operation or event identifier;
- witness receipt timestamp or epoch, if the chosen witness can provide trustworthy time;
- witness signature or another independently verifiable inclusion/consistency proof.

The witness must reject a second, conflicting head for the same provider and sequence. It must not silently overwrite history. The application must verify witness responses cryptographically using pinned trust material, not accept a bare success boolean.

## Ordering and failure behavior

The exact protocol ordering depends on the selected witness guarantees and must be threat-modelled before implementation. In particular, avoid claiming an atomic transaction spanning SQLite, an external anchor, and a witness unless the protocol actually provides one.

Required behavior:

- Fail closed when witness evidence is missing, malformed, invalidly signed, or inconsistent.
- Preserve pending state after an uncertain remote outcome; do not silently mark the candidate accepted.
- Make retries idempotent using a stable operation identifier and exact candidate tuple.
- Treat conflicting or equivocal witness statements as a durable review condition.
- Expose distinct outcomes for locally committed, externally anchored, witness-confirmed, and indeterminate states.
- Never label the system rollback-resistant merely because an anchor API returned success.

## Acceptance tests before qualification

1. Local-only rollback: current witness proves the local head is stale.
2. Anchor-only rollback: witness rejects the older head.
3. Coordinated local-plus-anchor rollback: witness still reports the newer sequence/head.
4. Witness outage before submission: no accepted local state is fabricated.
5. Timeout after witness submission: retry discovers the exact prior operation without duplicating it.
6. Same sequence, different head: witness refuses the conflicting append and application quarantines the candidate.
7. Invalid signature, wrong provider, malformed proof, or altered receipt: verification fails closed.
8. Concurrent writers: at most one head is accepted for a given provider sequence.
9. Recovery after process restart: exact witness-confirmed candidate can be finalized idempotently.
10. A stale witness replica cannot override a newer independently verified checkpoint.

## Decisions still required

- Witness implementation and its operator trust model.
- Whether the witness is a transparency log, independently operated service, or another append-only system.
- Key rotation and witness identity recovery.
- Retention, replication, monitoring, and disaster recovery.
- Privacy and metadata leakage from publishing provider IDs or head hashes.
- Cost, latency, and behavior during network partitions.

## Current claims that remain valid

The current prototype can validate local journal linkage against an observed external anchor and fail closed on several mismatched states. It does not establish protection against coordinated rollback of both state stores. Qualification remains `NOT_ESTABLISHED` until an independent witness is implemented, tested, and reviewed.
