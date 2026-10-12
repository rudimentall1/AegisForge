# Replay Registry Recovery Protocol

Status: recovery is not implemented. This document defines constraints for future recovery work.

## Current evidence persistence

The registry stores the canonical JSON representation of each accepted signed receipt envelope and its dossier in `attestation_replay_evidence`. The evidence row is committed in the same SQLite transaction as the accepted-attestation reservation, journal event, and journal state. It is linked by provider ID, sequence, run ID, nonce, receipt digest, and journal head. The data is evidence to re-verify, not a trusted source by itself.

## Recovery must fail closed

The anchored write path commits SQLite state before performing an external compare-and-set (CAS). A failure between these operations can leave the local database ahead of the external anchor. A local hash chain is unkeyed, so an attacker with database write access can forge a consistent suffix. Never advance an external anchor merely because the local chain is internally consistent.

Given an external anchor `(provider_id, A_seq, A_head)`, a future recovery implementation must:

1. Read the anchor from a linearizable store outside the SQLite backup/restore domain.
2. Verify the complete local chain and ensure its event at `A_seq` matches `A_head` exactly. Never move the anchor backward.
3. For every event after the anchor, load the stored dossier and envelope, re-run signature and dossier-binding verification with independently provisioned trusted keys and current trust policy, and match provider, run ID, nonce, receipt digest, sequence, and journal head.
4. Produce a deterministic plan without mutating the database or anchor. Bind the plan to the observed anchor, suffix event IDs, receipt digests, trust-policy version, and terminal head.
5. Require an operator to confirm that exact plan. Any changed anchor or suffix invalidates the plan.
6. CAS from the exact observed anchor to the verified terminal head. A conflict requires investigation and a fresh plan, not blind retry.
7. Write the decision and plan digest to an independent audit sink. If that sink is unavailable, do not claim recovery completed.

Missing, malformed, duplicated, or mismatched evidence is a hard failure. Do not truncate or rewrite an unexplained suffix automatically.

## Concurrency and crash boundaries

SQLite transactionality does not make the local commit and external CAS a distributed transaction. Concurrent writers can leave an unanchored suffix even if the external anchor rejects one writer. Before production use, writes need per-provider serialization across processes and hosts, or a redesigned protocol that prevents unanchored commits from being treated as accepted.

Fault-injection tests must cover process termination before SQLite commit, after commit but before CAS, after CAS success but before returning, audit-sink failure, simultaneous writers, anchor timeout, CAS conflict, stale backup restore, deleted evidence, modified middle events, expired/revoked keys, and an anchor ahead of local SQLite.

## Acceptance criteria

- No local-only fallback when the external anchor is unavailable.
- Exact signed evidence persisted atomically with each journal event.
- Every suffix receipt and every journal link re-verified from the trusted anchor.
- Operator-confirmed immutable plan and independent audit record.
- Cross-process serialization or equivalent proven protocol.
- Replay detection, tamper evidence, rollback resistance, and runner qualification documented as distinct properties.

Until these controls are implemented and tested, recovery and production rollback resistance remain `NOT_ESTABLISHED`.

## Implemented read-only planner

`shared/replay_registry_recovery.py` now implements a read-only recovery-plan builder. The caller must supply the anchor value read from the real external store and the independently provisioned trusted public keys. The planner checks the entire local journal, matches the supplied anchor to the exact historical head, verifies row counts and bindings across journal, accepted records, and stored evidence, and re-verifies every signed receipt/dossier pair before describing the unanchored suffix. It returns a deterministic plan digest and explicitly reports that it performed no writes and did not update the anchor.

This is not the recovery executor. The plan must be revalidated against a freshly read anchor before any future operator-confirmed CAS. Cross-process writer serialization, the operator confirmation workflow, and an independent audit sink are still not implemented. A valid plan is not permission to execute or qualify a lab result.


`revalidate_replay_recovery_plan(...)` now rebuilds the plan from the current local registry and the freshly supplied external anchor values, then requires exact equality with the reviewed plan. It rejects a mutated plan or a plan made stale by a changed registry suffix. The caller is responsible for actually reading the current anchor from the authoritative store; reusing the old anchor values defeats the freshness check. Revalidation remains read-only and is not an approval or CAS operation.
