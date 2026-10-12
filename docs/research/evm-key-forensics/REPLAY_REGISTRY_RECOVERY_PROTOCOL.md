# Replay Registry Recovery Protocol

Status: design constraint, not an implemented recovery feature.

## Problem

The replay registry commits an accepted receipt and an unkeyed local hash-chain event in one SQLite transaction. The anchored adapter publishes the new head in a separate external compare-and-set (CAS). A process failure or CAS error between those operations can leave SQLite ahead of the external anchor.

That state must be treated as unavailable for new accepted work. A local hash chain is useful for detecting inconsistent edits against its stored state, but it is not proof that an unanchored suffix was created by valid signed receipts. An attacker able to rewrite the database can recompute an unkeyed suffix.

## Non-negotiable recovery rules

1. Never advance an external anchor to a local head merely because the local chain is internally consistent.
2. Never accept new receipts while the local sequence/head differs from the external anchor.
3. Never describe a failed anchored call as accepted or safe to execute, even if its SQLite transaction committed.
4. Do not automatically truncate, rewrite, or re-anchor an unexplained suffix.
5. Recovery must be an explicit operator action and must leave an audit record outside the SQLite restore domain.
6. If the evidence needed to verify every event in a suffix is absent or ambiguous, recovery must stop and require restoration from a trusted backup or manual incident handling.

## Evidence required for a recoverable suffix

A future implementation must durably retain the exact signed receipt envelope and the exact dossier used for each journal event. The record must be committed in the same SQLite transaction as the replay reservation and journal event. It must be linked by provider ID, run ID, nonce, receipt digest, key ID, journal sequence, and journal head.

The stored envelope and dossier are evidence to re-verify, not trusted inputs. During recovery, every suffix record must be revalidated against an independently provisioned trust policy and pinned public keys. The recomputed verified receipt digest and identity fields must match the journal event exactly. Missing, duplicate, malformed, or mismatched evidence is a hard failure.

The database is still mutable by an attacker. Therefore stored receipts alone do not make the database trustworthy; they only let an operator independently re-verify what the suffix claims to contain. Trust must originate from the signatures and out-of-band keys/policy, while the anchor establishes the last trusted prefix.

## Required recovery algorithm

Given external anchor (provider_id, A_seq, A_head):

1. Read and validate the anchor from a linearizable external store.
2. Verify the local journal from genesis, including all sequence numbers, previous-head links, event hashes, and journal state.
3. Confirm that the event at A_seq has head A_head. If the local chain is shorter than the anchor, or its prefix conflicts with the anchor, stop. Never roll the external anchor backward.
4. For each event with sequence greater than A_seq, load its durable signed envelope and dossier. Re-run the normal attestation verifier with currently valid trust policy and pinned keys. Verify exact provider/run/nonce/digest binding and ensure each event's journal link is continuous.
5. Produce a recovery plan containing the anchor, suffix event IDs, receipt digests, verifier/key-policy version, and proposed resulting head. Do not mutate state while generating the plan.
6. Require an explicit operator confirmation of that exact plan. Any change to the anchor or local suffix invalidates the plan and requires a fresh verification.
7. Publish only the verified terminal head with CAS from the exact original (A_seq, A_head) to the verified terminal (N_seq, N_head). A conflict means stop and investigate; do not retry against a newly observed anchor without re-verifying.
8. Record the recovery decision and plan digest in an independent audit sink. If the external audit sink is unavailable, do not claim recovery completed.

This algorithm is a target contract, not currently available functionality. In particular, current registry records do not durably retain the original signed envelope and dossier, and the current anchored adapter does not implement recovery or a distributed write lock.

## Concurrency and crash requirements

The ordinary anchored write path has a local SQLite transaction followed by external CAS; these are not one distributed transaction. Two callers can race after reading the same anchor. CAS protects the external head from conflicting updates, but a losing call may already have committed locally. Production use therefore also needs a per-provider serialization mechanism or a redesigned protocol that prevents unanchored local commits from being treated as accepted.

A production implementation must test process termination at each boundary: before SQLite commit, after SQLite commit, before CAS, after CAS success but before returning, and during audit publication. It must also test two simultaneous writers, anchor-service timeout, CAS conflict, stale backup restore, deleted suffix evidence, modified middle events, expired/revoked signing keys, and an external anchor ahead of local SQLite.

## Acceptance criteria before production claims

- No local-only fallback when the anchor is unavailable.
- No automatic re-anchoring based on local hashes alone.
- Exact signed receipt and dossier evidence persisted atomically with each accepted event.
- Recovery verifies every suffix receipt and its complete journal linkage from the trusted anchor.
- Per-provider writes are serialized across processes and hosts, or the protocol proves equivalent safety.
- Recovery requires an operator-confirmed immutable plan and writes an independent audit event.
- Fault-injection and concurrency tests cover the boundaries above.
- Documentation distinguishes replay detection, tamper evidence, rollback resistance, and independent runner qualification. None implies the others.

Until these criteria are implemented and tested, recovery and production rollback resistance remain NOT ESTABLISHED.
