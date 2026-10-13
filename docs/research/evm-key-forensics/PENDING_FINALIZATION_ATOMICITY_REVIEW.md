# Pending finalization atomicity review

Status: design finding, not a production qualification.

## Finding

The pending-first replay path verifies that the external anchor equals the candidate head immediately before calling `_finalize_pending`. The finalizer then re-verifies the signed dossier and envelope, checks the candidate hash, reads local journal state, and writes accepted state and the pending status.

The external anchor and local SQLite database are separate transactional systems. The final anchor read and the local acceptance commit are not atomic with one another. The anchor can move after the final read but before local finalization commits. A successful read therefore proves only that the candidate was anchored at the instant of that read; it does not lock that head for the duration of local finalization.

This is a time-of-check/time-of-use window. Re-reading the anchor later narrows the window but does not remove it.

## Required invariant

A result must not be described as currently externally anchored unless the system can prove the relationship between the exact local acceptance commit and an authoritative anchor state under the documented concurrency model.

The existing `qualification=NOT_ESTABLISHED` label must remain. The current final-read pattern is useful fail-closed defense, but it is not a distributed transaction.

## Safe next design

Before changing the acceptance semantics, choose and specify one protocol:

1. **Anchor-side reservation/lease.** The anchor atomically reserves a provider sequence for a candidate and prevents conflicting advancement until the local commit is acknowledged or the lease expires. The protocol must define expiry, recovery, and fencing tokens.
2. **Transactional outbox with reconciliation.** Persist a candidate as unaccepted, publish its exact head through CAS, then commit acceptance only after authoritative confirmation. If another writer advances the anchor after confirmation, define whether acceptance means historically anchored or current head; never silently imply the latter.
3. **Single authority service.** Move both the replay registry mutation and anchor advancement behind one service boundary with durable serialization, while retaining independently protected rollback evidence.

A second read alone is not a complete solution.

## Required fault-injection tests

- Anchor changes to an unrelated successor after the final pre-finalization read but before the SQLite acceptance commit.
- Two independent processes attempt distinct candidates from the same prior head.
- CAS commits but the response is lost.
- Local commit succeeds but the process dies before marking the pending candidate finalized.
- A candidate is anchored, then a later valid candidate advances the anchor before the first caller returns.
- Recovery starts while another process is finalizing the same candidate.

Each test must assert accepted rows, pending status, local journal head, external anchor head, and the exact success/error result. Tests must distinguish “anchored at a point in time” from “the current external head”.

## Acceptance criteria

- No candidate is reported successful before the exact candidate has been confirmed by the anchor.
- Duplicate `run_id` or `nonce` cannot be accepted twice under concurrent writers.
- Unknown outcomes remain pending and require authoritative reconciliation.
- An unrelated anchor advance never triggers automatic truncation, rewriting, or anchor advancement.
- The result metadata accurately describes whether the returned head was confirmed historically or is still the current external head.
- Qualification remains `NOT_ESTABLISHED` until independent-anchor and operational fault-injection testing are complete.
