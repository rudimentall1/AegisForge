# Arbitova — Dust retained by independent floor divisions in resolve()

**Date found:** 2026-10-15 (provided by researcher)  
**Date submitted:** Not submitted  
**Severity:** Low (researcher-assessed; not independently validated)  
**Status:** PoC reported as ready; not submitted  
**Component:** `EscrowV1.resolve()`  
**Contract:** `0xA8a031bcaD2f840b451c19db8e43CEAF86a088fC` on Base Sepolia (address supplied by researcher; deployment not independently verified here)  
**Source revision:** Unknown  
**PoC:** `test/forked/ArbitovaResolve.t.sol` in local `~/arbitova`; file was not available in the repository context used to create this record.

## Summary
The researcher reports that separate floor divisions used to compute buyer and seller gross amounts can leave a small remainder in the escrow contract for some low-value amounts. The report says a fork test passed and printed `=== DUST LOCKED IN CONTRACT ===`; this result was not independently reproduced for this tracker.

## Technical details
The alleged issue is rounding dust caused by separate integer divisions in `resolve()`. Whether the remainder is permanently inaccessible, economically material, or already covered by intended accounting semantics remains to be established against the exact contract source and test.

## Proof of Concept
Not independently run here. The local PoC file was not supplied. Do not represent the reported test output as independently verified evidence.

## Impact and severity rationale
Potential impact is residual value retained by the contract for affected small amounts. Confirm whether the amount is recoverable, who owns the remainder, the minimum viable transaction, and aggregate worst-case loss before final severity assessment.

## Recommendation
Use a conservation-of-funds invariant in tests, explicitly define ownership of rounding remainder, and route any remainder deterministically to a documented recipient or refund path.

## Timeline
- 2026-10-15 — report details and claimed PoC result supplied by researcher.
- 2026-10-15 — recorded as not submitted.
