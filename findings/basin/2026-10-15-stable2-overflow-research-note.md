# Basin — Stable2.calcLpTokenSupply arithmetic overflow (research note, REJECTED)

**Date researched:** 2026-10-15
**Status:** Research note — NOT SUBMITTED. Initial Critical hypothesis was disproven by PoC. Kept for methodology tracking.
**Severity assessment:** Low / Informational (would be $0–$500 if submitted)
**Component:** `src/functions/Stable2.sol` → `calcLpTokenSupply()`
**Repository:** https://github.com/BeanstalkFarms/Basin
**Related audit:** Cyfrin Basin audit (2023-06-16) — H-3 and M-2 do NOT cover this

## Summary

`Stable2.calcLpTokenSupply()` (the StableSwap invariant solver used by Basin Wells) reverts with `Panic(0x11)` (arithmetic overflow) for valid non-zero reserves that differ by more than approximately 10^6 (6-decimal tokens) or 10^12 (18-decimal tokens). This is a real code-level bug.

Initial hypothesis: an attacker could permissionlessly drive a Well into this regime via a single large swap, then trigger a subsequent Well call, causing `MultiFlowPump.update()` to overflow, return `[0, 0]` from `tryCalcLPTokenUnderlying`, and reset the pump — destroying the oracle and triggering downstream effects in Beanstalk.

This hypothesis was **disproven by a full PoC against the real Well + Stable2 + MultiFlowPump stack**. The pump's `_capReserves` correctly handles the overflow via the try/catch path: `_capLpTokenSupply` returns an empty array on overflow, forcing `_capRates` to run first and cap reserves back into a safe range. The pump is NOT reset.

## What was confirmed

### 1. calcLpTokenSupply overflow (real bug)

Fuzz test with r0 ~ 1e18 and r1 ~ 1e11 for 6-decimal tokens (ratio 10^7) and r0 ~ 1e30, r1 ~ 1e18 for 18-decimal tokens (ratio 10^12) triggers Panic(0x11) inside `calcLpTokenSupply`.

Reproducer:

    forge test --match-test testFuzzRealistic18Decimals -vv
    // counterexample: r0 = 1e30, r1 = 1e18

Root cause: inside the Newton iteration, the intermediate

    dP = dP * lpTokenSupply / (scaledReserves[0] * N)

overflows uint256 because dP grows without bound when reserves are extremely imbalanced.

### 2. Reachability via Well (confirmed)

`Well.swapFrom()` uses `calcReserve` (which does NOT overflow on the same inputs) for the swap math, and `_setReserves()` writes the resulting extreme reserves to storage. A single large swap therefore creates reserves[0] ~= 1e30 and reserves[1] ~= 5e11 in a 2-token 18-decimal Well seeded with 1e24/1e24.

### 3. Pump reset via tryCalcLPTokenUnderlying (disproven)

In isolation, `tryCalcLPTokenUnderlying(MAX_UINT256_SQRT, reserves, ...)` returns `[0, 0]` for extreme reserves, which would cause `MultiFlowPump.update()` to hit the reset branch and reset the pump.

However, in the real update flow, `_capReserves` runs BEFORE this reset check and never returns `[0, 0]`:

    cappedReserves = _capLpTokenSupply(lastReserves, reserves, ..., true);
    if (cappedReserves.length == 0) {
        cappedReserves = _capRates(lastReserves, reserves, ...);
        cappedReserves = _capLpTokenSupply(lastReserves, cappedReserves, ..., false);
    } else {
        cappedReserves = _capRates(lastReserves, cappedReserves, ...);
    }

`_capLpTokenSupply` returns an empty array when the overflow-driven lpTokenSupply == MAX_UINT256_SQRT exceeds the capped max LP supply and returnIfBelowMin == true. The flow then runs `_capRates` first, which caps reserves back into a safe band via `calcReservesAtRatioSwap`. The final `_capLpTokenSupply(..., false)` call returns bounded reserves, not `[0, 0]`.

End-to-end PoC output (`test/FullPumpResetPoC.t.sol`):

    === After seeding ===
    reserves[0]: 1001000000000000000000000
    reserves[1]: 1001000000000000000000000
    Pump reserves[0] before: 1000000000000000000000000
    Pump reserves[1] before: 1000000000000000000000000
    === TX1: attacker swap (extreme imbalance) ===
    reserves[0] after swap: 1000001001000000000000000000000
    reserves[1] after swap: 501501249498
    === TX2: small swap triggers Pump.update ===
    swap2 succeeded
    === Pump state after ===
    Pump reserves[0] after: 76886718750000000000000
    Pump reserves[1] after: 76886718750000000000000
    Pump NOT reset (values still non-zero)

## Why it is Low / Informational, not Critical

- No funds lost: swap, addLiquidity, removeLiquidity all use `calcReserve`, which does not overflow on the same inputs.
- Pump survives: `_capReserves` path handles the overflow via try/catch and bounded re-derivation.
- The only user-visible symptom is a revert in direct `calcLpTokenSupply` calls (view / off-chain) and inside `Well.sync()` on extreme reserves — recoverable by `skim()` if triggered by an unsolicited transfer.

## Why we did NOT submit to Immunefi

Beanstalk Immunefi requires a runnable PoC demonstrating impact. The impact here is limited to a temporary revert of `calcLpTokenSupply` on extreme reserves, with no loss of funds and no oracle corruption. It does not meet the Critical or High bar, and would likely be rejected as Informational / Low.

## Repository state at time of research

- Basin: commit at the time of `test/FullPumpResetPoC.t.sol` run
- Relevant audit: `Beanstalk-Audits/ecosystem/06-16-23-basin-cyfrin-report.txt`
  - [H-3] removeLiquidity logic — different issue, resolved
  - [M-2] LibLastReserveBytes::storeLastReserves — different issue, acknowledged
- New: `calcLpTokenSupply` overflow is NOT covered by either finding

## Recommendation (for downstream auditors)

If `Stable2.calcLpTokenSupply` is ever called directly by a consumer that trusts its output on extreme reserves, that consumer will see a revert rather than a wrong answer. Consider adding a bounded input check in the caller, or documenting the max safe ratio (~10^6 for 6-decimal tokens, ~10^12 for 18-decimal tokens) in the Well function NatSpec.
