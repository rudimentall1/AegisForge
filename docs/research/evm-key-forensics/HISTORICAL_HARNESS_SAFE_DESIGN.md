# Historical Profanity Harness — Safe Design Gate

Status: design review only. No historical seed-generation code has been executed by this design note.

## Objective

Decide whether a narrowly scoped harness can produce useful, reproducible evidence about the pinned historical seed-construction statement without reproducing vanity search or creating/exporting wallet material.

Pinned upstream revision: `johguse/profanity@0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6`.

Relevant function: `Dispatcher::Device::createSeed()` in `Dispatcher.cpp`.

## What the source says

Outside `PROFANITY_DEBUG`, the function constructs `std::random_device rd`, initializes `std::mt19937_64 eng(rd())`, and calls `distr(eng)` four times to populate four 64-bit words. The four words are outputs from one PRNG engine initialized by one call to `rd()`; they are not four separate calls to the entropy source.

This does not tell us the effective entropy of `rd()`, the concrete engine state space on a given implementation, or whether any particular build's output is predictable.

## Harness options and decision

| Option | Evidence it could provide | Main limitation / risk | Decision |
|---|---|---|---|
| Static source-semantic checker | Confirms the pinned source contains the expected construction pattern and source hash | Does not exercise C++ runtime behavior | **Proceed first** |
| Environment-only `random_device` probe | Records bounded type, reported entropy, and observations for the current toolchain | Does not exercise historical application code or prove entropy | Already implemented; keep separate |
| Fixed synthetic-seed PRNG control | Tests deterministic expectations and positive/negative controls | Tests a synthetic fixture, not the historical entropy source | Use only as a control |
| Execute historical `createSeed()` and record its four words | Exercises more of the historical runtime path | Creates seed-like material and can be misrepresented as a wallet-key reproduction; output disclosure adds risk without proving exploitability | **Do not implement in the initial MVP** |
| Build and run full Profanity | Could reproduce application behavior in its original context | Invokes wallet/vanity-search path and may emit private-key material | **Out of scope; stop** |

## First implementation gate

Implement a local, offline static checker for a repository-owned copy of the *small reviewed source excerpt*, not a downloaded-and-executed binary. It should:

1. Require the expected upstream commit SHA as a literal constant.
2. Hash the supplied pinned source file or reviewed excerpt and report the exact hash checked.
3. Check for the expected sequence: one `rd()` in the engine initialization and four `distr(eng)` calls in the non-debug branch.
4. Detect and report the `PROFANITY_DEBUG` fixed-seed branch separately.
5. Fail closed if the excerpt is missing, ambiguous, or does not match the reviewed pattern.
6. Emit JSON with a narrow conclusion such as `SOURCE_PATTERN_MATCHED` or `INCONCLUSIVE`.
7. Explicitly set `historical_code_executed=false`, `wallet_material_used=false`, and `historical_vulnerability_reproduced=false`.
8. Never download source at runtime, execute the historical application, produce key/address material, or access the network.

The checker must not claim to prove the source file came from upstream merely because a locally supplied SHA matches. Upstream provenance must be established separately from the pinned commit and reviewed source reference.

## Negative controls

- Change the seed initialization to contain two `rd()` calls: the source-pattern predicate must fail.
- Change one `distr(eng)` call: the expected count predicate must fail.
- Remove the debug branch marker: the checker must flag an ambiguous/unreviewed source excerpt.
- Supply an unrelated file: the checker must return `INCONCLUSIVE`, not a success-shaped result.

## Build identity boundary

A compiler/toolchain manifest is useful only for a build that is actually performed. A static source checker must not emit a `BUILD_RECORDED` or `HISTORICAL_PATH_EXERCISED` status. If no safe runtime experiment directly supports a stronger claim, stop at source review and label historical reproduction `INCONCLUSIVE`.

## Acceptance criteria

- Unit tests cover all positive and negative controls.
- JSON output is deterministic and machine-readable.
- No network, subprocess, wallet material, private keys, public keys, addresses, or vanity-search loop.
- Existing lab receipt/verifier formats are reused if artifact packaging is added; no parallel signature format.
- A passing CI run establishes only that the checker behaves as specified.
