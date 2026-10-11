# EVM Key Forensics: Profanity source review

Status: source-level review only; not a vulnerability reproduction.

## Scope

Compare the pinned pre-disclosure release and post-disclosure archive of `johguse/profanity`.

- Pre-disclosure tag: `v1.50`
- Pinned pre-disclosure commit: `0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6`
- Post-disclosure ref: `master`
- Pinned post-disclosure commit: `186b9b27ab3e24a1899f648adcabcbf0e5f3131e`

All source URLs must use these immutable commit SHAs, not moving branch or tag names.

## Observations from the pinned source

### 1. Seed initialization appears unchanged in the reviewed file

In `Dispatcher.cpp`, both pinned revisions contain the same relevant sequence in `Dispatcher::Device::createSeed()`:

```cpp
std::random_device rd;
std::mt19937_64 eng(rd());
std::uniform_int_distribution<cl_ulong> distr;

cl_ulong4 r;
r.s[0] = distr(eng);
r.s[1] = distr(eng);
r.s[2] = distr(eng);
r.s[3] = distr(eng);
return r;
```

Source links:

- [Pre-disclosure Dispatcher.cpp](https://github.com/johguse/profanity/blob/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/Dispatcher.cpp)
- [Post-disclosure Dispatcher.cpp](https://github.com/johguse/profanity/blob/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/Dispatcher.cpp)

This is a source-level observation, not by itself a complete proof of effective entropy. The security conclusion depends on the actual `std::random_device` implementation and seed-sequence behavior in the relevant build/runtime environment. The code shown seeds `std::mt19937_64` with a single value from `rd()`; do not equate the 64-bit output width of the PRNG with 64 bits of seed entropy.

### 2. The post-disclosure README explicitly warns users

The pinned post-disclosure README says the project was abandoned after fundamental private-key-generation security issues were reported, advises against use, and links issue #61. This is primary-source evidence that the maintainer acknowledged a serious issue, but the README is not a substitute for reproducing the defect.

- [Post-disclosure README](https://github.com/johguse/profanity/blob/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/README.md)
- [Issue #61](https://github.com/johguse/profanity/issues/61)

## Current conclusion

- `SOURCE_REVIEWED`: the relevant seed initialization pattern is present in both pinned versions.
- `HISTORICAL_IMPLEMENTATION_REPRODUCED`: **false**.
- `VULNERABILITY_REPRODUCED`: **not established by this review**.
- `INCONCLUSIVE` remains the correct experiment status until a bounded, reproducible test validates the historical behavior.

## Safe next experiment

Build a harness that tests the seed-generation property using synthetic fixtures and a pinned toolchain/runtime. The harness should:

1. Record OS, compiler, standard-library implementation/version, build flags, and exact source commit.
2. Separate source-derived facts from assumptions about runtime entropy.
3. Use synthetic seed samples only; never import or enumerate real wallet addresses or private keys.
4. Define the expected property before running the test and include a negative/control case.
5. Emit a machine-readable result, command, stdout/stderr hashes, source-file SHA-256 values, and environment manifest.
6. Be independently verifiable from the exported artifact. A signature authenticates the signer only when checked against an explicitly trusted key; it does not prove the runner is honest.

Do not execute historical code on the production agent-farm host. Use a disposable isolated environment with no credentials, network access disabled during execution, resource limits, and a read-only pinned source checkout.

## Acceptance criteria

A reproduction claim requires all of the following:

- immutable source revision and file hashes;
- pinned, recorded toolchain/runtime;
- a predeclared test vector or synthetic fixture;
- a passing experiment that actually exercises the relevant historical implementation;
- a structured result artifact bound to the command and source;
- independent validation of the artifact and reproduction criteria.

Until those conditions hold, describe the result as source review or a synthetic harness test—not as recovery of real wallet keys or proof that a specific live wallet is vulnerable.
