# Profanity Historical Reproduction Protocol

Status: protocol proposed; historical vulnerability reproduction is **not established**.

## Research question

Can the key-generation seed construction in a pinned historical Profanity revision be shown, under a recorded build/runtime environment, to have a materially narrower or predictable state space than the application assumes?

This protocol is deliberately limited to immutable source review, build-environment identification for harmless diagnostics, and synthetic statistical or deterministic tests. It does not attempt to recover keys, scan addresses, target funded wallets, or reproduce vanity-address searching. The historical `createSeed()` function must not be executed by this project: it produces seed material in the real key-generation path, and an operational harness around it would cross the agreed safety boundary.

## Pinned source and primary references

- Pre-disclosure revision: `johguse/profanity@0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6`
- Historical seed function: [Dispatcher.cpp at pinned revision](https://github.com/johguse/profanity/blob/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/Dispatcher.cpp)
- Historical build recipe: [Makefile at pinned revision](https://github.com/johguse/profanity/blob/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/Makefile)
- Original report: [Issue #61 — Private key safety](https://github.com/johguse/profanity/issues/61)
- Maintainer's later warning: [README at archived revision](https://github.com/johguse/profanity/blob/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/README.md)
- Public disclosure: [1inch security write-up](https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool-68ed7455fc8c)

## Source observation (not a reproduction)

At the pinned revision, `Dispatcher::Device::createSeed()` creates one `std::random_device`, initializes one `std::mt19937_64` from a single `rd()` result, then obtains four values from the PRNG. This means four output words are not four independent calls to the entropy source.

That observation alone does **not** establish:
- the effective entropy of `std::random_device` on a particular platform;
- the number of possible seeds in a concrete build/runtime;
- that a generated key can be predicted or recovered;
- that any real address or wallet is vulnerable.

The GitHub issue records an early hypothesis, not a complete exploit demonstration. The maintainer's later warning and the 1inch disclosure establish that the project had a serious security issue, but AegisForge must independently validate any narrower technical claim it makes.

## Safe lab boundaries

1. Use an ephemeral, disposable VM/container with no credentials, wallet files, cloud metadata access, or production network access.
2. Pin the exact source revision and record source archive SHA-256, compiler and version, standard library, OS image digest, build flags, and relevant runtime configuration.
3. Do not run the full vanity-address search workload. Do not add address targets, candidate-key search, balance checks, or key-export functionality.
4. Limit experiments to a source-level seed-construction harness and synthetic test vectors. The harness must not derive Ethereum private keys, public keys, or addresses.
5. Do not execute downloaded artifacts on the AegisForge production farm. Do not use real wallet material.
6. Preserve raw logs and structured JSON; do not replace failed or inconclusive results with a stronger narrative.

## Experiment stages and gates

### Stage A — Reproducible source/build record

- Verify the pinned commit and source hashes.
- Record the toolchain and dependency versions.
- Review the historical Makefile and dependencies before any build.
- Stop if the test requires enabling the real vanity-search path or emitting key material.

**Pass means:** the source and build environment are identifiable and reproducible. It does not mean the vulnerability is reproduced.

### Stage B — Generic runtime diagnostics

- Use only the repository-owned diagnostic probe, which calls the standard-library API without invoking the historical Profanity function or emitting seed values.
- Record the exact compiler, standard library, OS, build flags, and bounded observations.
- Keep the diagnostic probe distinct from the historical application source.
- Do not interpret observed diversity or a nonzero `entropy()` return as proof of cryptographic unpredictability.

**Pass means:** the diagnostic environment was observed. It does not establish the behavior of the historical application build or prove exploitability.

### Stage C — Bounded synthetic validation

- Define a small synthetic state-space experiment with known expected results before execution.
- Test whether the proposed model predicts those synthetic results.
- Include a negative control that should fail under the same test procedure.
- Have a second verifier check the artifact hashes and the interpretation against the stated acceptance criteria.

**Pass means:** the model survives the specified synthetic test. It does not demonstrate recovery of historical wallet keys.

### Stage D — Independent source-level review

A conclusion stronger than source review is not available from the current implementation. An independent reviewer can check:
- immutable source references and source hashes;
- the exact claim against the pinned source text;
- reproducible checker commands and raw outputs;
- positive and negative controls for the repository-owned synthetic model;
- the limits of every inference.

This review must not execute the historical seed-generation function or turn the project into an operational key-generation/search harness. Any claim requiring historical runtime behavior remains `INCONCLUSIVE` until a separately approved, safe method can establish it without generating or retaining key material.

## Evidence bundle requirements

Keep these fields in the machine-readable manifest:

- schema version and experiment ID;
- pinned upstream commit and source hashes;
- local harness source hash;
- compiler, standard library, OS/container image and build flags;
- exact bounded test command and exit status;
- synthetic test-vector identifier;
- raw output hash and verifier version;
- conclusion and limitations;
- whether the historical application was executed (must remain `false` for this protocol);
- whether wallet material or real target addresses were used (must remain `false`).

Hashes prove file consistency against a manifest, not who produced the files or whether observations are truthful. Authenticity requires a separate trusted signature or provenance mechanism.

## Current conclusion

`SOURCE_REVIEW_ONLY`; `HISTORICAL_VULNERABILITY_REPRODUCED = false`; `INCONCLUSIVE`.

The source checker and generic runtime diagnostic are not a historical reproduction. The next useful gate is independent review of the pinned source claim and its evidence package, including a reviewer independently re-fetching the immutable upstream revisions and recomputing the Git blob IDs. Do not add a harness that executes the historical `createSeed()` path, and do not run this work on the production agent farm.
