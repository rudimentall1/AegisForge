# EVM Key Forensics — Experiment Acceptance Matrix

Status: planning artifact; no historical vulnerability reproduction is claimed.

## Decision under test

**Narrow claim:** the reviewed historical Profanity seed-construction path initializes `std::mt19937_64` from one call to `std::random_device::operator()()`, then derives four machine-word outputs from that engine. The four outputs are therefore deterministic functions of the engine state; they are not four independent entropy-source calls.

This is a source-semantics claim. It is not a claim that the seed has exactly 32 bits of entropy, that any particular build is exploitable, or that a real key can be recovered.

## Evidence levels

| Level | Required evidence | Permitted conclusion |
|---|---|---|
| E0 — Source inspection | Immutable upstream commit and reviewed function | `SOURCE_REVIEWED` |
| E1 — Build identity | Source file hashes, compiler, standard library, OS/image, flags | `BUILD_RECORDED` |
| E2 — Runtime observation | Bounded diagnostic of `random_device` type and implementation behavior | `ENVIRONMENT_OBSERVED`; not an entropy proof |
| E3 — Synthetic control | Predeclared finite toy state space; positive and negative controls; deterministic expected results | `SYNTHETIC_MODEL_VALIDATED`; not historical exploitability |
| E4 — Historical behavior | Isolated harness exercises the pinned historical seed-construction path, with exact build provenance and independently checked outputs | `HISTORICAL_PATH_EXERCISED`; still not a wallet compromise claim |
| E5 — Independent review | Reviewer independently checks inputs, raw artifacts, verifier output, assumptions, and conclusion | Claim may be promoted only to the level actually supported |

## Required controls

1. **Positive control:** a small, repository-owned synthetic fixture whose expected output is calculated and checked before execution.
2. **Negative control:** a deliberately altered fixture or input that must fail the same acceptance predicate.
3. **Mutation control:** alter one recorded source/output digest and confirm artifact verification fails.
4. **Interpretation control:** ensure the output explicitly states that sample diversity and `random_device::entropy()` are not proof of cryptographic entropy.
5. **Scope control:** the experiment must not derive private keys, public keys, or addresses; search wallet candidates; accept target addresses; query balances; or export key material.

## Reproducibility manifest

Every experiment artifact should record:

- experiment ID and schema version;
- immutable upstream repository URL and commit SHA;
- hashes of the exact reviewed source files and local harness;
- compiler version, standard library, OS/container image digest, and complete build command;
- exact command, exit status, and bounded resource limits;
- raw stdout/stderr hashes and structured output hash;
- positive- and negative-control identifiers and outcomes;
- verifier version and verifier result;
- conclusion, assumptions, limitations, and reviewer identity;
- explicit booleans for historical source execution and wallet material use.

Do not treat a hash manifest as proof of authorship. If a signature is used, verify it against a public key configured independently of the artifact. A valid signature authenticates a signer statement, not the truth of the experiment or the integrity of the runner.

## Stop conditions

Stop and report `INCONCLUSIVE` if the exact historical path cannot be built safely, toolchain details cannot be pinned, a negative control is absent, outputs cannot be independently checked, or the test would require running the vanity-search workload or handling wallet material.

## Current status

- Source review: complete.
- Environment diagnostic: implemented; CI-tested.
- Portable integrity verifier: implemented; CI-tested; unsigned artifacts remain untrusted.
- Synthetic controls for a historical-path experiment: not yet implemented as a distinct experiment.
- Historical vulnerability reproduction: **not established**.
- Wallet compromise: **not tested and not claimed**.

## Next engineering gate

Before expanding the pipeline, implement one bounded experiment that satisfies the controls above and exports a manifest. Reuse the existing lab receipt/verifier architecture where it fits; do not create a parallel signature format. Run it only in a disposable, isolated environment, never on the production agent farm.
