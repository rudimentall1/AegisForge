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
- Environment diagnostic: implemented; CI-tested. It records bounded environment observations, not cryptographic entropy.
- Portable integrity verifier: implemented; CI-tested; strict JSON parsing rejects duplicate keys and non-standard constants in the exported artifact and structured result payload. Unsigned artifacts remain untrusted.
- Synthetic positive/negative control harness: implemented and covered by tests; it validates only the repository-owned toy state space.
- Portable verification instructions: documented in `tools/evm_key_forensics/README.md`; signed artifacts require a public key trusted independently of the artifact.
- Latest observed CI: `AegisForge CI` ([run 38136331275](https://github.com/rudimentall1/AegisForge/actions/runs/38136331275)) and `EVM Key Forensics Probe` ([run 38136331264](https://github.com/rudimentall1/AegisForge/actions/runs/38136331264)) both passed at commit `d710cb26e36f4c4253dabfabbeb43e778b3e3c61`. These are CI results for the checker and tests, not independent validation of the historical claim.
- E3 status: **synthetic harness controls pass**; this validates only the toy model and its control logic, not the historical Profanity behavior.
- E1 build identity: not yet complete for a historical reproduction.
- E4 historical-path reproduction: **not established**.
- Portable artifact gate: **automated CLI coverage passes** for a valid synthetic artifact signed by a trusted key (exit `0`), an artifact mutated after signing (exit `1`), and a validly signed artifact checked against an unrelated trusted key (exit `2`). Tests exercise the verifier CLI using generated synthetic fixtures; no manually captured external artifact bundle has yet been archived. See [AegisForge CI](https://github.com/rudimentall1/AegisForge/actions/runs/38136331275).
- E5 independent review: pending.
- Wallet compromise: **not tested and not claimed**.

## Next engineering gate

The portable verifier gate is now covered by automated CLI tests, but this does not validate the historical vulnerability. Next, prepare a design-only plan for a bounded build-identity/seed-construction harness around the pinned historical source. Before implementation, document the exact source lines, required compiler/standard-library provenance, expected observations, and an independent negative control. Do not invoke vanity search, generate wallet material, or accept real addresses. If the historical seed-construction path cannot be exercised safely without running the wallet-search workload or handling key material, stop at source review and report `INCONCLUSIVE`.

Reuse the existing lab receipt/verifier architecture where it fits; do not create a parallel signature format. Never run this experiment on the production agent farm.
