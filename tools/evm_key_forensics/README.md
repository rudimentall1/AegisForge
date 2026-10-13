# Profanity seed environment probe

This utility is a small diagnostic for a **disposable, isolated research environment**. It is not Profanity, does not compile or execute historical Profanity source, and does not use wallet addresses or private keys.

## Build and run

With a C++11-or-newer compiler:

```sh
c++ -std=c++11 -O2 -Wall -Wextra -pedantic \
  tools/evm_key_forensics/profanity_seed_environment_probe.cpp \
  -o profanity_seed_environment_probe
./profanity_seed_environment_probe 256
```

The optional sample count is bounded to 1–10,000. Save the compiler command, compiler version, OS/container image identity, stdout, stderr, and SHA-256 hashes alongside the output if using this as an experiment artifact.

## Interpretation

The output records:

- the bit width of `std::random_device::result_type`;
- the implementation's `random_device::entropy()` report;
- the number of distinct outputs in a bounded sample;
- compiler-family and standard-library version macros when exposed.

**These observations do not prove entropy.** `entropy()` may be an implementation-provided estimate, and a finite sample cannot establish unpredictability or the true support of the distribution. The probe reports environmental context only. It does not establish how a historical Profanity build behaved, whether its seed was predictable, or whether any wallet was vulnerable.

## Next research gate

To move beyond this diagnostic, a separate controlled experiment must pin the historical source revision and toolchain, exercise the relevant historical code path in an isolated environment, predefine the property being tested, and export an artifact that the independent AegisForge Validator can check. Until that exists, keep the historical reproduction status `INCONCLUSIVE`.

## Combined evidence ZIP verification

For the combined package published by the EVM Key Forensics Probe workflow, download `evm-key-forensics-complete-evidence.zip` and run:

```sh
python tools/evm_key_forensics/verify_complete_evidence.py evm-key-forensics-complete-evidence.zip
```

A successful result verifies archive member safety, the probe bundle's internal hashes, and consistency between the probe metadata, independent rebuild report, and combined index. It reports `UNTRUSTED_UNSIGNED` and `NOT_CHECKED_OFFLINE` for authenticity and GitHub attestation because those checks are separate. Verify provenance against the exact downloaded ZIP with:

```sh
gh attestation verify evm-key-forensics-complete-evidence.zip --repo rudimentall1/AegisForge
```

The offline verifier does not execute files from the archive. It does not prove historical Profanity runtime behavior or upgrade the research conclusion beyond `INCONCLUSIVE`.

## Portable artifact verification

For a lab experiment exported by the AegisForge runner, use the shared offline verifier from the repository root:

```sh
python -m shared.verify_lab_artifact path/to/experiment.json
```

To verify a signed receipt, provide the signer's public key through a trust decision made independently of the artifact:

```sh
python -m shared.verify_lab_artifact path/to/experiment.json \
  --trusted-key runner-key=path/to/runner-key.pub
```

The key ID must match the receipt envelope. The public key must be obtained and trusted out-of-band; accepting a public key supplied only inside the same artifact would not establish trust. Never put a signing private key in the artifact or repository.

Exit codes:

- `0`: integrity checks pass and the receipt signature verifies against an explicitly configured trusted key.
- `1`: malformed input or failed integrity checks.
- `2`: internal integrity checks pass, but the artifact is unsigned or its signature is invalid/untrusted.

A self-consistent artifact is not necessarily authentic: anyone able to edit an unsigned artifact can recompute its hashes. A trusted signature authenticates the signed statement under the configured key, not the honesty, isolation, or correctness of the runner. The verifier is offline and does not contact the issuer.

## Known-vulnerability benchmark

The source-backed Profanity benchmark defines evidence labels, negative controls, confounder handling, and the acceptance boundary for a known historical case:

- [Known-vulnerability benchmark](../../docs/research/evm-key-forensics/KNOWN_VULNERABILITY_BENCHMARK.md)

The case is publicly documented by the upstream maintainer and CVE-2022-40769. That makes it a useful detection benchmark, not proof that this project reproduced the historical exploit. The current lab remains synthetic-only; do not use target wallet addresses or implement private-key recovery.

Run the new deterministic classification benchmark from the repository root:

```sh
python -m tools.evm_key_forensics.known_vulnerability_benchmark --pretty
pytest -q tests/test_known_vulnerability_benchmark.py
```

The benchmark includes a positive Profanity case, a generic PRNG negative, two vulnerability-class confounders, and a missing-source case. It is a small rule-based baseline with synthetic text fixtures, not a measurement of the full agent pipeline. Its report keeps historical runtime reproduction and individual-wallet exposure as `NOT_ESTABLISHED`.
