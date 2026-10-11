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
