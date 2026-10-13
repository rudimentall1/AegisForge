# Direct Cross-Revision Check: Profanity `createSeed()`

Date: 2026-10-13

## Inputs retrieved

The two raw files were fetched directly from GitHub using immutable commit URLs, not read from the AegisForge probe artifact:

- Pre-disclosure: https://raw.githubusercontent.com/johguse/profanity/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/Dispatcher.cpp
- Post-disclosure archive: https://raw.githubusercontent.com/johguse/profanity/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/Dispatcher.cpp

The retrieved file lengths were 16,491 and 16,799 characters, respectively. The GitHub API returned the expected Git blob IDs for these exact files:

| Revision | Commit | `Dispatcher.cpp` blob |
|---|---|---|
| Pre-disclosure | `0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6` | `c9226fc02a52633a84664cbf3aaf2b4af8a59b25` |
| Post-disclosure archive | `186b9b27ab3e24a1899f648adcabcbf0e5f3131e` | `884ced30ed6e55794ea5bda0451b52e81ddec1dd` |

## Direct function extraction

A separate, minimal brace-depth extraction was performed on each retrieved file, starting at the exact signature:

`cl_ulong4 Dispatcher::Device::createSeed()`

The extracted function body, including its opening and closing braces and preprocessor branches, was 357 bytes in each file. The two extracted byte strings compared equal.

The independent source-body review in the CI evidence artifact reports the same SHA-256 function-body fingerprint for both revisions:

`897d89b20fc71072543bb5aa4538c4dfb17c77e81eab5d2af2f749fb1563859c`

The complete files have different SHA-256 and Git blob SHA-1 values. This is consistent with changes elsewhere in the files while this extracted function body remains unchanged.

## Source-level security observation

The production branch contains this sequence in both revisions:

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

This establishes a source-level fact: the PRNG is initialized from one call to `rd()`, and four later distribution outputs are generated from that engine. Those four outputs are not four independent entropy-source calls. The diagnostic run also reported `random_device` result type width and reported entropy as 32, but the probe explicitly does not treat those observations as proof of cryptographic entropy.

Do not convert this observation into a claim of exactly 32 bits of effective entropy, predictable private keys, or compromised wallets. Those stronger conclusions require evidence about the concrete standard-library implementation, runtime behavior, and the complete key-generation path. The historical application code was not built or executed by this workflow.

## CI and evidence package

The latest verified source-review test commit at the time of this record is `c3c5c5e859e1a1400a575b1702b52afff9f86179`.

- [AegisForge CI run 652](https://github.com/rudimentall1/AegisForge/actions/runs/38383784794): success. Includes the independent source-body comparison and Python test step.
- [EVM Key Forensics Probe run 341](https://github.com/rudimentall1/AegisForge/actions/runs/38383784782): success. All three jobs completed, including clean-runner rebuild comparison and complete evidence-package attestation verification.
- The complete evidence artifact reports `PASS` for package attestation and probe/rebuild linkage. This verifies the stated provenance and linkage checks for the artifact; it does not independently prove the truth of the underlying scientific interpretation.
- The probe's own source-evidence report keeps `historical_vulnerability_reproduced=false` and the overall conclusion `INCONCLUSIVE`.

The runs use GitHub's pull-request merge ref (`refs/pull/32/merge`) with merge SHA `e3d5c98ffc847cb0a21d7ad932f7cd21823497a4`, and record the PR head SHA separately as `c3c5c5e859e1a1400a575b1702b52afff9f86179`.

## What this establishes

- The pinned source identities match the expected Git blob IDs.
- The extracted `createSeed()` body is byte-for-byte equal across the two retrieved revisions.
- The source pattern uses one `random_device` result to initialize the PRNG, followed by four PRNG distribution calls.
- The relevant CI workflows and evidence-package verification completed successfully for the recorded PR merge revision.

## What this does not establish

- It is not an independent human audit or an independent implementation of a C++ parser.
- It does not prove which binary was distributed or executed, establish source-to-binary provenance, or prove remediation status for the full application.
- It does not establish effective runtime entropy, private-key predictability, exploitability, or exposure of any wallet.
- No historical Profanity code was built or executed, and no wallet material was used.

## Status

Source identity and cross-revision function-text comparison: **checked**.

CI and evidence-package checks for the recorded PR merge revision: **passed**.

Independent human review: **pending**.

Historical vulnerability reproduction: **not established**.

Research conclusion: **INCONCLUSIVE**.

The next useful gate is an independent reviewer reproducing the pinned-source retrieval and hash checks in a clean environment, then reviewing the exact source-level claim and limitations. Do not execute the historical `createSeed()` path or upgrade the conclusion based on CI success alone.
