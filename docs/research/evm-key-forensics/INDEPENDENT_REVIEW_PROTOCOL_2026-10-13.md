# Independent review protocol: EVM key-forensics source cross-check

Date: 2026-10-13

Purpose: let a second reviewer independently verify the pinned upstream source identities and the limited claim about `Dispatcher::Device::createSeed()`. This protocol does not reproduce the historical vulnerability.

## Scope and safety

- Read source at immutable upstream commits only.
- Do not build or execute historical Profanity code.
- Do not use wallet data, derive private keys, scan addresses, or generate target lists.
- Do not infer effective entropy or exploitability from the source comparison alone.
- Keep the research conclusion `INCONCLUSIVE` unless separate, adequate evidence justifies a change.

## Pinned inputs

| Revision | Commit | Expected `Dispatcher.cpp` Git blob |
|---|---|---|
| Pre-disclosure | `0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6` | `c9226fc02a52633a84664cbf3aaf2b4af8a59b25` |
| Post-disclosure archive | `186b9b27ab3e24a1899f648adcabcbf0e5f3131e` | `884ced30ed6e55794ea5bda0451b52e81ddec1dd` |

Expected extracted function-body SHA-256, as recorded by the current source-body review: `897d89b20fc71072543bb5aa4538c4dfb17c77e81eab5d2af2f749fb1563859c`.

## Reproduce in a clean environment

The commands below fetch source history and inspect text only.

```bash
set -euo pipefail
git clone --filter=blob:none --no-checkout https://github.com/johguse/profanity.git profanity-review
cd profanity-review
git fetch --depth=1 origin 0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6
git fetch --depth=1 origin 186b9b27ab3e24a1899f648adcabcbf0e5f3131e

git show 0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6:Dispatcher.cpp > /tmp/Dispatcher-pre.cpp
git show 186b9b27ab3e24a1899f648adcabcbf0e5f3131e:Dispatcher.cpp > /tmp/Dispatcher-post.cpp

test "$(git rev-parse 0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6:Dispatcher.cpp)" = c9226fc02a52633a84664cbf3aaf2b4af8a59b25
test "$(git rev-parse 186b9b27ab3e24a1899f648adcabcbf0e5f3131e:Dispatcher.cpp)" = 884ced30ed6e55794ea5bda0451b52e81ddec1dd

sha256sum /tmp/Dispatcher-pre.cpp /tmp/Dispatcher-post.cpp
```

Then, from a clean checkout of AegisForge at the reviewed PR head, run the existing source-body review tool against the clone:

```bash
python tools/evm_key_forensics/independent_source_body_review.py --repo /path/to/profanity-review
```

The tool should report that the selected function bodies match and retain the conclusion `INCONCLUSIVE`. If output differs, stop and document the exact commits, commands, environment, and output. Do not change the expected hashes merely to make the check pass.

## Reviewer record

The reviewer should independently record:

- Date and operating system.
- AegisForge commit reviewed.
- Upstream commit IDs and observed Git blob IDs.
- Exact command output, including the source-body fingerprint.
- Whether function boundaries were manually inspected.
- Any ambiguity or discrepancy.
- Reviewer identity and whether the review is independent of the original author.

Do not mark independent review complete until a second person has performed and recorded the checks. A successful CI run is not an independent human review.

## Interpretation boundary

The source pattern initializes `std::mt19937_64` using one call to `std::random_device`, then draws four values from the PRNG. This shows that the four values are not four separate entropy-source calls. It does not establish effective runtime entropy, predictable private keys, exploitability, which binary was distributed, or exposure of any wallet.

Historical vulnerability reproduction remains **not established**.
