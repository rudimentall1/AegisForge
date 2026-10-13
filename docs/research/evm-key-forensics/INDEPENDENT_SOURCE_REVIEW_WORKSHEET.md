# Independent source review worksheet

Status: **PENDING**. This file is a review procedure, not evidence that a review has occurred.

## Purpose

Let a reviewer who did not rely on the AegisForge checker output independently retrieve the two pinned upstream files, verify their Git object identities, inspect the narrow source claim, and record any disagreement. This procedure does not execute Profanity, derive key material, or establish source-to-binary provenance.

## Review rules

- Use a clean temporary directory and an independent checkout or direct retrieval from the immutable upstream commit URLs.
- Do not treat this worksheet, the dossier, a GitHub Actions pass, or a SHA-256 manifest as proof that the historical vulnerability was reproduced.
- Do not execute the historical application or `Dispatcher::Device::createSeed()`.
- Record failures and discrepancies as-is. Do not edit expected hashes or checker output to make a mismatch pass.
- A reviewer should record their identity and review date. If the reviewer authored the implementation being reviewed, label the review self-review, not independent review.

## Reproduce source identity

From the repository root, run these commands in a clean directory. They retrieve source text only.

```bash
set -euo pipefail
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --filter=blob:none --no-checkout https://github.com/johguse/profanity.git "$tmp/profanity"
git -C "$tmp/profanity" fetch --depth=1 origin 0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6
git -C "$tmp/profanity" fetch --depth=1 origin 186b9b27ab3e24a1899f648adcabcbf0e5f3131e

git -C "$tmp/profanity" show 0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6:Dispatcher.cpp > "$tmp/Dispatcher-pre.cpp"
git -C "$tmp/profanity" show 186b9b27ab3e24a1899f648adcabcbf0e5f3131e:Dispatcher.cpp > "$tmp/Dispatcher-post.cpp"

printf 'pre blob: '; git -C "$tmp/profanity" rev-parse '0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6:Dispatcher.cpp'
printf 'post blob: '; git -C "$tmp/profanity" rev-parse '186b9b27ab3e24a1899f648adcabcbf0e5f3131e:Dispatcher.cpp'
sha256sum "$tmp/Dispatcher-pre.cpp" "$tmp/Dispatcher-post.cpp"

python tools/evm_key_forensics/check_historical_source_pattern.py "$tmp/Dispatcher-pre.cpp" --revision pre-disclosure --pretty
python tools/evm_key_forensics/check_historical_source_pattern.py "$tmp/Dispatcher-post.cpp" --revision post-disclosure --pretty
```

Expected Git blob IDs:

| Revision role | Commit | Expected Git blob SHA-1 |
|---|---|---|
| Pre-disclosure | `0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6` | `c9226fc02a52633a84664cbf3aaf2b4af8a59b25` |
| Post-disclosure archive | `186b9b27ab3e24a1899f648adcabcbf0e5f3131e` | `884ced30ed6e55794ea5bda0451b52e81ddec1dd` |

If a command fails, a commit cannot be fetched, a blob ID differs, or either checker result is not `SOURCE_PATTERN_MATCHED`, stop and record the result as a discrepancy. Do not infer that the source claim is false or true from a retrieval failure alone.

## Review the claim, not just the hashes

Review the pinned `Dispatcher.cpp` function and independently answer:

1. Does the production branch contain one `std::random_device` declaration and one call to `rd()` to initialize `std::mt19937_64`?
2. Are the four distribution calls outputs from that PRNG engine, rather than four independent entropy-source calls?
3. Does the debug branch differ from the production branch in the way the checker reports?
4. Is the checker matching the function definition and its body, rather than a comment, declaration, or unrelated function?
5. Do the checker result and comparison report correctly state the limits: no runtime entropy proof, no exploitability finding, no wallet compromise, and no source-to-binary provenance?

Record exact file paths and line ranges from the pinned revision for each answer. If any answer differs from the current claim, quote only the minimum necessary source and explain the discrepancy.

## Review report and integrity boundaries

Inspect `SOURCE_EVIDENCE_DOSSIER.json`, the source comparison report, and the verifier implementation. Confirm that:

- the expected commit and blob IDs are fixed in the checker and dossier;
- malformed or mismatched source stays `INCONCLUSIVE`;
- the report's reproducibility hashes are hashes of exact input/script bytes;
- hashes are not presented as proof of authorship, trustworthy execution, or truth;
- historical execution, wallet material use, historical reproduction, and source-to-binary provenance are not falsely marked as established.

Do not rely on a report's own `validated: true` field as an independent trust anchor. Recompute the source identities yourself.

## Review record

Complete this section only after performing the procedure. Do not fill it from CI status alone.

- Reviewer:
- Affiliation / review independence: `INDEPENDENT` or `SELF_REVIEW`
- Review date (UTC):
- AegisForge commit reviewed:
- Pre-disclosure Git blob matched: `YES / NO / NOT_CHECKED`
- Post-disclosure Git blob matched: `YES / NO / NOT_CHECKED`
- Checker outputs reproduced: `YES / NO / PARTIAL`
- Narrow source claim supported: `YES / NO / QUALIFIED`
- Report/verifier boundary checks: `PASS / FAIL / PARTIAL`
- Discrepancies and supporting paths/line ranges:
- Reviewer conclusion:
- Limitations acknowledged:

Until a completed record is reviewed and committed, the dossier must continue to report `independent_review: PENDING` and `overall_conclusion: INCONCLUSIVE`. This worksheet alone does not change either status.
