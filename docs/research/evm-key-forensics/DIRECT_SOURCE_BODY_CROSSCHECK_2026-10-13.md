# Direct Cross-Revision Check: Profanity `createSeed()`

Date: 2026-10-13

## Inputs retrieved

The two raw files were fetched directly from GitHub using the pinned commit URLs, not read from the project probe artifact:

- Pre-disclosure: https://raw.githubusercontent.com/johguse/profanity/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/Dispatcher.cpp
- Post-disclosure archive: https://raw.githubusercontent.com/johguse/profanity/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/Dispatcher.cpp

The retrieved file lengths were 16,491 and 16,799 characters, respectively.

## Direct function extraction

A separate, minimal brace-depth extraction was performed on each retrieved file, starting at the exact signature:

`cl_ulong4 Dispatcher::Device::createSeed()`

The extracted function body, including its opening and closing braces and preprocessor branches, was 357 characters in each file. The two extracted strings compared byte-for-byte equal in this retrieval.

The existing Probe artifact independently records the same SHA-256 function-body fingerprint for both revisions:

`897d89b20fc71072543bb5aa4538c4dfb17c77e81eab5d2af2f749fb1563859c`

The artifact reports distinct whole-file SHA-256 values and distinct Git blob SHA-1 values for the two revisions. That is consistent with files changing elsewhere while this extracted function body remains unchanged.

## What this establishes

- The two retrieved pinned file versions contain byte-for-byte equal text in the function body selected by the signature and brace-depth extraction described above.
- This is a direct cross-revision source-text observation, not just a claim copied from the project report.

## What this does not establish

- It is not an independent human review or an independent audit of the extraction logic.
- This check did not independently recompute the Git blob SHA-1 or SHA-256 values of the complete raw files.
- It does not prove which binary was distributed or executed, establish source-to-binary provenance, or prove remediation status for the full application.
- It does not demonstrate entropy failure, private-key predictability, exploitability, or exposure of any wallet.
- No historical Profanity code was built or executed for this check.

## Status

Independent review worksheet: `PENDING`.

Research conclusion: `INCONCLUSIVE`.

Next gate: a reviewer should reproduce the retrieval and hashes in a clean environment, verify the expected Git blob IDs, inspect function boundaries, record the exact commands and environment, and sign the review record. Do not upgrade the conclusion until that review and any required historical evidence are actually available.
