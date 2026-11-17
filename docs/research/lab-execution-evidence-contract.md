# Lab Execution Evidence Contract (v1)

## Purpose

Define what AegisForge may conclude from a lab-run record and what it must not conclude. This contract currently covers the repository-owned synthetic entropy demonstration. It is not a claim that the historical Profanity implementation has been reproduced.

## Current record

`LabRunner.run_synthetic_entropy_demo()` starts a fixed, repository-owned Python script through `subprocess.run` with `shell=False` and a five-second timeout. The script does not fetch, import, or execute candidate source. The resulting `execution_record` records:

- record schema and kind;
- executor label and exact argv list;
- SHA-256 of canonical JSON encoding of argv;
- observed process exit code, or null on timeout;
- captured stdout and stderr, plus SHA-256 for each UTF-8 encoded stream;
- timeout and test-pass flags.

The Validator recomputes the command and stream hashes and checks basic outcome consistency. If a stream is changed without updating its hash, the record fails this consistency check.

## What this establishes

For the current in-process data structure, these checks can detect accidental corruption and simple post-hoc edits that do not also update the relevant digests. The subprocess call documents an observed local execution path for the fixed toy script.

## What this does not establish

The record is not signed and has no independent trusted timestamp. An agent or process able to fabricate the entire record can also fabricate its fields and hashes. Therefore:

- a matching digest is an integrity check, not proof of origin;
- a self-reported `test_passed` value is not a security attestation;
- the current subprocess is not a hardened sandbox for untrusted code;
- a successful synthetic experiment is not evidence of a historical vulnerability;
- no real private keys or live wallet addresses are used by this demo.

The Validator must keep `historical_reproduction_confirmed = false` unless the historical-source criteria are independently met. The current toy experiment must remain labelled illustrative only.

## Required contract for a future historical experiment

Before any historical-reproduction claim can be considered, a future runner must provide all of the following:

1. **Immutable inputs:** repository URL, full source commit, source-file digests, test-vector identifier, and exact command/argv.
2. **Constrained execution:** a disposable isolated environment, explicit CPU/memory/time/output limits, no network by default, no credentials mounted, and synthetic test vectors only.
3. **Observed outputs:** exit status, timeout state, stdout/stderr, generated artifact bytes, and digests computed by the runner from the captured bytes.
4. **Run identity:** a unique run ID tying inputs, process outcome, and artifacts together.
5. **Independent verification:** Validator re-hashes artifact bytes, checks input/revision/vector binding, verifies expected result semantics, and rejects missing or contradictory fields.
6. **Trust boundary:** a documented mechanism that authenticates the runner record (for example, a signature from a separately controlled runner key, with explicit key custody and rotation). A signature proves the statement came from that key; it does not prove the runner was uncompromised.
7. **Honest outcomes:** failed, timed-out, incomplete, or ambiguous runs remain failed or `INCONCLUSIVE`; they are never converted to a positive claim by an agent's narrative.

## Acceptance tests

- A clean synthetic run has internally consistent command/stdout/stderr digests.
- Changing stdout, stderr, or argv without updating the corresponding digest is detected.
- A missing record, malformed digest, invalid exit/timeout combination, or failed test is not treated as a passing run.
- Even a structurally valid synthetic record does not establish historical reproduction.
- A fabricated record with recomputed hashes must not be described as authentic unless the separate runner-authentication mechanism validates it.

## Next implementation step

Implement the contract incrementally: first make Validator reject malformed or failed run records; then define a canonical serialized receipt and signature verification interface; only after that implement an isolated runner for pinned historical source. Do not claim production-grade sandboxing or historical reproduction before those controls are present and tested.
