# EVM Key-Generation Forensics: Initial Research Track

AegisForge runs a bounded research pipeline for historical EVM key-generation issues.

1. Source Researcher collects official historical publications and GitHub issue/PR discovery leads.
2. Crypto Analyst turns source notes into falsifiable hypotheses and separates generation faults from key-file/storage faults and contract-logic vulnerabilities.
3. Lab Runner runs a fixed toy entropy demonstration with synthetic seeds only. It never executes downloaded code or operates on real wallet keys.
4. The existing Validator re-fetches allowlisted public pages, checks provenance and experiment scope, and reports whether the historical implementation was actually reproduced.
5. The planner retries incomplete source collection for at most three search rounds, then preserves an inconclusive verdict if evidence remains insufficient.

## Start a research task

Run the following command in the server checkout:

    python aegisforge.py tasks submit --role source_researcher "Research historical EVM key-generation weaknesses in early Ethereum clients and Profanity. Find primary sources and exact affected revisions. Do not target live wallets."

Start worker processes using the same environment and database as existing workers:

    python -m agents.worker source_researcher
    python -m agents.worker crypto_analyst
    python -m agents.worker lab_runner

The existing planner and validator workers must also be running.

## Exported probe artifact verification

The offline verifier accepts a self-contained directory containing the run metadata,
JSON output, C++ source, and compiled probe binary. It rejects symlinked roots and
files, duplicate JSON keys, invalid UTF-8, non-object JSON roots, excessive JSON
nesting, and oversized evidence. Current read limits are 2 MiB per JSON file,
4 MiB for the source file, and 64 MiB for the binary.

A successful result means only that the bundle passes the implemented structural,
scope, and hash-consistency checks. The manifest is unsigned, so the verifier does
not authenticate the producer, runner, build environment, or truth of the output.
Do not treat this artifact as proof of a historical key-generation vulnerability.

## Limits

- Public-source retrieval is restricted to an explicit HTTPS host allowlist.
- Downloaded text is untrusted and is never executed.
- The synthetic lab demonstrates only the math of a deliberately small seed space.
- It is not a reproduction of Profanity, secp256k1, or a historical Ethereum implementation.
- No real keys, seed phrases, signatures, or live-wallet target lists are accepted or generated.
- A reachable source is not proof that every claim in it is correct.
- This milestone must remain inconclusive until an exact historical implementation is pinned and reproduced in an isolated test.
