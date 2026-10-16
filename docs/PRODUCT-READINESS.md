# AegisForge — Product Readiness Gate

**Purpose:** define what “ready” means for the first usable AegisForge — EVM Key Forensics release. This is an acceptance checklist, not a claim that the checks have passed.

## Product promise

Given a pinned public EVM source revision and a documented forensic question, AegisForge should produce a portable evidence bundle that another engineer can validate and that clearly separates source observations, synthetic demonstrations, historical reproduction, and claims about real wallets.

The first release does **not** promise to find every vulnerability, identify vulnerable wallets, recover private keys, or prove historical exploitability from source patterns alone.

## Release blockers

A release is not ready while any blocker below is open.

### 1. One supported end-to-end workflow

- [ ] A documented command starts a case with a unique case ID, pinned target commit, scope/source references, hypothesis, expected invariant, and falsification criteria.
- [ ] The case flows through Source Researcher → Crypto Analyst → Lab Runner → Validator without manually copying identifiers between stages.
- [ ] Missing or mismatched case identity fails closed at the actual execution boundary.
- [ ] Legacy queue/CLI entrypoints cannot silently run a security-research task without the required case binding.
- [ ] Retries, timeouts, and terminal states are bounded and documented.

### 2. Reproducible forensic evidence

- [ ] The run records exact source commit and relevant Git object identities.
- [ ] The run records tool versions, command, environment assumptions, inputs, exit status, and artifact hashes.
- [ ] Export creates a portable evidence bundle with a schema version and deterministic manifest.
- [ ] A separate verifier checks paths, size limits, schema, hashes, required fields, and consistency between case and artifacts.
- [ ] A clean runner can validate the bundle using documented commands without access to the original SQLite database.
- [ ] Tampered, truncated, malformed, or contradictory bundles are rejected.

### 3. Correctness and honest conclusions

- [ ] Tests cover a positive fixture, unrelated-source negative fixtures, missing evidence, malformed source, and tampered artifacts.
- [ ] Explicit negative context defeats keyword-only matches.
- [ ] CONFIRMED, REJECTED, INCONCLUSIVE, OUT_OF_SCOPE, and NOT_REPRODUCED have distinct documented semantics.
- [ ] A synthetic entropy demo is labelled synthetic and cannot be promoted to historical reproduction.
- [ ] Source hashes, CI runs, and attestations are never described as proof of exploitability or individual-wallet exposure.
- [ ] No real seed phrases, private keys, or wallet-key recovery workflows are accepted by the MVP.

### 4. Operational usability

- [ ] A new user can install dependencies and run the supported workflow from a clean checkout using the README.
- [ ] Configuration is documented, validated at startup, and contains no committed secrets.
- [ ] Errors tell the user what failed and how to inspect the evidence; silent skips are not treated as success.
- [ ] Tests run in CI on the default branch; skipped checks and external dependencies are visible.
- [ ] The repository has one authoritative setup path and no conflicting status claims across README, architecture, and research docs.

### 5. Release and maintenance

- [ ] Open PRs are reviewed against current main; overlapping changes are consolidated rather than merged redundantly.
- [ ] Release notes state supported capabilities, limitations, and known gaps.
- [ ] A sample case and expected output are checked into the repository using synthetic/public data only.
- [ ] The verifier has a stable CLI and a machine-readable exit code contract.
- [ ] At least one engineer other than the implementation author can follow the reproduction guide and explain what the result proves.

## Explicitly deferred

These are not MVP blockers and must not distract from closing the release blockers:

- Finding a new SSV Network bounty vulnerability.
- Autonomous mainnet interaction or exploit execution.
- Live-wallet discovery, key recovery, or handling private key material.
- A hosted SaaS, billing, team accounts, or a dashboard.
- More agents, model providers, protocol specializations, or databases before the core workflow is reliable.

## Exit rule

The MVP is **release-candidate ready** only when every release blocker has evidence linked from this checklist and CI is green on the exact candidate commit. It is not “100% ready” merely because documentation is complete or a benchmark test passes. Remaining product risks must be listed explicitly.
