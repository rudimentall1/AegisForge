# External Component Evaluation — AI/API Security Lab

**Reviewed:** 2026-11-14  
**Candidate:** [Parakh-Shinde/AegisForge](https://github.com/Parakh-Shinde/AegisForge)  
**Upstream license:** Apache-2.0 (verify the exact upstream LICENSE and NOTICE again at the commit selected for any reuse).  
**Relationship:** Independent third-party repository. It is not owned by rudimentall1 and must not be represented as our code.

## Decision

Keep this repository separate. Do not merge repositories or copy its framework wholesale.

It is a potentially useful reference/optional engine for a future AI/API security testing product, but it does not improve the immediate AegisForge smart-contract evidence vertical slice. Do not let it delay the Foundry + Slither path.

## Useful capabilities identified from upstream documentation

- Synthetic AI/API attack scenarios, including poisoned-RAG and cross-tenant access attempts.
- Deterministic authorization simulation.
- Telemetry normalization and attack-chain correlation.
- Evaluation protocol with a separate holdout set.
- Hash-based report provenance and CI quality gates.
- CLI and local FastAPI control plane.

These are candidate capabilities, not integrated features in our repository.

## Evidence and limitations

The upstream project documents important limitations:

- Its API is a local control plane, not production identity or tenant isolation.
- Local-model integration is experimental.
- Regex/normalization-based prompt detection does not generalize to arbitrary semantic attacks.
- PostgreSQL persistence is roadmap work; telemetry persistence is incomplete.
- It is not a general-purpose penetration-testing scanner.

The documented untouched synthetic holdout v2 results are weak:
- Rule-only: precision 0.3333, recall 0.0833, F1 0.1333, FPR 0.1667 (TP=1, TN=10, FP=2, FN=11).
- The documented hybrid result is the same; the semantic reference provider did not improve classification.
- The later 24-case adapted regression reports perfect metrics on cases adapted from holdout failures. This is a regression suite, not an independent holdout result.

Do not market this upstream detector as proven production-grade AI security.

## Reuse conditions

Before adopting any component:
1. Inspect the actual source and tests at a pinned upstream commit, not only README claims.
2. Confirm Apache-2.0 notices and inspect any NOTICE file and transitive dependency licenses.
3. Preserve upstream copyright and attribution; mark modified files; retain license/NOTICE obligations.
4. Keep the upstream component isolated behind an adapter. Do not transplant its code into our core without a measured reason.
5. Run it locally from a clean checkout and record reproducible commands, versions, outputs and limitations.

## Product boundary

Our AegisForge remains focused on reproducible smart-contract security research and portable evidence. The external repository is a separate candidate for an AI/API security lab. If we later pursue AI-agent security, evaluate its scenario runner and telemetry correlation as optional components; do not import its prompt detector as an authorization control.

## Branding risk

Both repositories use the name **AegisForge**. They are unrelated projects. Keep repository ownership and attribution explicit in all internal and public materials; do not imply affiliation.
