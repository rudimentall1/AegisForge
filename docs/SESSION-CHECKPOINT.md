# Session Checkpoint — AegisForge

**Updated:** 2026-11-14  
**Repository:** https://github.com/rudimentall1/AegisForge  
**Working branch:** `feat/persist-local-experiment-evidence-main`  
**PR:** [#196](https://github.com/rudimentall1/AegisForge/pull/196) — OPEN, DRAFT, not merged  
**Release gate:** [Issue #158](https://github.com/rudimentall1/AegisForge/issues/158) — OPEN

## 1. Where we stopped (verified repository state)

- PR #196 head is `25bade6f4ce64354197fd3e841c89afd4328d10b`; base is `main` at `0adfc88c41e8c48c8ed25f2b25ef8db67cab5370`.
- PR contains 236 commits, 43 changed files, +9,860/-138 lines. It remains Draft. Do not merge it as-is.
- The only workflow run returned for the current PR head is run #1614 / ID `40369651993`; conclusion: **FAILURE**. The previously recorded failure is the Bubblewrap fixture runner failing to create loopback networking in the hosted runner (`RTM_NEWADDR: Operation not permitted`). This is an environment/acceptance blocker, not evidence that the complete isolated execution contract works.
- Issue #158 remains open. Its acceptance contract still requires one clean-runner, local-only path from immutable Research Case registration through bounded experiment, evidence export, independent verification, adversarial rejection tests, and honest machine-readable statuses.
- `docs/SESSION-CHECKPOINT.md` did not exist on the default branch when checked. This file records the current handoff on the PR branch.
- `README.md`, `docs/ARCHITECTURE.md`, and `docs/PRODUCT-READINESS.md` all explicitly say release readiness and commercial fit are not established.
- Current Python requirements are small (requests, python-dotenv, cryptography, pydantic). No confirmed Slither or Echidna integration was found in the files reviewed. Foundry appears in the target architecture, not as proof of a completed end-to-end adapter.

## 2. What has already been built (do not rewrite)

PR #196 has substantial evidence infrastructure:
- persisted local experiment records with task/case/round identity checks and bounded artifact storage;
- planned RoundSpec identity kept distinct from runtime round IDs;
- Research Case bundle schema v3 with offline identity checks;
- deterministic experiment ZIP export and offline artifact/hash/path/size verification;
- paired control/counter-test binding;
- fixed repository-owned synthetic fixture subprocess with output/time/resource limits;
- combined evidence packages and detached Ed25519 attestations;
- trusted-key verification, freshness checks, and durable SQLite replay protection;
- adversarial tests for identity substitution, altered case digests, tampering, archive abuse, incomplete signatures, and replay.

These mechanisms establish specific package/record/signature properties only. They do **not** establish runner honesty, a security sandbox for arbitrary target code, historical vulnerability reproduction, or a confirmed finding. Synthetic outcomes stay `INCONCLUSIVE`.

## 3. Product direction

Build **AegisForge as a reproducible smart-contract security research and evidence workbench**, not another AI scanner or autonomous exploit bot.

Core value:
1. Take an authorized, pinned EVM repository and a falsifiable security question.
2. Run mature deterministic security tools through bounded adapters.
3. Preserve raw outputs, tool versions, exact commands, inputs, exit codes and artifact hashes.
4. Correlate findings and counter-tests without allowing an LLM to confirm them.
5. Export a portable evidence package that another engineer can verify independently.

Sell saved researcher/reviewer time and defensible evidence, not access to free scanners. First commercial target: a boutique smart-contract audit team or independent researcher willing to run a paid pilot. No billing system, hosted SaaS, dashboard, token, or blockchain layer until a real buyer validates the workflow.

## 4. What we reuse, and from whom

**Our foundation — keep and extend, do not replace:**
- AegisForge existing Python agent/orchestration code, Research Case and scope gate, SQLite queue, Evidence Ledger, package verifier and CLI.
- Preserve existing authorship and project history. No rewrite of the core.

**External engines to integrate as separate, replaceable tools (not copy into our codebase):**
- [Foundry](https://github.com/foundry-rs/foundry) by the Foundry project: Solidity build/test execution, local EVM and reproducible test runs. First integration candidate.
- [Slither](https://github.com/crytic/slither) by Trail of Bits/Crytic: Solidity static analysis. Invoke as a pinned external executable and preserve its raw output. Verify current license and distribution obligations before packaging or modifying it.
- [Echidna](https://github.com/crytic/echidna) by Trail of Bits/Crytic: property-based fuzzing and invariant testing. Add only after the Foundry + Slither slice works.

**Not selected for the MVP:**
- Do not adopt Certora, Sherlock, Olympix, AuditAgent or other commercial/closed products as code dependencies without a clearly licensed public source and explicit rights.
- Do not add generic pentest agents, Nuclei, MCP wrappers, LangGraph, extra LLM agents, or another database merely to increase feature count.
- No code from the candidate upstream projects has been copied or integrated as of this checkpoint. Attribution, exact version pinning, license review, NOTICE files and dependency inventory are required before any reuse/distribution.

## 5. Immediate execution order

1. Reconcile PR #196 with current `main`; inspect the exact failing job and reproduce the Bubblewrap limitation. Keep PR Draft and issue #158 open.
2. Close the release-critical gap with a truthful clean-checkout acceptance path. Do not relabel process limits as a security sandbox. If hosted CI cannot provide the required namespace capability, use a supported runner/isolated environment or mark that acceptance as NOT_RUN; do not fake a pass.
3. Once the case-to-bundle workflow is reproducible, add **one** vertical slice: pinned Solidity target → Foundry build/test → Slither static analysis → raw outputs and tool metadata recorded in the existing evidence model → offline bundle verification.
4. Pin tool versions, record installation provenance and licenses. Keep tools as subprocess/container adapters; never execute commands taken from an evidence bundle.
5. Add Echidna only after the first slice is independently reproducible.
6. Put the workflow in front of 2–3 audit researchers. Measure setup time, time saved, false-positive review effort and whether they will pay for a pilot.

## 6. Explicit non-goals until the above is proven

- No new agent farm or broad OWNERA merge.
- No SSV bounty hunting restart before the product release gate passes.
- No historical Profanity/key-generation claim based on synthetic fixtures.
- No arbitrary untrusted-code execution through the current fixed-fixture subprocess.
- No dashboard, SaaS billing, multi-tenant cloud, PostgreSQL migration, token or on-chain anchoring.
- No mass feature expansion or commit-count target.

## 7. Definition of the next meaningful result

A clean checkout can run one pinned, authorized Solidity case using Foundry and Slither, retain raw and attributable evidence, export a portable bundle, and have a second environment verify it. Every stage reports PASS/FAIL/INCONCLUSIVE/NOT_RUN honestly. Then a researcher outside the project can reproduce and review the result.

**Current status:** substantial evidence foundation exists; release gate is not passed; commercial demand is not validated; Foundry/Slither/Echidna integrations are plans, not completed capabilities.
