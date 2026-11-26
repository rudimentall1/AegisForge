# AegisForge — Master Context

**Canonical project context.** Update this file when product direction, verified implementation status, or priorities change. Architecture and research-track documents must not maintain conflicting priorities.

## Product direction

AegisForge is a reproducible security-research and forensic evidence platform. Its primary product focus remains **EVM Key Forensics**: bind an authorized target and immutable source revision to a falsifiable hypothesis, controlled experiment, counter-tests, evidence artifacts, and an independently reviewable conclusion.

This is not a claim that the end-to-end workflow is release-ready. The product-readiness checklist remains the acceptance authority. Active SSV bounty hunting is paused; do not resume it as a delivery priority without an explicit decision.

## Architecture principles

1. Evidence takes precedence over agent confidence, source-pattern matches, and CI success.
2. AI agents propose and investigate hypotheses. Deterministic tools and independent review establish only what their evidence supports.
3. Research Case is the control-plane contract for target identity, scope, hypothesis, execution mode, and evidence linkage.
4. Reuse existing agent roles and canonical evidence components. Do not add agents or duplicate evidence systems without a demonstrated gap.
5. SQLite remains the initial persistence layer until measured concurrency or customer requirements justify a change.
6. Preserve distinct outcomes: `CONFIRMED`, `REJECTED`, `INCONCLUSIVE`, `OUT_OF_SCOPE`, and `NOT_REPRODUCED`.
7. Never claim vulnerability, source-to-binary provenance, or individual-wallet exposure without the corresponding reproducible evidence.
8. Capability and execution controls support controlled research; they are not a substitute for a useful product workflow.
9. No live state-changing actions or testing outside explicitly authorized scope. Prefer pinned local forks, testnets, or bounded environments.

## Verified main-branch implementation

The following components are present on the reviewed `main` snapshot (commit `da91e18a69a1bc455f53b0ea4dc0ea53bb3ce261`, 2026-11-26):

- Python CLI and role-based agent runtime under `aegisforge.py`, `agents/`, and `model_research/`.
- Task orchestration and task graph under `orchestrator/`, backed by the SQLite queue in `shared/queue.py`.
- Research Case contract and case-binding checks in `shared/research_case.py`; the current required-role set is limited to `source_researcher`, `crypto_analyst`, and `lab_runner`.
- Capability, signed intent, authority, execution-gate, executor registry, and execution-attempt components under `shared/`.
- Evidence ledger, manifests, dossiers, proof bundles, verification, replay, and recovery components under `shared/`.
- EVM Key Forensics tools, source fixtures, probe workflows, and extensive regression tests.
- Separate `scam_intelligence/` functionality and Solidity fixtures/Foundry tests.
- GitHub Actions CI and dedicated Foundry runner integration workflows.

Presence of these components does not establish that every path is integrated, that every legacy path is gated, or that the product release criteria have passed.

## Product and release gaps

- `docs/PRODUCT-READINESS.md` remains the release gate; its checklist is not satisfied merely because individual components or tests exist.
- README and architecture documentation explicitly state that legacy/unbound task paths and end-to-end case/evidence propagation still require validation.
- Profanity work is a synthetic/source-evidence track, not historical runtime reproduction and not evidence about individual wallets.
- Independent human source review is not established by the existence of a procedure or template.
- Main dependency resolution was repaired in squash merge `9e136d2e10765ade28d43bd30e985e2aff62ea4d`: `web3==7.10.0` now satisfies `slither-analyzer==0.11.6` (`web3>=7.10,<8`). Exact PR head `ca91cb7bd6fd4a2cd78a4660fcfad3c0aec16c7a` passed Python/EVM CI (1,631 passed, 30 subtests, 3 warnings) and Node.js 24 syntax/tests (run `45771098259`). The post-merge main CI run `45771315581` passed on merge commit `9e136d2e10765ade28d43bd30e985e2aff62ea4d` (1,631 passed, 30 subtests, 3 warnings; Node.js 24 job passed).
- Commercial product-market fit, revenue, and willingness to pay remain unvalidated hypotheses.


- The merged main commit removes stale top-level Worker imports that referenced nonexistent `validator.py`/`notify.py`, removes the obsolete OpenRouter/Telegram/host-side Foundry/Arbitrum fallback path, and adds regression coverage. The obsolete root manual scripts `test_bounty_local.py` and `test_live_openrouter.py` were removed because they depended on that retired path and were collected as broken tests.
- `tests/test_fork_runtime_evidence.py` existed on main without its implementation module. The candidate adds the self-contained read-only observation validator from the fork-runtime work and aligns its fixture with the expected network identity. It does not claim packet-path isolation or secure runtime execution.
- The Foundry integration workflow previously triggered on generic dependency/runtime-helper edits and failed because the full fork Compose stack was not present on main. The candidate restricts that workflow to the complete fork integration surface and adds manual dispatch; the real Anvil/Foundry integration is not claimed as passed by this change.
- Documentation was reconciled: the architecture roadmap and legacy agent map now reflect the existing partial Research Case implementation and the paused SSV track.

## Server verification — 2026-11-26

- The connected Linux host `Gensyn2.play2go.cloud` reports Node.js `v24.18.0`, npm `11.16.0`, and system Python `3.10.12`.
- The host checkout at `/root/AegisForge` remains on older feature branch `feat/persist-local-experiment-evidence-main` at `c69dbcc5142c98d38fcc01ebf721a77ce4e282db`, with untracked `dump.txt` and `tree.txt`; it was deliberately left untouched.
- A separate clean worktree from current `main` was used for documentation and scaffold checks. In `my-project/`, `npm run check` passed and `npm test` passed (1 test, 0 failures, 0 skipped).
- No AegisForge, Foundry, Anvil, or Firecracker process was observed during the point-in-time host inspection. No AegisForge service was deployed, started, restarted, or modified.
- The scaffold remains an isolated Node.js metadata package with no approved product domain or parent-runtime integration. The server checks do not establish production readiness.
- The server's Git remote uses HTTPS without an available credential helper/token, so `git push` from that host failed with a non-interactive authentication error. The verified documentation update is therefore published through the connected GitHub integration on a dedicated branch/PR, not by claiming that the server push succeeded.

## Open pull requests and consolidation state (2026-11-26)

The open PR inventory contains multiple independent and stacked tracks. A branch being mergeable, or its description reporting a green run, is not sufficient for merging.

### Stacked on-chain research track

The dependency chain is:

`#196 (main) → #207 (feat/first-foundry-exploit-benchmark) → #208 (feat/onchain-contract-intake) → #210 (fix/onchain-security-checker-offline) → #211 (feat/onchain-bytecode-verification)`.

- #196's PR description proposes a large task-bound local-experiment/evidence package (59 files, approximately 13.2k additions). Its implementation has not been fully source-reviewed here. It is a prerequisite branch for #207, not an isolated small patch.
- #207's PR description proposes case-bound Foundry execution/evidence (30 files, approximately 3.9k additions). Its PR body says its checks had not executed at the time recorded.
- #208's PR description proposes on-chain source intake and structural research (21 files, approximately 3.5k additions). Its recorded CI attempts failed before a runner executed tests.
- #210's PR description claims fixes and tests for the on-chain worker pipeline (10 files). Its reported test results must be verified against the exact current head and its full dependency chain.
- #211's PR description proposes compiler/runtime equivalence, append-only on-chain verification, admission, round storage, and Firecracker host preflight (32 files, approximately 4.1k additions). Its PR body records green runs on earlier heads, not automatically on the current combined candidate.
- Do not merge a child before its base. Review the combined diff against current `main`, rerun CI on the exact resulting head, and resolve security-boundary findings before advancing the chain.

### Separate deployment-discovery track

- #205 is based on the non-default `master` branch, not `main`; #206 is stacked on #205. Their PR descriptions propose deployment discovery, RPC monitoring, Slither analysis, RPC gateway, fork snapshots, and synthetic Anvil tests. They must not be merged by changing their base blindly. First reconcile branch ancestry, product scope, secrets/authorization boundaries, and overlap with the #208–#211 intake path.
- #197 is an SSV bounty-hunt result. SSV hunting is paused by product decision; do not merge or resume execution solely because a PR exists.

### Other open main-targeted work

Open PRs #138, #153, #156, #169, #175, #189–#196, and #72 cover case/round identity, diagnostics, provenance, local experiment evidence, and agent-role contracts. They are not automatically approved. Compare each against current `main`; later case-round and evidence changes may overlap or supersede earlier branches. Merge only a minimal, tested, non-duplicated sequence.

### Current scaffold PR

- #212 now contains the requested `my-project/` scaffold, root/subproject working rules, audited documentation, dependency correction, Worker legacy-path cleanup, and missing runtime-observation helper/test. The Python suite passed on commit `1d6b0c2`; Node.js 24 checks passed on commits `78362a0` and `4bd34c0`. Final exact-head CI is required before merge. The scaffold itself remains non-product code.
- The scaffold is not the AegisForge product runtime and must not duplicate the existing Python agents, queue, Research Case, sandbox, or evidence pipeline.

## Priority order

1. Restore deterministic dependency installation and verify CI on the exact candidate commit.
2. Audit and consolidate the stacked PRs against current `main`; do not merge large unverified branches wholesale.
3. Close the EVM Key Forensics workflow defined in `docs/PRODUCT-READINESS.md`: pinned public source → structured hypothesis → bounded experiment → independent validator → portable evidence bundle.
4. Enforce case identity at every relevant entrypoint and actual execution boundary; close legacy bypasses.
5. Propagate case ID, pinned target revision, and scope digest through experiment records, evidence ledger, and exported manifests.
6. Verify tamper rejection and clean-runner replay; make CI and the release checklist the acceptance gate.
7. Validate repeated use and willingness to pay before adding hosted SaaS, billing, more agents, or extra product tracks.

## SSV research boundary

SSV bounty hunting is paused. Existing source and scope notes are research history, not an active execution queue. Do not start new SSV hunts unless the user explicitly reopens that track. No eligible SSV vulnerability is established by the current product record.

## Product and commercial hypothesis

The first plausible users are independent smart-contract security researchers and small audit teams that repeatedly build PoCs and evidence packages. The value hypothesis is reducing time to a reviewer-ready, reproducible finding and helping distinguish a real exploit from a plausible false lead.

Potential later models include individual paid tooling, team subscriptions for collaboration/review/private artifacts, and enterprise deployment. Do not build billing or a broad SaaS control plane before interviews validate workflow pain, alternatives, budget owner, and willingness to pay.

## Success criteria

- A clean runner reproduces the documented result from pinned inputs.
- A reviewer can inspect the chain from attacker capability to impact.
- Negative results are recorded and prevent repeated wasted work.
- The verifier detects tampered, incomplete, or contradictory evidence bundles.
- AI-generated claims cannot bypass deterministic verification gates.
- A real researcher or audit team returns to the workflow.
- Time-to-reproduce and review effort improve measurably.

The long-term asset is the evidence model, reliable verification, accumulated reproducible research cases, and integration into security teams' workflows — not the number of agents.

## Source of truth

- [Architecture](ARCHITECTURE.md)
- [Legacy agent plan status](LEGACY-AGENT-PLAN-STATUS.md)
- [EVM Key Forensics](EVM-KEY-FORENSICS.md)
- [Product Readiness Gate](PRODUCT-READINESS.md)
- [Source provenance notes](evm-key-forensics-source-provenance.md)
- [Session checkpoint](SESSION-CHECKPOINT.md)
