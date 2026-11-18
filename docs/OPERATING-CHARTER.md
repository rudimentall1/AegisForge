# AegisForge Operating Charter

**Status:** Working project policy  
**Date:** 2026-11-18  
**Applies to:** AegisForge, its server deployment at `/opt/agent-farm`, research agents, monitoring services, incident tooling, and future OWNERA integrations.

This document is the durable operating agreement for continuing the project across sessions. It records the product objective, engineering principles, incident workflow, authority boundaries, release discipline, and audit process. It does not claim that every described capability is already implemented.

## 1. Mission and product direction

AegisForge is being developed as an autonomous EVM security research and emergency-response platform. Its commercial objective is to reduce the time between a security weakness becoming observable and a useful protective response, while producing evidence that owners, users, reviewers, and responders can independently inspect.

The product must not regress into a passive scanner or an LLM-generated report wrapper. It should combine:

- continuous multi-chain threat monitoring;
- vulnerability and exploit-path analysis;
- reproducible local/synthetic experiments;
- rapid incident triage and impact estimation;
- emergency response through technically available and properly authorized controls;
- recovery-vault accounting and asset-return workflows where a valid authority basis exists;
- owner/security-contact discovery and parallel notification;
- cryptographically verifiable evidence and incident timelines;
- a commercial layer for response retainers, subscriptions, and agreed rescue/recovery fees.

The immediate engineering priority is to establish what is actually running, close critical reliability/security gaps, and prove the complete end-to-end workflow. Do not rewrite working components merely to make the architecture look cleaner.

## 2. Core operating principles

1. **Speed matters.** Critical alerts must trigger automated triage and preparation immediately. Contact discovery, notification, evidence capture, simulation, and authorized protective actions should run in parallel rather than as a serial email-first workflow.
2. **A critical vulnerability is an unsafe-state signal.** Do not wait for an attacker transaction before escalating a validated critical weakness. Lack of observed exploit traffic is not proof that exposed assets are safe.
3. **Evidence before irreversible action.** Preserve source revision, chain ID, block number, contract addresses, relevant state, traces, simulation results, tool versions, timestamps, and hashes before or alongside response actions where technically possible.
4. **Fail closed on authority and uncertainty.** A vulnerability finding alone does not establish control over a third-party contract or assets. The executor must use a documented authority basis: protocol-granted role, emergency/guardian mechanism, explicit incident authorization, pre-agreed response mandate, or another reviewed legal/technical basis. If no such basis exists, the system may monitor, simulate, prepare, notify, and invoke public defensive mechanisms that do not transfer/control third-party assets; it must not autonomously sweep arbitrary assets to an operator-controlled address.
5. **No concealment.** Never falsify incident records, disguise asset provenance, hide transactions, or create documents intended to mislead owners, users, exchanges, investigators, or courts. Private disclosure is acceptable when requested by the owner and consistent with applicable obligations; it is not a method for concealing an unauthorized operation.
6. **Owner/user benefit is the primary recovery objective.** Recovery assets must be segregated, fully accounted for, and returned to verified rightful recipients. Fees must be agreed, documented, and auditable; no unilateral deduction or ransom-like hold.
7. **LLMs do not authorize transactions.** AI may summarize, classify, rank, propose hypotheses, and prepare actions. Deterministic policy and an independently verifiable authority check must gate irreversible execution.
8. **No unsupported claims.** Distinguish implemented, tested, deployed, observed, and merely planned capabilities in code, README, demos, and sales material.

## 3. Incident response model

### 3.1 State machine

Recommended incident lifecycle:

`OBSERVED -> TRIAGED -> VALIDATED -> RESPONSE_PLANNED -> AUTHORITY_CHECKED -> RESPONSE_EXECUTED -> CONTAINED -> OWNER_NOTIFIED -> REMEDIATION_VERIFIED -> RETURNED_OR_CLOSED`

Additional terminal or holding states:

- `FALSE_POSITIVE`
- `INCONCLUSIVE`
- `NO_SAFE_RESPONSE`
- `AUTHORITY_REQUIRED`
- `RESPONSE_FAILED`
- `DISPUTED_CUSTODY`

Every transition must record actor, timestamp, reason, evidence references, and transaction hashes where applicable. State changes must be idempotent and persisted transactionally.

### 3.2 Parallel first-response workflow

On a high-confidence critical signal, launch these jobs concurrently:

- capture immutable chain/source context;
- classify vulnerability and confidence;
- estimate affected contracts, assets, balances, and user impact;
- simulate the exploit and candidate mitigations against a pinned fork/state;
- enumerate available pause, guardian, emergency-withdrawal, upgrade, timelock, or protocol-defined response mechanisms;
- verify configured responder authority and destination constraints;
- discover official owner, security, multisig, and incident contacts;
- prepare a concise initial alert and full technical report;
- monitor relevant pending/confirmed transactions and state changes.

The response coordinator must not wait for contact discovery to finish before running technical triage or an already-authorized response.

### 3.3 Execution policy

The transaction executor may only perform actions that pass all applicable gates:

- chain ID and target address are verified;
- the exact method, calldata, value, token list, amount limits, and destination are allowlisted;
- the authority proof is valid, current, scoped to the incident, and not revoked;
- the action is simulated against current state and checked for expected postconditions;
- nonce, gas, fee, slippage, and replay protections are applied;
- a separate policy component signs off; the LLM is not the signer or authority source;
- a durable pre-execution record and post-execution receipt are written.

For asset custody/recovery, use a dedicated segregated vault with no commingling, no arbitrary withdrawals, explicit beneficiary records, independent access controls, and a return procedure. Do not use a personal/operator wallet as a general-purpose holding account. Any fee must be covered by a prior agreement or explicit post-incident agreement and must never be silently deducted.

### 3.4 No-authority scenario

For an unregistered third-party contract with no valid response authority, AegisForge must still act rapidly within its permitted capabilities: detect, validate, simulate, preserve evidence, monitor the attack, identify public defensive mechanisms, and send parallel notifications to verified official contacts. It must not convert a technical exploit path into an autonomous asset-transfer permission.

This boundary is a product constraint, not a reason to make the platform passive. The engineering objective is to build pre-authorized integrations and protocol-native response paths at scale, so execution latency is measured in blocks rather than human email round-trips wherever the protocol supports it.

## 4. Evidence and reporting

Each incident should produce a durable evidence bundle containing, as applicable:

- incident ID and lifecycle events;
- chain ID, block number/hash, contract and token addresses;
- source repository, immutable commit, verified bytecode/source relationship where available;
- vulnerability hypothesis, preconditions, attacker capabilities, invariant, impact, and falsification criteria;
- reproducible test/fork setup and tool versions;
- traces, simulation inputs/outputs, transaction calldata, receipts, and post-state;
- RPC endpoints by provider label (never credentials), failures, latency, and failover decisions;
- owner-contact discovery sources and notification delivery records;
- custody ledger, beneficiary mapping, approvals, returns, and fee agreement references;
- SHA-256 digests and signatures for evidence artifacts.

Reports must distinguish facts, inferences, and unknowns. A private report may be delivered through a verified owner-selected channel. Public disclosure requires a separate human decision and disclosure-policy review.

## 5. Security and secrets policy

- Never commit `.env`, private keys, seed phrases, API tokens, Telegram bot tokens, RPC credentials, or production credentials.
- Load secrets from environment variables or a dedicated secret manager; keep examples as placeholders.
- Treat any credential found in Git history, logs, bundles, or screenshots as compromised until rotated.
- Do not print secret values in diagnostic reports. Record only variable names, presence/absence, and redacted fingerprints if needed.
- Use separate keys and roles for monitoring, incident signing, vault custody, and administration.
- Keep signer services isolated; enforce allowlists, chain/domain separation, transaction limits, nonce protection, and explicit emergency stop controls.
- Do not let research agents execute arbitrary untrusted code on the production host. Use pinned tools and isolated runners; process limits or Docker alone are not a complete hostile-code sandbox.
- Never run live exploit tests against third-party production contracts. Use local forks, synthetic targets, or explicitly authorized test environments.
- Do not include real user PII or secret-bearing incident artifacts in public evidence bundles.

## 6. Engineering workflow and change policy

1. Inspect the current GitHub branch, exact commit SHA, server checkout SHA, working-tree state, and deployed process before editing.
2. Preserve the working deployment. Do not restart services, change live configuration, migrate databases, rotate keys, or move funds without an explicit operational plan and user approval.
3. Make changes in a dedicated branch. Do not push directly to `main` for substantial work.
4. Prefer small coherent changes with tests, migration notes, rollback instructions, and evidence.
5. Never delete hackathon history, existing experiments, or user work as cleanup without explicit approval.
6. Run relevant unit, integration, security, and end-to-end tests. Report exact commands and results.
7. A green CI run is evidence only for the checks that actually ran. It is not proof of production readiness or of a vulnerability claim.
8. Keep docs aligned with reality. Mark features `implemented`, `tested`, `deployed`, `planned`, or `blocked`.
9. Before merging, inspect the complete diff, dependency changes, secrets scan, test output, and deployment impact.
10. Every production change needs a rollback path and a post-deployment health check.

## 7. Product milestones

### Immediate: establish trustworthy baseline

- compare GitHub and server code/commit;
- map all processes, systemd units, timers, cron jobs, databases, queues, and signers;
- confirm which watcher/worker modules are actually running;
- validate each RPC endpoint against its expected chain ID and capability;
- fix failing chain pools and stale/incorrect endpoint mappings;
- identify empty/duplicate databases and determine the authoritative database before any cleanup;
- inspect secrets and credential exposure without copying secret values;
- produce a file/line-level code and runtime audit.

### MVP: reliable incident pipeline

- normalized multi-chain event ingestion with chain-specific cursors;
- contract/asset watchlists and event/transaction/state-change detection (not block-height polling alone);
- deterministic incident model and deduplicated alerting;
- exploit hypothesis + local-fork simulation + independent validation;
- policy/authority registry and allowlisted response executor;
- owner/contact discovery and parallel notifications;
- evidence bundle, custody ledger, and report generation;
- synthetic end-to-end tests covering attack detection, authorized response, failed response, replay, RPC outage, and recovery.

### 90 days: controlled pilot

- onboard a small number of protocols with documented response mandates;
- deploy a segregated recovery vault with independent controls and tested return flows;
- support a measured set of chains with healthy RPC redundancy;
- establish response-time, false-positive, recovery-integrity, and availability SLOs;
- run tabletop exercises and independent security review;
- validate paid incident-response retainers and agreed recovery fees.

### 12 months: platform

- protocol integrations and partner responder network;
- policy-driven response playbooks;
- evidence and incident APIs;
- multi-tenant access control and audit trails;
- continuous reliability/security monitoring;
- commercial subscriptions, response retainers, and transparent recovery-fee contracts.

## 8. Acceptance metrics

Do not claim success based only on number of chains or alerts. Track:

- time from first observable signal to alert;
- time to validated incident;
- time to simulated response;
- time to authorized transaction broadcast and confirmation;
- detection precision/recall on labelled incidents;
- false-positive rate and analyst override rate;
- RPC availability and chain-ID correctness;
- incident evidence completeness;
- successful recovery and return rate;
- custody reconciliation variance (target zero);
- unauthorized execution count (target zero);
- duplicate/replayed execution count (target zero);
- service uptime and recovery time after outage.

## 9. Required continuation behavior

At the start of each new work session:

1. Read this charter and the current architecture/product-readiness docs.
2. Check GitHub main HEAD and active PRs; do not assume previous SHAs are current.
3. Check server Git SHA and dirty state against GitHub.
4. Ask for or inspect the latest sanitized server audit package if not present.
5. Resume from the highest-priority verified blocker, not from a fresh redesign.
6. Record material decisions, commands, test evidence, commit SHA, and remaining blockers in the continuation checkpoint.

**This charter is a policy and target architecture. It is not a statement that all modules, safeguards, legal arrangements, or production capabilities already exist.**
