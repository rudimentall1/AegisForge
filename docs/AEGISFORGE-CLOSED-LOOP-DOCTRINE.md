# AEGISFORGE / OWNERA — CANONICAL SIX-PHASE OPERATING DOCTRINE

> **Document status:** Owner-approved product doctrine; implementation status must be reported separately.
> **Primary deployment target:** `/opt/agent-farm`
> **Product objective:** Detect, verify, contain, disclose, remediate, and close smart-contract security incidents through one auditable white-hat response loop.

This document is the canonical product specification for AegisForge. Agents and contributors must read it before changing monitoring, discovery, analysis, rescue, reporting, recovery, or incident-state behavior. A code change does not make a capability implemented: use the implementation-status vocabulary in this document and attach test or deployment evidence.

## 1. Mission and operating principles

AegisForge is an active EVM threat-intelligence, exploit-validation, emergency-response, and recovery system. It must identify vulnerable deployments before exploitation where possible, detect already active incidents, and continue watching vulnerable contracts even when they currently hold no assets.

The five product pillars, in priority order, are:

1. **Threat Intelligence** — discover deployments, suspicious activity, vulnerable code, and attacker behavior.
2. **Exploit Intelligence** — independently investigate and reproduce concrete exploit paths.
3. **Emergency Response** — initiate the fastest appropriate protective response when a critical threat is confirmed.
4. **Recovery Infrastructure** — coordinate evidence-backed, authorized asset protection and return.
5. **Commercial Layer** — deliver owner-facing reports, remediation support, transparent bounty accounting, and a sustainable service.

A critical finding must trigger parallel workstreams, not a slow serial queue: preserve evidence, notify the owner, prepare remediation, monitor assets and transactions, and assess the authorized emergency-response path.

Detection and analysis should be thorough and adversarial. Live actions must remain within an established authority basis. A fork simulation proves behavior in the simulated state; it does not, by itself, authorize moving third-party assets. The configured recovery destination is the intended escrow destination, not proof of authority over any particular contract or token.

## 2. Supported network scope

The target monitoring set is:

- Ethereum
- Arbitrum
- Base
- Optimism
- BNB Smart Chain (BSC)
- Robin
- Arc

Each network must have an explicit, validated network profile: canonical name, chain ID, RPC configuration, explorer/source adapter where available, native asset metadata, finality/reorg policy, and operational health. **Robin is a user-specified network label and must not be treated as production-ready until its canonical chain identity and RPC are confirmed.** Do not silently substitute another network. Arc must likewise be configured and health-checked before its monitor is marked operational.

The network list is the target scope, not a claim that all seven monitors are currently deployed or healthy.

## 3. Target universe and persistent watch registry

AegisForge must handle all four target classes:

1. **New deployments:** newly created contracts and protocol components, including liquidity pools, DEX/swap contracts, farms, staking systems, lending markets, vaults, bridges, and related infrastructure.
2. **Suspicious or potentially vulnerable contracts:** contracts showing anomalous behavior or suspected weaknesses, including unprotected initialization, reentrancy, authorization failures, access-control mistakes, unsafe upgrade paths, accounting/logic flaws, and other exploitable conditions. Inputs may come from `watcher.py`, RPC monitors, Slither, dynamic analysis, intelligence feeds, and agent research.
3. **Already compromised contracts:** contracts with evidence of prior exploitation or active attacker activity. Analyze the exploit path, attacker transactions, remaining balances/liquidity, reachable assets, and whether a safe, authorized recovery path remains.
4. **Vulnerable contracts with zero balance:** retain these in a durable watch registry. Zero balance is not a reason to discard or close a finding. Recheck relevant balances, deployments, code changes, ownership changes, and activity; when funds appear, reopen or advance the incident through the same response loop.

Every finding needs a stable identity/fingerprint and durable history. Preserve chain, contract address, discovery source, observed block/time, code or bytecode hash where available, evidence, confidence, severity, balance observations, status transitions, and links to related deployments/incidents. Deduplicate repeated observations without losing new evidence.

## 4. Canonical six-phase closed loop

These are the six product phases. Internal agents and tasks may subdivide them, but must not replace, reorder, or omit the six-phase lifecycle.

### Phase 1 — Continuous monitoring, discovery, and threat detection

- Continuously monitor the supported networks through configured RPC endpoints and the relevant services, including `watcher.py` and the RPC monitor.
- Detect new contract deployments and protocol activity, then classify likely pools, exchanges, farms, lending markets, vaults, bridges, and other high-value targets.
- Inspect verified source where available and runtime bytecode where source is unavailable. Use static analysis (including Slither where applicable), dynamic analysis, known vulnerability patterns, transaction/mempool signals where supported, and independent AI-agent research.
- Detect suspicious behavior, known exploit patterns, compromised contracts, and changes to previously assessed contracts.
- Create or update durable findings and the zero-balance watch registry. A deployment by itself is an informational observation, not a vulnerability verdict.
- Prioritize by exploitability, confidence, assets at risk, attacker activity, and response urgency.
- For a critical candidate, immediately start parallel evidence preservation, owner discovery/notification, remediation preparation, and asset/transaction monitoring while independent verification proceeds.

**Required output:** a traceable discovery/incident record with evidence, severity, confidence, affected chain/address, balance snapshot, and next actions.

### Phase 2 — Investigation and local exploit/rescue reproduction (Anvil Fork)

- Launch specialized research agents for independent code, runtime, transaction, and cryptographic analysis.
- Reconstruct the relevant chain state in an isolated Anvil Fork at a recorded block. Preserve the fork configuration and assumptions.
- Build and execute a reproducible PoC for the suspected exploit. Where relevant, model the attacker path and the protective/rescue path as separate transactions.
- Record pre-state and post-state balances, storage changes, permissions, call traces, gas use, emitted events, and exact transaction inputs/results.
- Test whether the exploit is reproducible, what assets are reachable, what conditions invalidate the PoC, and whether the proposed protection path works in the simulated state.
- Store scripts, fixtures, logs, traces, block references, and hashes as incident evidence. Do not describe an exploit as confirmed unless the evidence supports that exact claim.
- Submit the evidence to the independent Security Checker. A checker must be able to reject unsupported conclusions and identify missing assumptions.

**Required output:** reproducible fork evidence and an independently reviewed finding, with explicit limitations. Fork success is not live-chain authorization.

### Phase 3 — Emergency asset protection (`rescue.py`)

When a critical vulnerability or active compromise is confirmed, emergency response begins immediately and runs in parallel with disclosure and remediation.

- Inventory affected native-coin and ERC-20 balances, including relevant assets such as USDC, USDT, WETH, and chain-specific tokens. Recheck balances and pending activity immediately before any authorized action.
- Evaluate the fastest viable protection route: protocol-native pause/emergency withdrawal, owner- or guardian-authorized rescue, a pre-authorized recovery mechanism, or an owner-signed transaction.
- The configured intended recovery/escrow multisig is:

  `0xF462A261266C543A31Ef43A94bb48d7575299B97`

- Validate the destination and token/network compatibility for each chain. Record the authorization evidence, transaction simulation, signer/guardian approval, nonce, gas assumptions, transaction hash, confirmations, and resulting balances.
- `rescue.py` must support the workflow for native assets and ERC-20 assets, but must not infer control over a third-party contract from the discovery of a vulnerability or from a successful fork PoC.
- If no valid authority path exists, immediately alert the owner, provide the tested owner-executable rescue procedure, continue monitoring, and preserve evidence. Do not silently mark funds as rescued.
- Track each asset separately: detected, at-risk, rescue-ready, authorized, submitted, confirmed, failed, or unavailable.

**Required output:** verified asset inventory and a fully auditable protection outcome. A proposed or simulated rescue is not a completed rescue.

### Phase 4 — Technical report, PoC, owner disclosure, and bounty proposal (`reporter.py`)

Generate a technical advisory in Markdown and machine-readable JSON containing:

- incident ID, chain, contract addresses, discovery time, and affected components;
- concise vulnerability description, severity, confidence, and impact;
- evidence references, source/bytecode hashes, block references, and relevant transaction hashes;
- reproducible PoC and Anvil Fork results, including assumptions and limitations;
- assets observed, balance snapshots, and exact rescue status/amount if any;
- recommended containment, patch, migration, and validation steps;
- proposed recovery/return conditions and a transparent bounty calculation.

Identify protocol owners and verified disclosure channels. Attempt delivery through available verified contacts, the project's security contact, GitHub/security advisories/issues, official messaging channels, or developer/community channels as appropriate. Track each destination, attempt time, delivery result, response, and follow-up. Never claim a report was delivered when only generated.

A white-hat bounty proposal may use **5–10% as a negotiation range, with 7.5% as a starting proposal when appropriate**. This is not an automatic entitlement, a guaranteed payment, or a fixed deduction. The final amount, basis, recipient, and payment conditions must be agreed and recorded with the owner before settlement.

**Required output:** owner-ready advisory/PoC, disclosure-delivery record, and explicit proposed or agreed bounty terms.

### Phase 5 — Owner remediation, new deployment, and independent patch verification

- Track owner acknowledgement, remediation progress, patch publication, and any replacement or upgraded contract deployment.
- Preserve the original vulnerable address and evidence; link it to the proposed patched/new address rather than overwriting the incident history.
- Independently inspect the patch and new deployment. Verify source/bytecode identity where possible, access controls, initialization state, upgrade configuration, and relevant invariants.
- The Security Checker must retest the original PoC against the patched implementation and test plausible variants/regressions. A source diff alone is not sufficient proof that the issue is fixed.
- Confirm that the proposed return destination is the legitimate owner-controlled/new protocol address and that the return conditions match the recorded agreement.
- If the patch fails, a new vulnerability appears, or ownership/destination cannot be verified, keep the incident open and continue monitoring. Do not release escrowed assets.

**Required output:** independently verified patch result, validated return destination, and recorded owner agreement. If any condition is missing, the incident remains open.

### Phase 6 — Asset return, bounty settlement, reconciliation, and incident closure

- Return the protected principal/assets to the verified new protocol address or other owner-agreed destination, according to the recorded agreement and authorized instructions.
- Pay or retain only the explicitly agreed bounty amount and only under the agreed settlement arrangement. The principal/bounty split is not hard-coded to 92.5%/7.5%; calculate it from the actual agreement and actual recovered amount.
- Verify on-chain transaction finality and reconcile escrow balances, returned assets, bounty payment, fees, and any residual/dust amounts. Keep transaction hashes and before/after balances.
- Close an incident as `REWARD_PAID_AND_RETURNED` only after both the agreed return and bounty settlement are independently reconciled. If no bounty was agreed, record that explicitly and use the appropriate terminal outcome rather than inventing a payment.
- Preserve the full incident record, PoC, evidence, decisions, patch verification, communications, and settlement data. Feed validated patterns back into detection and regression tests.
- Resume normal discovery and keep any still-relevant watch entries active.

**Required output:** reconciled return and bounty ledger, verified terminal state, retained evidence, and updated detection knowledge.

## 5. Incident state and evidence rules

Use explicit states rather than free-form success claims. At minimum, distinguish:

- `DISCOVERED`
- `UNDER_INVESTIGATION`
- `FORK_REPRODUCED`
- `SECURITY_CHECK_PENDING`
- `CONFIRMED`
- `OWNER_NOTIFICATION_PENDING`
- `OWNER_NOTIFIED`
- `RESCUE_READY`
- `RESCUE_AUTHORIZATION_PENDING`
- `RESCUE_SUBMITTED`
- `ASSETS_PROTECTED`
- `PATCH_PENDING`
- `PATCH_VERIFICATION_PENDING`
- `PATCH_VERIFIED`
- `RETURN_PENDING`
- `SETTLEMENT_PENDING`
- `REWARD_PAID_AND_RETURNED`

Also support explicit non-success outcomes such as false positive, not reproducible, no authority path, no recoverable assets, owner unresponsive, patch rejected, rescue failed, and incident reopened. Store state transitions with timestamps, actor, evidence, and reason.

Never collapse these distinct facts into one boolean: vulnerability detected, exploit reproduced, checker approved, owner notified, rescue authorized, rescue submitted, assets confirmed protected, patch verified, assets returned, bounty settled.

## 6. Recovery destination and operational configuration

The configured multisig address above is the intended recovery destination. It must be checked against the target chain and asset before use. Network-specific RPCs, chain IDs, token metadata, explorer adapters, signer/guardian configuration, and authorization mechanisms belong in explicit configuration, not scattered hard-coded assumptions.

Secrets and signing authority must be managed through the deployment's established secret-management mechanism. Agents may prepare, simulate, validate, and request an authorized action; they must not fabricate approvals or report an unsigned transaction as executed.

## 7. Engineering and verification requirements

- Read this doctrine and `docs/AGENT_PROTOCOL.md` before work on relevant components.
- Prefer the canonical Discovery/TaskQueue intake and durable evidence store. Do not create a parallel queue or database without a migration plan.
- Every new detector or response path needs deterministic tests using fixtures or fake RPC. Unit tests must not depend on live networks.
- Preserve legacy evidence and incident data during migrations. No destructive DB reset or silent schema replacement.
- Every operational capability must have an owner-visible status and evidence.
- Do not claim a network is monitored, a vulnerability is confirmed, assets are protected, a patch is safe, or a payout is complete without the corresponding verification.

Use these implementation statuses consistently:

- `NOT_IMPLEMENTED` — no working implementation.
- `PARTIAL` — some components exist, but the full behavior is not verified.
- `IMPLEMENTED_TESTED` — implementation and automated tests pass.
- `DEPLOYED_VERIFIED` — deployed on the target environment and verified against operational evidence.

## 8. Change control

This doctrine captures the owner's canonical six-phase product goal. Contributors may propose amendments, but must not silently remove a target class, network, phase, evidence requirement, or recovery step. Changes to the operating doctrine require an explicit owner decision and a versioned repository change.

The roadmap may stage implementation over time; it may not redefine an unimplemented phase as out of scope or describe the overall closed loop as complete before all required phases are operationally verified.
