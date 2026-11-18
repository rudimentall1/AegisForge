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

## 3. The Canonical Six-Phase Operational Lifecycle

1. **Phase 1: Multi-Chain Surveillance (`watcher.py`)**  
   Continuous 24/7 monitoring across all 7 networks with automatic RPC pool rotation, failover handling, and mempool/new deployment inspection.
2. **Phase 2: Vulnerability Analysis & Discovery**  
   Running static and dynamic analysis tools (`slither-analyzer`, custom AST parsers) against newly deployed and active contracts without artificial censorship or stop-words.
3. **Phase 3: Exploit Reproduction & Simulation (`rescue.py` / Anvil Fork)**  
   Isolating vectors and running local fork simulations in Anvil sandbox environments to mathematically prove exploitability and expected asset flows.
4. **Phase 4: Emergency Containment & Secure Rescue**  
   Executing authorized asset protection workflows (`rescue.py`) to evacuate vulnerable liquidity to the designated secure escrow / multisig address ahead of malicious actors.
5. **Phase 5: Advisory Generation & Reporting (`reporter.py`)**  
   Compiling technical PoC reports, cryptographic attestation proofs, and transparent bounty/recovery terms (5–10% standard white-hat fee) for protocol owners.
6. **Phase 6: Remediation, Verification & Closure**  
   Verifying developer patches on new contract deployments, executing asset return (92.5%+), logging state transitions in SQLite (`shared/tasks.db`), and closing incidents with audit trails.
