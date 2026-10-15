# AegisForge Findings Register

This directory tracks security research claims, supporting evidence, disclosure dates, and resolution status. Entries are not endorsements that a bug is valid or bounty-eligible; statuses reflect the evidence available to the author and must be updated when the recipient responds.

| Date | Project | Component | Severity (reported) | Status | Record |
|---|---|---|---|---|---|
| 2026-10-15 | Arbitova | M-3 wrapUntrusted() | Critical (reported) | Reported; awaiting response | [M-3](arbitova/2026-10-15-m3-prompt-injection-bypass.md) |
| 2026-10-15 | Arbitova | M-4 content-hash gate | High (reported) | Reported; awaiting response | [M-4](arbitova/2026-10-15-m4-hash-gate-bypass.md) |
| 2026-10-15 | Arbitova | EscrowV1.resolve() | Low (proposed) | PoC reported by researcher; not submitted | [Dust lock](arbitova/2026-10-15-dust-lock-resolve.md) |
| 2026-08-16 | Cashmere CCTP | Solana Ed25519 instruction validation | Critical (reported) | Reported by email; no response or fix confirmed in available notes | [Cashmere technical report](cashmere/2026-08-16-solana-signature-bypass.md) |
| 2026-10-15 | YO Protocol | yoUSDT._deposit() | Low (reported) | Submitted via Immunefi (ID 96055); awaiting triage | [yoUSDT relay bug](yo-protocol/2026-10-15-yousdt-relay-bug.md) |
| 2026-10-15 | Basin | Stable2.calcLpTokenSupply() | Research note (not submitted) | REJECTED by PoC | [Stable2 overflow](basin/2026-10-15-stable2-overflow-research-note.md) |

## Research notes (not submitted)

Some findings are investigated to completion but not submitted to Immunefi because their real-world impact does not meet the program's severity threshold. These are kept for methodology tracking and to avoid re-investigating the same vector later.

- [Basin — Stable2.calcLpTokenSupply overflow (REJECTED by PoC)](basin/2026-10-15-stable2-overflow-research-note.md)

## Evidence and status policy

- Severity is the researcher's initial assessment, not a confirmed program rating or payout tier.
- A report is confirmed only when the affected code path and security impact are independently reproduced.
- Keep the exact source revision, test output, PoC hash, disclosure receipt, and response evidence with each case. Never imply a test ran when only code review or a written hypothesis exists.
- Do not include secrets, private keys, credentials, or private RPC tokens. Link only to public code and safe, authorized reproductions.
- Do not suppress findings indefinitely solely because a recipient is silent. Record the disclosure date and response status, publish evidence-backed technical analysis, and make unresolved limitations explicit.
- Keep reproduction within local tests, controlled test environments, or authorized forks. Do not attack mainnet or spend third-party assets. If a PoC could cause direct loss on a live deployment, document the mechanism, evidence, impact, and remediation while clearly identifying the safe reproduction boundary.

## Disclosure approach

The register favors factual, evidence-backed public disclosure over indefinite secrecy. Silence from a recipient is not proof that a vulnerability is valid, and publication is not proof of exploitability. Entries must distinguish source-code observations, researcher claims, reproduced results, and confirmed deployed impact. Update records when new test evidence, acknowledgements, fixes, or deployment information becomes available.
