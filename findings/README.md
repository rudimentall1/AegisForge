# AegisForge Findings Register

This directory tracks security research claims, supporting evidence, disclosure dates, and resolution status. Entries are not endorsements that a bug is valid or bounty-eligible; statuses reflect the evidence available to the author and must be updated when the recipient responds.

| Date | Project | Component | Severity (reported) | Status | Record and artifacts |
|---|---|---|---|---|---|
| 2026-10-15 | Arbitova | M-3 `wrapUntrusted()` | Critical (reported) | Reported; awaiting response | [Finding](arbitova/2026-10-15-m3-prompt-injection-bypass.md) · [Full report](arbitova/2026-10-15-m3-report.txt) |
| 2026-10-15 | Arbitova | M-4 content-hash gate | High (reported) | Reported; awaiting response | [Finding](arbitova/2026-10-15-m4-hash-gate-bypass.md) · [Full report](arbitova/2026-10-15-m4-report.txt) |
| 2026-10-15 | Arbitova | `EscrowV1.resolve()` | Low (proposed) | PoC supplied; not submitted; result not independently verified | [Finding](arbitova/2026-10-15-dust-lock-resolve.md) · [Fork PoC](arbitova/2026-10-15-dust-lock-poc.t.sol) |
| 2026-08-16 | Cashmere CCTP | Solana Ed25519 instruction validation | Critical (reported) | Reported by email; no response or fix confirmed in available notes | [Technical report](cashmere/2026-08-16-solana-signature-bypass.md) · [Research repository](https://github.com/rudimentall1/cashmere-solana-sig-bypass) |
| 2026-10-15 | YO Protocol | `yoUSDT._deposit()` | Low (reported) | Submitted via Immunefi; awaiting triage | [yoUSDT relay bug](https://github.com/rudimentall1/AegisForge/blob/main/findings/yo-protocol/2026-10-15-yousdt-relay-bug.md) |

## Evidence and status policy

- Severity is the researcher's initial assessment, not a confirmed program rating or payout tier.
- A report is **confirmed** only when the affected code path and security impact are independently reproduced.
- Keep the exact source revision, test output, PoC hash, disclosure receipt, and response evidence with each case. Never imply a test ran when only code review or a written hypothesis exists.
- Do not include secrets, private keys, credentials, or private RPC tokens. Link only to public code and safe, authorized reproductions.
- Do not suppress findings indefinitely solely because a recipient is silent. Record the disclosure date and response status, publish evidence-backed technical analysis, and make unresolved limitations explicit.
- Keep reproduction within local tests, controlled test environments, or authorized forks. Do not attack mainnet or spend third-party assets. If a PoC could cause direct loss on a live deployment, document the mechanism, evidence, impact, and remediation while clearly identifying the safe reproduction boundary.

## Responsible Disclosure

Reports should be sent through the project's official security contact or bounty process when one exists. Give the recipient a reasonable opportunity to acknowledge, triage, and remediate before coordinated public disclosure where practical. Acknowledgement or a fix must not be falsely implied, and silence alone is not proof that a finding is valid. Do not test against mainnet or use third-party assets; reproduce only in local tests, controlled test environments, or explicitly authorized forks. Public records must distinguish reported claims from independently reproduced behavior and confirmed deployed impact. Where a recipient remains unresponsive, document the timeline and evidence gaps and make a reasoned disclosure decision rather than withholding the report indefinitely.

## Template

Use [`_template.md`](_template.md) as the starting point for new entries. Keep each report tied to a pinned source revision and update its status as evidence changes.
