# AegisForge Findings Register

This directory tracks security research claims, supporting evidence, disclosure dates, and resolution status. Entries are not endorsements that a bug is valid or bounty-eligible; statuses reflect the evidence available to the author and must be updated when the recipient responds.

| Date | Project | Component | Severity (reported) | Status | Record |
|---|---|---|---|---|---|
| 2026-10-15 | Arbitova | M-3 `wrapUntrusted()` | Critical (reported) | Reported; awaiting response | [M-3](arbitova/2026-10-15-m3-prompt-injection-bypass.md) |
| 2026-10-15 | Arbitova | M-4 content-hash gate | High (reported) | Reported; awaiting response | [M-4](arbitova/2026-10-15-m4-hash-gate-bypass.md) |
| 2026-10-15 | Arbitova | `EscrowV1.resolve()` | Low (proposed) | PoC reported by researcher; not submitted | [Dust lock](arbitova/2026-10-15-dust-lock-resolve.md) |
| 2026-08-16 | Cashmere CCTP | Solana Ed25519 instruction validation | Critical (reported) | Emailed; no response recorded | [Cashmere](cashmere/2026-08-16-solana-signature-bypass.md) |

## Evidence and status policy

- Severity is the researcher's initial assessment, not a confirmed program rating or payout tier.
- A report is **confirmed** only when the affected code path and security impact are independently reproduced.
- Keep the exact source revision, test output, PoC hash, disclosure receipt, and response evidence with each case. Never imply a test ran when only code review or a written hypothesis exists.
- Do not include secrets, private keys, credentials, or private RPC tokens. Link only to public code and safe, authorized reproductions.
- Technical details and exploit PoCs for unresolved issues are intentionally withheld from this public index. Store the full report and reproducible PoC privately until coordinated disclosure is approved.

## Responsible Disclosure

Findings listed here are intended for coordinated, good-faith disclosure through the affected project's official security channel. Reports are published in redacted form while awaiting acknowledgement or a fix; sensitive reproduction details are withheld until the project acknowledges the report and disclosure is appropriate. PoCs must be limited to local tests, authorized test environments, or forks and must not be used to attack mainnet or third-party assets. Status changes should be backed by dated evidence. This tracker does not imply authorization to test systems outside an applicable program's scope.
