# Cashmere CCTP — Solana Ed25519 signature-instruction validation bypass (reported)

**Date found:** Date not established from the public repository content retrieved; README records email sent on 2026-08-16.  
**Date submitted:** 2026-08-16  
**Severity:** Critical (researcher-assessed; not independently validated)  
**Status:** Emailed to the team; README records no response and no confirmed mainnet fix  
**Component:** `utils/ed25519.rs` → `pre_transfer` / `verify_ed25519_ix` (as described in the source repository README)  
**Source revision:** Not pinned in the README retrieved for this record  
**Disclosure channel:** `hello@cashmere.exchange`; `cashmereprotocol@gmail.com`  
**Source repository:** [rudimentall1/cashmere-solana-sig-bypass](https://github.com/rudimentall1/cashmere-solana-sig-bypass)  
**PoC:** The source repository describes `poc/exploit.ts` as a Solana-devnet-only PoC and explicitly says it should remain private until a mainnet fix is confirmed.

## Summary
The private tracking repository describes a potential Solana Ed25519 instruction-validation flaw: instruction-index fields may be mutually consistent without being required to use the Solana instruction introspection sentinel `u16::MAX`. The report claims this could cause the program to read message and key fields from a different instruction's raw data instead of requiring the intended backend signature to be verified. This is a summary of the repository author's claim, not an independent reproduction.

## Technical details
The source README identifies `utils/ed25519.rs` and `pre_transfer` as relevant code paths. It also mentions a separate concern about a signed payload not committing to amount, recipient, or a signature-specific nonce; that secondary concern is not assessed in this record.

Exploit instructions and the PoC are intentionally not reproduced here because the source repository says the issue has not been fixed on mainnet and the PoC should remain private. See the [source README](https://github.com/rudimentall1/cashmere-solana-sig-bypass/blob/main/README.md) and the [source timeline](https://github.com/rudimentall1/cashmere-solana-sig-bypass/blob/main/TIMELINE.md).

## Proof of Concept
Not reproduced independently for this tracker. The source repository says a PoC was written but not run against a live devnet deployment. Keep `poc/exploit.ts` private until the project confirms a fix and coordinated disclosure is appropriate.

## Impact and severity rationale
The source README claims that the flaw may permit arbitrary fee and gas-drop parameters, including unauthorized use of funds in gas-drop collector accounts, but does not claim an unrestricted drain of all project funds. Severity must be evaluated by the project based on current deployments, reachable paths, and the practical value at risk.

## Recommendation
Require the canonical Solana instruction introspection sentinel where appropriate; validate the exact instruction identity, offsets, public key, message, and signature binding; bind authorization to amount and recipient where intended; and add adversarial tests for cross-instruction references and replay.

## Timeline
- Date of discovery: not established by retrieved public repository content.
- 2026-08-16 — email sent to the project team, according to the source README.
- As of the retrieved README — no response recorded and no mainnet fix confirmed.
- 2026-10-15 — entered into this public tracker in redacted form.
