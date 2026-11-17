# Cashmere CCTP — Solana Ed25519 instruction-validation bypass

**Date reported:** 2026-08-16  
**Researcher:** Rinat Nabiev  
**Component reported:** `utils/ed25519.rs::verify_ed25519_ix`, called through `pre_transfer` by `transfer` / `transfer_v2`  
**Severity:** Critical (researcher-assessed; not independently reproduced in this review)  
**Disclosure status:** Email reportedly sent to `hello@cashmere.exchange` and `cashmereprotocol@gmail.com` on 2026-08-16. The available project notes record no response and no confirmed mainnet fix.  
**Primary research repository:** https://github.com/rudimentall1/cashmere-solana-sig-bypass  
**Technical notes:** https://github.com/rudimentall1/cashmere-solana-sig-bypass/blob/main/technical-notes.md  
**Original report/email:** https://github.com/rudimentall1/cashmere-solana-sig-bypass/blob/main/email.md  
**PoC source:** https://github.com/rudimentall1/cashmere-solana-sig-bypass/blob/main/poc/exploit.ts  
**PoC run notes:** https://github.com/rudimentall1/cashmere-solana-sig-bypass/blob/main/poc/RUNNING.md  
**Timeline:** https://github.com/rudimentall1/cashmere-solana-sig-bypass/blob/main/TIMELINE.md

## Executive summary

The researcher's code-review finding is that the Solana Ed25519 verification helper checks whether the signature, public-key, and message instruction-index fields equal one another, but does not require those fields to use the same-instruction sentinel `u16::MAX` (or otherwise validate that the indexed data is the data being checked by the program).

If the report's reading of the deployed code path is correct, the native Ed25519 instruction can validate a different instruction's signature while the Cashmere program reads public-key/message bytes from the preceding instruction directly. Those bytes may therefore be compared with the configured signer and expected message without being the bytes cryptographically verified by the runtime. That would break the binding between the backend authorization signature and the transfer parameters.

This report records the researcher's claim and available artifacts. **It is not an independent confirmation that the vulnerable code remains deployed or that the exploit succeeds against a current deployment.** The original email says the work was code-reviewed and not tested against mainnet; the repository describes a PoC intended for Solana devnet.

## Reported technical mechanism

1. `verify_ed25519_ix` parses the native Ed25519 instruction's offset structure, including three instruction-index fields.
2. The code reportedly checks only that the three indices match one another.
3. It does not reportedly require each index to equal `u16::MAX`, the convention used by the standard SDK helper to refer to data in the same Ed25519 instruction.
4. The program then reads the public key and message bytes from the instruction immediately preceding the calling transfer instruction and compares those bytes with the configured signer key and expected transfer parameters.
5. The researcher's hypothesis is that the native runtime could verify a separate valid signature while the Cashmere program compares unverified bytes from the preceding instruction.

The affected entry points identified in the report are `transfer` and `transfer_v2`, through `pre_transfer`.

## Reported impact and limits

The original report explicitly does **not** claim that arbitrary existing balances in Cashmere accounts can be drained through this path. It says transfers in the examined flow move value from the caller to fee/gas-drop collector accounts.

The researcher claims the bypass could allow callers to supply unauthorized transfer parameters, including a zero fee and a deadline that does not expire, and to request gas-drop amounts up to the configured cap, potentially spending funds from gas-drop collector accounts. The original notes say the configured fee rate was zero at the time of analysis, so the fee impact was then limited; the gas-drop path was identified as the material potential loss.

These impact claims require verification against the exact deployed program, current configuration, reachable instruction paths, and a safe test environment. The separate concern about signed payloads not binding amount, recipient, or a signature-specific nonce is a secondary hypothesis and is not established by this report.

## Reproduction artifacts

The research repository publicly contains a TypeScript PoC and running notes:

- [PoC source](https://github.com/rudimentall1/cashmere-solana-sig-bypass/blob/main/poc/exploit.ts)
- [PoC running notes](https://github.com/rudimentall1/cashmere-solana-sig-bypass/blob/main/poc/RUNNING.md)

The source repository's README states that the PoC had been written but had not yet been run against a live devnet deployment. Do not describe the exploit as reproduced unless test output and the tested program revision are added here. Testing must stay in a local validator, a controlled devnet deployment, or another explicitly authorized environment; do not submit crafted transactions to mainnet or spend third-party funds.

## Recommended fix and tests

- Validate that the three Ed25519 offset instruction indices use the required same-instruction sentinel, or explicitly validate the referenced instruction indices against the intended Ed25519 instruction.
- Validate offsets and bounds before reading key, signature, and message data.
- Ensure the bytes compared by the program are exactly the bytes the runtime cryptographically verified.
- Add negative tests for mutually equal but non-sentinel instruction indices, cross-instruction references, malformed offsets, mismatched signer/message, and replay or parameter substitution.
- Review whether signed authorization should bind amount, recipient, gas-drop amount, and a unique nonce.

## Disclosure timeline

- **2026-08-16:** Research notes say the finding was identified by code review and an email was sent to `hello@cashmere.exchange` and `cashmereprotocol@gmail.com`.
- **As recorded in the source repository:** response pending; mainnet fix not confirmed.
- **2026-10-15:** Added to the public AegisForge findings register.

## Evidence gaps

- Exact vulnerable source commit and deployed program version are not pinned in the available report.
- The original email says the issue was not tested against mainnet; the repository README says the PoC had not yet been run against a live devnet deployment.
- No independent reproduction output or written response from Cashmere is included in the available artifacts.
- Current mainnet fix status has not been verified.

The record is public to preserve the research and its timeline. Severity and exploitability remain researcher-reported until supported by reproducible evidence.
