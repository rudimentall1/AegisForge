# Arbitova — M-3 prompt-injection boundary bypass (reported)

**Date found:** 2026-10-15 (provided by researcher)  
**Date submitted:** 2026-10-15 16:21 MSK (provided by researcher; delivery receipt not independently verified here)  
**Severity:** Critical (researcher-assessed; not independently validated)  
**Status:** Reported; awaiting response  
**Component:** `src/path_b/arbiter.js` → `wrapUntrusted()`  
**Source revision:** `f8bb861b7f845e1cec3b1781d138922e51b128da`  
**Disclosure channel:** `security@arbitova.com`; CC `jiayuanliang0716@gmail.com` (as reported)  
**PoC:** Full report and PoC were referenced as `~/arbitova/report-m3.txt`; that local file is not available in the GitHub repository context used to create this record.

## Summary
The researcher reports that malformed closing-tag variants may escape an untrusted-region wrapper and allow seller-controlled delivery payload data to influence an arbiter's decision. The claimed downstream impact is an incorrect seller payout decision. This public record does not independently confirm exploitability or severity.

## Technical details
The reported code location is `src/path_b/arbiter.js` → `wrapUntrusted()`, at source revision `f8bb861b7f845e1cec3b1781d138922e51b128da`. The submitted report reportedly discusses whitespace and zero-width-character variants of a closing tag. Detailed payloads, complete exploit steps, and the original report are withheld from this public branch while the issue is unresolved.

Source reference: [reported source revision](https://github.com/jiayuanliang0716-max/a2a-system/blob/f8bb861b7f845e1cec3b1781d138922e51b128da/src/path_b/arbiter.js).

## Proof of Concept
Not reproduced independently during creation of this tracker. The referenced local report was not supplied as a repository file, so its exact wording and test output could not be copied verbatim. Keep the original report and PoC privately; attach a safe regression test after coordinated disclosure.

## Impact and severity rationale
The report claims that attacker-controlled delivery evidence could cross a prompt-trust boundary and affect escrow arbitration. Critical severity and any stated bounty tier remain unverified until the program confirms scope, prerequisites, and impact.

## Recommendation
Use a parser or strict canonicalization for delimiters rather than relying on a permissive regular expression; ensure untrusted payloads cannot terminate their wrapper; add regression tests for malformed Unicode and whitespace delimiters; and treat model output as untrusted until deterministic authorization checks pass.

## Timeline
- 2026-10-15 — finding and report submission details supplied by researcher.
- 2026-10-15 — recorded in the public findings index in redacted form.
- Awaiting acknowledgement, triage, and remediation status.
