# Arbitova — M-4 content-hash gate URI-only fallback (reported)

**Date found:** 2026-10-15 (provided by researcher)  
**Date submitted:** 2026-10-15 16:34 MSK (provided by researcher; delivery receipt not independently verified here)  
**Severity:** High (researcher-assessed; not independently validated)  
**Status:** Reported; awaiting response  
**Component:** `src/path_b/arbiter.js` → `verifyDeliveryContentHash()`  
**Source revision:** `f8bb861b7f845e1cec3b1781d138922e51b128da`  
**Disclosure channel:** `security@arbitova.com`; CC `jiayuanliang0716@gmail.com` (as reported)  
**PoC:** Original report referenced as `~/arbitova/report-m4.txt`; not available in this repository context.

## Summary
The researcher reports that an URI-only fallback can be accepted as a successful content-hash match, while a related MCP flow allegedly hashes the URI rather than the content. The claimed impact is that delivery content could change without the intended content-integrity check detecting it. This record is a report summary, not an independent validation.

## Technical details
Reported component: `src/path_b/arbiter.js` → `verifyDeliveryContentHash()`. The report also references `spec/A2A-ESCROW-RFC-v0.1.md` §4.1 as requiring a hash of content rather than a URI. Full payloads and reproduction steps are withheld publicly pending coordinated disclosure.

Source reference: [reported source revision](https://github.com/jiayuanliang0716-max/a2a-system/blob/f8bb861b7f845e1cec3b1781d138922e51b128da/src/path_b/arbiter.js).

## Proof of Concept
Not independently reproduced while preparing this index. The original report was not available to copy verbatim. Preserve its exact contents privately and add a regression test that changes fetched content while keeping the URI constant.

## Impact and severity rationale
The report claims a content-integrity failure in an escrow delivery path. Severity and bounty eligibility require confirmation of the reachable code path, attacker prerequisites, and meaningful financial impact.

## Recommendation
Require a canonical content digest, fail closed when it is absent or malformed, and never treat a URI digest as equivalent to a content digest. Add tests for content mutation at a stable URI and for URI-only inputs.

## Timeline
- 2026-10-15 — finding and submission details supplied by researcher.
- 2026-10-15 — recorded in the public index in redacted form.
- Awaiting acknowledgement, triage, and remediation status.
