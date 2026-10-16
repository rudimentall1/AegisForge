# Profanity case run record — 2026-10-16

The original portable ZIP is represented in this repository as a base64-encoded file at `docs/research/evm-key-forensics/evidence/profanity-master-driven-2026-10-16.zip.base64`. Decode it using the instructions in [recovery guide](../../ops/RECOVERY.md).

## Case and result

- Case ID: `profanity-master-driven-2026-10-16`
- Target: pinned public `johguse/profanity` source revisions
- Workflow: Source Researcher → Crypto Analyst → Lab Runner → Validator
- Completed tasks: 12 across three bounded rounds; 3 completed tasks per role
- Bundle schema: `aegisforge-research-case-bundle-v1`
- Bundle SHA-256 (canonical bundle digest): `4987f1fb0253e93657bf8146cbf3784348a9efe83f17b006b6a246ecd4bb6730`
- Case digest: `5c1a648d6624a34a747e84927589b9a2e117034ce453ef1e87bf5c7708d5ea25`
- Evidence observations: 12
- ZIP file SHA-256: `9ffc6325639a830ed1b3b088ff970662d2416e8a0350a53074cf944fcf573105`
- Export verification: passed
- Tamper check: passed; appending one byte to `tasks.json` was rejected as `bundle_member_digest_mismatch:tasks.json`

## Interpretation

The validator outcome is **INCONCLUSIVE**, with `CONTINUE_RESEARCH` recorded as its decision. The run completed its bounded round budget, not a confirmed security conclusion.

Open blockers:

- `source_origin_independence_not_established`
- `historical_reproduction_not_qualified`
- lab receipt integrity was checked, but the receipts are not trusted
- historical reproduction remains unconfirmed

The lab used a synthetic demonstration; it did not execute the historical Profanity implementation. This run is not a confirmed vulnerability finding and does not establish exposure of any individual wallet.

The canonical bundle digest and ZIP file hash cover different byte scopes and must not be conflated.
