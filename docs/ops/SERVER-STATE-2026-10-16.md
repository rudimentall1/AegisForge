# Server state and recovery checkpoint — 2026-10-16

This checkpoint records what was verified on the AegisForge host and what is, and is not, recoverable from GitHub.

## Repository and tests

- Repository: `rudimentall1/AegisForge`
- Mainline recovery/evidence work merged through PR [#60](https://github.com/rudimentall1/AegisForge/pull/60).
- The server checkout was reset to `origin/main` after the merge.
- Full test suite: **1072 passed, 2 warnings, 6 subtests passed** in 161.70 seconds. The two warnings are deliberate duplicate ZIP-member fixtures used to test rejection behavior.
- Focused case pipeline tests: **12 passed**.
- All five systemd units were active after the test run: Master, Source Researcher, Crypto Analyst, Lab Runner, Validator.

## Portable research evidence

- Case: `profanity-master-driven-2026-10-16`
- Reconstructable archive: `docs/research/evm-key-forensics/evidence/profanity-master-driven-2026-10-16.zip.base64`
- Reconstructed ZIP SHA-256: `9ffc6325639a830ed1b3b088ff970662d2416e8a0350a53074cf944fcf573105`
- Offline verifier: `valid=true`, 12 tasks, 12 evidence observations.
- Tampered member check rejected the modified `tasks.json`.

The case result remains **INCONCLUSIVE**. Historical implementation reproduction, independent source-origin provenance, and trusted execution receipts are not established.

## Runtime database snapshot

- Active database: `/opt/agent-farm/data/agent_farm.db`
- Snapshot: `/root/aegisforge-backups/20261016T063633Z/agent_farm.db`
- Snapshot size: 80,576,512 bytes
- `PRAGMA integrity_check`: `ok`
- Tables found: 17

**This snapshot is not encrypted and is stored on the same server. It is a tested local recovery point, not protection against total server loss.** Off-host encrypted backup remains open because no external destination/credentials were configured during this work. Do not claim full disaster recovery until a separate destination and restore drill are verified.

## Preserved but not promoted

The server still contains untracked historical source backups, legacy SSV dispatch scripts, and experimental files. They were not deleted. Most dated backup copies appear to be earlier snapshots of files whose active history is already in Git, but unique files such as `shared/mcp_executor.py`, `shared/result.py`, and `*.v2` have not yet received a full review and are **not** included in the repository's supported product path. Treat them as unreviewed local material, not trusted runtime dependencies.

## Remaining recovery and product work

1. Configure encrypted off-host backup for the active SQLite database, including retention and a tested restore procedure.
2. Review unique untracked source files and intentionally promote or discard them only after dependency and security review.
3. Close the product blockers for source-origin independence, trusted receipt provenance, and historical reproduction without promoting the Profanity result beyond INCONCLUSIVE.
