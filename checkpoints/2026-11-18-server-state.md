# AegisForge checkpoint — 2026-11-18 server state

## Purpose

This checkpoint records the observed server/repository state before the next AegisForge work session. Start future sessions by reading this file, then verify whether the live server and GitHub have moved since this point.

This is an observation record, not an instruction to deploy, restart, migrate, delete, or modify anything.

## Capture metadata

- Captured: 2026-11-18 13:26 UTC
- Host: `Gensyn2.play2go.cloud`
- Server working directory: `/opt/agent-farm`
- Server Git branch: `master`
- Server HEAD: `06ed7532f7db3e98fd2552d1a27826a6448017de`
- Server Git status: clean (no entries were printed by `git status --short`)
- Origin: `rudimentall1/AegisForge`

## Important repository divergence

The server is on `master` at `06ed753`. The separately inspected development branch/PR #205 (`feat/aegisforge-working-state-2026-11-18`) is not deployed on this server. Do not assume server code includes PR #205 changes.

Do not merge PR #205 or deploy another branch as part of routine checkpoint refresh. Compare the intended commit, server HEAD, and working-tree state first.

## Runtime services observed

Active/running:
- `aegisforge-audit-bot.service`
- `aegisforge-master.service`
- `aegisforge-monitor.service`
- `aegisforge-orchestrator.service`
- `aegisforge-watcher.service`
- `aegisforge-webhook.service`
- `aegisforge-worker@1.service`
- `aegisforge-worker@2.service`
- `aegisforge-worker@3.service`
- `aegisforge-worker@4.service`
- `agent-farm.service`

Problem state:
- `aegisforge-worker.service` was `activating (auto-restart)`.
- Its latest captured log shows `agents/worker.py:65` querying `queue` for a `chain` column and failing with `sqlite3.OperationalError: no such column: chain`.
- Several named role template units (`analyst`, `crypto_analyst`, `developer`, `executor`, `lab_runner`, `opportunity_hunter`, `researcher`, `security_checker`, `source_researcher`, `validator`) were loaded but inactive/dead. This alone does not establish whether that is an error.
- Both `aegisforge-master.service` and `agent-farm.service` are active. Their ownership of queue production/consumption and overlap must be mapped before stopping or changing either service.

## Database observations

### Primary database

Path: `/opt/agent-farm/data/agent_farm.db`

- Size: 80,576,512 bytes
- Tables include `queue`, `tasks`, `research_cases`, `evidence_ledger`, `evidence_observations`, `evidence_provenance`, and planner/review tables.
- `queue`: 9,858 rows
  - pending: 9,358
  - completed: 477
  - failed: 23
- `tasks`: 500 rows
- `research_cases`: 6 rows
- `pending_human_review`: 8 rows (7 OPEN, 1 RESOLVED)
- `evidence_ledger`: 19,374 rows
- `evidence_observations`: 5,000 rows
- `evidence_provenance`: 55,846 rows
- `planner_decision_traces`: 32,933 rows
- `planner_shadow_evaluations`: 3,521 rows (3,520 completed, 1 failed)

### Secondary/legacy database

Path: `/opt/agent-farm/shared/tasks.db`

- Size: 12,288 bytes
- Contains only a `queue` table in the captured schema.
- `queue`: 0 rows.

The two databases are not interchangeable based on this evidence. Do not migrate, merge, delete, or reinitialize either database without schema inspection, a verified backup, and an explicit migration plan.

## Host resources

- Uptime: 85 days
- Load average: 10.53 / 10.51 / 10.67
- RAM: 47 GiB total, 10 GiB used, 36 GiB available
- Swap: 16 GiB configured, approximately 14.2 GiB used
- Root filesystem: 394 GiB total, 81 GiB used, 295 GiB available (22%)

Swap use is high despite available RAM. Investigate process memory history and swap activity before changing memory or service configuration.

## Monitor and network observations

- `agents.rpc_monitor` was running and showed approximately 19.8% CPU at capture time, with an elapsed runtime of nearly two days.
- The monitor was continuously logging newly detected deployments on Base.
- The separate `agent-farm.service` watcher reported successful RPC checks for Ethereum, Arbitrum, Base, Optimism, BSC, and Robinhood in the captured window.
- ARC RPC endpoints were failing: one timed out; another returned HTTP 403 / API-key access denied. ARC was therefore not reachable through the configured endpoint pool at capture time.

## Security incident: exposed Telegram bot credential

The supplied journal output included a Telegram Bot API URL containing the bot token in plaintext. The credential is intentionally not copied into this checkpoint.

Required response:
1. Revoke/regenerate the exposed bot token through Telegram BotFather.
2. Update the server secret store/environment using the new token.
3. Restart only the relevant bot service after the rotation is prepared and verified.
4. Treat old journal entries and the shared diagnostic output as sensitive because the old token remains visible there. Do not repost the raw output.

No token rotation or service restart was performed as part of this checkpoint.

## Known issues to investigate next

Priority 0 — credential exposure:
- Rotate the exposed Telegram bot token.
- Verify the bot uses the replacement credential without printing it.

Priority 1 — worker/schema mismatch:
- Inspect the actual schema of the primary `queue` table and the SQL in `agents/worker.py`.
- Determine which database the failing worker opens.
- Compare the deployed worker source with the GitHub commit.
- Add a regression test for the schema/worker contract before changing code.
- Do not alter database schema or queue contents until the correct contract and backup procedure are established.

Priority 2 — queue growth and ownership:
- Trace which service creates the 9,358 pending jobs and which workers consume them.
- Map `aegisforge-master`, `aegisforge-orchestrator`, `aegisforge-worker@1..4`, and `agent-farm` to their code paths and database paths.
- Check for duplicate producers, incompatible queue formats, starvation, and retry loops.
- Do not stop services based only on their names.

Priority 3 — RPC reliability:
- Repair or replace the ARC RPC configuration only after confirming the supported endpoint and credentials.
- Investigate the long-running RPC monitor CPU usage and cursor/progress behavior.

Priority 4 — resource pressure:
- Investigate high swap usage and the large number of Playwright driver child processes.
- Identify process ownership before terminating anything.

## Next-session operating procedure

1. Read this checkpoint first.
2. Run a fresh read-only server diagnostic and record its timestamp.
3. Compare server HEAD, branch, and clean/dirty status with GitHub.
4. Re-check service state, database paths/schema/counts, queue trends, and recent errors.
5. Update this checkpoint with a new dated file; preserve older checkpoint files as historical records.
6. Make code changes on a separate feature branch, with a failing regression test first.
7. Do not edit existing doctrine, `AGENTS_RULEBOOK.md`, or other policy documents unless the repository owner explicitly authorizes the exact change.
8. Do not merge/deploy, migrate databases, restart/stop services, or submit live state-changing blockchain transactions without explicit authorization.

## Scope of this checkpoint

- Captured from the operator-provided read-only diagnostic output.
- No server files, services, databases, wallets, or live networks were modified.
- No claim is made that the observed issues have been fixed.
