# AegisForge Continuation Checkpoint

**Date:** 2026-11-18  
**Repository:** `rudimentall1/AegisForge`  
**Server project path:** `/opt/agent-farm`  
**Purpose:** Resume work in a new chat without losing the operating plan or current investigation state.

## Product direction

Read [OPERATING-CHARTER.md](OPERATING-CHARTER.md) first. The target is a commercial autonomous EVM security research and emergency-response platform: fast multi-chain threat detection, exploit analysis, simulation, authorized emergency response, recovery accounting, owner notification, verifiable evidence, and paid response/recovery services.

Do not reduce the product to a passive scanner. Do not assume an arbitrary vulnerability grants authority to move third-party assets. The executor must use a documented, scoped authority basis and segregated custody controls. Detection, simulation, evidence capture, contact discovery, and notifications should run in parallel; an already-authorized response must not wait for email.

## Current known repository context

- The GitHub README describes AegisForge as an evidence-first EVM security research toolkit.
- README identifies the release gate as `docs/PRODUCT-READINESS.md` and the architecture as `docs/ARCHITECTURE.md`.
- README says the full end-to-end run-to-evidence workflow and independent portable-bundle verifier still require release-level validation.
- A previous GitHub inspection surfaced recent work including a multi-chain watcher, RPC failover, Telegram alerts, Slither report validation, and worker fixes. A recent commit previously observed was `7667ee8603138dc7b336b53615a5ecbae1d47632` ("feat: setup robust 7-chain watcher with automatic RPC failover pools"). Re-check main HEAD before relying on this SHA.
- A prior inspection found a hardcoded Telegram bot credential in a tracked `audit_bot.py` patch. Treat it as compromised unless rotation and history cleanup have been verified. Never reproduce the value. Inspect current main and Git history; rotate any exposed credential.
- Previous concerns to re-verify against current code: watcher database path may differ from the main task queue; watcher may only poll block height rather than contract events/transactions; RPC chain IDs and endpoint mappings need validation; worker imports/role mapping need clean-checkout testing. These are investigation items, not asserted current failures.

## Server snapshot supplied on 2026-11-18

The user provided a sanitized diagnostic transcript generated from `/opt/agent-farm`. It is a snapshot, not a live connection and not proof of current state.

Observed in that snapshot:

- Watcher logs were present under PID `964168` and showed repeated block-height progress for Ethereum, Arbitrum, Base, Optimism, BSC, and Robin.
- ARC RPC pool repeatedly failed: one endpoint timed out and another returned HTTP 403 / API-key access denied. ARC should be treated as unhealthy until a valid endpoint is configured and verified.
- Some Ethereum RPC fallback attempts also returned empty responses or authentication errors in the captured log window. Verify each endpoint independently rather than trusting a generic "failover pool" label.
- Database files and sizes reported:
  - `data/queue.db`: 0 bytes
  - `data/aegisforge.db`: 0 bytes
  - `data/agent_farm_backup_before_test.db`: 884,736 bytes
  - `data/agent_farm.db`: 80,576,512 bytes
  - `shared/tasks.db`: 348,160 bytes
  - `state.db`: 0 bytes
- The snapshot listed `ownera-openradar.timer`, `ownera-immunefi.timer`, and `aegisforge-farm-cleanup.timer` among active timers. Confirm unit definitions and ownership before changing them.
- The snapshot showed `/opt/agent-farm/.env` exists. Its contents were not included and must never be pasted into chat or committed.
- The diagnostic archive was written as `/tmp/aegisforge-audit.txt.gz` (approximately 1.6 MB). The attempted SCP command used the placeholder hostname `YOUR_SERVER_IP` and failed. Transfer it from the user's workstation using the actual server address, or use another secure transfer method.
- The audit output was truncated in the chat. Obtain the actual archive before claiming a complete line-by-line server audit.

## Immediate next actions

1. Obtain and inspect the complete sanitized server audit archive. Do not ask the user to expose `.env`, private keys, seed phrases, bot tokens, or API credentials.
2. Confirm server Git branch, HEAD SHA, remote, and dirty state. Compare with GitHub main and active PR branches.
3. Map the actual systemd unit and process tree for watcher, workers, rescue, signer, and cleanup. Establish which process owns each database.
4. Read all source files with line numbers, excluding secrets, virtual environments, vendored dependencies, generated artifacts, and runtime data.
5. Verify the authoritative SQLite database and table ownership read-only. Do not merge, delete, truncate, or migrate databases during the audit.
6. Validate all RPC URLs with `eth_chainId`, expected chain ID, latest block progression, timeout, and failover behavior. Do not log credentials embedded in URLs.
7. Re-test clean checkout imports, worker startup, watcher startup, and the synthetic end-to-end research case.
8. Produce a prioritized report: P0 exposed secrets/unsafe signer/unauthorized execution; P1 data loss, broken chain coverage, failed worker pipeline; P2 reliability/observability; P3 cleanup/documentation.
9. Only then propose code changes in a dedicated branch, with tests and rollback plan. Preserve the running production service until changes are reviewed and approved.

## Safe server commands

The earlier diagnostic script at `/tmp/aegisforge_audit.py` generated the archive. Before reusing it, review its redaction behavior: regex-based redaction is not guaranteed to catch every secret format. Inspect output locally and manually remove secrets before sharing.

Useful read-only baseline commands:

```bash
cd /opt/agent-farm
git status --short --branch
git rev-parse HEAD
git log -15 --date=iso --pretty=format:'%h %ad %an %s'
systemctl status agent-farm.service --no-pager -l
systemctl show agent-farm.service -p User -p Group -p WorkingDirectory -p ExecStart -p EnvironmentFiles -p Restart -p ActiveState -p SubState
pgrep -af 'python|uvicorn|worker|watcher|rescue|agent' || true
find /opt/agent-farm -type f \( -name '*.db' -o -name '*.sqlite*' \) -printf '%p %s bytes\n'
journalctl -u agent-farm.service -n 300 --no-pager -o short-iso
```

Do not paste raw process environments, full systemd Environment values, database rows containing personal data, or secret-bearing logs. Prefer environment variable names and presence/absence.

## Handoff checklist for a new chat

- [ ] Read `docs/OPERATING-CHARTER.md`
- [ ] Read this checkpoint
- [ ] Confirm current GitHub main SHA
- [ ] Confirm server SHA and dirty state
- [ ] Obtain complete sanitized server audit archive
- [ ] Confirm which watcher/worker/signer processes are active
- [ ] Resolve ARC RPC outage and verify chain IDs
- [ ] Identify authoritative DB and resolve empty/duplicate DB ambiguity safely
- [ ] Verify exposed Telegram credential rotation and Git-history remediation
- [ ] Produce file-and-line-level audit before implementation changes

**No production code or service was changed by creating this checkpoint.**
