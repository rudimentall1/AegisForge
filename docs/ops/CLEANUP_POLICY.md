# AegisForge farm disk hygiene

## Scope boundary

The cleanup job is allowed to touch **only** the checkout at `/opt/agent-farm`, and only the classes of generated files listed below. It must never inspect for deletion or modify other projects, user home directories, Docker resources, system logs, other systemd services, other nodes, or bots.

## Automatic cleanup

The weekly systemd timer runs `scripts/farm_cleanup.sh --apply` on Sunday around 04:35 UTC/server-local time with a randomized delay. The script's default mode is dry-run; deletion requires explicit `--apply`.

Allowed deletion classes:

- Python `__pycache__` directories outside excluded paths.
- `.pytest_cache`, `.mypy_cache`, and `.ruff_cache` outside excluded paths.
- Files named `*.log` or `*.log.*` older than 30 days, and only under `/opt/agent-farm/logs`.
- Files ending in `.tmp`, `.part`, or `.partial` older than 14 days, and only under `artifacts/tmp`, `artifacts/.tmp`, or `staging-execution`.

The script excludes `data/`, `.git/`, `.venv/`, and `ssv-network/`. It does not delete arbitrary untracked files.

## Never automatically delete

- SQLite databases, `-wal`/`-shm` files, DB snapshots, `*.backup*`, `*.bak*`, or compressed database archives.
- Research-case evidence, findings, artifacts not explicitly named as temporary, source files, source backups, Git worktrees, dependencies, secrets, or configuration.
- Any path outside the AegisForge checkout.

Historical database snapshots are compressed manually to `.zst` only after verifying the decompressed SHA-256 against the original. Keep them out of Git because they contain operational history and can contain sensitive data.

## Operator commands

Dry-run first:

```bash
cd /opt/agent-farm
bash scripts/farm_cleanup.sh --dry-run
```

Apply only after reviewing the listed paths:

```bash
bash scripts/farm_cleanup.sh --apply
```

Check timer and last run:

```bash
systemctl status aegisforge-farm-cleanup.timer aegisforge-farm-cleanup.service
systemctl list-timers aegisforge-farm-cleanup.timer
journalctl -u aegisforge-farm-cleanup.service -n 100 --no-pager
```

## Storage policy

- GitHub is for source code, small portable research evidence, recovery instructions, and reproducible scripts.
- Runtime DBs and their backups stay outside Git.
- Local DB backups do not protect against host loss. Keep an encrypted off-host backup separately.
- Before deleting any historical database, first confirm it is redundant, create and verify a compressed archive, compare the decompressed SHA-256, and record the action.
- Do not run system-wide `docker system prune`, `apt autoremove`, journal vacuum, or broad `/tmp` cleanup as part of AegisForge maintenance.
