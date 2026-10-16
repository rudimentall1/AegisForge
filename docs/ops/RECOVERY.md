# AegisForge recovery and durable state

## Source of truth

1. **GitHub repository:** authoritative versioned source, tests, architecture, operating instructions, research protocols, and portable evidence.
2. **Portable case evidence:** keep verified exports under `docs/research/evm-key-forensics/evidence/`, with a nearby Markdown run record describing the result and limitations.
3. **Server runtime state:** SQLite queue/case/evidence data, logs, environment configuration, and service state. These are operational data and must not be committed directly to Git.

## Server state observed 2026-10-16

- Runtime root: `/opt/agent-farm`
- Main SQLite database: `data/agent_farm.db` (about 77 MiB at inspection)
- `data/agent_farm.pre_retention_20260921.db` is a historical database around 7 GiB; do not copy it into Git or delete it without a separate retention decision.
- `data/aegisforge.db` and `data/queue.db` were 0-byte files at inspection; do not treat them as authoritative.
- The current Profanity evidence bundle is stored as a base64 text archive in this repository so the binary artifact can be reconstructed after server loss.
- Numerous untracked `*.backup*`, `*.bak*`, legacy SSV scripts, and other historical files were found. They were deliberately left untouched pending classification. A Git clone does not restore those files unless their useful contents are intentionally promoted into tracked source or documentation.

## Restore source code on a replacement host

```bash
git clone https://github.com/rudimentall1/AegisForge.git
cd AegisForge
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q
```

To reconstruct the checked-in evidence archive:

```bash
base64 -d docs/research/evm-key-forensics/evidence/profanity-master-driven-2026-10-16.zip.base64 > /tmp/profanity-master-driven-2026-10-16.zip
sha256sum /tmp/profanity-master-driven-2026-10-16.zip
python -m shared.research_case_bundle verify /tmp/profanity-master-driven-2026-10-16.zip
```

Use the service deployment instructions for the selected host and review `docs/RESEARCH-CASE-CLI.md` and `tools/evm_key_forensics/README.md` before connecting any runtime database. Do not copy secrets into Git; recreate secrets from a separately managed secret store.

## Runtime database backup requirements

Run the snapshot helper from the repository root (it is invoked through Bash so the command also works if executable permissions are not preserved by a GitHub file update):

```bash
bash scripts/backup_aegisforge_state.sh
```

The helper writes a consistent SQLite snapshot under `~/aegisforge-backups/<UTC timestamp>/`. This snapshot is **not encrypted by the script** and remains on the same host; encrypt it and copy it to a separate destination before treating it as disaster recovery.

- Use SQLite's online backup API or a transactionally consistent snapshot. Do not copy a live SQLite database with a plain `cp` and assume the result is consistent.
- Keep backups encrypted and access-controlled; include the matching application commit, UTC timestamp, database integrity-check result, and SHA-256 manifest.
- Retain more than one generation and periodically test restoration into an isolated directory.
- **A backup stored only on the same server is not disaster recovery.** Configure a separate off-host destination (object storage or another machine), credentials, encryption, and a scheduled upload before claiming the runtime state is protected against server loss.
- Never put `.env`, API tokens, private keys, live wallet material, SQLite databases, logs containing secrets, or multi-gigabyte historical DBs into GitHub.

## Recovery acceptance checklist

- [ ] Fresh clone of the repository succeeds from a separate machine.
- [ ] CI and local tests pass on the recovery commit.
- [ ] The checked-in Profanity archive can be reconstructed, passes the offline verifier, and matches the recorded ZIP SHA-256.
- [ ] Current production SQLite database has a consistent, encrypted backup outside the host.
- [ ] A restore drill has opened the restored database, run `PRAGMA integrity_check`, and verified that case/task/evidence tables are present.
- [ ] Service environment and credentials can be recreated from a secret manager, not from Git history.
- [ ] A replacement host can start the required services using the documented commit and configuration.

This document describes the recovery standard. A checkbox must not be marked complete without recorded evidence.
