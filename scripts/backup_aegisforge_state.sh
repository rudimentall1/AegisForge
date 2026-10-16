#!/usr/bin/env bash
set -euo pipefail

# Creates a consistent local snapshot of the active SQLite database.
# Local snapshots alone are NOT off-host disaster recovery.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_PATH="${AEGISFORGE_DB_PATH:-$ROOT/data/agent_farm.db}"
BACKUP_DIR="${AEGISFORGE_BACKUP_DIR:-$HOME/aegisforge-backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_DIR/$STAMP"
PYTHON="$ROOT/.venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON="$(command -v python3)"

if [[ ! -f "$DB_PATH" ]]; then
  echo "Database not found: $DB_PATH" >&2
  exit 2
fi
mkdir -p "$DEST"
chmod 700 "$BACKUP_DIR" "$DEST"
export AEGISFORGE_DB_PATH="$DB_PATH"
export AEGISFORGE_DB_SNAPSHOT="$DEST/agent_farm.db"
"$PYTHON" - <<'PY'
import os, sqlite3
src = sqlite3.connect(f"file:{os.environ['AEGISFORGE_DB_PATH']}?mode=ro", uri=True, timeout=30)
try:
    dst = sqlite3.connect(os.environ["AEGISFORGE_DB_SNAPSHOT"])
    try:
        src.backup(dst)
        check = dst.execute("PRAGMA integrity_check").fetchone()[0]
        if check != "ok":
            raise SystemExit(f"SQLite integrity_check failed: {check}")
    finally:
        dst.close()
finally:
    src.close()
PY
(
  cd "$ROOT"
  git rev-parse HEAD > "$DEST/git-commit.txt"
  git status --short > "$DEST/git-status.txt"
)
printf '%s  %s\n' "$(sha256sum "$DEST/agent_farm.db" | cut -d ' ' -f1)" "agent_farm.db" > "$DEST/SHA256SUMS"
printf 'Local backup created: %s\n' "$DEST"
printf 'WARNING: copy this encrypted backup to a separate host/object store to protect against server loss.\n'
