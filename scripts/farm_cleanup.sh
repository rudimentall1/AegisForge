#!/usr/bin/env bash
set -euo pipefail

# AegisForge-only cleanup. Default is dry-run; --apply enables deletion.
ROOT="/opt/agent-farm"
MODE="${1:---dry-run}"
case "$MODE" in
  --dry-run|--apply) ;;
  *) echo "Usage: $0 [--dry-run|--apply]" >&2; exit 2 ;;
esac

if [[ ! -d "$ROOT/.git" || ! -f "$ROOT/scripts/farm_cleanup.sh" ]]; then
  echo "Refusing cleanup: expected AegisForge checkout not found at $ROOT" >&2
  exit 3
fi

if [[ "$MODE" == "--apply" ]]; then
  exec 9>/run/lock/aegisforge-farm-cleanup.lock
  flock -n 9 || { echo "Another AegisForge cleanup is already running; exiting."; exit 0; }
fi

remove_path() {
  local path="$1"
  if [[ "$MODE" == "--dry-run" ]]; then
    printf 'WOULD REMOVE %s\n' "$path"
  else
    rm -rf -- "$path"
    printf 'REMOVED %s\n' "$path"
  fi
}

echo "AegisForge cleanup mode: $MODE"
echo "Scope: $ROOT only; data/, .git/, .venv/, and ssv-network/ are excluded."

# Python/test caches are reproducible. Do not traverse the database, Git history,
# virtual environment, or the separately maintained SSV source directory.
while IFS= read -r -d '' path; do
  remove_path "$path"
done < <(
  find "$ROOT" -xdev \
    \( -path "$ROOT/.git" -o -path "$ROOT/.venv" -o -path "$ROOT/data" -o -path "$ROOT/ssv-network" \) -prune -o \
    -type d \( -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache -o -name .ruff_cache \) -prune -print0
)

# Remove only aged log files inside the farm's own logs directory.
if [[ -d "$ROOT/logs" ]]; then
  while IFS= read -r -d '' path; do
    remove_path "$path"
  done < <(find "$ROOT/logs" -xdev -type f \( -name '*.log' -o -name '*.log.*' \) -mtime +30 -print0)
fi

# Remove only old, explicitly temporary artifacts. Never delete arbitrary files.
for tmpdir in "$ROOT/artifacts/tmp" "$ROOT/artifacts/.tmp" "$ROOT/staging-execution"; do
  [[ -d "$tmpdir" ]] || continue
  while IFS= read -r -d '' path; do
    remove_path "$path"
  done < <(find "$tmpdir" -xdev -type f \( -name '*.tmp' -o -name '*.part' -o -name '*.partial' \) -mtime +14 -print0)
done

echo "Cleanup complete."
