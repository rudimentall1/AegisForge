#!/usr/bin/env python3
"""Bounded, resumable migration of legacy queue results to AFZ1 blobs."""

import argparse
import json
import os
import sqlite3
import time
import sys
from pathlib import Path

ROOT = Path("/opt/agent-farm")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.result_codec import encode

DB = Path("/opt/agent-farm/data/agent_farm.db")
STATE = Path("/opt/agent-farm/data/.db_compactor_state.json")
MAGIC = b"AFZ1"


def load_state():
    if not STATE.exists():
        return {"last_rowid": 0, "converted": 0, "scanned": 0, "invalid": 0}
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {"last_rowid": 0, "converted": 0, "scanned": 0, "invalid": 0}


def save_state(state):
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True))
    os.replace(tmp, STATE)


def db_bytes():
    try:
        return DB.stat().st_size
    except OSError:
        return -1


def wal_bytes():
    wal = Path(str(DB) + "-wal")
    try:
        return wal.stat().st_size
    except OSError:
        return 0


def compact(batch_size, max_rows, max_seconds, pause):
    state = load_state()
    started = time.monotonic()
    scanned_run = converted_run = invalid_run = 0
    conn = sqlite3.connect(DB, timeout=30)
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA wal_autocheckpoint=10000000")
    conn.execute("PRAGMA synchronous=NORMAL")

    try:
        while scanned_run < max_rows and time.monotonic() - started < max_seconds:
            rows = conn.execute(
                "SELECT rowid, result FROM queue "
                "WHERE rowid > ? AND typeof(result) = 'text' "
                "ORDER BY rowid LIMIT ?",
                (state["last_rowid"], batch_size),
            ).fetchall()
            if not rows:
                print("DONE: no remaining legacy TEXT results")
                break

            updates = []
            for rowid, raw in rows:
                state["last_rowid"] = rowid
                state["scanned"] += 1
                scanned_run += 1
                try:
                    value = json.loads(raw)
                    encoded = encode(value)
                except (TypeError, ValueError, json.JSONDecodeError):
                    state["invalid"] += 1
                    invalid_run += 1
                    continue
                if isinstance(encoded, bytes) and encoded.startswith(MAGIC):
                    updates.append((encoded, rowid))

            if updates:
                conn.executemany("UPDATE queue SET result = ? WHERE rowid = ?", updates)
                converted = len(updates)
                state["converted"] += converted
                converted_run += converted
            conn.commit()
            save_state(state)

            print(
                f"batch rows={len(rows)} converted={len(updates)} "
                f"cursor={state['last_rowid']} db={db_bytes()/1024**3:.2f}GiB "
                f"wal={wal_bytes()/1024**2:.1f}MiB",
                flush=True,
            )
            if pause:
                time.sleep(pause)
    finally:
        conn.close()

    elapsed = max(time.monotonic() - started, 0.001)
    print(
        f"RUN scanned={scanned_run} converted={converted_run} invalid={invalid_run} "
        f"rate={scanned_run/elapsed:.1f}/s total_converted={state['converted']} "
        f"cursor={state['last_rowid']}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--max-rows", type=int, default=500)
    parser.add_argument("--max-seconds", type=float, default=45)
    parser.add_argument("--pause", type=float, default=0.25)
    args = parser.parse_args()
    compact(args.batch_size, args.max_rows, args.max_seconds, args.pause)
