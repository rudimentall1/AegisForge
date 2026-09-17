import argparse
import json
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path('/opt/agent-farm')
sys.path.insert(0, str(PROJECT_ROOT))

from shared.evidence_ledger import EvidenceLedger
from shared.result_codec import decode
from orchestrator.master import AutonomousPlanner

DB = PROJECT_ROOT / 'data/agent_farm.db'
STATE = PROJECT_ROOT / 'data/.evidence_backfill_state.json'
BATCH = 100


def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {'last_rowid': 0, 'processed': 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-tasks', type=int, default=BATCH)
    args = parser.parse_args()
    st = load_state()
    db = sqlite3.connect(DB, timeout=30)
    db.execute('PRAGMA busy_timeout=30000')
    ledger = EvidenceLedger(db)
    remaining = max(0, args.max_tasks)
    processed = 0
    while remaining:
        limit = min(BATCH, remaining)
        rows = db.execute('''SELECT rowid,id,role,finished_at,result FROM queue
                             WHERE rowid>? AND status='completed' AND result IS NOT NULL
                             ORDER BY rowid LIMIT ?''',
                          (st['last_rowid'], limit)).fetchall()
        if not rows:
            break
        db.execute('BEGIN')
        try:
            for rowid, task_id, role, finished_at, raw in rows:
                result = decode(raw)
                atoms = AutonomousPlanner.evidence_atoms(result)
                ledger.record(task_id, role, atoms, finished_at, commit=False)
                st['last_rowid'] = rowid
                st['processed'] += 1
                processed += 1
            db.commit()
        except Exception:
            db.rollback()
            raise
        STATE.write_text(json.dumps(st, separators=(',', ':')))
        remaining -= len(rows)
    print(f'processed={processed} cursor={st["last_rowid"]} total={st["processed"]} ledger={ledger.stats()}')


if __name__ == '__main__':
    main()
