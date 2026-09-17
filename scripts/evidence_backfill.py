import json
import sqlite3
from pathlib import Path
from shared.evidence_ledger import EvidenceLedger
from shared.result_codec import decode
from orchestrator.master import AutonomousPlanner

DB=Path('/opt/agent-farm/data/agent_farm.db')
STATE=Path('/opt/agent-farm/data/.evidence_backfill_state.json')
BATCH=100

def load_state():
    if STATE.exists(): return json.loads(STATE.read_text())
    return {'last_rowid':0,'processed':0}

st=load_state()
db=sqlite3.connect(DB, timeout=30)
db.execute('PRAGMA busy_timeout=30000')
ledger=EvidenceLedger(db)
rows=db.execute('''SELECT rowid,id,role,finished_at,result FROM queue
                  WHERE rowid>? AND status='completed' AND result IS NOT NULL
                  ORDER BY rowid LIMIT ?''',(st['last_rowid'],BATCH)).fetchall()
processed=0
for rowid,task_id,role,finished_at,raw in rows:
    try:
        result=decode(raw)
        atoms=AutonomousPlanner.evidence_atoms(result)
        ledger.record(task_id,role,atoms,finished_at)
    except Exception as exc:
        print(f'ROW_ERROR rowid={rowid} task={task_id}: {exc}', flush=True)
    st['last_rowid']=rowid
    st['processed']+=1
    processed+=1
STATE.write_text(json.dumps(st,separators=(',',':')))
print(f'processed={processed} cursor={st["last_rowid"]} total={st["processed"]} ledger={ledger.stats()}', flush=True)
