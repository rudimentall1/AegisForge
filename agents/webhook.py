import sqlite3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="AegisForge Ingest Gateway")

class TaskPayload(BaseModel):
    chain: str
    contract: str
    description: str

@app.post("/ingest")
def ingest_task(payload: TaskPayload):
    try:
        conn = sqlite3.connect('shared/tasks.db')
        cursor = conn.cursor()
        
        case_id = f"{payload.chain}:{payload.contract}"
        cursor.execute('''
            INSERT INTO queue (description, research_case_id, status)
            VALUES (?, ?, 'pending')
        ''', (payload.description, case_id))
        
        conn.commit()
        conn.close()
        return {"status": "success", "case_id": case_id, "message": "Task added to queue"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
