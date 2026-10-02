from shared.trust_evaluation import TrustDecision
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from shared import memory as memory_module
from shared import queue as queue_module
from shared.queue import TaskQueue
from agents.worker import Worker

class StateHandler(BaseHTTPRequestHandler):
    state={"status":"pending"}
    def do_POST(self):
        n=int(self.headers.get("content-length","0")); type(self).state=json.loads(self.rfile.read(n) or b"{}"); body=json.dumps(type(self).state).encode()
        self.send_response(201); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        body=json.dumps(type(self).state).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass
def test_http_execution_pipeline_is_authorized_and_independently_proven(tmp_path,monkeypatch):
    db=tmp_path/"pipeline.db"; monkeypatch.setattr(queue_module,"DB_PATH",db); monkeypatch.setattr(memory_module,"DB_PATH",db)
    server=ThreadingHTTPServer(("127.0.0.1",0),StateHandler); threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        url=f"http://127.0.0.1:{server.server_port}/state"; monkeypatch.setenv("AEGISFORGE_HTTP_ALLOWED_HOSTS","127.0.0.1")
        q=TaskQueue(); ledger=Worker("validator").evidence_ledger; authority_registry=__import__("shared.agent_authority", fromlist=["AgentAuthorityRegistry"]).AgentAuthorityRegistry(ledger.db); authority_registry.register("developer"); authority_registry.record_trust("developer", TrustDecision(status="TRUSTED", reason="seeded_test_authority", proof_id="proof-seed", verifier="test")); rec=ledger.record_capability_claim("destination-proof","validator","destination_allowed")
        intent={"role":"developer","agent_id":"developer","action":"api_request","target":url,"resource":"http_api","destination":"staging_api","data_scope":"application_data","requires_network":True,"read_only":False,"evidence_required":True,"parameters":{"method":"POST","url":url,"body":{"status":"ready"},"outcome_contract":{"type":"http_state","verifier":"http_independent_get_v1","verify_url":url,"expected_state":{"status":"ready"}}}}
        intent.update({"irreversible":False,"requires_shell":False,"requires_filesystem":False,"financial":False,"privileged":False})
        parent=q.add(description="test governed api request",role="developer",capability_intent=intent); q.claim("developer-test-worker",role="developer"); q.fail(parent,result={"error":"capability_evidence_required","error_type":"CapabilityEvidenceRequired","status":"blocked","decision":"REQUIRE_EVIDENCE","intent":intent,"evidence_claims":{"destination_allowed":{"status":rec["status"],"source":rec["source"],"evidence_id":rec["evidence_id"]}}})
        vid=q.add(description="[CAPABILITY_EVIDENCE_REQUEST] verify API authorization",role="validator",parent_task_id=parent,capability_intent={"action":"verify","resource":"authorization_prerequisites","destination":"internal","data_scope":"validation_evidence","read_only":True,"evidence_required":False},allow_failed_parent=True)
        assert Worker("validator").run_once() is True and q.get_result(vid)["status"]=="VERIFIED"
        rows=q.db.execute("SELECT id FROM queue WHERE role='executor' AND parent_task_id=?",(vid,)).fetchall(); assert len(rows)==1
        assert Worker("executor").run_once() is True
        result=q.get_result(rows[0][0]); assert result["status"]=="PROVEN"; assert result["receipt"]["result"]["status_code"]==201; assert result["outcome"]["verifier"]=="http_independent_get_v1"; assert result["outcome"]["observed_state"]=={"status":"ready"}
    finally: server.shutdown(); server.server_close()
