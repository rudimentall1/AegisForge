import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from shared.mcp_outcome_verifier import McpOutcomeVerificationError, McpOutcomeVerifier


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(size))
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"state": "ready"},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def test_mcp_outcome_verifier_proves_expected_state():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/mcp"

        class Intent:
            action = "mcp_tool_call"
            target = endpoint
            parameters = {
                "verification": {
                    "endpoint": endpoint,
                    "tool": "staging.read",
                    "arguments": {},
                    "read_only": True,
                    "expected_state": {"state": "ready"},
                }
            }

        class Receipt:
            status = "EXECUTED"
            intent_hash = None
            action = "mcp_tool_call"
            receipt_id = "receipt-1"

            def to_dict(self):
                return {
                    "status": self.status,
                    "intent_hash": self.intent_hash,
                    "action": self.action,
                    "receipt_id": self.receipt_id,
                }

        from shared.capability_grant import intent_hash
        Receipt.intent_hash = intent_hash(Intent())

        outcome = McpOutcomeVerifier(allowed_hosts={"127.0.0.1"}).verify(
            Intent(), Receipt()
        )
        assert outcome["status"] == "PROVEN"
        assert outcome["verifier"] == "mcp_independent_read_v1"
        assert outcome["observed_state"] == {"state": "ready"}
    finally:
        server.shutdown()
        server.server_close()


def test_mcp_outcome_verifier_requires_read_only_contract():
    class Intent:
        action = "mcp_tool_call"
        target = "http://127.0.0.1/mcp"
        parameters = {
            "verification": {
                "tool": "staging.read",
                "arguments": {},
                "expected_state": {"state": "ready"},
            }
        }

    class Receipt:
        status = "EXECUTED"
        intent_hash = None
        action = "mcp_tool_call"
        receipt_id = "receipt-2"

    from shared.capability_grant import intent_hash
    Receipt.intent_hash = intent_hash(Intent())

    try:
        McpOutcomeVerifier(allowed_hosts={"127.0.0.1"}).verify(Intent(), Receipt())
    except McpOutcomeVerificationError as exc:
        assert str(exc) == "mcp_verification_must_be_read_only"
    else:
        raise AssertionError("missing read_only contract was accepted")
