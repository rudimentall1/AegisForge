import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from shared.capability_policy import ActionIntent
from shared.capability_grant import intent_hash
from shared.mcp_outcome_verifier import McpOutcomeVerificationError, McpOutcomeVerifier


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(size))
        body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": {"state": "ready"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def make_intent(endpoint, verification):
    return ActionIntent(
        role="developer",
        action="mcp_tool_call",
        target=endpoint,
        resource="mcp_server",
        destination="internal",
        data_scope="staging",
        read_only=False,
        requires_network=True,
        parameters={"outcome_contract": verification},
    )


def test_mcp_outcome_verifier_proves_expected_state():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/mcp"
        intent = make_intent(endpoint, {
            "type": "mcp_state",
            "verifier": "mcp_independent_read_v1",
            "endpoint": endpoint,
            "tool": "staging.read",
            "arguments": {},
            "read_only": True,
            "expected_state": {"state": "ready"},
        })

        class Receipt:
            status = "EXECUTED"
            intent_hash = intent_hash(intent)
            action = "mcp_tool_call"
            receipt_id = "receipt-1"

            def to_dict(self):
                return self.__class__.__dict__.copy()

        outcome = McpOutcomeVerifier(allowed_hosts={"127.0.0.1"}).verify(intent, Receipt())
        assert outcome["status"] == "PROVEN"
        assert outcome["verifier"] == "mcp_independent_read_v1"
        assert outcome["observed_state"] == {"state": "ready"}
    finally:
        server.shutdown()
        server.server_close()


def test_mcp_outcome_verifier_requires_read_only_contract():
    intent = make_intent("http://127.0.0.1/mcp", {
        "type": "mcp_state",
        "verifier": "mcp_independent_read_v1",
        "endpoint": "http://127.0.0.1/mcp",
        "tool": "staging.read",
        "arguments": {},
        "read_only": False,
        "expected_state": {"state": "ready"},
    })

    class Receipt:
        status = "EXECUTED"
        intent_hash = intent_hash(intent)
        action = "mcp_tool_call"
        receipt_id = "receipt-2"

        def to_dict(self):
            return self.__class__.__dict__.copy()

    try:
        McpOutcomeVerifier(allowed_hosts={"127.0.0.1"}).verify(intent, Receipt())
    except McpOutcomeVerificationError as exc:
        assert str(exc) == "outcome_contract_mcp_arguments_invalid"
    else:
        raise AssertionError("missing read_only contract was accepted")
