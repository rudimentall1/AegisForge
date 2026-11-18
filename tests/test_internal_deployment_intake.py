from agents.rpc_monitor import (
    _fetch_block_traces,
    record_internal_contract_deployments,
)
from shared.task_queue import TaskQueue


TX_HASH = "0x" + "11" * 32
ADDRESS_A = "0x" + "aa" * 20
ADDRESS_B = "0x" + "bb" * 20
CREATOR = "0x" + "cc" * 20


def test_internal_create_and_create2_are_enqueued_with_trace_provenance(tmp_path):
    queue = TaskQueue(tmp_path / "queue.db")
    trace_response = {
        "result": [
            {
                "type": "create",
                "transactionHash": TX_HASH,
                "traceAddress": [0],
                "action": {"from": CREATOR, "creationMethod": "create"},
                "result": {"address": ADDRESS_A},
            },
            {
                "type": "create",
                "transactionHash": TX_HASH,
                "traceAddress": [1],
                "action": {"from": ADDRESS_A, "creationMethod": "create2"},
                "result": {"address": ADDRESS_B},
            },
        ]
    }

    try:
        results = record_internal_contract_deployments(
            queue,
            "base",
            12345,
            trace_response,
            lambda tx_hash: {"status": 1, "contractAddress": None},
        )
        assert len(results) == 2
        rows = queue.db.execute(
            "SELECT role, contract_address, description FROM queue ORDER BY contract_address"
        ).fetchall()
        assert [row[0] for row in rows] == ["deep_researcher", "deep_researcher"]
        assert {row[1].lower() for row in rows} == {ADDRESS_A, ADDRESS_B}
        import json
        payloads = [json.loads(row[2])["discovery_finding"]["evidence"] for row in rows]
        assert {item["deployment_origin"] for item in payloads} == {"internal_trace"}
        assert {item["creation_method"] for item in payloads} == {"create", "create2"}
    finally:
        queue.db.close()


def test_reverted_root_transaction_does_not_enqueue_internal_creations(tmp_path):
    queue = TaskQueue(tmp_path / "queue.db")
    try:
        results = record_internal_contract_deployments(
            queue,
            "base",
            12345,
            {
                "result": [{
                    "type": "create",
                    "transactionHash": TX_HASH,
                    "traceAddress": [0],
                    "action": {"from": CREATOR, "creationMethod": "create"},
                    "result": {"address": ADDRESS_A},
                }]
            },
            lambda tx_hash: {"status": 0},
        )
        assert results == []
        assert queue.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0] == 0
    finally:
        queue.db.close()


class FakeProvider:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def make_request(self, method, params):
        self.calls.append((method, params))
        return self.responses[method]


class FakeWeb3:
    def __init__(self, responses):
        self.provider = FakeProvider(responses)


def test_trace_fetch_falls_back_from_parity_to_geth_call_tracer():
    w3 = FakeWeb3({
        "trace_block": {"error": {"code": -32601, "message": "method not found"}},
        "debug_traceBlockByNumber": {"result": []},
    })

    result = _fetch_block_traces(w3, 123)

    assert result == {"result": []}
    assert w3.provider.calls == [
        ("trace_block", ["0x7b"]),
        ("debug_traceBlockByNumber", ["0x7b", {"tracer": "callTracer"}]),
    ]


def test_trace_fetch_does_not_retry_after_provider_failure():
    w3 = FakeWeb3({
        "trace_block": {"error": {"code": -32000, "message": "timeout"}},
    })

    assert _fetch_block_traces(w3, 123) is None
    assert w3.provider.calls == [("trace_block", ["0x7b"])]
