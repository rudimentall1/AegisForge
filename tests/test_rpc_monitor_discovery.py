from shared.discovery import enqueue_discovery_finding
from shared.task_queue import TaskQueue
from agents.rpc_monitor import record_contract_deployment


class FakeHex(bytes):
    def hex(self):
        return "0x" + super().hex()


def test_contract_deployment_is_sent_to_canonical_research_queue(tmp_path):
    queue = TaskQueue(tmp_path / "agent_farm.db")
    transaction = {
        "hash": FakeHex(bytes.fromhex("11" * 32)),
        "from": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    }
    receipt = {
        "contractAddress": "0x1234567890abcdef1234567890abcdef12345678",
        "status": 1,
    }

    try:
        task_id, created = record_contract_deployment(
            queue, "base", 12345, transaction, receipt
        )
        row = queue.db.execute(
            "SELECT role, contract_address, fingerprint, description FROM queue WHERE id = ?",
            (task_id,),
        ).fetchone()

        assert created is True
        assert row[0] == "deep_researcher"
        assert row[1].lower() == receipt["contractAddress"].lower()
        assert row[2]
        assert '"task_type":"deep_research_intake"' in row[3]
    finally:
        queue.db.close()


def test_repeated_contract_deployment_is_deduplicated(tmp_path):
    queue = TaskQueue(tmp_path / "agent_farm.db")
    transaction = {
        "hash": FakeHex(bytes.fromhex("22" * 32)),
        "from": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    }
    receipt = {
        "contractAddress": "0x1234567890abcdef1234567890abcdef12345678",
        "status": 1,
    }

    try:
        first = record_contract_deployment(queue, "base", 12345, transaction, receipt)
        second = record_contract_deployment(queue, "base", 12346, transaction, receipt)
        assert first[1] is True
        assert second == (first[0], False)
        assert queue.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0] == 1
    finally:
        queue.db.close()


def test_failed_contract_creation_without_address_is_ignored(tmp_path):
    queue = TaskQueue(tmp_path / "agent_farm.db")
    transaction = {
        "hash": FakeHex(bytes.fromhex("33" * 32)),
        "from": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    }
    try:
        assert record_contract_deployment(
            queue, "base", 12345, transaction, {"contractAddress": None, "status": 0}
        ) is None
        assert queue.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0] == 0
    finally:
        queue.db.close()


def test_failed_contract_creation_with_derived_address_is_ignored(tmp_path):
    queue = TaskQueue(tmp_path / "agent_farm.db")
    transaction = {
        "hash": FakeHex(bytes.fromhex("44" * 32)),
        "from": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    }
    receipt = {
        "contractAddress": "0x1234567890abcdef1234567890abcdef12345678",
        "status": 0,
    }

    try:
        assert record_contract_deployment(queue, "base", 12345, transaction, receipt) is None
        assert queue.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0] == 0
    finally:
        queue.db.close()
