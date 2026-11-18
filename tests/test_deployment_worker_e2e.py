import json

from agents import worker as worker_module
from agents.deep_researcher.agent import DeepResearcher
from agents.rpc_monitor import record_contract_deployment
from agents.worker import Worker
from shared.task_queue import TaskQueue


ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"


class FakeHex(bytes):
    def hex(self):
        return "0x" + super().hex()


class FakeEth:
    chain_id = 8453

    def __init__(self):
        self.requested_block = None

    def get_code(self, address, block_identifier):
        self.requested_block = block_identifier
        return b"\x60\x01\x60\x00"


class FakeWeb3:
    def __init__(self):
        self.eth = FakeEth()

    def is_connected(self):
        return True


class MemoryStub:
    def save_task(self, task):
        return None


def test_discovery_to_deep_research_completes_through_real_worker_loop(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    queue = TaskQueue(tmp_path / "agent_farm.db")
    fake_web3 = FakeWeb3()

    monkeypatch.setattr(
        Worker,
        "_apply_memory_guard",
        staticmethod(lambda: None),
    )
    monkeypatch.setattr(worker_module, "TaskQueue", lambda: queue)
    monkeypatch.setattr(worker_module, "Memory", MemoryStub)

    worker = Worker("deep_researcher")
    worker.agent = DeepResearcher(
        rpc_endpoints={"base": "https://rpc.example"},
        chain_ids={"base": 8453},
        evidence_dir=tmp_path / "evidence",
        web3_factory=lambda endpoint: fake_web3,
    )

    transaction = {
        "hash": FakeHex(bytes.fromhex("11" * 32)),
        "from": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    }
    receipt = {
        "contractAddress": ADDRESS,
        "status": 1,
    }

    try:
        task_id, created = record_contract_deployment(
            queue, "base", 12345, transaction, receipt
        )
        assert created is True

        assert worker.run_once() is True

        row = queue.db.execute(
            "SELECT status, result FROM queue WHERE id = ?",
            (task_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "completed"

        result = json.loads(row[1])
        assert result["agent"] == "deep_researcher"
        assert result["discovery_evidence"]["chain_id"] == 8453
        assert result["discovery_evidence"]["observed_block"] == 12345
        assert result["source_verification"]["status"] == "NOT_CONFIGURED"
        assert fake_web3.eth.requested_block == 12345

        artifact = tmp_path / "evidence" / result["evidence_artifact"]["metadata_path"]
        bytecode = tmp_path / "evidence" / result["evidence_artifact"]["bytecode_path"]
        assert artifact.is_file()
        assert bytecode.read_bytes() == b"\x60\x01\x60\x00"

        observations = queue.db.execute(
            "SELECT COUNT(*) FROM evidence_observations WHERE task_id = ?",
            (task_id,),
        ).fetchone()[0]
        assert observations >= 1
    finally:
        queue.db.close()
