import hashlib
import json

from web3 import Web3

from agents.deep_researcher.agent import DeepResearcher
from shared.discovery import FINDING_SCHEMA
from shared.task import Task


ADDRESS = "0x1234567890abcdef1234567890abcdef12345678"


class FakeEth:
    def __init__(self, chain_id=8453, code=b"\x60\x01\x60\x00"):
        self.chain_id = chain_id
        self.code = code
        self.requested_block = None

    def get_code(self, address, block_identifier):
        self.requested_block = block_identifier
        return self.code


class FakeWeb3:
    def __init__(self, chain_id=8453, code=b"\x60\x01\x60\x00"):
        self.eth = FakeEth(chain_id=chain_id, code=code)

    def is_connected(self):
        return True


class FakeResponse:
    status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return {"status": "1", "result": [{"SourceCode": "contract Vault {}"}]}


def make_task(**overrides):
    values = {
        "chain": "base",
        "contract_address": ADDRESS,
        "finding_type": "contract_deployment",
        "severity": "info",
        "title": "New contract deployment detected",
        "description": "Read-only deployment discovery.",
        "evidence": {"transaction_hash": "0x" + "11" * 32},
        "observed_block": 12345,
        "source": "rpc_deployment_monitor",
        "transaction_hash": "0x" + "11" * 32,
    }
    values.update(overrides)
    identity = {
        "chain": values["chain"].lower(),
        "contract_address": values["contract_address"].lower(),
        "finding_type": values["finding_type"].lower(),
    }
    fingerprint = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    finding = {"schema": FINDING_SCHEMA, **values, "fingerprint": fingerprint}
    description = json.dumps(
        {"task_type": "deep_research_intake", "discovery_finding": finding}
    )
    return Task(task_id="research-task-1", description=description)


def test_deployment_intake_fetches_runtime_code_at_observed_block(tmp_path, monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    fake_web3 = FakeWeb3()
    researcher = DeepResearcher(
        rpc_endpoints={"base": "https://rpc.example"},
        chain_ids={"base": 8453},
        evidence_dir=tmp_path,
        web3_factory=lambda endpoint: fake_web3,
    )
    task = make_task()

    result = researcher.run(task)

    assert task.status == "deep_researched"
    assert fake_web3.eth.requested_block == 12345
    assert result.result["discovery_evidence"]["chain_id"] == 8453
    assert result.result["discovery_evidence"]["runtime_bytecode_size_bytes"] == 4
    assert result.result["discovery_evidence"]["runtime_bytecode_keccak256"].removeprefix("0x") == Web3.keccak(
        b"\x60\x01\x60\x00"
    ).hex().removeprefix("0x")
    assert result.result["source_verification"]["status"] == "NOT_CONFIGURED"
    artifact = tmp_path / result.result["evidence_artifact"]["metadata_path"]
    bytecode = tmp_path / result.result["evidence_artifact"]["bytecode_path"]
    assert artifact.is_file()
    assert bytecode.read_bytes() == b"\x60\x01\x60\x00"


def test_deployment_intake_fails_closed_on_rpc_chain_mismatch(tmp_path, monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    fake_web3 = FakeWeb3(chain_id=1)
    researcher = DeepResearcher(
        rpc_endpoints={"base": "https://rpc.example"},
        chain_ids={"base": 8453},
        evidence_dir=tmp_path,
        web3_factory=lambda endpoint: fake_web3,
    )
    task = make_task()

    result = researcher.run(task)

    assert task.status == "source_research_failed"
    assert result.result["error"] == "rpc_chain_id_mismatch"
    assert fake_web3.eth.requested_block is None
    assert list(tmp_path.rglob("*")) == []


def test_deployment_intake_persists_verified_source_hash(tmp_path, monkeypatch):
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    calls = []

    def fake_get(url, params, timeout):
        calls.append((url, params, timeout))
        return FakeResponse()

    researcher = DeepResearcher(
        rpc_endpoints={"base": "https://rpc.example"},
        chain_ids={"base": 8453},
        explorer_urls={"base": "https://basescan.org"},
        evidence_dir=tmp_path,
        web3_factory=lambda endpoint: FakeWeb3(),
        http_get=fake_get,
    )
    task = make_task()

    result = researcher.run(task)

    assert task.status == "deep_researched"
    assert result.result["source_verification"]["status"] == "VERIFIED"
    assert result.result["source_verification"]["source_sha256"] == hashlib.sha256(
        b"contract Vault {}"
    ).hexdigest()
    assert result.result["source_verification"]["explorer_url"] == (
        f"https://basescan.org/address/{Web3.to_checksum_address(ADDRESS)}#code"
    )
    assert len(calls) == 1
    source_path = tmp_path / result.result["source_verification"]["source_path"]
    assert source_path.read_text(encoding="utf-8") == "contract Vault {}"


def test_deployment_intake_rejects_tampered_finding_fingerprint(tmp_path):
    task = make_task()
    payload = json.loads(task.description)
    payload["discovery_finding"]["fingerprint"] = "0" * 64
    task.description = json.dumps(payload)
    researcher = DeepResearcher(
        rpc_endpoints={"base": "https://rpc.example"},
        chain_ids={"base": 8453},
        evidence_dir=tmp_path,
        web3_factory=lambda endpoint: FakeWeb3(),
    )

    result = researcher.run(task)

    assert task.status == "source_research_failed"
    assert result.result["error"] == "discovery_fingerprint_mismatch"



def test_deployment_intake_persists_static_analysis_report(tmp_path, monkeypatch):
    import agents.source_researcher.deployment_intake as intake_module

    monkeypatch.setenv("ETHERSCAN_API_KEY", "test-key")
    expected_analysis = {
        "schema": "aegisforge.slither_analysis.v1",
        "status": "ANALYZED",
        "findings": [
            {
                "detector": "reentrancy-eth",
                "impact": "HIGH",
                "confidence": "MEDIUM",
                "description": "Potential reentrancy.",
                "elements": [],
                "status": "UNVERIFIED_POTENTIAL",
            }
        ],
        "finding_count": 1,
        "vulnerabilities_confirmed": False,
    }
    observed_source = []

    def fake_analysis(source_code):
        observed_source.append(source_code)
        return expected_analysis

    monkeypatch.setattr(intake_module, "analyze_source", fake_analysis)
    researcher = DeepResearcher(
        rpc_endpoints={"base": "https://rpc.example"},
        chain_ids={"base": 8453},
        evidence_dir=tmp_path,
        web3_factory=lambda endpoint: FakeWeb3(),
        http_get=lambda *args, **kwargs: FakeResponse(),
    )
    result = researcher.run(make_task())

    assert result.status == "deep_researched"
    assert observed_source == ["contract Vault {}"]
    assert result.result["static_analysis"] == expected_analysis
    analysis_path = tmp_path / result.result["evidence_artifact"]["analysis_path"]
    assert json.loads(analysis_path.read_text(encoding="utf-8")) == expected_analysis
    metadata_path = tmp_path / result.result["evidence_artifact"]["metadata_path"]
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["static_analysis"] == {
        "status": "ANALYZED",
        "finding_count": 1,
        "vulnerabilities_confirmed": False,
    }
