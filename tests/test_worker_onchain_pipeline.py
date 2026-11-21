from agents.crypto_analyst.agent import CryptoAnalyst
from agents.security_checker.agent import SecurityChecker
from agents.source_researcher.agent import SourceResearcher
from agents.worker import Worker
from shared.agent_identity import AgentIdentity
from shared.capability_policy import CapabilityPolicy
from shared.evidence_ledger import EvidenceLedger
from shared.onchain_research_case import OnchainResearchCase
from shared.onchain_target_store import OnchainTargetRecord, OnchainTargetStore
from shared.queue import TaskQueue


class _Memory:
    def save_task(self, task):
        return None


def test_worker_executes_complete_onchain_source_pipeline_with_case_binding(
    tmp_path, monkeypatch
):
    import agents.security_checker.agent as security_module

    def fail_if_github_is_initialized():
        raise AssertionError("on-chain pipeline must not initialize GitHub access")

    monkeypatch.setattr(security_module, "GitHubClient", fail_if_github_is_initialized)

    queue = TaskQueue(db_path=tmp_path / "onchain-worker-e2e.sqlite3")
    try:
        target = OnchainTargetRecord(
            chain_id=8453,
            address="0x" + "1" * 40,
            block_number=123,
            block_hash="0x" + "2" * 64,
            runtime_code_sha256="3" * 64,
            source_files={
                "src/Vault.sol": (
                    "contract Vault {\\n"
                    " function withdraw() external { _send(); }\\n"
                    " function _send() internal {\\n"
                    "   (bool ok,) = msg.sender.call{value: 1}(\\\"\\");\\n"
                    " }\\n"
                    " function upgrade(address impl) external {\\n"
                    "   (bool ok,) = impl.delegatecall(\\\"\\");\\n"
                    " }\\n"
                    "}\\n"
                )
            },
            source_provider="blockscout_v2",
            compiler_version="0.8.24",
            contract_name="Vault",
        )
        OnchainTargetStore(queue.db).put(target)
        case = OnchainResearchCase(
            case_id="worker-onchain-e2e",
            target_id=target.target_id,
            scope_url="https://example.com/scope",
            scope_digest="b" * 64,
            scope_reviewed_on="2026-11-21",
            authorization_reference="https://example.com/authorization",
            hypothesis="Review withdrawal and upgrade authorization paths.",
            expected_invariant="Only authorized callers may transfer assets or change implementation.",
            falsification_criteria="No untrusted caller can violate the stated invariant.",
        )
        queue.register_onchain_research_case(case)
        first_task_id = queue.add(
            "Review explicitly scoped Vault source",
            role="source_researcher",
            onchain_case_id=case.case_id,
        )

        agents = {
            "source_researcher": SourceResearcher(github=object()),
            "crypto_analyst": CryptoAnalyst(),
            "security_checker": SecurityChecker(),
        }
        expected_roles = [
            "source_researcher",
            "crypto_analyst",
            "security_checker",
        ]
        for role in expected_roles:
            worker = Worker.__new__(Worker)
            worker.role = role
            worker.worker_id = "integration-" + role
            worker.agent_id = "integration-agent-" + role
            worker.agent_identity = AgentIdentity(
                agent_id=worker.agent_id,
                role=role,
            )
            worker.queue = queue
            worker.memory = _Memory()
            worker.policy = CapabilityPolicy()
            worker.evidence_ledger = EvidenceLedger(queue.db)
            worker.agent = agents[role]

            assert worker.run_once() is True

        rows = queue.db.execute(
            "SELECT id, role, parent_task_id, onchain_case_id "
            "FROM queue ORDER BY rowid"
        ).fetchall()
        assert [row[1] for row in rows] == expected_roles
        assert [row[3] for row in rows] == [case.case_id] * 3
        assert rows[0][0] == first_task_id
        assert rows[1][2] == rows[0][0]
        assert rows[2][2] == rows[1][0]

        results = [queue.get_result(row[0]) for row in rows]
        assert all(
            result["onchain_research_case_binding"]["case_id"] == case.case_id
            for result in results
        )
        assert results[0]["research_track"] == "onchain_solidity_source_research"
        assert results[1]["onchain_source_analysis"]["candidate_hypotheses"] > 0
        assert results[1]["onchain_source_analysis"]["vulnerabilities_confirmed"] == 0
        review = results[2]["onchain_security_review"]
        assert review["structural_review"]["independently_recomputed"] is True
        assert review["vulnerabilities_confirmed"] == 0
        assert review["finding_created"] is False
        assert queue.db.execute(
            "SELECT COUNT(*) FROM queue WHERE role = 'lab_runner'"
        ).fetchone()[0] == 0
    finally:
        queue.db.close()
