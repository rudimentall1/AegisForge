from shared.task import Task
from shared.onchain_target_store import OnchainTargetRecord
from agents.source_researcher.agent import SourceResearcher
from agents.crypto_analyst.agent import CryptoAnalyst
from shared.onchain_research_case import OnchainResearchCase


def _target():
    return OnchainTargetRecord(
        chain_id=8453,
        address="0x" + "1" * 40,
        block_number=123,
        block_hash="0x" + "2" * 64,
        runtime_code_sha256="3" * 64,
        source_files={
            "src/Vault.sol": (
                "contract Vault {\n"
                " function withdraw() external {\n"
                "   (bool ok,) = msg.sender.call{value: 1}(\"\");\n"
                " }\n"
                " function upgrade(address impl) external {\n"
                "   (bool ok,) = impl.delegatecall(\"\");\n"
                " }\n"
                "}\n"
            )
        },
        source_provider="blockscout_v2",
        compiler_version="0.8.24",
        contract_name="Vault",
    )


def _case(target):
    return OnchainResearchCase(
        case_id="vault-source-case",
        target_id=target.target_id,
        scope_url="https://example.com/scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-11-21",
        authorization_reference="https://example.com/authorization",
        hypothesis="Review external value transfer and upgrade authorization.",
        expected_invariant="Only authorized callers can change implementation or withdraw assets.",
        falsification_criteria="No attacker-controlled path violates the invariant.",
    )


def test_source_researcher_reads_persisted_onchain_source_without_execution():
    target = _target()
    case = _case(target)
    task = Task(
        task_id="task-source",
        description="Review Base Vault source",
        payload={"onchain_research_case": case, "onchain_target": target},
    )
    result = SourceResearcher(github=object()).run(task)
    assert result.status == "source_researched"
    assert result.result["target"]["target_id"] == target.target_id
    signals = {item["signal"] for item in result.result["source_files"][0]["signals"]}
    assert {"low_level_call", "value_transfer", "delegatecall"} <= signals
    assert result.result["analysis_limits"]["source_executed"] is False
    assert result.result["analysis_limits"]["vulnerabilities_confirmed"] == 0


def test_crypto_analyst_turns_source_signals_into_unconfirmed_hypotheses():
    target = _target()
    case = _case(target)
    source_task = Task(
        task_id="task-source",
        description="Review Base Vault source",
        payload={"onchain_research_case": case, "onchain_target": target},
    )
    source_result = SourceResearcher(github=object()).run(source_task)
    analysis_task = Task(
        task_id="task-analysis",
        description="Analyze source leads",
        payload={"onchain_research_case": case},
        result=source_result.result,
    )
    analyzed = CryptoAnalyst().run(analysis_task)
    assert analyzed.status == "crypto_analyzed"
    assert analyzed.result["onchain_source_analysis"]["candidate_hypotheses"] >= 3
    assert analyzed.result["onchain_source_analysis"]["vulnerabilities_confirmed"] == 0
    assert all(item["finding"] is False for item in analyzed.result["hypotheses"])


def test_source_researcher_fails_closed_when_target_does_not_match_case():
    target = _target()
    case = _case(target)
    other = _target()
    task = Task(
        task_id="task-mismatch",
        description="Review mismatched target",
        payload={"onchain_research_case": case, "onchain_target": other},
    )
    result = SourceResearcher(github=object()).run(task)
    assert result.status == "source_research_failed"
    assert result.result["error"] == "onchain_target_missing_or_mismatched"


def test_security_checker_scans_full_persisted_onchain_source_as_potential_risks():
    from agents.security_checker.agent import SecurityChecker
    target = _target()
    case = _case(target)
    source_task = Task(
        task_id="task-source",
        description="Review Base Vault source",
        payload={"onchain_research_case": case, "onchain_target": target},
    )
    source_result = SourceResearcher(github=object()).run(source_task)
    analysis_task = Task(
        task_id="task-analysis",
        description="Analyze source leads",
        payload={"onchain_research_case": case, "onchain_target": target},
        result=source_result.result,
    )
    checked = SecurityChecker().run(analysis_task)
    review = checked.result["onchain_security_review"]
    assert checked.status == "security_checked"
    assert review["files_scanned"] == 1
    assert review["finding_summary"]["total"] >= 2
    assert all(item["status"] == "POTENTIAL_RISK" for item in review["findings"])
    assert review["vulnerabilities_confirmed"] == 0
    assert checked.result["security_integrity"]["complete"] is True


def test_onchain_agent_capabilities_are_role_scoped_and_offline():
    from shared.action_intent import build_action_intent
    from shared.capability_policy import CapabilityDecision, CapabilityPolicy
    policy = CapabilityPolicy()
    actions = {
        "source_researcher": "research",
        "crypto_analyst": "analyze",
        "security_checker": "security_scan",
    }
    for role, action in actions.items():
        task = Task(
            task_id="capability-" + role,
            description="Inspect persisted on-chain source",
            payload={
                "capability_intent": {
                    "action": action,
                    "resource": "persisted_onchain_source",
                    "destination": "internal",
                    "data_scope": "public_source_code",
                    "requires_network": False,
                    "read_only": True,
                }
            },
        )
        intent = build_action_intent(role, task)
        decision = policy.check(intent)
        assert decision["decision"] == CapabilityDecision.ALLOW
        assert intent.requires_network is False
        assert intent.read_only is True
