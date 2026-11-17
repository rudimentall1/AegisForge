from dataclasses import replace
import json

from agents.crypto_analyst.agent import CryptoAnalyst
from agents.lab_runner.agent import LabRunner
from agents.source_researcher.agent import SourceResearcher
from agents.validator.agent import Validator
from shared.task import Task
from shared.techniques.registry import TechniqueRegistry
from tools.evm_key_forensics.run_uniswap_v2_factory_round_case import (
    NoNetworkGitHub,
    main,
    make_case,
    run_case,
)


def test_uniswap_verified_source_flows_through_round_registry_and_review():
    output = run_case()

    assert output["schema_version"] == "aegisforge-uniswap-v2-factory-round-run-v1"
    assert [item["role"] for item in output["round"]["dispatches"]] == [
        "source_researcher", "crypto_analyst", "lab_runner"
    ]
    assert all(item["dispatch"]["status"] == "DISPATCHED" for item in output["round"]["dispatches"])
    assert output["result"]["research_track"] == "uniswap_v2_factory_fixture"
    assert output["result"]["source_observation"]["conclusion"] == "SOURCE_PATTERN_MATCHED"
    assert output["result"]["solidity_analysis"]["source_supported"] is True
    assert output["result"]["lab_summary"]["synthetic_controls_passed"] is True
    assert output["result"]["validation"]["status"] == "VALIDATED"
    assert all(output["result"]["validation"]["checks"].values())
    assert output["result"]["stage_history"] == [
        "source_research", "analysis", "synthetic_experiment", "validation", "human_review"
    ]
    assert output["acceptance"]["validation_passed"] is True
    assert output["acceptance"]["final_status"] == "INCONCLUSIVE"
    assert output["safety"]["network_access"] is False
    assert output["safety"]["rpc_used"] is False
    assert output["safety"]["transactions_sent"] is False
    assert output["safety"]["automatic_confirmation"] is False
    assert output["safety"]["finding_created"] is False
    assert output["safety"]["human_review_required"] is True


def test_uniswap_wrong_case_commit_fails_closed():
    wrong_case = replace(make_case(), target_commit="a" * 40)
    output = run_case(wrong_case)

    assert output["result"]["source_observation"]["conclusion"] == "INCONCLUSIVE"
    assert output["result"]["validation"]["status"] == "INCONCLUSIVE"
    assert output["acceptance"]["final_status"] == "INCONCLUSIVE"
    assert output["safety"]["automatic_confirmation"] is False
    assert output["safety"]["finding_created"] is False


def test_validator_rejects_tampered_uniswap_synthetic_controls():
    case = make_case()
    task = Task(
        task_id="uniswap-round-tamper-test",
        description="Test-only mutation of the synthetic control output.",
        payload={
            "research_case_id": case.case_id,
            "research_case": case,
            "round_spec": case.rounds[0],
            "technique": "source_pattern",
        },
    )
    registry = TechniqueRegistry()
    for role, agent in (
        ("source_researcher", SourceResearcher(github=NoNetworkGitHub())),
        ("crypto_analyst", CryptoAnalyst()),
        ("lab_runner", LabRunner()),
    ):
        task = registry.dispatch("source_pattern", role, task, delegate=agent)
    task.result["lab_experiments"][0]["controls"]["unauthorized_caller_rejected_for_fee_to"] = False

    validated = Validator().run(task)

    assert validated.result["validation"]["status"] == "INCONCLUSIVE"
    assert validated.result["validation"]["checks"]["synthetic_controls_recomputed"] is False
    assert validated.result["final_status"] == "INCONCLUSIVE"
    assert validated.result["review"]["automatic_confirmation"] is False


def test_uniswap_runner_output_does_not_overwrite_existing_file(tmp_path, capsys):
    path = tmp_path / "result.json"
    assert main(["--output", str(path)]) == 0
    original = path.read_bytes()

    assert main(["--output", str(path)]) == 2
    assert path.read_bytes() == original
    assert "file exists" in capsys.readouterr().err.lower()
