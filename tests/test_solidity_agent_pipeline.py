import hashlib

from agents.crypto_analyst.agent import CryptoAnalyst
from agents.lab_runner.agent import LabRunner
from agents.source_researcher.agent import SourceResearcher
from agents.validator.agent import Validator
from shared.research_case import ExecutionMode, ResearchCase, RoundSpec
from shared.task import Task
from tools.evm_key_forensics.solidity_source_pattern import PINNED_COMMIT


class NoNetworkGitHub:
    BASE_URL = "https://api.github.com"

    def get_json(self, *args, **kwargs):
        raise AssertionError("the pinned local fixture must not perform GitHub requests")


def make_case(commit=PINNED_COMMIT):
    return ResearchCase(
        case_id="openzeppelin-ownable-fixture-001",
        target_repository="OpenZeppelin/openzeppelin-contracts",
        target_commit=commit,
        scope_url=(
            "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/"
            f"{PINNED_COMMIT}/contracts/access/Ownable.sol"
        ),
        scope_digest=hashlib.sha256(b"pinned local acceptance fixture").hexdigest(),
        scope_reviewed_on="2026-10-16",
        hypothesis=(
            "The pinned source routes owner-only authorization through "
            "onlyOwner/_checkOwner and _msgSender."
        ),
        attacker_capability="A synthetic non-owner caller attempts a protected operation.",
        expected_invariant="Only the synthetic owner is authorized by the toy predicate.",
        falsification_criteria="A non-owner is accepted or the pinned source checks fail.",
        execution_mode=ExecutionMode.LOCAL,
        allowed_techniques=("source_pattern",),
        rounds=(
            RoundSpec(
                round_id="ownable-source-pattern",
                technique="source_pattern",
                hypothesis="Inspect the immutable Ownable source for access-control patterns.",
                expected_evidence_atoms=("pinned Git blob", "owner authorization pattern"),
                falsification_criteria="The pinned source identity or expected patterns do not match.",
                disclosure_deadline_days=30,
            ),
        ),
    )


def run_agent_pipeline(case):
    task = Task(
        task_id="solidity-agent-pipeline",
        description="Run the pinned Solidity negative-control fixture.",
        payload={
            "research_case_id": case.case_id,
            "research_case": case,
            "round_spec": case.rounds[0],
            "technique": "source_pattern",
        },
    )
    sourced = SourceResearcher(github=NoNetworkGitHub()).run(task)
    analyzed = CryptoAnalyst().run(sourced)
    labbed = LabRunner().run(analyzed)
    return Validator().run(labbed)


def test_real_agents_run_source_analysis_synthetic_lab_and_validation_in_order():
    validated = run_agent_pipeline(make_case())
    result = validated.result

    assert validated.status == "validated"
    assert result["research_track"] == "solidity_source_fixture"
    assert result["stage_history"] == [
        "source_research", "analysis", "synthetic_experiment", "validation", "human_review"
    ]
    assert result["source_observation"]["conclusion"] == "SOURCE_PATTERN_MATCHED"
    assert result["solidity_analysis"]["status"] == "SOURCE_PATTERN_MATCHED"
    assert result["lab_summary"]["synthetic_controls_passed"] is True
    assert result["validation"]["status"] == "VALIDATED"
    assert all(result["validation"]["checks"].values())
    assert result["final_status"] == "INCONCLUSIVE"
    assert result["review"]["human_review_required"] is True
    assert result["review"]["automatic_confirmation"] is False
    assert result["review"]["finding_created"] is False


def test_wrong_case_commit_stays_inconclusive_through_all_agents():
    validated = run_agent_pipeline(make_case(commit="a" * 40))
    result = validated.result

    assert validated.status == "validated"
    assert result["source_observation"]["conclusion"] == "INCONCLUSIVE"
    assert result["solidity_analysis"]["status"] == "INCONCLUSIVE"
    assert result["validation"]["status"] == "INCONCLUSIVE"
    assert result["final_status"] == "INCONCLUSIVE"
    assert result["review"]["automatic_confirmation"] is False


def test_validator_rejects_tampered_synthetic_control_result():
    case = make_case()
    task = Task(
        task_id="solidity-agent-pipeline-tamper",
        description="Run the pinned Solidity negative-control fixture.",
        payload={
            "research_case_id": case.case_id,
            "research_case": case,
            "round_spec": case.rounds[0],
            "technique": "source_pattern",
        },
    )
    sourced = SourceResearcher(github=NoNetworkGitHub()).run(task)
    analyzed = CryptoAnalyst().run(sourced)
    labbed = LabRunner().run(analyzed)
    labbed.result["lab_experiments"][0]["controls"]["non_owner_rejected"] = False

    validated = Validator().run(labbed)

    assert validated.result["validation"]["status"] == "INCONCLUSIVE"
    assert validated.result["validation"]["checks"]["synthetic_controls_recomputed"] is False
    assert validated.result["final_status"] == "INCONCLUSIVE"
    assert validated.result["review"]["automatic_confirmation"] is False
