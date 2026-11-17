from pathlib import Path

from tools.evm_key_forensics.solidity_fixture_pipeline import run_pipeline

FIXTURE = Path(__file__).parent / "fixtures" / "solidity" / "Ownable.sol"


def test_solidity_fixture_flows_through_all_bounded_stages():
    result = run_pipeline(FIXTURE)

    assert result["final_status"] == "INCONCLUSIVE"
    stages = result["stages"]
    assert stages["source_research"]["status"] == "SOURCE_PATTERN_MATCHED"
    assert stages["analysis"]["status"] == "ANALYZED"
    assert stages["analysis"]["claims_confirmed"] == 0
    assert stages["synthetic_experiment"]["status"] == "PASSED"
    assert stages["validation"]["status"] == "VALIDATED"
    assert all(stages["validation"]["checks"].values())
    assert stages["review"]["status"] == "INCONCLUSIVE"
    assert stages["review"]["human_review_required"] is True
    assert stages["review"]["automatic_confirmation"] is False
    assert stages["review"]["finding_created"] is False


def test_mutated_source_cannot_pass_the_pinned_case(tmp_path):
    changed = tmp_path / "Ownable.sol"
    changed.write_text(FIXTURE.read_text(encoding="utf-8") + "\\n// changed", encoding="utf-8")

    result = run_pipeline(changed)

    assert result["final_status"] == "INCONCLUSIVE"
    assert result["stages"]["source_research"]["status"] == "INCONCLUSIVE"
    assert result["stages"]["validation"]["status"] == "INCONCLUSIVE"
    assert result["stages"]["review"]["automatic_confirmation"] is False


def test_missing_source_fails_closed():
    result = run_pipeline(FIXTURE.parent / "missing.sol")
    assert result["final_status"] == "INCONCLUSIVE"
    assert result["error"] == "source_read_failed:FileNotFoundError"
    assert result["review"]["human_review_required"] is True
