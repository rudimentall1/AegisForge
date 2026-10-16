import json

from tools.evm_key_forensics.run_solidity_round_case import main, run_case


def test_round_runner_dispatches_source_analysis_lab_and_validation():
    output = run_case()

    assert output["schema_version"] == "aegisforge-solidity-round-run-v1"
    assert [item["role"] for item in output["round"]["dispatches"]] == [
        "source_researcher", "crypto_analyst", "lab_runner"
    ]
    assert all(item["dispatch"]["status"] == "DISPATCHED" for item in output["round"]["dispatches"])
    assert output["acceptance"]["validation_passed"] is True
    assert output["acceptance"]["final_status"] == "INCONCLUSIVE"
    assert output["acceptance"]["deployed_verified_contract_milestone_complete"] is False
    assert output["safety"]["network_access"] is False
    assert output["safety"]["rpc_used"] is False
    assert output["safety"]["transactions_sent"] is False
    assert output["safety"]["automatic_confirmation"] is False
    assert output["safety"]["finding_created"] is False
    assert output["safety"]["human_review_required"] is True


def test_round_runner_writes_new_artifact_without_overwriting(tmp_path, capsys):
    output_path = tmp_path / "acceptance-result.json"

    assert main(["--output", str(output_path)]) == 0
    first = output_path.read_bytes()
    payload = json.loads(first)
    assert payload["acceptance"]["validation_passed"] is True

    assert main(["--output", str(output_path)]) == 2
    assert output_path.read_bytes() == first
    error = capsys.readouterr().err.lower()
    assert "file exists" in error


def test_round_runner_output_is_not_a_deployed_contract_claim():
    output = run_case()
    assert output["target"]["deployed_contract_identity_verified"] is False
    assert any("not deployed bytecode" in item for item in output["limitations"])
