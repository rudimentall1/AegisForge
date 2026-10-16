import copy
import hashlib
import json

import pytest

from shared.reproduction_contract import (
    MAX_CONTRACT_BYTES,
    REPRODUCTION_CONTRACT_VERSION,
    ReproductionContractError,
    canonical_contract_bytes,
    contract_sha256,
    load_reproduction_contract,
    validate_reproduction_contract,
)


def valid_contract():
    return {
        "schema_version": REPRODUCTION_CONTRACT_VERSION,
        "contract_id": "repro-contract-001",
        "case_id": "case-2026-001",
        "hypothesis_id": "hypothesis-entropy-001",
        "target": {
            "repository": "owner/repository",
            "commit_sha": "a" * 40,
            "scope_reference": "https://example.com/security-scope",
            "source_path": "src/target.py",
        },
        "toolchain": {
            "runtime": "python",
            "version": "3.10.12",
            "image_ref": "python:3.10-slim@sha256:" + "b" * 64,
            "image_digest": "sha256:" + "b" * 64,
        },
        "command": ["python", "-m", "pytest", "tests/test_target.py", "-q"],
        "working_directory": ".",
        "environment": {"PYTHONHASHSEED": "0", "LC_ALL": "C.UTF-8"},
        "network_access": "disabled",
        "limits": {
            "timeout_seconds": 60,
            "cpu_cores": 2,
            "memory_mb": 1024,
            "max_processes": 32,
            "max_output_bytes": 1024 * 1024,
        },
        "expected_exit_code": 0,
        "expected_outputs": [
            {"path": "results/summary.json", "sha256": "c" * 64},
        ],
    }


def test_valid_contract_is_normalized_and_canonical():
    payload = valid_contract()

    normalized = validate_reproduction_contract(payload)
    canonical = canonical_contract_bytes(payload)

    assert normalized["schema_version"] == REPRODUCTION_CONTRACT_VERSION
    assert normalized["network_access"] == "disabled"
    assert normalized["expected_outputs"][0]["path"] == "results/summary.json"
    assert canonical == canonical_contract_bytes(normalized)
    assert contract_sha256(payload) == hashlib.sha256(canonical).hexdigest()


def test_strict_json_loader_rejects_duplicate_keys():
    with pytest.raises(ReproductionContractError, match="duplicate_json_key"):
        load_reproduction_contract('{"schema_version":"x","schema_version":"y"}')


@pytest.mark.parametrize("raw", [b"\xff", '{"value": NaN}'])
def test_strict_json_loader_rejects_invalid_json_bytes_or_constants(raw):
    with pytest.raises(ReproductionContractError):
        load_reproduction_contract(raw)


def test_contract_input_size_is_bounded():
    with pytest.raises(ReproductionContractError, match="contract_size_limit_exceeded"):
        load_reproduction_contract(b" " * (MAX_CONTRACT_BYTES + 1))


@pytest.mark.parametrize("bad_path", ["../escape.py", "/etc/passwd", "src\\target.py", "src/./target.py", "C:/target.py"])
def test_target_source_path_must_be_safe_relative_path(bad_path):
    payload = valid_contract()
    payload["target"]["source_path"] = bad_path

    with pytest.raises(ReproductionContractError, match="target_source_path_invalid"):
        validate_reproduction_contract(payload)


def test_scope_reference_must_be_https_url_without_credentials():
    for value in ("http://example.com/scope", "https://", "https://user:pass@example.com/scope", "https://[::1"):
        payload = valid_contract()
        payload["target"]["scope_reference"] = value
        with pytest.raises(ReproductionContractError, match="scope_reference_must_be_https_url"):
            validate_reproduction_contract(payload)


def test_network_must_remain_disabled():
    payload = valid_contract()
    payload["network_access"] = "enabled"

    with pytest.raises(ReproductionContractError, match="network_access_must_be_disabled"):
        validate_reproduction_contract(payload)


@pytest.mark.parametrize("key", ["API_TOKEN", "PRIVATE_KEY", "WALLET_SEED", "SEED_PHRASE", "AUTHORIZATION"])
def test_secret_bearing_environment_names_are_rejected(key):
    payload = valid_contract()
    payload["environment"][key] = "placeholder"

    with pytest.raises(ReproductionContractError, match="environment_secret_name_rejected"):
        validate_reproduction_contract(payload)


@pytest.mark.parametrize("field,value", [
    ("timeout_seconds", True),
    ("cpu_cores", 0),
    ("memory_mb", -1),
    ("max_processes", 1000),
    ("max_output_bytes", 0),
])
def test_resource_limits_reject_malformed_values(field, value):
    payload = valid_contract()
    payload["limits"][field] = value

    with pytest.raises(ReproductionContractError, match=f"{field}_out_of_bounds"):
        validate_reproduction_contract(payload)


def test_toolchain_must_be_pinned_by_sha256_digest():
    payload = valid_contract()
    payload["toolchain"]["image_digest"] = "sha256:latest"

    with pytest.raises(ReproductionContractError, match="toolchain_image_digest_invalid"):
        validate_reproduction_contract(payload)


@pytest.mark.parametrize("bad_digest", ["z" * 64, "A" * 64, "abc"])
def test_expected_output_digest_rejects_malformed_nonempty_values(bad_digest):
    payload = valid_contract()
    payload["expected_outputs"][0]["sha256"] = bad_digest

    with pytest.raises(ReproductionContractError, match="expected_output_sha256_invalid"):
        validate_reproduction_contract(payload)


def test_expected_output_paths_must_be_unique():
    payload = valid_contract()
    payload["expected_outputs"].append(copy.deepcopy(payload["expected_outputs"][0]))

    with pytest.raises(ReproductionContractError, match="expected_output_path_duplicate"):
        validate_reproduction_contract(payload)


def test_unknown_contract_fields_are_rejected():
    payload = valid_contract()
    payload["auto_confirm_finding"] = True

    with pytest.raises(ReproductionContractError, match="contract_fields_invalid"):
        validate_reproduction_contract(payload)


def test_contract_is_declaration_only_and_does_not_execute_command():
    payload = valid_contract()
    result = validate_reproduction_contract(payload)

    assert result["command"] == payload["command"]
    assert result["network_access"] == "disabled"
    assert "execution_result" not in result
    assert "finding" not in result



def test_command_and_environment_values_preserve_exact_bytes():
    payload = valid_contract()
    payload["command"].append("  --exact-argument  ")
    payload["environment"]["EXTRA_VALUE"] = "  exact value  "

    normalized = validate_reproduction_contract(payload)

    assert normalized["command"][-1] == "  --exact-argument  "
    assert normalized["environment"]["EXTRA_VALUE"] == "  exact value  "


def test_empty_command_executable_is_rejected():
    payload = valid_contract()
    payload["command"][0] = "   "

    with pytest.raises(ReproductionContractError, match="command_executable_invalid"):
        validate_reproduction_contract(payload)



def test_toolchain_image_reference_must_be_pinned_to_matching_digest():
    payload = valid_contract()
    payload["toolchain"]["image_ref"] = "python:3.10-slim:latest@sha256:" + "d" * 64

    with pytest.raises(ReproductionContractError, match="toolchain_image_ref_invalid"):
        validate_reproduction_contract(payload)
