import copy
import hashlib

import pytest

from shared.experiment_dossier import (
    ExperimentDossierError,
    canonical_json,
    dossier_sha256,
    validate_experiment_dossier,
)


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _dossier():
    argv = ["python", "-m", "pytest", "tests/test_synthetic_fixture.py", "-q"]
    return {
        "schema_version": "evm-key-forensics-experiment-dossier-v1",
        "experiment_id": "synthetic-source-check-v1",
        "run_id": "run-synthetic-0001",
        "nonce": "operator-supplied-unique-nonce-0001",
        "source": {"repository": "https://github.com/rudimentall1/AegisForge", "revision": "a" * 40},
        "fixture": {"fixture_id": "fixture-synthetic-001", "sha256": _sha("fixture")},
        "command": {"argv": argv, "argv_sha256": _sha(canonical_json(argv))},
        "harness": {"harness_sha256": _sha("harness"), "build_recipe_sha256": _sha("build recipe")},
        "runner": {"provider_id": "local-test-only", "runner_id": "pytest-worker", "image_digest": None},
        "execution": {
            "started_at": "2026-10-12T06:00:00Z",
            "completed_at": "2026-10-12T06:00:03Z",
            "exit_code": 0,
            "timed_out": False,
            "test_passed": True,
        },
        "result_sha256": _sha("result"),
        "artifacts": [{"name": "result.json", "sha256": _sha("artifact")}],
        "safety": {
            "scope": "synthetic_only",
            "historical_code_executed": False,
            "real_key_material_handled": False,
        },
    }


def test_valid_dossier_is_structurally_valid_but_not_qualified():
    result = validate_experiment_dossier(_dossier())
    assert result["valid"] is True
    assert result["qualification"] == "NOT_ESTABLISHED"
    assert result["artifact_count"] == 1
    assert len(result["dossier_sha256"]) == 64


def test_dossier_digest_is_stable_under_object_key_reordering():
    dossier = _dossier()
    reordered = dict(reversed(list(dossier.items())))
    assert dossier_sha256(dossier) == dossier_sha256(reordered)


@pytest.mark.parametrize("field", [
    "experiment_id", "run_id", "nonce", "source", "fixture", "command",
    "harness", "runner", "execution", "result_sha256", "artifacts", "safety",
])
def test_missing_top_level_claim_is_rejected(field):
    dossier = _dossier()
    del dossier[field]
    with pytest.raises(ExperimentDossierError, match="dossier_fields_missing"):
        validate_experiment_dossier(dossier)


def test_unknown_top_level_claim_is_rejected():
    dossier = _dossier()
    dossier["independent"] = True
    with pytest.raises(ExperimentDossierError, match="dossier_fields_unknown"):
        validate_experiment_dossier(dossier)


def test_command_argument_tampering_is_rejected_even_if_dossier_is_rehashed():
    dossier = _dossier()
    dossier["command"]["argv"][0] = "malicious-command"
    with pytest.raises(ExperimentDossierError, match="command_argv_digest_mismatch"):
        validate_experiment_dossier(dossier)


def test_short_source_revision_is_rejected():
    dossier = _dossier()
    dossier["source"]["revision"] = "abc123"
    with pytest.raises(ExperimentDossierError, match="source_revision_must_be_full_git_object_id"):
        validate_experiment_dossier(dossier)


@pytest.mark.parametrize("field", ["fixture", "harness", "result_sha256"])
def test_invalid_digest_is_rejected(field):
    dossier = _dossier()
    if field == "fixture":
        dossier["fixture"]["sha256"] = "not-a-digest"
    elif field == "harness":
        dossier["harness"]["harness_sha256"] = "0" * 63
    else:
        dossier["result_sha256"] = "G" * 64
    with pytest.raises(ExperimentDossierError, match="invalid_sha256"):
        validate_experiment_dossier(dossier)


def test_naive_execution_timestamp_is_rejected():
    dossier = _dossier()
    dossier["execution"]["started_at"] = "2026-10-12T06:00:00"
    with pytest.raises(ExperimentDossierError, match="execution_started_at_invalid_timestamp"):
        validate_experiment_dossier(dossier)


def test_execution_end_before_start_is_rejected():
    dossier = _dossier()
    dossier["execution"]["completed_at"] = "2026-10-12T05:59:59Z"
    with pytest.raises(ExperimentDossierError, match="execution_time_order_invalid"):
        validate_experiment_dossier(dossier)


def test_boolean_exit_code_is_rejected_as_python_bool_is_an_int_subclass():
    dossier = _dossier()
    dossier["execution"]["exit_code"] = False
    with pytest.raises(ExperimentDossierError, match="execution_exit_code_must_be_integer"):
        validate_experiment_dossier(dossier)


def test_duplicate_artifact_names_are_rejected():
    dossier = _dossier()
    dossier["artifacts"].append(copy.deepcopy(dossier["artifacts"][0]))
    with pytest.raises(ExperimentDossierError, match="duplicate_artifact_name"):
        validate_experiment_dossier(dossier)


def test_synthetic_scope_cannot_claim_real_key_material():
    dossier = _dossier()
    dossier["safety"]["real_key_material_handled"] = True
    with pytest.raises(ExperimentDossierError, match="synthetic_scope_conflicts_with_key_material_claim"):
        validate_experiment_dossier(dossier)


def test_source_inspection_scope_cannot_claim_historical_execution():
    dossier = _dossier()
    dossier["safety"]["scope"] = "source_inspection_only"
    dossier["safety"]["historical_code_executed"] = True
    with pytest.raises(ExperimentDossierError, match="source_inspection_scope_conflicts_with_execution_claim"):
        validate_experiment_dossier(dossier)


def test_unsupported_schema_is_rejected():
    dossier = _dossier()
    dossier["schema_version"] = "future-schema"
    with pytest.raises(ExperimentDossierError, match="unsupported_dossier_schema"):
        validate_experiment_dossier(dossier)


def test_dossier_canonicalization_rejects_nan():
    with pytest.raises(ExperimentDossierError, match="dossier_not_canonicalizable"):
        canonical_json({"x": float("nan")})


@pytest.mark.parametrize("value", [
    {1: "integer key"},
    {1: "integer key", "1": "string key"},
    {"nested": ({ "not": "a JSON array" },)},
    {"nested": {"bad\\ud800": "surrogate"}},
])
def test_canonicalization_rejects_ambiguous_or_non_json_values(value):
    with pytest.raises(ExperimentDossierError):
        canonical_json(value)


def test_canonicalization_accepts_nested_json_values():
    assert canonical_json({"items": [None, True, 3, 1.5, "ok"]}) == (
        '{"items":[null,true,3,1.5,"ok"]}'
    )
