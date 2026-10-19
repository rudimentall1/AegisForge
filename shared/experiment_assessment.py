"""Conservative assessment of paired local-experiment evidence.

The assessment distinguishes evidence-pipeline status from vulnerability status.
A successful control/counter-test pair never automatically confirms a finding.
"""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
import zipfile

from shared.local_experiment_bundle import verify_local_experiment_bundle

ASSESSMENT_SCHEMA_VERSION = "aegisforge-experiment-assessment-v1"


def assess_local_experiment_pair(
    *,
    control_bundle: bytes | None,
    countertest_bundle: bytes | None,
    expected_case_id: str,
    expected_round_id: str,
    expected_target_repository: str,
    expected_target_commit: str,
    semantic_criteria: dict | None = None,
    synthetic_fixture: bool = False,
) -> dict:
    """Assess two independently verifiable bundles without confirming a finding."""
    missing = []
    if control_bundle is None:
        missing.append("control_bundle")
    if countertest_bundle is None:
        missing.append("countertest_bundle")
    base = {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "case_id": expected_case_id,
        "round_id": expected_round_id,
        "target_repository": expected_target_repository,
        "target_commit": expected_target_commit,
        "synthetic_fixture": bool(synthetic_fixture),
        "semantic_criteria_sha256": None,
        "missing_evidence": missing,
        "vulnerability_confirmed": False,
        "vulnerability_status": "INCONCLUSIVE",
    }
    if len(missing) == 2:
        return {
            **base,
            "status": "NOT_RUN",
            "checks": {"control_bundle_present": False, "countertest_bundle_present": False},
            "errors": ["control_and_countertest_evidence_missing"],
        }
    if missing:
        return {
            **base,
            "status": "INCONCLUSIVE",
            "checks": {
                "control_bundle_present": control_bundle is not None,
                "countertest_bundle_present": countertest_bundle is not None,
            },
            "errors": ["required_pair_evidence_missing"],
        }

    control = verify_local_experiment_bundle(control_bundle)
    countertest = verify_local_experiment_bundle(countertest_bundle)
    reports = {"control": control, "countertest": countertest}
    for name, report in reports.items():
        if report.get("status") != "PASS":
            return {
                **base,
                "status": "FAIL",
                "checks": {
                    "control_bundle_integrity": control.get("status") == "PASS",
                    "countertest_bundle_integrity": countertest.get("status") == "PASS",
                },
                "errors": [f"{name}_bundle_invalid"],
                "bundle_reports": reports,
            }

    expected = {
        "case_id": expected_case_id,
        "round_id": expected_round_id,
        "target_repository": expected_target_repository,
        "target_commit": expected_target_commit,
    }
    for name, report in reports.items():
        if any(report.get(field) != value for field, value in expected.items()):
            return {
                **base,
                "status": "FAIL",
                "checks": {
                    "control_bundle_integrity": True,
                    "countertest_bundle_integrity": True,
                    "identity_match": False,
                },
                "errors": [f"{name}_identity_mismatch"],
                "bundle_reports": reports,
            }

    if control.get("task_id") == countertest.get("task_id"):
        return {
            **base,
            "status": "FAIL",
            "checks": {
                "control_bundle_integrity": True,
                "countertest_bundle_integrity": True,
                "identity_match": True,
                "distinct_tasks": False,
            },
            "errors": ["control_and_countertest_must_use_distinct_tasks"],
            "bundle_reports": reports,
        }
    if control.get("argv") == countertest.get("argv"):
        return {
            **base,
            "status": "FAIL",
            "checks": {
                "control_bundle_integrity": True,
                "countertest_bundle_integrity": True,
                "identity_match": True,
                "distinct_tasks": True,
                "distinct_experiment_commands": False,
            },
            "errors": ["control_and_countertest_commands_must_differ"],
            "bundle_reports": reports,
        }
    if control.get("toolchain") != countertest.get("toolchain"):
        return {
            **base,
            "status": "FAIL",
            "checks": {
                "control_bundle_integrity": True,
                "countertest_bundle_integrity": True,
                "identity_match": True,
                "distinct_tasks": True,
                "distinct_experiment_commands": True,
                "toolchain_match": False,
            },
            "errors": ["control_and_countertest_toolchain_mismatch"],
            "bundle_reports": reports,
        }

    if semantic_criteria is None:
        return {
            **base,
            "status": "INCONCLUSIVE",
            "checks": {
                "control_bundle_integrity": True,
                "countertest_bundle_integrity": True,
                "identity_match": True,
                "semantic_criteria_present": False,
            },
            "errors": ["semantic_criteria_missing"],
            "bundle_reports": reports,
            "limitations": [
                "Exit codes and artifact hashes do not establish that output satisfies the Research Case invariant or falsification criteria."
            ],
        }

    required_criteria_keys = {
        "case_id", "round_id", "target_repository", "target_commit",
        "invariant", "falsification_criteria", "control", "countertest",
    }
    if not isinstance(semantic_criteria, dict) or set(semantic_criteria) != required_criteria_keys:
        return {
            **base,
            "status": "FAIL",
            "checks": {"semantic_criteria_valid": False},
            "errors": ["semantic_criteria_schema_invalid"],
            "bundle_reports": reports,
        }
    if any(semantic_criteria.get(field) != value for field, value in expected.items()):
        return {
            **base,
            "status": "FAIL",
            "checks": {"semantic_criteria_valid": True, "semantic_criteria_identity_match": False},
            "errors": ["semantic_criteria_identity_mismatch"],
            "bundle_reports": reports,
        }
    if any(not isinstance(semantic_criteria.get(field), str) or not semantic_criteria[field].strip()
           for field in ("invariant", "falsification_criteria")):
        return {
            **base,
            "status": "FAIL",
            "checks": {"semantic_criteria_valid": False},
            "errors": ["semantic_criteria_contract_text_missing"],
            "bundle_reports": reports,
        }

    def _validate_role_criteria(value):
        if not isinstance(value, dict) or set(value) != {"must_contain", "must_not_contain"}:
            return None
        must_contain = value.get("must_contain")
        must_not_contain = value.get("must_not_contain")
        if (not isinstance(must_contain, list) or not must_contain
                or not isinstance(must_not_contain, list)
                or any(not isinstance(token, str) or not token or len(token.encode("utf-8")) > 256
                       for token in must_contain + must_not_contain)
                or len(must_contain) > 32 or len(must_not_contain) > 32):
            return None
        return value

    control_criteria = _validate_role_criteria(semantic_criteria["control"])
    counter_criteria = _validate_role_criteria(semantic_criteria["countertest"])
    if control_criteria is None or counter_criteria is None:
        return {
            **base,
            "status": "FAIL",
            "checks": {"semantic_criteria_valid": False},
            "errors": ["semantic_role_criteria_invalid"],
            "bundle_reports": reports,
        }

    canonical_criteria = json.dumps(
        semantic_criteria, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    criteria_digest = sha256(canonical_criteria).hexdigest()
    base["semantic_criteria_sha256"] = criteria_digest

    def _stdout(bundle_bytes):
        with zipfile.ZipFile(BytesIO(bundle_bytes), "r") as archive:
            return archive.read("stdout.bin")

    try:
        control_stdout = _stdout(control_bundle)
        counter_stdout = _stdout(countertest_bundle)
    except (OSError, KeyError, zipfile.BadZipFile, RuntimeError):
        return {
            **base,
            "status": "FAIL",
            "checks": {"semantic_outputs_readable": False},
            "errors": ["semantic_outputs_unreadable"],
            "bundle_reports": reports,
        }

    def _matches(output, role_criteria):
        return (
            all(token.encode("utf-8") in output for token in role_criteria["must_contain"])
            and all(token.encode("utf-8") not in output for token in role_criteria["must_not_contain"])
        )

    control_semantics_match = _matches(control_stdout, control_criteria)
    counter_semantics_match = _matches(counter_stdout, counter_criteria)
    checks_semantic = {
        "semantic_criteria_present": True,
        "semantic_criteria_identity_match": True,
        "control_output_matches_invariant": control_semantics_match,
        "countertest_output_matches_falsification_criteria": counter_semantics_match,
    }
    if not control_semantics_match or not counter_semantics_match:
        errors = []
        if not control_semantics_match:
            errors.append("control_semantic_criteria_not_met")
        if not counter_semantics_match:
            errors.append("countertest_semantic_criteria_not_met")
        return {
            **base,
            "status": "FAIL",
            "checks": {
                "control_bundle_integrity": True,
                "countertest_bundle_integrity": True,
                "identity_match": True,
                **checks_semantic,
            },
            "errors": errors,
            "bundle_reports": reports,
            "limitations": [
                "Semantic matching evaluates explicit byte-string criteria only; it is not a general proof of program correctness or vulnerability."
            ],
        }

    experiment_statuses = {
        control.get("experiment_status"),
        countertest.get("experiment_status"),
    }
    checks = {
        "control_bundle_integrity": True,
        "countertest_bundle_integrity": True,
        "identity_match": True,
        "control_ran": control.get("experiment_status") != "NOT_RUN",
        "countertest_ran": countertest.get("experiment_status") != "NOT_RUN",
        "control_exit_expectation_met": control.get("experiment_status") == "PASS",
        "countertest_exit_expectation_met": countertest.get("experiment_status") == "PASS",
        **checks_semantic,
    }
    if "FAIL" in experiment_statuses:
        status = "FAIL"
        errors = ["experiment_exit_expectation_not_met"]
    elif "NOT_RUN" in experiment_statuses:
        status = "INCONCLUSIVE"
        errors = ["one_or_more_experiments_not_run"]
    elif synthetic_fixture:
        status = "INCONCLUSIVE"
        errors = ["synthetic_fixture_cannot_establish_target_behavior"]
    else:
        status = "PASS"
        errors = []

    return {
        **base,
        "status": status,
        "checks": checks,
        "errors": errors,
        "bundle_reports": reports,
        "limitations": [
            "Bundle integrity does not authenticate the runner or execution environment.",
            "A passing experiment pair does not prove a vulnerability exists.",
            "Semantic matching evaluates declared byte-string criteria, not arbitrary program behavior.",
            "Vulnerability confirmation requires independent analysis and target-specific proof.",
        ],
    }
