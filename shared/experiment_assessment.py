"""Conservative assessment of paired local-experiment evidence.

The assessment distinguishes evidence-pipeline status from vulnerability status.
A successful control/counter-test pair never automatically confirms a finding.
"""
from __future__ import annotations

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
            "Vulnerability confirmation requires independent analysis and target-specific proof.",
        ],
    }
