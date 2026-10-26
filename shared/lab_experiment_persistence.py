"""Persist the built-in synthetic LabRunner experiment as portable evidence.

This adapter only accepts the repository-owned synthetic entropy demo. It does
not execute commands and does not treat integrity verification as proof of a
vulnerability or of an authenticated execution environment.
"""
from __future__ import annotations

import hashlib
import json
import platform
import sys

from agents.lab_runner.agent import LabRunner
from shared.local_experiment import build_experiment_record
from shared.research_case import research_case_binding


def persist_synthetic_lab_experiment(
    *, queue, ledger, task_id, role, research_case, round_spec, result_value
):
    """Persist one case-bound synthetic subprocess result after its task is terminal.

    Returns a small public-safe evidence reference, or None when the result is
    not the supported built-in experiment. Invalid/mismatched evidence raises.
    """
    if role != "lab_runner" or research_case is None or not isinstance(result_value, dict):
        return None
    if result_value.get("research_track") != "evm_key_forensics":
        return None

    experiments = result_value.get("lab_experiments")
    if not isinstance(experiments, list) or len(experiments) != 1:
        return None
    experiment = experiments[0]
    if not isinstance(experiment, dict):
        return None
    if (
        experiment.get("experiment_id") != "synthetic-entropy-demo-v1"
        or experiment.get("synthetic_test_only") is not True
        or experiment.get("uses_real_private_keys") is not False
        or experiment.get("uses_real_wallet_addresses") is not False
    ):
        return None

    execution = experiment.get("execution_record")
    if not isinstance(execution, dict):
        raise ValueError("synthetic_lab_execution_record_required")
    command = execution.get("command")
    stdout_text = execution.get("stdout")
    stderr_text = execution.get("stderr")
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(arg, str) for arg in command)
        or not isinstance(stdout_text, str)
        or not isinstance(stderr_text, str)
    ):
        raise ValueError("synthetic_lab_execution_artifacts_invalid")

    stdout_bytes = stdout_text.encode("utf-8")
    stderr_bytes = stderr_text.encode("utf-8")
    script_bytes = LabRunner._SYNTHETIC_EXPERIMENT_SCRIPT.encode("utf-8")
    expected_command = [sys.executable, "-c", LabRunner._SYNTHETIC_EXPERIMENT_SCRIPT]
    if command != expected_command:
        raise ValueError("synthetic_lab_command_not_allowlisted")
    if hashlib.sha256(script_bytes).hexdigest() != execution.get("script_source_sha256"):
        raise ValueError("synthetic_lab_script_digest_mismatch")
    command_bytes = json.dumps(
        command, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    if hashlib.sha256(command_bytes).hexdigest() != execution.get("command_sha256"):
        raise ValueError("synthetic_lab_command_digest_mismatch")
    if hashlib.sha256(stdout_bytes).hexdigest() != execution.get("stdout_sha256"):
        raise ValueError("synthetic_lab_stdout_digest_mismatch")
    if hashlib.sha256(stderr_bytes).hexdigest() != execution.get("stderr_sha256"):
        raise ValueError("synthetic_lab_stderr_digest_mismatch")
    exit_code = execution.get("exit_code")
    test_passed = execution.get("test_passed")
    if exit_code == 0 and test_passed is not True:
        raise ValueError("synthetic_lab_pass_claim_inconsistent")
    if test_passed is True and exit_code != 0:
        raise ValueError("synthetic_lab_pass_claim_inconsistent")

    binding = result_value.get("research_case_binding")
    expected_binding = research_case_binding(research_case)
    if binding != expected_binding:
        raise ValueError("synthetic_lab_case_binding_mismatch")
    if round_spec is None:
        raise ValueError("synthetic_lab_round_spec_required")

    row = queue.db.execute(
        "SELECT research_case_id, round_id, round_spec_id, status FROM queue WHERE id = ?",
        (task_id,),
    ).fetchone()
    if row is None:
        raise ValueError("synthetic_lab_task_identity_missing")
    case_id, runtime_round_id, planned_round_spec_id, task_status = row
    if task_status not in {"completed", "failed"}:
        raise ValueError("synthetic_lab_task_not_terminal")
    if case_id != research_case.case_id:
        raise ValueError("synthetic_lab_task_case_mismatch")
    if not runtime_round_id:
        raise ValueError("synthetic_lab_runtime_round_required")
    if planned_round_spec_id != round_spec.round_id:
        raise ValueError("synthetic_lab_planned_round_spec_mismatch")

    record, artifacts = build_experiment_record(
        case_id=research_case.case_id,
        round_id=runtime_round_id,
        round_spec_id=planned_round_spec_id,
        task_id=task_id,
        target_repository=research_case.target_repository,
        target_commit=research_case.target_commit.lower(),
        argv=command,
        toolchain={
            "python": sys.version.split()[0],
            "platform": platform.system() + "-" + platform.machine(),
        },
        # The built-in subprocess receives no stdin; argv and script hash are
        # separately retained in the record and receipt.
        input_bytes=b"",
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        exit_code=execution.get("exit_code"),
        expected_exit_code=0,
    )
    stored = ledger.record_local_experiment(record, artifacts)
    ledger.record_observation(
        task_id,
        role,
        f"local_experiment_record:{stored['record_digest']}",
    )
    return {
        "status": "PERSISTED",
        "record_digest": stored["record_digest"],
        "case_id": stored["case_id"],
        "round_id": stored["round_id"],
        "round_spec_id": stored["round_spec_id"],
        "task_id": stored["task_id"],
        "experiment_status": stored["experiment_status"],
        "integrity_only": True,
        "authenticated_execution": False,
        "vulnerability_confirmed": False,
    }
