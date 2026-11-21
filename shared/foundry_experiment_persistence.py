"""Persist bounded Foundry execution observations as portable local evidence.

A successful Foundry test is not automatically a confirmed vulnerability. This
module stores the exact bounded output and immutable source/harness provenance;
it deliberately leaves confirmation to independent review and counter-tests.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from urllib.parse import urlsplit

from shared.local_experiment import build_experiment_record
from shared.research_case import research_case_binding
from shared.scope_gate import validate_case


def _repository_slug(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("foundry_target_repository_invalid")
    if "://" in value:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("foundry_target_repository_invalid")
        parts = parsed.path.strip("/").split("/")
        if len(parts) != 2:
            raise ValueError("foundry_target_repository_invalid")
        value = "/".join(parts)
    if value.endswith(".git"):
        value = value[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("foundry_target_repository_invalid")
    return value


def persist_foundry_lab_experiment(
    *, queue, ledger, task_id, role, research_case, round_spec, result_value
):
    """Persist one completed Foundry observation after queue identity is terminal."""
    if role != "lab_runner" or research_case is None or not isinstance(result_value, dict):
        return None
    if result_value.get("execution_adapter") != "foundry_test":
        return None
    if (
        result_value.get("dynamic_verified") is True
        or result_value.get("vulnerability_confirmed") is True
        or result_value.get("confirmed") is True
    ):
        raise ValueError("foundry_adapter_cannot_self_confirm_vulnerability")
    if (
        result_value.get("execution_truth") != "LOCAL_CONTAINER_OBSERVATION_ONLY"
        or result_value.get("network_access") is not False
        or result_value.get("host_filesystem_access") is not False
        or result_value.get("project_mount_read_only") is not True
        or result_value.get("transactions_sent") is not False
    ):
        raise ValueError("foundry_sandbox_invariants_not_proven")

    stdout_text = result_value.get("stdout")
    stderr_text = result_value.get("stderr")
    stdout_digest = result_value.get("stdout_sha256")
    stderr_digest = result_value.get("stderr_sha256")
    command = result_value.get("command")
    if (
        not isinstance(stdout_text, str)
        or not isinstance(stderr_text, str)
        or not isinstance(stdout_digest, str)
        or not isinstance(stderr_digest, str)
        or not isinstance(command, list)
        or not command
        or any(not isinstance(arg, str) for arg in command)
    ):
        return None

    stdout_bytes = stdout_text.encode("utf-8")
    stderr_bytes = stderr_text.encode("utf-8")
    if hashlib.sha256(stdout_bytes).hexdigest() != stdout_digest:
        raise ValueError("foundry_stdout_digest_mismatch")
    if hashlib.sha256(stderr_bytes).hexdigest() != stderr_digest:
        raise ValueError("foundry_stderr_digest_mismatch")

    scope_decision = validate_case(research_case)
    if not scope_decision.allowed:
        raise ValueError(f"foundry_lab_scope_gate_rejected:{scope_decision.reason}")
    expected_binding = research_case_binding(research_case)
    if result_value.get("research_case_binding") != expected_binding:
        raise ValueError("foundry_lab_case_binding_mismatch")
    if round_spec is None or round_spec.round_id != result_value.get("round_spec_id"):
        raise ValueError("foundry_lab_round_spec_mismatch")
    registered_round = next(
        (item for item in research_case.rounds if item.round_id == round_spec.round_id),
        None,
    )
    if registered_round != round_spec:
        raise ValueError("foundry_lab_round_spec_not_registered")

    row = queue.db.execute(
        "SELECT research_case_id, round_id, round_spec_id, status FROM queue WHERE id = ?",
        (task_id,),
    ).fetchone()
    if row is None:
        raise ValueError("foundry_lab_task_identity_missing")
    case_id, runtime_round_id, planned_round_spec_id, task_status = row
    if task_status != "completed":
        raise ValueError("foundry_lab_task_not_completed")
    if case_id != research_case.case_id:
        raise ValueError("foundry_lab_task_case_mismatch")
    if not runtime_round_id or result_value.get("round_id") != runtime_round_id:
        raise ValueError("foundry_lab_runtime_round_mismatch")
    if planned_round_spec_id != round_spec.round_id:
        raise ValueError("foundry_lab_planned_round_spec_mismatch")

    target_repository = _repository_slug(research_case.target_repository)
    target_commit = research_case.target_commit.lower()
    source_digests = result_value.get("source_sha256")
    if not isinstance(source_digests, dict) or not source_digests:
        raise ValueError("foundry_source_digest_manifest_required")
    source_prefix = round_spec.foundry_source_root.rstrip("/") + "/"
    if any(
        not isinstance(path, str)
        or not path.startswith(source_prefix)
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        for path, digest in source_digests.items()
    ):
        raise ValueError("foundry_source_digest_manifest_invalid")
    if result_value.get("source_provenance") != "git_object_database_at_verified_commit":
        raise ValueError("foundry_source_provenance_invalid")
    if result_value.get("target_commit") != target_commit:
        raise ValueError("foundry_target_commit_mismatch")
    pinned_tree_digest = result_value.get("pinned_source_tree_sha256")
    if not isinstance(pinned_tree_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", pinned_tree_digest):
        raise ValueError("foundry_pinned_source_tree_digest_invalid")

    harness_digest = hashlib.sha256(
        round_spec.test_harness_source.encode("utf-8")
    ).hexdigest()
    if result_value.get("test_harness_sha256") != harness_digest:
        raise ValueError("foundry_test_harness_digest_mismatch")
    control_tests = result_value.get("control_tests")
    if result_value.get("status") == "EXECUTED_PASS":
        test_statuses = result_value.get("test_statuses")
        test_counts = result_value.get("test_counts")
        complete_suite = (
            isinstance(test_counts, dict)
            and type(test_counts.get("total")) is int
            and type(test_counts.get("passed")) is int
            and type(test_counts.get("failed")) is int
            and type(test_counts.get("skipped")) is int
            and test_counts["total"] >= 2
            and test_counts["passed"] == test_counts["total"]
            and test_counts["failed"] == 0
            and test_counts["skipped"] == 0
        )
        if (
            not isinstance(test_statuses, dict)
            or test_statuses.get(round_spec.positive_control_test) != "Success"
            or test_statuses.get(round_spec.negative_control_test) != "Success"
            or not isinstance(control_tests, dict)
            or control_tests.get("positive") != {
                "name": round_spec.positive_control_test, "status": "Success"
            }
            or control_tests.get("negative") != {
                "name": round_spec.negative_control_test, "status": "Success"
            }
            or not complete_suite
        ):
            raise ValueError("foundry_required_control_test_evidence_missing")
    if result_value.get("compiler_version") != round_spec.solc_version:
        raise ValueError("foundry_compiler_version_mismatch")
    if result_value.get("container_image") != round_spec.foundry_image:
        raise ValueError("foundry_container_image_digest_mismatch")
    if result_value.get("foundry_source_root") != round_spec.foundry_source_root:
        raise ValueError("foundry_source_root_mismatch")
    compiler_digest = result_value.get("compiler_sha256")
    if compiler_digest is not None and (
        not isinstance(compiler_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", compiler_digest)
    ):
        raise ValueError("foundry_compiler_digest_invalid")

    input_payload = {
        "schema_version": "aegisforge-foundry-inputs-v1",
        "case_id": case_id,
        "round_id": runtime_round_id,
        "round_spec_id": planned_round_spec_id,
        "target_repository": target_repository,
        "target_commit": target_commit,
        "scope_digest": research_case.scope_digest,
        "source_provenance": result_value["source_provenance"],
        "pinned_source_tree_sha256": result_value.get("pinned_source_tree_sha256"),
        "source_sha256": dict(sorted(source_digests.items())),
        "test_harness_sha256": harness_digest,
        "compiler_version": round_spec.solc_version,
        "foundry_image": round_spec.foundry_image,
        "foundry_source_root": round_spec.foundry_source_root,
        "compiler_sha256": result_value.get("compiler_sha256"),
        "control_tests": control_tests,
        "test_statuses": result_value.get("test_statuses"),
        "test_counts": result_value.get("test_counts"),
        "execution_status": result_value.get("status"),
        "execution_error": result_value.get("execution_error"),
        "container_image": result_value.get("container_image"),
        "execution_truth": result_value.get("execution_truth"),
        "network_access": result_value.get("network_access"),
        "host_filesystem_access": result_value.get("host_filesystem_access"),
        "project_mount_read_only": result_value.get("project_mount_read_only"),
        "transactions_sent": result_value.get("transactions_sent"),
    }
    input_bytes = json.dumps(
        input_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")

    exit_code = result_value.get("exit_code")
    if exit_code is not None and type(exit_code) is not int:
        raise ValueError("foundry_exit_code_invalid")
    if result_value.get("status") == "EXECUTED_PASS" and exit_code != 0:
        raise ValueError("foundry_pass_exit_code_mismatch")
    toolchain = {
        "foundry_image": str(result_value.get("container_image") or round_spec.foundry_image),
        "compiler_version": round_spec.solc_version,
        "python_version": sys.version.split()[0],
        "execution_adapter": "foundry_test",
        "network_access": "disabled",
        "source_provenance": "verified_git_object_database",
        "container_image_provenance_verified": "false",
    }
    compiler_digest = result_value.get("compiler_sha256")
    if isinstance(compiler_digest, str) and re.fullmatch(r"[0-9a-f]{64}", compiler_digest):
        toolchain["compiler_sha256"] = compiler_digest
    record, artifacts = build_experiment_record(
        case_id=case_id,
        round_id=runtime_round_id,
        round_spec_id=planned_round_spec_id,
        task_id=task_id,
        target_repository=target_repository,
        target_commit=target_commit,
        argv=command,
        toolchain=toolchain,
        input_bytes=input_bytes,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        exit_code=exit_code,
        # Only a complete, non-skipped Foundry pass is a PASS record. A zero
        # process exit with skipped/partial/invalid output remains a failed
        # experiment observation rather than being promoted by exit code alone.
        expected_exit_code=(
            0 if result_value.get("status") == "EXECUTED_PASS"
            else (1 if exit_code == 0 else 0)
        ),
    )
    stored = ledger.record_local_experiment(record, artifacts)
    ledger.record_observation(
        task_id,
        role,
        f"foundry_execution_record:{stored['record_digest']}",
    )
    return {
        "status": "PERSISTED",
        "record_digest": stored["record_digest"],
        "case_id": stored["case_id"],
        "round_id": stored["round_id"],
        "round_spec_id": stored["round_spec_id"],
        "task_id": stored["task_id"],
        "experiment_status": stored["experiment_status"],
        "source_provenance": result_value["source_provenance"],
        "pinned_source_tree_sha256": result_value.get("pinned_source_tree_sha256"),
        "test_harness_sha256": harness_digest,
        "execution_status": result_value.get("status"),
        "dynamic_verified": False,
        "vulnerability_confirmed": False,
        "authenticated_execution": False,
    }
