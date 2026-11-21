"""Read-only admission gate for future pinned-target tool adapters.

This module resolves execution authority from TaskQueue's persisted records.
Callers cannot submit a ResearchCase payload, target URL, commit, argv, or
environment. It does not spawn processes and is not a sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import hashlib
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit

from shared.queue import TaskQueue
from shared.pinned_git_source import PinnedSourceError, load_pinned_solidity_sources
from shared.scope_gate import validate_case
from shared.research_case import (
    CaseStatus,
    ExecutionMode,
    ResearchCase,
    RoundSpec,
    validate_task_binding,
)


class TargetExecutionAdmissionError(ValueError):
    """A target-tool request is not authorized by persisted case state."""


class AdapterProfile(str, Enum):
    FOUNDRY_TEST = "foundry_test"
    SLITHER_STATIC = "slither_static"


@dataclass(frozen=True, slots=True)
class TargetExecutionRequest:
    """Minimal request: identity only; never accepts target or command material."""

    task_id: str
    adapter_profile: AdapterProfile


@dataclass(frozen=True, slots=True)
class AdmittedTarget:
    """Resolved, immutable execution context sourced from the local registry."""

    task_id: str
    case_id: str
    round_id: str
    round_spec_id: str | None
    adapter_profile: AdapterProfile
    research_case: ResearchCase
    round_spec: RoundSpec | None
    execution_assurance: str = "NOT_RUN"


def admit_target_execution(
    queue: TaskQueue,
    request: TargetExecutionRequest,
) -> AdmittedTarget:
    """Resolve a running lab task against authoritative SQLite state.

    This is an authorization/admission check only. It provides no process
    isolation, source checkout, tool invocation, or execution-truth guarantee.
    """
    if not isinstance(request, TargetExecutionRequest):
        raise TargetExecutionAdmissionError("typed_request_required")
    if not isinstance(request.task_id, str) or not request.task_id.strip():
        raise TargetExecutionAdmissionError("task_id_required")
    try:
        profile = AdapterProfile(request.adapter_profile)
    except (TypeError, ValueError) as exc:
        raise TargetExecutionAdmissionError("adapter_profile_not_allowed") from exc

    db = queue.db
    try:
        db.execute("BEGIN")
        row = db.execute(
            """
            SELECT id, status, role, research_case_id, round_id, round_spec_id
            FROM queue WHERE id = ?
            """,
            (request.task_id,),
        ).fetchone()
        if row is None:
            raise TargetExecutionAdmissionError("task_not_registered")
        task_id, status, role, case_id, round_id, round_spec_id = row

        if status != "running":
            raise TargetExecutionAdmissionError("task_not_running")
        if role != "lab_runner":
            raise TargetExecutionAdmissionError("task_role_not_lab_runner")
        if not case_id:
            raise TargetExecutionAdmissionError("task_case_binding_missing")
        if not round_id:
            raise TargetExecutionAdmissionError("task_runtime_round_binding_missing")

        case = queue.get_research_case(case_id)
        if case is None:
            raise TargetExecutionAdmissionError("research_case_not_registered")
        validate_task_binding(case, case_id)
        scope_decision = validate_case(case)
        if not scope_decision.allowed:
            raise TargetExecutionAdmissionError(
                f"scope_gate_rejected:{scope_decision.reason}"
            )
        if case.status not in {CaseStatus.READY, CaseStatus.RUNNING}:
            raise TargetExecutionAdmissionError("research_case_not_runnable")
        if case.execution_mode is not ExecutionMode.LOCAL:
            raise TargetExecutionAdmissionError("execution_mode_not_supported_by_local_adapter")

        if round_spec_id is None:
            if case.rounds:
                raise TargetExecutionAdmissionError("planned_round_spec_binding_missing")
            round_spec = None
        else:
            round_spec = next(
                (item for item in case.rounds if item.round_id == round_spec_id),
                None,
            )
            if round_spec is None:
                raise TargetExecutionAdmissionError("round_spec_not_declared_in_registered_case")

        round_row = db.execute(
            """
            SELECT root_task_id, round_spec_id, status
            FROM research_case_rounds
            WHERE case_id = ? AND round_id = ?
            """,
            (case_id, round_id),
        ).fetchone()
        if round_row is None:
            raise TargetExecutionAdmissionError("runtime_round_not_registered")
        root_task_id, registered_spec_id, round_status = round_row
        if round_status != "RUNNING":
            raise TargetExecutionAdmissionError("runtime_round_not_running")
        if registered_spec_id != round_spec_id:
            raise TargetExecutionAdmissionError("task_round_spec_registry_mismatch")

        if round_spec is None:
            raise TargetExecutionAdmissionError("planned_round_spec_binding_missing")
        required_technique = {
            AdapterProfile.FOUNDRY_TEST: "runtime_probe",
            AdapterProfile.SLITHER_STATIC: "source_pattern",
        }[profile]
        if round_spec.technique != required_technique:
            raise TargetExecutionAdmissionError(
                f"adapter_technique_mismatch:{profile.value}:{required_technique}"
            )

        root = db.execute(
            """
            SELECT research_case_id, round_id, role
            FROM queue WHERE id = ?
            """,
            (root_task_id,),
        ).fetchone()
        if root is None or root[0] != case_id or root[1] != round_id:
            raise TargetExecutionAdmissionError("runtime_round_root_binding_invalid")
        if root[2] != "source_researcher":
            raise TargetExecutionAdmissionError("runtime_round_root_role_invalid")

        db.commit()
        return AdmittedTarget(
            task_id=task_id,
            case_id=case_id,
            round_id=round_id,
            round_spec_id=round_spec_id,
            adapter_profile=profile,
            research_case=case,
            round_spec=round_spec,
        )
    except Exception:
        db.rollback()
        raise


def _github_repository_slug(value: str) -> str:
    """Normalize only an explicit GitHub owner/repository identifier."""
    if "://" not in value:
        slug = value
    else:
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise TargetExecutionAdmissionError("target_repository_not_github") from exc
        parts = parsed.path.strip("/").split("/")
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or len(parts) != 2
        ):
            raise TargetExecutionAdmissionError("target_repository_not_github")
        slug = "/".join(parts)
    if slug.endswith(".git"):
        slug = slug[:-4]
    if len(slug.split("/")) != 2 or any(not part for part in slug.split("/")):
        raise TargetExecutionAdmissionError("target_repository_not_github")
    return slug


def resolve_foundry_sources(
    queue: TaskQueue,
    request: TargetExecutionRequest,
    *,
    checkout_root: str | Path,
) -> tuple[AdmittedTarget, dict]:
    """Admit a Foundry task and load only its planned Solidity paths from Git objects.

    The planned path list is part of the immutable RoundSpec. The loader verifies
    the checkout origin and exact commit, then reads blobs from that commit rather
    than mutable working-tree files. This function still does not execute Foundry.
    """
    admitted = admit_target_execution(queue, request)
    if admitted.adapter_profile is not AdapterProfile.FOUNDRY_TEST:
        raise TargetExecutionAdmissionError("foundry_adapter_profile_required")
    round_spec = admitted.round_spec
    if round_spec is None or not round_spec.target_source_paths:
        raise TargetExecutionAdmissionError("round_target_source_paths_required")
    repository = _github_repository_slug(admitted.research_case.target_repository)
    try:
        source_bundle = load_pinned_solidity_sources(
            checkout_root,
            repository=repository,
            commit_sha=admitted.research_case.target_commit.lower(),
            source_paths=round_spec.target_source_paths,
        )
    except PinnedSourceError as exc:
        raise TargetExecutionAdmissionError(str(exc)) from exc
    source_bundle["case_id"] = admitted.case_id
    source_bundle["round_id"] = admitted.round_id
    source_bundle["round_spec_id"] = admitted.round_spec_id
    source_bundle["scope_digest"] = admitted.research_case.scope_digest
    return admitted, source_bundle


def resolve_foundry_execution_inputs(
    queue: TaskQueue,
    request: TargetExecutionRequest,
    *,
    checkout_root: str | Path,
) -> tuple[AdmittedTarget, dict]:
    """Resolve all immutable inputs required by the Foundry execution adapter."""
    admitted, source_bundle = resolve_foundry_sources(
        queue, request, checkout_root=checkout_root
    )
    round_spec = admitted.round_spec
    if round_spec is None:
        raise TargetExecutionAdmissionError("planned_round_spec_binding_missing")
    if (
        not round_spec.test_harness_source
        or not round_spec.solc_version
        or not round_spec.foundry_image
    ):
        raise TargetExecutionAdmissionError("round_foundry_harness_toolchain_required")
    if not round_spec.positive_control_test or not round_spec.negative_control_test:
        raise TargetExecutionAdmissionError("round_foundry_control_test_names_required")
    if not source_bundle.get("sources"):
        raise TargetExecutionAdmissionError("round_target_source_paths_required")
    return admitted, {
        **source_bundle,
        "test_harness_source": round_spec.test_harness_source,
        "test_harness_sha256": hashlib.sha256(
            round_spec.test_harness_source.encode("utf-8")
        ).hexdigest(),
        "compiler_version": round_spec.solc_version,
        "foundry_image": round_spec.foundry_image,
        "foundry_source_root": round_spec.foundry_source_root,
        "test_harness_provenance": "immutable_research_case_round_spec",
        "positive_control_test": round_spec.positive_control_test,
        "negative_control_test": round_spec.negative_control_test,
    }


def run_admitted_foundry_round(
    queue: TaskQueue,
    request: TargetExecutionRequest,
    *,
    checkout_root: str | Path,
    image: str | None = None,
    timeout_seconds: int = 120,
) -> dict:
    """Execute the case-pinned harness only after persisted-case admission.

    This returns an execution observation, never a confirmed vulnerability.
    The Foundry process runs in the network-disabled container adapter.
    """
    if os.getenv("AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED", "").strip() != "1":
        raise TargetExecutionAdmissionError("docker_runtime_authorization_required")
    admitted, inputs = resolve_foundry_execution_inputs(
        queue, request, checkout_root=checkout_root
    )
    if image is not None and image != inputs["foundry_image"]:
        raise TargetExecutionAdmissionError("foundry_image_override_mismatch")
    image = inputs["foundry_image"]
    from agents.security_checker.foundry_runner import run_foundry_test

    # RoundSpec paths are repository-root-relative. Map only files under its
    # declared Foundry source root into the generated project's src/ directory.
    source_root = inputs["foundry_source_root"].rstrip("/")
    source_prefix = source_root + "/"
    foundry_sources = {}
    for repository_path, source_text in inputs["sources"].items():
        if not repository_path.startswith(source_prefix):
            raise TargetExecutionAdmissionError("foundry_source_path_outside_declared_source_root")
        relative_path = repository_path[len(source_prefix):]
        if not relative_path or relative_path in foundry_sources:
            raise TargetExecutionAdmissionError("foundry_source_layout_collision")
        foundry_sources[relative_path] = source_text

    execution = run_foundry_test(
        foundry_sources,
        inputs["test_harness_source"],
        compiler_version=inputs["compiler_version"],
        image=image,
        timeout_seconds=timeout_seconds,
    )
    # A bounded adapter result is a completed observation even when execution
    # could not start. Keep its diagnostic distinct from Worker-level failures.
    if "error" in execution:
        execution["execution_error"] = execution.pop("error")
    if (
        execution.get("network_access") is not False
        or execution.get("host_filesystem_access") is not False
        or execution.get("project_mount_read_only") is not True
        or execution.get("transactions_sent") is not False
    ):
        execution["status"] = "SANDBOX_INVARIANT_VIOLATION"
        execution["execution_error"] = "foundry_sandbox_invariant_not_proven"
        execution["test_passed"] = False
    observed_tests = execution.get("test_statuses")
    positive_name = inputs["positive_control_test"]
    negative_name = inputs["negative_control_test"]
    control_tests = {
        "positive": {
            "name": positive_name,
            "status": observed_tests.get(positive_name) if isinstance(observed_tests, dict) else None,
        },
        "negative": {
            "name": negative_name,
            "status": observed_tests.get(negative_name) if isinstance(observed_tests, dict) else None,
        },
    }
    if execution.get("status") == "EXECUTED_PASS":
        counts = execution.get("test_counts")
        controls_passed = all(
            item["status"] == "Success" for item in control_tests.values()
        )
        suite_complete = (
            isinstance(counts, dict)
            and type(counts.get("total")) is int
            and type(counts.get("passed")) is int
            and type(counts.get("failed")) is int
            and type(counts.get("skipped")) is int
            and counts["total"] >= 2
            and counts["passed"] == counts["total"]
            and counts["failed"] == 0
            and counts["skipped"] == 0
        )
        if not controls_passed or not suite_complete:
            execution["status"] = "CONTROL_COVERAGE_INVALID"
            execution["execution_error"] = "required_controls_or_complete_suite_not_passed"
            execution["test_passed"] = False

    execution.setdefault("container_image", inputs["foundry_image"])
    execution.update({
        "execution_adapter": "foundry_test",
        "case_id": admitted.case_id,
        "round_id": admitted.round_id,
        "round_spec_id": admitted.round_spec_id,
        "target_repository": admitted.research_case.target_repository,
        "target_commit": admitted.research_case.target_commit.lower(),
        "scope_digest": admitted.research_case.scope_digest,
        "source_provenance": inputs["source_provenance"],
        "pinned_source_tree_sha256": inputs["source_tree_sha256"],
        "source_sha256": inputs["source_sha256"],
        "test_harness_sha256": inputs["test_harness_sha256"],
        "test_harness_provenance": inputs["test_harness_provenance"],
        "compiler_version": inputs["compiler_version"],
        "foundry_image": inputs["foundry_image"],
        "foundry_source_root": source_root,
        "control_tests": control_tests,
        "dynamic_verified": False,
        "confirmed": False,
        "vulnerability_confirmed": False,
        "execution_truth": "LOCAL_CONTAINER_OBSERVATION_ONLY",
    })
    return execution
