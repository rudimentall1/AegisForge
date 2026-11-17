"""Controlled evidence-to-attestation workflow for offline Solidity acceptance cases.

The workflow requires an explicit operator verdict, uses only the loopback signer,
verifies the signed attestation and registry checkpoint against trusted public keys,
and writes local artifacts without overwriting existing files. It never publishes
to a remote registry or treats source patterns as proof of a vulnerability.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from datetime import datetime

from shared.attestation import ALLOWED_VERDICTS, canonical_json, sha256_hex, verify_attestation
from shared.attestation_registry import (
    AttestationRegistryError,
    build_inclusion_proof,
    build_registry,
    checkpoint_for,
    entry_from_attestation,
    registry_sha256,
    verify_inclusion_proof,
    verify_registry,
    verify_registry_chain,
    verify_signed_checkpoint,
)
from shared.attestation_signer_client import request_attestation, request_registry_checkpoint
from shared.research_case import verify_research_case_binding

MAX_EVIDENCE_BYTES = 1024 * 1024
SUPPORTED_RUNNERS = {
    "aegisforge-solidity-round-run-v1": "tools.evm_key_forensics.run_solidity_round_case",
    "aegisforge-uniswap-v2-factory-round-run-v1": "tools.evm_key_forensics.run_uniswap_v2_factory_round_case",
}
WORKFLOW_VERDICTS = frozenset({"INCONCLUSIVE", "OUT_OF_SCOPE"})
OUTPUT_FILES = (
    "attestation.json",
    "registry.json",
    "checkpoint.json",
    "inclusion-proof.json",
    "workflow-summary.json",
)


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _load_json(path: str | os.PathLike[str], *, max_bytes: int = MAX_EVIDENCE_BYTES):
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError("input_path_must_be_regular_non_symlink_file")
    raw = target.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError("json_file_size_limit_exceeded")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError(f"nonstandard_json_constant:{item}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid_json_file") from exc
    return value, raw


def _load_trusted_keys(path: str | os.PathLike[str]) -> dict[str, str]:
    keys, _ = _load_json(path)
    if not isinstance(keys, dict) or not keys or not all(
        isinstance(key_id, str) and key_id.strip() and isinstance(public_key, str)
        for key_id, public_key in keys.items()
    ):
        raise ValueError("trusted_keys_must_be_nonempty_key_id_to_base64_public_key_object")
    return keys


def _timestamp(value, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}_missing")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label}_invalid") from exc
    return value


def _prepare_inputs(evidence: dict, evidence_raw: bytes, evidence_path: Path, verdict: str, rationale: str) -> dict:
    schema = evidence.get("schema_version")
    if schema not in SUPPORTED_RUNNERS:
        raise ValueError("unsupported_evidence_runner_schema")
    if verdict not in WORKFLOW_VERDICTS or verdict not in ALLOWED_VERDICTS:
        raise ValueError("source_only_workflow_verdict_must_be_INCONCLUSIVE_or_OUT_OF_SCOPE")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("human_verdict_rationale_required")
    if len(rationale.encode("utf-8")) > 8192:
        raise ValueError("human_verdict_rationale_too_long")

    acceptance = evidence.get("acceptance")
    safety = evidence.get("safety")
    target = evidence.get("target")
    round_info = evidence.get("round")
    result = evidence.get("result")
    if not all(isinstance(item, dict) for item in (acceptance, safety, target, round_info, result)):
        raise ValueError("evidence_result_structure_invalid")
    if acceptance.get("validation_passed") is not True or acceptance.get("final_status") != "INCONCLUSIVE":
        raise ValueError("evidence_must_be_validated_and_remain_INCONCLUSIVE")
    if (
        safety.get("network_access") is not False
        or safety.get("rpc_used") is not False
        or safety.get("transactions_sent") is not False
        or safety.get("private_keys_loaded") is not False
        or safety.get("automatic_confirmation") is not False
        or safety.get("finding_created") is not False
        or safety.get("human_review_required") is not True
    ):
        raise ValueError("evidence_safety_invariants_missing_or_unsafe")
    if result.get("final_status") != "INCONCLUSIVE":
        raise ValueError("research_result_must_remain_INCONCLUSIVE")
    if result.get("stage_history") != [
        "source_research", "analysis", "synthetic_experiment", "validation", "human_review"
    ]:
        raise ValueError("evidence_stage_history_invalid")
    validation = result.get("validation")
    observation = result.get("source_observation")
    analysis = result.get("solidity_analysis")
    if not isinstance(validation, dict) or validation.get("status") != "VALIDATED":
        raise ValueError("research_validation_not_passed")
    if not isinstance(validation.get("checks"), dict) or not validation["checks"] or not all(
        value is True for value in validation["checks"].values()
    ):
        raise ValueError("research_validation_checks_incomplete")
    if not isinstance(observation, dict) or observation.get("conclusion") != "SOURCE_PATTERN_MATCHED":
        raise ValueError("source_observation_not_supported")
    if not isinstance(analysis, dict) or analysis.get("source_supported") is not True:
        raise ValueError("analysis_not_source_supported")
    if analysis.get("finding_created") is not False:
        raise ValueError("finding_creation_not_prohibited")
    if target.get("commit") is None or target.get("path") is None or target.get("expected_git_blob_sha1") is None:
        raise ValueError("target_pin_incomplete")

    binding = result.get("research_case_binding")
    case = verify_research_case_binding(binding)
    case_digest = binding.get("case_digest")
    if (
        case.get("target_commit") != target.get("commit")
        or case.get("target_repository") != target.get("repository")
        or not isinstance(case_digest, str)
        or len(case_digest) != 64
    ):
        raise ValueError("research_case_binding_does_not_match_target")
    started_at = _timestamp(evidence.get("run_started_at"), "run_started_at")
    completed_at = _timestamp(evidence.get("run_completed_at"), "run_completed_at")
    if datetime.fromisoformat(completed_at.replace("Z", "+00:00")) < datetime.fromisoformat(started_at.replace("Z", "+00:00")):
        raise ValueError("run_timestamps_out_of_order")

    module = SUPPORTED_RUNNERS[schema]
    command = ["python", "-m", module]
    artifact = {
        "path": evidence_path.name,
        "sha256": hashlib.sha256(evidence_raw).hexdigest(),
        "size_bytes": len(evidence_raw),
    }
    contract = {
        "schema_version": schema,
        "case_digest": case_digest,
        "target": target,
        "round": round_info,
        "acceptance": acceptance,
        "safety": safety,
    }
    finding_id = "source-observation-" + str(case["case_id"])
    question = str(analysis.get("question") or case.get("hypothesis") or "Pinned source observation")
    return {
        "case_ref": {
            "case_id": case["case_id"],
            "case_digest": case_digest,
            "target_repository": case["target_repository"],
            "target_commit": case["target_commit"],
            "scope_url": case["scope_url"],
            "scope_digest": case["scope_digest"],
        },
        "finding_ref": {
            "finding_id": finding_id,
            "claim": (
                "Source-only observation: " + question
                + " No vulnerability finding or runtime exploitability is asserted."
            ),
            "affected_component": str(target.get("contract_address") or target.get("path")),
            "source_locations": [{
                "path": target["path"],
                "git_blob_sha1": target["expected_git_blob_sha1"],
            }],
            "impact_path": "not-established; source-only observation; no vulnerability finding",
        },
        "reproduction": {
            "reproduction_contract_sha256": sha256_hex(canonical_json(contract)),
            "commands": [command],
            "environment": {
                "execution_mode": "local",
                "evidence_schema": schema,
                "source_revision": target["commit"],
                "solidity_compiled": False,
                "evm_executed": False,
                "rpc_used": False,
            },
            "network_access": False,
            "artifacts": [artifact],
            "started_at": started_at,
            "completed_at": completed_at,
            "exit_code": 0,
        },
        "verdict": verdict,
        "verdict_rationale": rationale.strip(),
    }


def _write_new_json(path: Path, value: dict) -> None:
    if path.is_symlink():
        raise ValueError("output_path_must_not_be_symlink")
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def run_attestation_workflow(
    *,
    evidence_path: str | os.PathLike[str],
    verdict: str,
    rationale: str,
    trusted_keys_path: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    previous_registry_path: str | os.PathLike[str] | None = None,
) -> dict:
    """Sign, verify, and locally register a human-selected source-only verdict."""
    evidence_file = Path(evidence_path)
    evidence, evidence_raw = _load_json(evidence_file)
    trusted = _load_trusted_keys(trusted_keys_path)
    inputs = _prepare_inputs(evidence, evidence_raw, evidence_file, verdict, rationale)

    output = Path(output_dir)
    if output.is_symlink() or not output.is_dir():
        raise ValueError("output_dir_must_be_existing_non_symlink_directory")
    paths = {name: output / name for name in OUTPUT_FILES}
    for path in paths.values():
        if path.exists() or path.is_symlink():
            raise ValueError("refusing_to_overwrite_workflow_output:" + path.name)

    attestation = request_attestation(inputs)
    attestation_verification = verify_attestation(
        attestation,
        trusted_keys=trusted,
        expected_case_digest=inputs["case_ref"]["case_digest"],
        artifact_root=evidence_file.parent,
    )
    if attestation_verification.status != "VALID":
        raise ValueError("signed_attestation_verification_failed:" + attestation_verification.status)

    previous = None
    entries = []
    previous_checkpoint = None
    if previous_registry_path is not None:
        previous, _ = _load_json(previous_registry_path, max_bytes=16 * 1024 * 1024)
        verify_registry(previous)
        previous_checkpoint = checkpoint_for(previous)
        entries = [dict(entry) for entry in previous["entries"]]
    entry = entry_from_attestation(attestation)
    if any(item.get("attestation_id") == entry["attestation_id"] for item in entries):
        raise AttestationRegistryError("duplicate_attestation_id")
    entries.append(entry)
    registry = build_registry(entries, previous_checkpoint=previous_checkpoint)
    if previous is not None:
        verify_registry_chain(registry, previous)

    checkpoint = request_registry_checkpoint(registry)
    checkpoint_verification = verify_signed_checkpoint(
        checkpoint, trusted_keys=trusted, registry=registry
    )
    proof = build_inclusion_proof(registry, attestation["attestation_id"])
    proof_verification = verify_inclusion_proof(
        proof,
        expected_root=registry["merkle_root"],
        expected_size=registry["size"],
    )
    if not proof_verification.get("valid"):
        raise ValueError("inclusion_proof_verification_failed")

    summary = {
        "status": "ATTESTED_AND_REGISTERED_LOCALLY",
        "attestation_id": attestation["attestation_id"],
        "verdict": verdict,
        "signature_status": attestation_verification.status,
        "case_digest": inputs["case_ref"]["case_digest"],
        "registry_size": registry["size"],
        "merkle_root": registry["merkle_root"],
        "registry_sha256": registry_sha256(registry),
        "checkpoint_id": checkpoint_verification["checkpoint_id"],
        "inclusion_proof_valid": proof_verification["valid"],
        "published_remotely": False,
        "automatic_confirmation": False,
        "finding_created": False,
        "output_files": list(OUTPUT_FILES),
    }
    payloads = {
        "attestation.json": attestation,
        "registry.json": registry,
        "checkpoint.json": checkpoint,
        "inclusion-proof.json": proof,
        "workflow-summary.json": summary,
    }
    written = []
    try:
        for name, value in payloads.items():
            _write_new_json(paths[name], value)
            written.append(paths[name])
    except Exception:
        for path in written:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return summary
