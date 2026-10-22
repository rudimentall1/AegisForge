"""One portable package linking a Research Case dossier to raw experiment bundles.

The package is an unsigned integrity transport. Nested bundle checks and identity
cross-links protect against accidental or partially forged substitutions, but the
package is not an authenticity anchor and does not prove execution truth.
"""
from __future__ import annotations

import argparse
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile
import zlib

from shared.execution_attestation import (
    ATTESTATION_SCHEMA_VERSION,
    verify_execution_attestation,
)
from shared.local_experiment_bundle import verify_local_experiment_bundle
from shared.research_case_bundle import verify_research_case_bundle


LEGACY_PACKAGE_SCHEMA_VERSION = "aegisforge-research-case-evidence-package-v1"
PACKAGE_SCHEMA_VERSION = "aegisforge-research-case-evidence-package-v2"
_MANIFEST_NAME = "manifest.json"
_DOSSIER_NAME = "case-dossier.zip"
_EXPERIMENT_PATH_RE = re.compile(r"^experiments/[0-9]{4}\\.zip$")
_ATTESTATION_PATH_RE = re.compile(r"^attestations/[0-9]{4}\\.json$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_MAX_EXPERIMENTS = 32
_MAX_MANIFEST_BYTES = 512 * 1024
_MAX_DOSSIER_BYTES = 64 * 1024 * 1024
_MAX_EXPERIMENT_BYTES = 21 * 1024 * 1024
_MAX_ATTESTATION_BYTES = 256 * 1024
_MAX_TOTAL_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
_MAX_PACKAGE_BYTES = 128 * 1024 * 1024
_MAX_MEMBER_COUNT = _MAX_EXPERIMENTS * 2 + 2



def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _strict_json(raw: bytes, *, error: str):
    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate_json_key")
            value[key] = item
        return value

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_json_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(error) from exc


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    chunks = []
    actual_size = 0
    with archive.open(info, "r") as stream:
        while True:
            chunk = stream.read(min(1024 * 1024, limit - actual_size + 1))
            if not chunk:
                break
            actual_size += len(chunk)
            if actual_size > limit:
                raise ValueError("package_member_size_limit_exceeded")
            chunks.append(chunk)
    if actual_size != info.file_size:
        raise ValueError("package_member_size_mismatch")
    return b"".join(chunks)


def _read_verified_dossier(dossier_bytes: bytes) -> tuple[dict, dict]:
    if not isinstance(dossier_bytes, bytes) or not dossier_bytes:
        raise ValueError("case_dossier_bytes_required")
    if len(dossier_bytes) > _MAX_DOSSIER_BYTES:
        raise ValueError("case_dossier_size_limit_exceeded")
    try:
        with tempfile.TemporaryDirectory(prefix="aegisforge-case-package-") as temp:
            path = Path(temp) / _DOSSIER_NAME
            path.write_bytes(dossier_bytes)
            report = verify_research_case_bundle(path)
        if not isinstance(report, dict) or report.get("valid") is not True:
            raise ValueError("case_dossier_invalid")
        with zipfile.ZipFile(BytesIO(dossier_bytes), "r") as archive:
            case_file = _strict_json(archive.read("case.json"), error="case_dossier_case_invalid")
            tasks_file = _strict_json(archive.read("tasks.json"), error="case_dossier_tasks_invalid")
            evidence_file = _strict_json(archive.read("evidence.json"), error="case_dossier_evidence_invalid")
            rounds_file = (
                _strict_json(archive.read("rounds.json"), error="case_dossier_rounds_invalid")
                if "rounds.json" in archive.namelist() else None
            )
        binding = case_file.get("research_case_binding") if isinstance(case_file, dict) else None
        case_payload = binding.get("case") if isinstance(binding, dict) else None
        if not isinstance(case_payload, dict):
            raise ValueError("case_dossier_case_binding_invalid")
        tasks = tasks_file.get("tasks") if isinstance(tasks_file, dict) else None
        observations = evidence_file.get("observations") if isinstance(evidence_file, dict) else None
        if not isinstance(tasks, list) or not isinstance(observations, list):
            raise ValueError("case_dossier_payload_invalid")
        rounds = rounds_file.get("rounds") if isinstance(rounds_file, dict) else []
        if not isinstance(rounds, list):
            raise ValueError("case_dossier_rounds_invalid")
        payloads = {
            "case_id": report["case_id"],
            "case_digest": report["case_digest"],
            "case": case_payload,
            "tasks": tasks,
            "observations": observations,
            "rounds": rounds,
            "registry_available": (
                rounds_file.get("registry_available") is True
                if isinstance(rounds_file, dict) else False
            ),
        }
        return report, payloads
    except ValueError:
        raise
    except (OSError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError, zlib.error) as exc:
        raise ValueError("case_dossier_invalid") from exc


def _validate_linkage(dossier_bytes: bytes, experiment_bundles: list[bytes]) -> tuple[dict, list[dict]]:
    if not isinstance(experiment_bundles, list) or not 1 <= len(experiment_bundles) <= _MAX_EXPERIMENTS:
        raise ValueError("package_experiment_count_invalid")
    dossier_report, payload = _read_verified_dossier(dossier_bytes)
    tasks = {
        task.get("id"): task for task in payload["tasks"]
        if isinstance(task, dict) and isinstance(task.get("id"), str)
    }
    if len(tasks) != len(payload["tasks"]):
        raise ValueError("case_dossier_task_identity_invalid")
    observations = payload["observations"]
    case_id = payload["case_id"]
    case = payload["case"]
    target_repository = case.get("target_repository")
    target_commit = case.get("target_commit")
    declared_spec_ids = {
        item.get("round_id") for item in case.get("rounds", [])
        if isinstance(item, dict) and isinstance(item.get("round_id"), str)
    }
    runtime_rounds = {
        item.get("round_id"): item for item in payload["rounds"]
        if isinstance(item, dict) and isinstance(item.get("round_id"), str)
    }

    reports = []
    seen_tasks = set()
    seen_digests = set()
    for bundle in experiment_bundles:
        report = verify_local_experiment_bundle(bundle)
        if report.get("status") != "PASS":
            raise ValueError("experiment_bundle_invalid")
        if report.get("case_id") != case_id:
            raise ValueError("experiment_case_identity_mismatch")
        if (
            report.get("target_repository") != target_repository
            or report.get("target_commit") != target_commit
        ):
            raise ValueError("experiment_target_identity_mismatch")
        task_id = report.get("task_id")
        task = tasks.get(task_id)
        if task is None:
            raise ValueError("experiment_task_not_in_case_dossier")
        if task.get("status") not in {"completed", "failed"}:
            raise ValueError("experiment_task_not_terminal")
        if (
            task.get("research_case_id") != case_id
            or task.get("round_id") != report.get("round_id")
            or task.get("round_spec_id") != report.get("round_spec_id")
        ):
            raise ValueError("experiment_task_round_identity_mismatch")

        spec_id = report.get("round_spec_id")
        runtime_id = report.get("round_id")
        if spec_id is not None:
            if spec_id not in declared_spec_ids:
                raise ValueError("experiment_round_spec_not_declared")
            if not payload["registry_available"]:
                raise ValueError("experiment_runtime_registry_required")
            registry = runtime_rounds.get(runtime_id)
            if registry is None or registry.get("case_id") != case_id:
                raise ValueError("experiment_runtime_round_not_registered")
            if registry.get("round_spec_id") != spec_id:
                raise ValueError("experiment_runtime_round_spec_mismatch")
        elif task.get("round_spec_id") is not None:
            raise ValueError("experiment_planned_round_identity_missing")

        record_digest = report.get("record_digest")
        if not isinstance(record_digest, str) or not _SHA256_RE.fullmatch(record_digest):
            raise ValueError("experiment_record_digest_invalid")
        link_matches = [
            item for item in observations
            if isinstance(item, dict)
            and item.get("task_id") == task_id
            and item.get("kind") == "local_experiment_record"
            and item.get("value") == record_digest
            and item.get("case_id") == case_id
            and item.get("round_id") == runtime_id
            and item.get("round_spec_id") == spec_id
        ]
        if len(link_matches) != 1:
            raise ValueError("experiment_dossier_evidence_link_missing")
        if task_id in seen_tasks:
            raise ValueError("package_duplicate_experiment_task")
        if record_digest in seen_digests:
            raise ValueError("package_duplicate_experiment_record")
        seen_tasks.add(task_id)
        seen_digests.add(record_digest)
        reports.append(report)

    # The package must include every experiment-record reference carried by the
    # dossier, not silently omit one and still call itself a complete package.
    dossier_experiment_links = [
        item for item in observations
        if isinstance(item, dict) and item.get("kind") == "local_experiment_record"
    ]
    linked_digests = [item.get("value") for item in dossier_experiment_links]
    if (
        len(linked_digests) != len(reports)
        or any(not isinstance(value, str) or not _SHA256_RE.fullmatch(value) for value in linked_digests)
        or set(linked_digests) != seen_digests
    ):
        raise ValueError("package_experiment_set_does_not_match_dossier_evidence")

    reports.sort(key=lambda item: (item["task_id"], item["record_digest"]))
    return dossier_report, reports



def _read_experiment_record(bundle_bytes: bytes) -> dict:
    """Read the canonical record from an integrity-verified experiment bundle."""
    report = verify_local_experiment_bundle(bundle_bytes)
    if report.get("status") != "PASS":
        raise ValueError("experiment_bundle_invalid")
    try:
        with zipfile.ZipFile(BytesIO(bundle_bytes), "r") as archive:
            info = archive.getinfo("manifest.json")
            raw = _read_member(archive, info, 256 * 1024)
        manifest = _strict_json(raw, error="experiment_bundle_manifest_invalid")
        record = manifest.get("record") if isinstance(manifest, dict) else None
        if not isinstance(record, dict):
            raise ValueError("experiment_bundle_record_invalid")
        digest = _sha256(_canonical_json(record))
        if digest != report.get("record_digest"):
            raise ValueError("experiment_bundle_record_digest_mismatch")
        return record
    except ValueError:
        raise
    except (OSError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError, zlib.error) as exc:
        raise ValueError("experiment_bundle_record_unreadable") from exc


def _validate_detached_attestation(attestation: object, records_by_digest: dict) -> dict:
    """Validate signed envelope shape and bind its claims to an included exact record.

    This structural check does not establish signature validity. That requires a
    trusted public key supplied separately to package verification.
    """
    if not isinstance(attestation, dict) or set(attestation) != {
        "claims", "signature_ed25519", "authenticity"
    }:
        raise ValueError("execution_attestation_envelope_invalid")
    if attestation.get("authenticity") != "SIGNED_CLAIMS_ONLY":
        raise ValueError("execution_attestation_authenticity_label_invalid")
    claims = attestation.get("claims")
    required_claims = {
        "schema_version", "signer_id", "runner_id", "case_id", "round_id",
        "task_id", "target_repository", "target_commit", "record_sha256",
        "environment_sha256", "issued_at", "nonce",
    }
    if not isinstance(claims, dict) or set(claims) != required_claims:
        raise ValueError("execution_attestation_claims_invalid")
    if claims.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
        raise ValueError("execution_attestation_schema_unsupported")
    signature = attestation.get("signature_ed25519")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{128}", signature):
        raise ValueError("execution_attestation_signature_encoding_invalid")
    for field in ("signer_id", "runner_id", "case_id", "round_id", "task_id", "nonce"):
        if not isinstance(claims.get(field), str) or not _ID_RE.fullmatch(claims[field]):
            raise ValueError(f"execution_attestation_{field}_invalid")
    if not isinstance(claims.get("target_repository"), str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", claims["target_repository"]
    ):
        raise ValueError("execution_attestation_target_repository_invalid")
    if not isinstance(claims.get("target_commit"), str) or not _COMMIT_RE.fullmatch(
        claims["target_commit"]
    ):
        raise ValueError("execution_attestation_target_commit_invalid")
    for field in ("record_sha256", "environment_sha256"):
        if not isinstance(claims.get(field), str) or not _SHA256_RE.fullmatch(claims[field]):
            raise ValueError(f"execution_attestation_{field}_invalid")
    issued_at = claims.get("issued_at")
    if not isinstance(issued_at, str) or not issued_at.strip() or len(issued_at) > 64:
        raise ValueError("execution_attestation_issued_at_invalid")

    record_digest = claims["record_sha256"]
    record = records_by_digest.get(record_digest)
    if record is None:
        raise ValueError("execution_attestation_record_not_in_package")
    for field in (
        "case_id", "round_id", "task_id", "target_repository", "target_commit"
    ):
        if claims.get(field) != record.get(field):
            raise ValueError(f"execution_attestation_{field}_mismatch")
    return {
        "record_digest": record_digest,
        "task_id": record["task_id"],
        "signer_id": claims["signer_id"],
        "record": record,
        "attestation": attestation,
    }


def _prepare_attestations(
    execution_attestations: object,
    experiment_bundles: list[bytes],
) -> list[dict]:
    """Bind each optional detached attestation to one included experiment record."""
    if execution_attestations is None:
        execution_attestations = []
    if not isinstance(execution_attestations, list):
        raise ValueError("execution_attestations_must_be_a_list")
    if len(execution_attestations) > _MAX_EXPERIMENTS:
        raise ValueError("execution_attestation_count_invalid")
    records_by_digest = {}
    for bundle in experiment_bundles:
        report = verify_local_experiment_bundle(bundle)
        if report.get("status") != "PASS":
            raise ValueError("experiment_bundle_invalid")
        digest = report.get("record_digest")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise ValueError("experiment_record_digest_invalid")
        records_by_digest[digest] = _read_experiment_record(bundle)

    normalized = []
    seen_digests = set()
    for attestation in execution_attestations:
        prepared = _validate_detached_attestation(attestation, records_by_digest)
        digest = prepared["record_digest"]
        if digest in seen_digests:
            raise ValueError("package_duplicate_execution_attestation")
        seen_digests.add(digest)
        normalized.append(prepared)
    normalized.sort(key=lambda item: (item["record_digest"], item["signer_id"]))
    return normalized


def _evaluate_attestations(
    prepared: list[dict],
    *,
    trusted_attestors,
    max_age_seconds: int | None,
    max_future_skew_seconds: int,
    now,
) -> tuple[str, list[dict]]:
    """Return a separate signature-verification status without conflating integrity."""
    if not prepared:
        return "NOT_PRESENT", []
    if trusted_attestors is None:
        return "NOT_CHECKED", [
            {
                "record_digest": item["record_digest"],
                "task_id": item["task_id"],
                "signer_id": item["signer_id"],
                "status": "NOT_CHECKED",
                "attestation_verified": False,
                "execution_truth_established": False,
                "errors": [],
            }
            for item in prepared
        ]
    if not isinstance(trusted_attestors, dict):
        results = []
        for item in prepared:
            results.append({
                "record_digest": item["record_digest"],
                "task_id": item["task_id"],
                "signer_id": item["signer_id"],
                "status": "FAIL",
                "attestation_verified": False,
                "execution_truth_established": False,
                "errors": ["trusted_attestor_policy_invalid"],
            })
        return "FAIL", results

    results = []
    for item in prepared:
        signer_id = item["signer_id"]
        key = trusted_attestors.get(signer_id)
        if key is None:
            result = {
                "status": "UNTRUSTED",
                "attestation_verified": False,
                "execution_truth_established": False,
                "errors": ["attestation_signer_not_in_trust_store"],
            }
        else:
            result = verify_execution_attestation(
                item["attestation"],
                trusted_public_key_bytes=key,
                expected_signer_id=signer_id,
                expected_record=item["record"],
                max_age_seconds=max_age_seconds,
                max_future_skew_seconds=max_future_skew_seconds,
                now=now,
            )
        results.append({
            "record_digest": item["record_digest"],
            "task_id": item["task_id"],
            "signer_id": signer_id,
            "status": result.get("status", "FAIL"),
            "attestation_verified": result.get("attestation_verified") is True,
            "execution_truth_established": False,
            "errors": result.get("errors", []),
        })
    summary = "PASS" if all(item["status"] == "PASS" for item in results) else "FAIL"
    return summary, results


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.create_system = 3
            archive.writestr(info, files[name])
    return output.getvalue()


def build_research_case_evidence_package(
    case_dossier: bytes,
    experiment_bundles: list[bytes],
) -> bytes:
    """Build a deterministic package after checking all dossier-to-experiment links."""
    dossier_report, reports = _validate_linkage(case_dossier, experiment_bundles)
    by_digest = {}
    for bundle in experiment_bundles:
        report = verify_local_experiment_bundle(bundle)
        if report.get("status") != "PASS":
            raise ValueError("experiment_bundle_invalid")
        by_digest[report["record_digest"]] = bundle
    files = {_DOSSIER_NAME: case_dossier}
    experiment_metadata = []
    for index, report in enumerate(reports):
        path = f"experiments/{index:04d}.zip"
        bundle = by_digest[report["record_digest"]]
        if len(bundle) > _MAX_EXPERIMENT_BYTES:
            raise ValueError("experiment_bundle_size_limit_exceeded")
        files[path] = bundle
        experiment_metadata.append({
            "path": path,
            "task_id": report["task_id"],
            "record_digest": report["record_digest"],
            "round_id": report["round_id"],
            "round_spec_id": report["round_spec_id"],
        })

    members = [
        {"path": name, "sha256": _sha256(raw), "size_bytes": len(raw)}
        for name, raw in sorted(files.items())
    ]
    core = {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "case_id": dossier_report["case_id"],
        "case_digest": dossier_report["case_digest"],
        "members": members,
        "experiments": experiment_metadata,
    }
    manifest = dict(core)
    manifest["package_sha256"] = _sha256(_canonical_json(core))
    files[_MANIFEST_NAME] = _canonical_json(manifest)
    if sum(len(value) for value in files.values()) > _MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise ValueError("package_uncompressed_size_limit_exceeded")
    package_bytes = _zip_bytes(files)
    if len(package_bytes) > _MAX_PACKAGE_BYTES:
        raise ValueError("package_size_limit_exceeded")
    report = verify_research_case_evidence_package(package_bytes)
    if report.get("status") != "PASS":
        raise ValueError("package_self_verification_failed")
    return package_bytes


def verify_research_case_evidence_package(package_bytes: bytes) -> dict:
    """Verify package/archive integrity, nested bundles, and semantic evidence links."""
    if not isinstance(package_bytes, bytes):
        return {"status": "FAIL", "errors": ["package_bytes_required"]}
    if len(package_bytes) > _MAX_PACKAGE_BYTES:
        return {"status": "FAIL", "errors": ["package_size_limit_exceeded"]}
    try:
        with zipfile.ZipFile(BytesIO(package_bytes), "r") as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(names) > _MAX_MEMBER_COUNT or len(names) < 3 or len(set(names)) != len(names):
                raise ValueError("package_member_set_invalid")
            files = {}
            total = 0
            for info in infos:
                name = info.filename
                if (
                    not name or "\\" in name or name.endswith("/")
                    or PurePosixPath(name).is_absolute()
                    or any(part in ("", ".", "..") for part in PurePosixPath(name).parts)
                    or name not in {_MANIFEST_NAME, _DOSSIER_NAME}
                       and not _EXPERIMENT_PATH_RE.fullmatch(name)
                ):
                    raise ValueError("package_member_path_invalid")
                mode = (info.external_attr >> 16) & 0o170000
                if info.is_dir() or info.flag_bits & 0x1 or mode == stat.S_IFLNK:
                    raise ValueError("package_member_type_invalid")
                if mode and mode != stat.S_IFREG:
                    raise ValueError("package_member_type_invalid")
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ValueError("package_compression_unsupported")
                limit = (
                    _MAX_MANIFEST_BYTES if name == _MANIFEST_NAME
                    else _MAX_DOSSIER_BYTES if name == _DOSSIER_NAME
                    else _MAX_EXPERIMENT_BYTES
                )
                if info.file_size > limit:
                    raise ValueError("package_member_size_limit_exceeded")
                total += info.file_size
                if total > _MAX_TOTAL_UNCOMPRESSED_BYTES:
                    raise ValueError("package_uncompressed_size_limit_exceeded")
                files[name] = _read_member(archive, info, limit)

        if _MANIFEST_NAME not in files or _DOSSIER_NAME not in files:
            raise ValueError("package_required_member_missing")
        manifest_bytes = files[_MANIFEST_NAME]
        manifest = _strict_json(manifest_bytes, error="package_manifest_invalid")
        fields = {
            "schema_version", "case_id", "case_digest", "members",
            "experiments", "package_sha256",
        }
        if not isinstance(manifest, dict) or set(manifest) != fields:
            raise ValueError("package_manifest_fields_invalid")
        if manifest.get("schema_version") != PACKAGE_SCHEMA_VERSION:
            raise ValueError("package_schema_unsupported")
        if _canonical_json(manifest) != manifest_bytes:
            raise ValueError("package_manifest_not_canonical")
        if (
            not isinstance(manifest.get("case_id"), str) or not manifest["case_id"].strip()
            or not isinstance(manifest.get("case_digest"), str)
            or not _SHA256_RE.fullmatch(manifest["case_digest"])
        ):
            raise ValueError("package_identity_invalid")
        experiments = manifest.get("experiments")
        members = manifest.get("members")
        if not isinstance(experiments, list) or not 1 <= len(experiments) <= _MAX_EXPERIMENTS:
            raise ValueError("package_experiment_count_invalid")
        if not isinstance(members, list) or len(members) != len(files) - 1:
            raise ValueError("package_member_manifest_invalid")
        expected_paths = set(files) - {_MANIFEST_NAME}
        member_paths = []
        for item in members:
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "size_bytes"}:
                raise ValueError("package_member_manifest_invalid")
            name = item["path"]
            digest = item["sha256"]
            size = item["size_bytes"]
            if (
                not isinstance(name, str) or name not in expected_paths
                or not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest)
                or type(size) is not int or size < 0
            ):
                raise ValueError("package_member_manifest_invalid")
            if size != len(files[name]) or digest != _sha256(files[name]):
                raise ValueError("package_member_digest_mismatch")
            member_paths.append(name)
        if member_paths != sorted(member_paths) or set(member_paths) != expected_paths:
            raise ValueError("package_member_manifest_invalid")
        core = {key: manifest[key] for key in (
            "schema_version", "case_id", "case_digest", "members", "experiments"
        )}
        if (
            not isinstance(manifest.get("package_sha256"), str)
            or not _SHA256_RE.fullmatch(manifest["package_sha256"])
            or manifest["package_sha256"] != _sha256(_canonical_json(core))
        ):
            raise ValueError("package_manifest_digest_mismatch")

        exp_paths = [f"experiments/{index:04d}.zip" for index in range(len(experiments))]
        if set(expected_paths) != {_DOSSIER_NAME, *exp_paths}:
            raise ValueError("package_experiment_member_set_invalid")
        if experiments != sorted(experiments, key=lambda item: item.get("path", "") if isinstance(item, dict) else ""):
            raise ValueError("package_experiment_manifest_order_invalid")
        bundle_bytes = [files[name] for name in exp_paths]
        dossier_report, reports = _validate_linkage(files[_DOSSIER_NAME], bundle_bytes)
        if (
            manifest["case_id"] != dossier_report["case_id"]
            or manifest["case_digest"] != dossier_report["case_digest"]
        ):
            raise ValueError("package_case_identity_mismatch")
        if len(experiments) != len(reports):
            raise ValueError("package_experiment_manifest_invalid")
        for item, report, expected_path in zip(experiments, reports, exp_paths):
            expected = {
                "path": expected_path,
                "task_id": report["task_id"],
                "record_digest": report["record_digest"],
                "round_id": report["round_id"],
                "round_spec_id": report["round_spec_id"],
            }
            if not isinstance(item, dict) or set(item) != set(expected) or item != expected:
                raise ValueError("package_experiment_identity_mismatch")

        return {
            "status": "PASS",
            "schema_version": PACKAGE_SCHEMA_VERSION,
            "case_id": dossier_report["case_id"],
            "case_digest": dossier_report["case_digest"],
            "experiment_count": len(reports),
            "task_ids": [report["task_id"] for report in reports],
            "record_digests": [report["record_digest"] for report in reports],
            "round_ids": sorted({report["round_id"] for report in reports}),
            "round_spec_ids": sorted({
                report["round_spec_id"] for report in reports
                if report["round_spec_id"] is not None
            }),
            "authenticity": "UNSIGNED_INTEGRITY_ONLY",
            "vulnerability_confirmed": False,
            "errors": [],
        }
    except ValueError as exc:
        return {"status": "FAIL", "errors": [str(exc)]}
    except (OSError, EOFError, KeyError, TypeError, zipfile.BadZipFile, RuntimeError, zlib.error) as exc:
        return {"status": "FAIL", "errors": ["package_malformed_or_unreadable"]}

def _read_input_file(path_text: str, limit: int) -> bytes:
    path = Path(path_text)
    if path.is_symlink() or not path.is_file():
        raise ValueError("input_file_required")
    size = path.stat().st_size
    if size <= 0 or size > limit:
        raise ValueError("input_file_size_limit_exceeded")
    raw = path.read_bytes()
    if len(raw) != size or len(raw) > limit:
        raise ValueError("input_file_size_changed_during_read")
    return raw


def _write_output_atomic(path_text: str, data: bytes) -> None:
    output = Path(path_text)
    if output.is_symlink():
        raise ValueError("output_path_must_not_be_symlink")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output.name}.", suffix=".tmp",
            dir=output.parent, delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, output)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def main(argv=None) -> int:
    """CLI for assembling/verifying offline packages; never executes a command."""
    parser = argparse.ArgumentParser(
        description="Assemble or verify a portable AegisForge case-evidence package."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser(
        "build", help="Combine one verified case dossier and its experiment ZIPs."
    )
    build_parser.add_argument("--case-dossier", required=True)
    build_parser.add_argument(
        "--experiment", action="append", required=True,
        help="Path to one persisted local-experiment ZIP; repeat for every linked record.",
    )
    build_parser.add_argument("--output", required=True)
    verify_parser = commands.add_parser(
        "verify", help="Verify a combined case-evidence package offline."
    )
    verify_parser.add_argument("package")
    args = parser.parse_args(argv)

    try:
        if args.command == "build":
            dossier = _read_input_file(args.case_dossier, _MAX_DOSSIER_BYTES)
            if len(args.experiment) > _MAX_EXPERIMENTS:
                raise ValueError("package_experiment_count_invalid")
            experiments = [
                _read_input_file(name, _MAX_EXPERIMENT_BYTES)
                for name in args.experiment
            ]
            package = build_research_case_evidence_package(dossier, experiments)
            _write_output_atomic(args.output, package)
            report = verify_research_case_evidence_package(package)
        else:
            package = _read_input_file(args.package, _MAX_PACKAGE_BYTES)
            report = verify_research_case_evidence_package(package)

        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False))
        return 0 if report.get("status") == "PASS" else 2
    except (OSError, ValueError) as exc:
        print(json.dumps(
            {"status": "FAIL", "errors": [str(exc)]},
            sort_keys=True, indent=2, ensure_ascii=False,
        ))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
