"""Portable ZIP bundles for bounded local-experiment evidence.

A bundle is an integrity-checked transport format, not an authenticated execution
attestation. Verification proves only that the bundled record and bytes are
internally consistent.
"""
from __future__ import annotations

from io import BytesIO
import hashlib
import json
import stat
import zipfile

from shared.local_experiment import verify_experiment_record

BUNDLE_SCHEMA_VERSION = "aegisforge-local-experiment-bundle-v1"
_MANIFEST_NAME = "manifest.json"
_ARTIFACT_NAMES = ("input.bin", "stdout.bin", "stderr.bin")
_ALLOWED_NAMES = {_MANIFEST_NAME, *_ARTIFACT_NAMES}
_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_UNCOMPRESSED_BYTES = 20 * 1024 * 1024
_MAX_BUNDLE_BYTES = _MAX_TOTAL_UNCOMPRESSED_BYTES + 1024 * 1024


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def export_local_experiment_bundle(record: object, artifacts: dict[str, bytes]) -> bytes:
    """Return a deterministic, bounded ZIP containing a record and raw artifacts."""
    report = verify_experiment_record(record, artifacts)
    if report.get("status") != "PASS":
        raise ValueError("local_experiment_record_invalid")
    manifest = _canonical_json({
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "record": record,
    })
    if len(manifest) > _MAX_MANIFEST_BYTES:
        raise ValueError("local_experiment_manifest_too_large")

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, data in ((_MANIFEST_NAME, manifest), *((n, artifacts[n]) for n in _ARTIFACT_NAMES)):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.create_system = 3
            archive.writestr(info, data)
    result = buffer.getvalue()
    if len(result) > _MAX_BUNDLE_BYTES:
        raise ValueError("local_experiment_bundle_too_large")
    return result


def export_persisted_local_experiment_bundle(ledger, record_digest: str) -> bytes:
    """Export a bundle from a persisted ledger row, never from caller-supplied artifacts.

    The digest binds the canonical record JSON. Stored identity columns must match
    the record before raw artifact bytes are passed to the normal bundle exporter.
    """
    if not isinstance(record_digest, str) or len(record_digest) != 64:
        raise ValueError("local_experiment_record_digest_invalid")
    try:
        int(record_digest, 16)
    except ValueError as exc:
        raise ValueError("local_experiment_record_digest_invalid") from exc

    row = ledger.db.execute(
        """SELECT case_id, round_id, task_id, record_json,
                  input_bytes, stdout_bytes, stderr_bytes
           FROM local_experiment_records WHERE record_digest = ?""",
        (record_digest.lower(),),
    ).fetchone()
    if row is None:
        raise ValueError("local_experiment_record_not_found")

    case_id, round_id, task_id, record_json, input_bytes, stdout_bytes, stderr_bytes = row
    try:
        record = json.loads(record_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("local_experiment_persisted_record_invalid") from exc
    canonical = _canonical_json(record)
    if hashlib.sha256(canonical).hexdigest() != record_digest.lower():
        raise ValueError("local_experiment_persisted_record_digest_mismatch")
    if (not isinstance(record, dict)
            or record.get("case_id") != case_id
            or record.get("round_id") != round_id
            or record.get("task_id") != task_id):
        raise ValueError("local_experiment_persisted_identity_mismatch")

    artifacts = {
        "input.bin": input_bytes,
        "stdout.bin": stdout_bytes,
        "stderr.bin": stderr_bytes,
    }
    return export_local_experiment_bundle(record, artifacts)


def verify_local_experiment_bundle(bundle_bytes: bytes) -> dict:
    """Fail closed on malformed archives, unsafe names, missing or extra files."""
    if not isinstance(bundle_bytes, bytes):
        return {"status": "FAIL", "errors": ["bundle_bytes_required"]}
    if len(bundle_bytes) > _MAX_BUNDLE_BYTES:
        return {"status": "FAIL", "errors": ["bundle_size_limit_exceeded"]}

    try:
        with zipfile.ZipFile(BytesIO(bundle_bytes), "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(infos) != len(_ALLOWED_NAMES) or len(set(names)) != len(names):
                return {"status": "FAIL", "errors": ["bundle_entry_set_invalid"]}
            if set(names) != _ALLOWED_NAMES:
                return {"status": "FAIL", "errors": ["bundle_entry_set_invalid"]}

            total_size = 0
            for info in infos:
                if info.is_dir() or info.flag_bits & 0x1:
                    return {"status": "FAIL", "errors": ["bundle_entry_type_invalid"]}
                mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                # Some ZIP writers preserve only permission bits and omit the
                # Unix file-type bits. Accept that portable representation, but
                # reject explicit symlink/device/FIFO/socket types.
                if stat.S_ISLNK(mode) or (file_type and file_type != stat.S_IFREG):
                    return {"status": "FAIL", "errors": ["bundle_entry_type_invalid"]}
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    return {"status": "FAIL", "errors": ["bundle_compression_unsupported"]}
                limit = _MAX_MANIFEST_BYTES if info.filename == _MANIFEST_NAME else _MAX_ARTIFACT_BYTES
                if info.file_size > limit:
                    return {"status": "FAIL", "errors": ["bundle_entry_size_limit_exceeded"]}
                total_size += info.file_size
                if total_size > _MAX_TOTAL_UNCOMPRESSED_BYTES:
                    return {"status": "FAIL", "errors": ["bundle_uncompressed_size_limit_exceeded"]}

            manifest_bytes = archive.read(_MANIFEST_NAME)
            manifest = json.loads(
                manifest_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_json_constant")),
            )
            if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "record"}:
                return {"status": "FAIL", "errors": ["bundle_manifest_invalid"]}
            if manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION:
                return {"status": "FAIL", "errors": ["bundle_schema_unsupported"]}
            if _canonical_json(manifest) != manifest_bytes:
                return {"status": "FAIL", "errors": ["bundle_manifest_not_canonical"]}

            artifacts = {name: archive.read(name) for name in _ARTIFACT_NAMES}
            experiment_report = verify_experiment_record(manifest.get("record"), artifacts)
            if experiment_report.get("status") != "PASS":
                return {
                    "status": "FAIL",
                    "errors": ["local_experiment_record_invalid"],
                    "experiment_report": experiment_report,
                }
            return {
                "status": "PASS",
                "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
                "case_id": experiment_report["case_id"],
                "round_id": experiment_report["round_id"],
                "task_id": experiment_report["task_id"],
                "target_repository": experiment_report["target_repository"],
                "target_commit": experiment_report["target_commit"],
                "experiment_status": experiment_report["experiment_status"],
                "checked_artifacts": experiment_report["checked_artifacts"],
                "integrity_only": True,
                "authenticated_execution": False,
                "vulnerability_confirmed": False,
                "errors": [],
            }
    except (OSError, EOFError, UnicodeDecodeError, json.JSONDecodeError, ValueError, zipfile.BadZipFile, RuntimeError):
        return {"status": "FAIL", "errors": ["bundle_malformed_or_unreadable"]}
