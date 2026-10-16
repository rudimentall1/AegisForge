"""Independent offline verifier for case-bound AegisForge evidence bundles.

Level 1 validates package structure, canonical manifest digest, safe paths, file
sizes, and artifact SHA-256 hashes. Levels 2 and 3 are reported honestly as
unverified until trusted attestation verification and controlled experiment
reruns are explicitly implemented. This module never executes bundle content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_FILENAME = "case-artifact-manifest.json"
MANIFEST_SCHEMA_VERSION = "aegisforge-case-artifact-manifest-v1"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_ARTIFACTS = 10_000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("manifest_duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"manifest_nonstandard_json_constant:{value}")


def _load_manifest(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest_size_limit_exceeded")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("manifest_invalid_utf8") from exc
    try:
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("manifest_invalid_json") from exc
    if not isinstance(value, dict):
        raise ValueError("manifest_root_must_be_object")
    return value


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _safe_file(root: Path, relative_path: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path or "\\" in relative_path:
        raise ValueError("artifact_path_invalid")
    if len(relative_path) > 4096:
        raise ValueError("artifact_path_too_long")
    # Validate raw components before pathlib normalizes dot segments or repeated slashes.
    if any(part in ("", ".", "..") for part in relative_path.split("/")):
        raise ValueError("artifact_path_invalid")
    rel = PurePosixPath(relative_path)
    if rel.is_absolute() or (rel.parts and ":" in rel.parts[0]):
        raise ValueError("artifact_path_invalid")

    candidate = root
    for part in rel.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError("artifact_symlink_not_allowed")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("artifact_missing_or_outside_bundle") from exc
    if not resolved.is_file():
        raise ValueError("artifact_not_regular_file")
    return resolved


def _hash_file(path: Path, *, expected_size: int) -> tuple[str, int]:
    if expected_size > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact_size_limit_exceeded")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES:
                raise ValueError("artifact_size_limit_exceeded")
            digest.update(chunk)
    if total != expected_size:
        raise ValueError("artifact_size_mismatch")
    return digest.hexdigest(), total


def _validate_manifest_shape(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    expected_fields = {
        "schema_version", "case_id", "hypothesis_id", "artifacts", "manifest_sha256"
    }
    if set(manifest) != expected_fields:
        raise ValueError("manifest_fields_invalid")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError("manifest_schema_unsupported")
    for field in ("case_id", "hypothesis_id"):
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"manifest_{field}_invalid")
    digest = manifest.get("manifest_sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError("manifest_digest_invalid")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("manifest_artifacts_required")
    if len(artifacts) > MAX_ARTIFACTS:
        raise ValueError("manifest_artifact_count_limit_exceeded")

    seen: set[str] = set()
    total_size = 0
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size_bytes"}:
            raise ValueError("manifest_artifact_entry_invalid")
        path = item.get("path")
        file_digest = item.get("sha256")
        size = item.get("size_bytes")
        if not isinstance(path, str) or not path:
            raise ValueError("artifact_path_invalid")
        # Path validation is also done before any filesystem access.
        if "\\" in path or len(path) > 4096 or any(part in ("", ".", "..") for part in path.split("/")):
            raise ValueError("artifact_path_invalid")
        parsed = PurePosixPath(path)
        if parsed.is_absolute() or (parsed.parts and ":" in parsed.parts[0]):
            raise ValueError("artifact_path_invalid")
        if path in seen:
            raise ValueError("manifest_duplicate_artifact_path")
        seen.add(path)
        if not isinstance(file_digest, str) or not SHA256_RE.fullmatch(file_digest):
            raise ValueError("artifact_digest_invalid")
        if type(size) is not int or size < 0:
            raise ValueError("artifact_size_invalid")
        if size > MAX_ARTIFACT_BYTES:
            raise ValueError("artifact_size_limit_exceeded")
        total_size += size
        if total_size > MAX_TOTAL_ARTIFACT_BYTES:
            raise ValueError("bundle_size_limit_exceeded")
    return artifacts


def _verify_level_one(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    artifacts = _validate_manifest_shape(manifest)
    payload = {
        "schema_version": manifest["schema_version"],
        "case_id": manifest["case_id"],
        "hypothesis_id": manifest["hypothesis_id"],
        "artifacts": artifacts,
    }
    actual_manifest_digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
    if actual_manifest_digest != manifest["manifest_sha256"]:
        raise ValueError("manifest_digest_mismatch")

    checked = []
    for item in artifacts:
        path = _safe_file(root, item["path"])
        actual_digest, actual_size = _hash_file(path, expected_size=item["size_bytes"])
        if actual_digest != item["sha256"]:
            raise ValueError(f"artifact_digest_mismatch:{item['path']}")
        if actual_size != item["size_bytes"]:
            raise ValueError(f"artifact_size_mismatch:{item['path']}")
        checked.append(item["path"])
    return {
        "level": 1,
        "name": "package_integrity",
        "status": "PASS",
        "case_id": manifest["case_id"],
        "hypothesis_id": manifest["hypothesis_id"],
        "checked_artifacts": len(checked),
        "checked_paths": checked,
        "manifest_sha256": actual_manifest_digest,
    }


def verify_bundle(path: str | Path, *, max_level: int = 3) -> dict[str, Any]:
    """Verify an exported bundle without importing the orchestrator or running its contents.

    max_level=1 is useful for a focused package-integrity check. Levels 2 and 3
    are deliberately not marked PASS: this implementation does not yet verify
    workflow attestations against a trust root or execute experiments.
    """
    if type(max_level) is not int or max_level not in (1, 2, 3):
        raise ValueError("max_level_must_be_1_2_or_3")
    root = Path(path)
    levels: list[dict[str, Any]] = []
    try:
        if root.is_symlink():
            raise ValueError("bundle_root_must_not_be_symlink")
        if not root.is_dir():
            raise ValueError("bundle_root_missing_or_not_directory")
        root = root.resolve(strict=True)
        manifest_path = root / MANIFEST_FILENAME
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError("manifest_missing_or_not_regular_file")
        manifest = _load_manifest(manifest_path)
        levels.append(_verify_level_one(root, manifest))
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        levels.append({
            "level": 1,
            "name": "package_integrity",
            "status": "FAIL",
            "error": str(exc) or type(exc).__name__,
        })
        return {
            "schema_version": 1,
            "overall_status": "FAIL",
            "highest_completed_level": 0,
            "levels": levels,
            "limitations": [
                "A valid digest establishes consistency with the supplied manifest, not authenticity or truth.",
                "No bundle code or reproduction command was executed.",
            ],
        }

    if max_level >= 2:
        attestation = root / "workflow-attestation.json"
        levels.append({
            "level": 2,
            "name": "workflow_provenance",
            "status": "INCONCLUSIVE",
            "reason": (
                "attestation_present_but_not_cryptographically_verified"
                if attestation.is_file() and not attestation.is_symlink()
                else "trusted_workflow_attestation_not_supplied"
            ),
        })
    if max_level >= 3:
        levels.append({
            "level": 3,
            "name": "experiment_rerun",
            "status": "NOT_RUN",
            "reason": "bundle_contents_are_never_executed_by_this_verifier",
        })

    overall = "PASS" if all(item["status"] == "PASS" for item in levels) else "INCOMPLETE"
    return {
        "schema_version": 1,
        "overall_status": overall,
        "highest_completed_level": 1,
        "levels": levels,
        "limitations": [
            "Manifest hashes prove consistency relative to the supplied manifest, not authenticity or truth.",
            "Workflow provenance is not authenticated by this verifier.",
            "Experiment rerun and security impact are not established.",
            "A PASS at level 1 does not imply levels 2 or 3 passed.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_path", help="Directory containing case-artifact-manifest.json and its files")
    parser.add_argument("--max-level", type=int, choices=(1, 2, 3), default=3)
    args = parser.parse_args(argv)
    result = verify_bundle(args.bundle_path, max_level=args.max_level)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
