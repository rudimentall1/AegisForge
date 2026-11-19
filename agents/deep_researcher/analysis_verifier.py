from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_ANALYSIS_STATUSES = {
    "ANALYZED",
    "PARTIAL_ANALYSIS",
    "NOT_RUN",
    "SOURCE_EMPTY",
    "SOURCE_TOO_LARGE",
    "UNSUPPORTED_SOURCE_FORMAT",
    "INVALID_SOURCE_PROJECT",
    "INVALID_CONFIGURATION",
    "TOOL_UNAVAILABLE",
    "COMPILER_UNAVAILABLE",
    "COMPILER_VERSION_MISMATCH",
    "TIMEOUT",
    "EXECUTION_FAILED",
    "INVALID_REPORT",
    "REPORT_TOO_LARGE",
    "SOURCE_READ_FAILED",
}
_ALLOWED_IMPACTS = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL",
    "OPTIMIZATION",
}
_ALLOWED_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}


def _verified_source_files(source_bytes: bytes) -> dict:
    try:
        source_text = source_bytes.decode("utf-8")
    except (AttributeError, UnicodeDecodeError):
        return {}

    stripped = source_text.strip()
    json_text = stripped[1:-1] if stripped.startswith("{{") and stripped.endswith("}}") else stripped
    if stripped.startswith("{"):
        try:
            payload = json.loads(json_text)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        sources = payload.get("sources") if isinstance(payload, dict) else None
        if not isinstance(sources, dict):
            return {}
        files = {}
        for name, entry in sources.items():
            content = entry.get("content") if isinstance(entry, dict) else None
            if isinstance(name, str) and isinstance(content, str):
                files[name] = content
        return files

    return {"Contract.sol": source_text}


def _verify_source_mappings(source_bytes: bytes, findings: list) -> dict:
    source_files = _verified_source_files(source_bytes)
    source_metadata = {
        name: (len(content.splitlines()), len(content.encode("utf-8")))
        for name, content in source_files.items()
    }
    mapped = 0
    dependency = 0
    missing = 0
    invalid = False
    total = 0

    for finding in findings:
        elements = finding.get("elements", []) if isinstance(finding, dict) else []
        if not isinstance(elements, list):
            invalid = True
            continue
        for element in elements:
            total += 1
            mapping = element.get("source_mapping") if isinstance(element, dict) else None
            if not isinstance(mapping, dict):
                missing += 1
                invalid = True
                continue
            if mapping.get("is_dependency") is True:
                dependency += 1
                continue

            filename = (
                mapping.get("filename_relative")
                or mapping.get("filename_used")
                or mapping.get("filename_short")
            )
            if not isinstance(filename, str) or not filename or "\\\\" in filename:
                invalid = True
                continue
            relative = PurePosixPath(filename)
            if relative.is_absolute() or not relative.parts or any(
                part in ("", ".", "..") for part in relative.parts
            ):
                invalid = True
                continue
            source_dimensions = source_metadata.get(relative.as_posix())
            if source_dimensions is None:
                invalid = True
                continue
            source_line_count, source_length = source_dimensions

            lines = mapping.get("lines")
            if (
                not isinstance(lines, list)
                or not lines
                or any(
                    not isinstance(line, int)
                    or isinstance(line, bool)
                    or line < 1
                    or line > source_line_count
                    for line in lines
                )
            ):
                invalid = True
                continue

            start = mapping.get("start")
            length = mapping.get("length")
            if (
                not isinstance(start, int)
                or isinstance(start, bool)
                or not isinstance(length, int)
                or isinstance(length, bool)
                or start < 0
                or length < 0
                or start + length > source_length
            ):
                invalid = True
                continue
            mapped += 1

    return {
        "valid": not invalid,
        "total_elements": total,
        "mapped_elements": mapped,
        "dependency_elements": dependency,
        "unmapped_elements": missing,
        "coverage": (mapped + dependency) / total if total else 1.0,
    }


def verify_analysis_evidence(
    *,
    source_bytes: bytes,
    analysis_bytes: bytes,
    expected_source_sha256: str,
    expected_analysis_sha256: str,
) -> dict:
    """Independently verify persisted analysis artifact integrity, not exploitability."""
    try:
        source_hash = hashlib.sha256(source_bytes).hexdigest()
    except (TypeError, ValueError):
        source_hash = None
    try:
        analysis_hash = hashlib.sha256(analysis_bytes).hexdigest()
    except (TypeError, ValueError):
        analysis_hash = None

    try:
        payload = json.loads(analysis_bytes)
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = None

    report_is_object = isinstance(payload, dict)
    analysis_status = payload.get("status") if report_is_object else None
    schema_valid = (
        report_is_object
        and payload.get("schema") == "aegisforge.slither_analysis.v1"
        and isinstance(analysis_status, str)
        and analysis_status in _ALLOWED_ANALYSIS_STATUSES
        and payload.get("vulnerabilities_confirmed") is False
    )

    findings = payload.get("findings") if report_is_object else None
    findings_are_list = isinstance(findings, list)
    finding_count = payload.get("finding_count") if report_is_object else None
    finding_count_matches = (
        findings_are_list
        and len(findings) <= 500
        and isinstance(finding_count, int)
        and not isinstance(finding_count, bool)
        and finding_count == len(findings)
    )

    finding_shapes_valid = findings_are_list
    findings_unconfirmed = (
        report_is_object and payload.get("vulnerabilities_confirmed") is False
    )
    if findings_are_list:
        for finding in findings:
            if not isinstance(finding, dict):
                finding_shapes_valid = False
                findings_unconfirmed = False
                continue
            if (
                not isinstance(finding.get("detector"), str)
                or not finding["detector"]
                or not isinstance(finding.get("impact"), str)
                or finding.get("impact") not in _ALLOWED_IMPACTS
                or not isinstance(finding.get("confidence"), str)
                or finding.get("confidence") not in _ALLOWED_CONFIDENCE
                or not isinstance(finding.get("description"), str)
                or len(finding.get("description", "")) > 16_000
                or not isinstance(finding.get("elements"), list)
                or len(finding.get("elements", [])) > 50
                or any(not isinstance(element, dict) for element in finding.get("elements", []))
                or len(finding.get("detector", "")) > 256
                or finding.get("status") != "UNVERIFIED_POTENTIAL"
            ):
                finding_shapes_valid = False
            if finding.get("status") != "UNVERIFIED_POTENTIAL":
                findings_unconfirmed = False

    source_mapping_coverage = _verify_source_mappings(
        source_bytes if isinstance(source_bytes, bytes) else b"",
        findings if findings_are_list else [],
    )
    checks = {
        "source_mappings_valid": bool(source_mapping_coverage["valid"]),
        "source_sha256_matches": (
            isinstance(expected_source_sha256, str)
            and bool(_SHA256_RE.fullmatch(expected_source_sha256))
            and source_hash == expected_source_sha256
        ),
        "analysis_sha256_matches": (
            isinstance(expected_analysis_sha256, str)
            and bool(_SHA256_RE.fullmatch(expected_analysis_sha256))
            and analysis_hash == expected_analysis_sha256
        ),
        "analysis_schema_valid": bool(schema_valid),
        "finding_count_matches": bool(finding_count_matches),
        "finding_shapes_valid": bool(finding_shapes_valid),
        "findings_unconfirmed": bool(findings_unconfirmed),
    }
    return {
        "schema": "aegisforge.analysis_validation.v1",
        "status": "VALID" if all(checks.values()) else "INVALID",
        "validation_scope": "artifact_integrity_only",
        "checks": checks,
        "source_sha256": source_hash,
        "analysis_sha256": analysis_hash,
        "finding_count": len(findings) if findings_are_list else 0,
        "source_mapping_coverage": {
            key: value
            for key, value in source_mapping_coverage.items()
            if key != "valid"
        },
        "vulnerabilities_confirmed": False,
    }
