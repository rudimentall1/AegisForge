from __future__ import annotations

import hashlib
import json
import re


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_ANALYSIS_STATUSES = {
    "ANALYZED",
    "NOT_RUN",
    "SOURCE_EMPTY",
    "SOURCE_TOO_LARGE",
    "UNSUPPORTED_SOURCE_FORMAT",
    "INVALID_CONFIGURATION",
    "TOOL_UNAVAILABLE",
    "COMPILER_UNAVAILABLE",
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
    schema_valid = (
        report_is_object
        and payload.get("schema") == "aegisforge.slither_analysis.v1"
        and payload.get("status") in _ALLOWED_ANALYSIS_STATUSES
        and payload.get("vulnerabilities_confirmed") is False
    )

    findings = payload.get("findings") if report_is_object else None
    findings_are_list = isinstance(findings, list)
    finding_count = payload.get("finding_count") if report_is_object else None
    finding_count_matches = (
        findings_are_list
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
                or finding.get("impact") not in _ALLOWED_IMPACTS
                or finding.get("confidence") not in _ALLOWED_CONFIDENCE
                or not isinstance(finding.get("description"), str)
                or not isinstance(finding.get("elements"), list)
                or finding.get("status") != "UNVERIFIED_POTENTIAL"
            ):
                finding_shapes_valid = False
            if finding.get("status") != "UNVERIFIED_POTENTIAL":
                findings_unconfirmed = False

    checks = {
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
        "vulnerabilities_confirmed": False,
    }
