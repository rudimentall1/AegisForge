from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 500
MAX_ELEMENTS_PER_FINDING = 50
MAX_DESCRIPTION_CHARS = 16_000


def _empty_result(status: str, error: str | None = None) -> dict:
    result = {
        "schema": "aegisforge.slither_analysis.v1",
        "status": status,
        "findings": [],
        "finding_count": 0,
        "vulnerabilities_confirmed": False,
    }
    if error:
        result["error"] = error
    return result


def parse_slither_json(report: str) -> dict:
    if not isinstance(report, str) or not report.strip():
        return _empty_result("INVALID_REPORT", "empty_slither_report")
    if len(report.encode("utf-8")) > MAX_REPORT_BYTES:
        return _empty_result("REPORT_TOO_LARGE", "slither_report_exceeds_size_limit")

    try:
        payload = json.loads(report)
    except (TypeError, ValueError, json.JSONDecodeError):
        return _empty_result("INVALID_REPORT", "slither_report_invalid_json")

    if not isinstance(payload, dict):
        return _empty_result("INVALID_REPORT", "slither_report_not_object")

    results = payload.get("results")
    detectors = results.get("detectors") if isinstance(results, dict) else None
    if not isinstance(detectors, list):
        return _empty_result("INVALID_REPORT", "slither_detectors_missing")

    findings = []
    for detector in detectors[:MAX_FINDINGS]:
        if not isinstance(detector, dict):
            continue
        check = detector.get("check")
        impact = detector.get("impact")
        confidence = detector.get("confidence")
        description = detector.get("description")
        if not all(isinstance(value, str) and value.strip() for value in (
            check, impact, confidence, description
        )):
            continue
        elements = detector.get("elements")
        if not isinstance(elements, list):
            elements = []
        findings.append({
            "detector": check[:256],
            "impact": impact.upper()[:32],
            "confidence": confidence.upper()[:32],
            "description": description[:MAX_DESCRIPTION_CHARS],
            "elements": [
                element for element in elements[:MAX_ELEMENTS_PER_FINDING]
                if isinstance(element, dict)
            ],
            "status": "UNVERIFIED_POTENTIAL",
        })

    return {
        "schema": "aegisforge.slither_analysis.v1",
        "status": "ANALYZED",
        "findings": findings,
        "finding_count": len(findings),
        "detectors_truncated": len(detectors) > MAX_FINDINGS,
        "vulnerabilities_confirmed": False,
    }


def analyze_source(
    source_code: str,
    *,
    slither_executable: str = "slither",
    timeout: int = 90,
) -> dict:
    """Run Slither on one verified, flattened Solidity source file.

    Slither detector output is retained as unverified potential findings. This
    function never promotes a detector result to a confirmed vulnerability.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return _empty_result("SOURCE_EMPTY", "verified_source_empty")
    if len(source_code.encode("utf-8")) > MAX_SOURCE_BYTES:
        return _empty_result("SOURCE_TOO_LARGE", "verified_source_exceeds_size_limit")
    if source_code.lstrip().startswith("{"):
        return _empty_result(
            "UNSUPPORTED_SOURCE_FORMAT",
            "multi_file_or_json_source_requires_project_extraction",
        )
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        return _empty_result("INVALID_CONFIGURATION", "slither_timeout_invalid")

    executable = shutil.which(slither_executable)
    if not executable:
        return _empty_result("TOOL_UNAVAILABLE", "slither_executable_not_found")

    try:
        with tempfile.TemporaryDirectory(prefix="aegisforge-slither-") as temp_dir:
            source_path = Path(temp_dir) / "Contract.sol"
            source_path.write_text(source_code, encoding="utf-8")
            try:
                completed = subprocess.run(
                    [executable, str(source_path), "--json", "-"],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return _empty_result("TIMEOUT", "slither_execution_timed_out")
            except FileNotFoundError:
                return _empty_result("TOOL_UNAVAILABLE", "slither_executable_not_found")
            except OSError as exc:
                return _empty_result(
                    "EXECUTION_FAILED",
                    f"slither_execution_failed:{type(exc).__name__}",
                )

        if completed.stdout and len(completed.stdout.encode("utf-8")) > MAX_REPORT_BYTES:
            return _empty_result("REPORT_TOO_LARGE", "slither_report_exceeds_size_limit")

        parsed = parse_slither_json(completed.stdout or "")
        if parsed["status"] != "ANALYZED":
            compiler_error = "solc" in (completed.stderr or "").lower()
            if compiler_error:
                parsed = _empty_result("COMPILER_UNAVAILABLE", "solidity_compiler_unavailable")
            else:
                parsed = _empty_result(
                    "EXECUTION_FAILED",
                    "slither_did_not_return_valid_json",
                )

        parsed["tool"] = "slither"
        parsed["tool_exit_code"] = completed.returncode
        stderr = (completed.stderr or "").strip()
        if stderr:
            parsed["stderr_excerpt"] = stderr[:2000]
        return parsed
    except Exception as exc:
        return _empty_result(
            "EXECUTION_FAILED",
            f"slither_execution_failed:{type(exc).__name__}",
        )
