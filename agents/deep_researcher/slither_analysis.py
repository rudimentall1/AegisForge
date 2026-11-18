from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath


MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_SOURCE_FILES = 1000
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 500
MAX_ELEMENTS_PER_FINDING = 50
MAX_DESCRIPTION_CHARS = 16_000
MAX_REMAPPINGS = 100


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


def _source_project(source_code: str) -> dict:
    """Decode flattened or Etherscan standard-JSON verified source."""
    stripped = source_code.strip()
    if not stripped.startswith("{"):
        return {
            "status": "OK",
            "mode": "single_file",
            "files": {"Contract.sol": source_code},
            "remappings": [],
        }

    json_text = stripped
    if json_text.startswith("{{") and json_text.endswith("}}"):
        json_text = json_text[1:-1]
    try:
        payload = json.loads(json_text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"status": "INVALID_SOURCE_PROJECT", "error": "verified_source_json_invalid"}

    if not isinstance(payload, dict):
        return {"status": "INVALID_SOURCE_PROJECT", "error": "verified_source_json_not_object"}
    if payload.get("language", "Solidity") != "Solidity":
        return {"status": "INVALID_SOURCE_PROJECT", "error": "source_project_language_unsupported"}

    sources = payload.get("sources")
    if not isinstance(sources, dict) or not sources:
        return {"status": "UNSUPPORTED_SOURCE_FORMAT", "error": "verified_source_sources_missing"}
    if len(sources) > MAX_SOURCE_FILES:
        return {"status": "INVALID_SOURCE_PROJECT", "error": "source_project_file_count_exceeded"}

    files = {}
    total_bytes = 0
    for name, entry in sources.items():
        if not isinstance(name, str) or not name or "\\" in name:
            return {"status": "INVALID_SOURCE_PROJECT", "error": "source_project_path_invalid"}
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in ("", ".", "..") for part in relative.parts)
            or ":" in relative.parts[0]
            or relative.suffix.lower() != ".sol"
        ):
            return {"status": "INVALID_SOURCE_PROJECT", "error": "source_project_path_invalid"}

        content = entry.get("content") if isinstance(entry, dict) else None
        if not isinstance(content, str):
            return {"status": "INVALID_SOURCE_PROJECT", "error": "source_project_content_missing"}
        encoded = content.encode("utf-8")
        total_bytes += len(encoded)
        if total_bytes > MAX_SOURCE_BYTES:
            return {"status": "SOURCE_TOO_LARGE", "error": "verified_source_exceeds_size_limit"}
        files[relative.as_posix()] = content

    settings = payload.get("settings") or {}
    remappings = settings.get("remappings", []) if isinstance(settings, dict) else []
    if not isinstance(remappings, list) or len(remappings) > MAX_REMAPPINGS:
        return {"status": "INVALID_SOURCE_PROJECT", "error": "source_project_remappings_invalid"}
    clean_remappings = []
    for remapping in remappings:
        if (
            not isinstance(remapping, str)
            or not remapping
            or len(remapping) > 512
            or any(ord(char) < 32 for char in remapping)
            or remapping.startswith("-")
        ):
            return {"status": "INVALID_SOURCE_PROJECT", "error": "source_project_remapping_invalid"}
        clean_remappings.append(remapping)

    return {
        "status": "OK",
        "mode": "multi_file",
        "files": files,
        "remappings": clean_remappings,
    }


def analyze_source(
    source_code: str,
    *,
    slither_executable: str = "slither",
    timeout: int = 90,
) -> dict:
    """Run Slither on flattened or Etherscan standard-JSON verified source.

    Multi-file source is extracted into a bounded temporary project. Paths are
    validated before writing. Detector output remains unverified potential
    evidence; this function never confirms a vulnerability.
    """
    if not isinstance(source_code, str) or not source_code.strip():
        return _empty_result("SOURCE_EMPTY", "verified_source_empty")
    if len(source_code.encode("utf-8")) > MAX_SOURCE_BYTES:
        return _empty_result("SOURCE_TOO_LARGE", "verified_source_exceeds_size_limit")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        return _empty_result("INVALID_CONFIGURATION", "slither_timeout_invalid")

    project = _source_project(source_code)
    if project["status"] != "OK":
        return _empty_result(project["status"], project["error"])

    executable = shutil.which(slither_executable)
    if not executable:
        return _empty_result("TOOL_UNAVAILABLE", "slither_executable_not_found")

    try:
        with tempfile.TemporaryDirectory(prefix="aegisforge-slither-") as temp_dir:
            root = Path(temp_dir).resolve()
            written_paths = []
            for relative_name, content in project["files"].items():
                relative = PurePosixPath(relative_name)
                target = root.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                resolved = target.resolve()
                if root not in resolved.parents:
                    return _empty_result("INVALID_SOURCE_PROJECT", "source_project_path_escape")
                target.write_text(content, encoding="utf-8")
                written_paths.append(target)

            target_arg = str(written_paths[0]) if project["mode"] == "single_file" else str(root)
            command = [executable, target_arg]
            if project["remappings"]:
                command.extend(["--solc-remaps", " ".join(project["remappings"])])
            command.extend(["--json", "-"])

            try:
                completed = subprocess.run(
                    command,
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
            if "solc" in (completed.stderr or "").lower():
                parsed = _empty_result("COMPILER_UNAVAILABLE", "solidity_compiler_unavailable")
            else:
                parsed = _empty_result(
                    "EXECUTION_FAILED",
                    "slither_did_not_return_valid_json",
                )

        parsed["tool"] = "slither"
        parsed["source_mode"] = project["mode"]
        parsed["source_file_count"] = len(project["files"])
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
