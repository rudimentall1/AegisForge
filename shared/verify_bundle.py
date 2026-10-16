"""Independent offline verifier for portable AegisForge evidence bundles.

Level 1 checks artifact bytes against a case-bound manifest.
Level 2 validates case/task/evidence linkage for exported research-case ZIPs.
Level 3 is reported INCONCLUSIVE until a trusted, sandboxed replay adapter is
available; a recorded exit code or receipt is not an experiment rerun.
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

from shared.evidence_ledger import verify_case_artifact_manifest
from shared.research_case_bundle import (
    ResearchCaseBundleError,
    verify_research_case_bundle,
)


class BundleVerificationError(ValueError):
    """A bundle could not be parsed or verified safely."""


def _strict_json(path: Path) -> object:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BundleVerificationError(f"duplicate_json_key:{key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise BundleVerificationError(f"nonstandard_json_constant:{value}")

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except BundleVerificationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BundleVerificationError("bundle_json_unreadable_or_invalid") from exc


def _level(level: int, name: str, status: str, detail: str) -> dict:
    return {"level": level, "name": name, "status": status, "detail": detail}


def verify_bundle(path: str | Path) -> dict:
    """Verify a supported bundle without executing bundle-controlled code.

    Supported inputs:
    - A directory containing manifest.json from the case-artifact manifest API.
    - A ZIP emitted by shared.research_case_bundle.

    Level 3 deliberately remains INCONCLUSIVE. Automatically executing arbitrary
    commands from an evidence bundle would turn verification into code execution.
    """
    bundle_path = Path(path)
    levels = []

    if bundle_path.is_symlink():
        return {
            "valid": False,
            "verification_levels": [
                _level(1, "package_integrity", "FAIL", "bundle_path_must_not_be_symlink")
            ],
            "limitations": ["No bundle contents were opened."],
        }

    if bundle_path.is_dir():
        manifest_path = bundle_path / "manifest.json"
        try:
            manifest = _strict_json(manifest_path)
            result = verify_case_artifact_manifest(bundle_path, manifest)
        except (BundleVerificationError, OSError, ValueError, TypeError) as exc:
            return {
                "valid": False,
                "verification_levels": [
                    _level(1, "package_integrity", "FAIL", str(exc) or "manifest_invalid")
                ],
                "limitations": ["No workflow provenance or experiment replay was established."],
            }
        if result.get("status") != "PASS":
            return {
                "valid": False,
                "verification_levels": [
                    _level(1, "package_integrity", "FAIL", ";".join(result.get("errors", [])))
                ],
                "limitations": ["No workflow provenance or experiment replay was established."],
            }
        levels.append(_level(
            1, "package_integrity", "PASS",
            f"case_id={result['case_id']}; artifacts={result['checked_artifacts']}; "
            f"manifest_sha256={result['manifest_sha256']}",
        ))
        levels.append(_level(
            2, "workflow_provenance", "INCONCLUSIVE",
            "This bundle format does not include a verified workflow attestation.",
        ))
    elif bundle_path.is_file() and zipfile.is_zipfile(bundle_path):
        try:
            result = verify_research_case_bundle(bundle_path)
        except (ResearchCaseBundleError, OSError, ValueError, TypeError) as exc:
            return {
                "valid": False,
                "verification_levels": [
                    _level(1, "package_integrity", "FAIL", str(exc) or "bundle_invalid")
                ],
                "limitations": ["No workflow provenance or experiment replay was established."],
            }
        levels.append(_level(
            1, "package_integrity", "PASS",
            f"bundle_sha256={result['bundle_sha256']}",
        ))
        levels.append(_level(
            2, "case_and_evidence_linkage", "PASS",
            f"case_id={result['case_id']}; tasks={result['task_count']}; "
            f"evidence_observations={result['evidence_observation_count']}",
        ))
    else:
        return {
            "valid": False,
            "verification_levels": [
                _level(1, "package_integrity", "FAIL", "unsupported_bundle_path_or_format")
            ],
            "limitations": ["Supported formats are a manifest directory or research-case ZIP."],
        }

    levels.append(_level(
        3, "experiment_rerun", "INCONCLUSIVE",
        "No trusted sandboxed replay adapter is configured; recorded execution metadata "
        "is not treated as a rerun.",
    ))
    return {
        "valid": all(item["status"] in {"PASS", "SKIP"} for item in levels),
        "verification_levels": levels,
        "limitations": [
            "A matching digest establishes integrity relative to the supplied manifest, not authenticity.",
            "Workflow provenance is not established unless the format-specific level 2 check passes.",
            "Level 3 is not implemented: no bundle-controlled command is executed.",
            "No result here establishes exploitability or authorizes a CONFIRMED finding.",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an AegisForge evidence bundle offline without executing its contents."
    )
    parser.add_argument("path", help="Evidence bundle directory or research-case ZIP")
    args = parser.parse_args(argv)
    result = verify_bundle(args.path)
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
    if any(item["status"] == "FAIL" for item in result["verification_levels"]):
        return 1
    if any(item["status"] == "INCONCLUSIVE" for item in result["verification_levels"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
