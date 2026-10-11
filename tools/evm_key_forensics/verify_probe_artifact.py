"""Offline verifier for an exported EVM Key Forensics probe artifact.

This verifies file hashes and metadata consistency only. It does not prove entropy,
runner honesty, historical vulnerability reproduction, or wallet compromise.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact(root: Path) -> dict:
    metadata_path = root / "probe-run-metadata.json"
    output_path = root / "probe-output.json"
    source_path = root / "probe-source.cpp"
    binary_path = root / "probe-binary"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    output = json.loads(output_path.read_text(encoding="utf-8"))

    checks = {
        "schema_version_supported": metadata.get("schema_version") == 1,
        "output_schema_supported": output.get("schema_version") == 1,
        "diagnostic_only_purpose": metadata.get("purpose") == "diagnostic_environment_observation_only",
        "historical_vulnerability_not_claimed": metadata.get("historical_vulnerability_reproduced") is False,
        "entropy_not_claimed": metadata.get("entropy_proven") is False,
        "probe_does_not_claim_historical_execution": output.get("historical_profanity_code_executed") is False,
        "probe_does_not_use_wallet_material": output.get("wallet_material_used") is False,
        "sample_observations_not_entropy_proof": output.get("observations_are_entropy_proof") is False,
        "source_hash_matches": metadata.get("source_sha256") == sha256(source_path),
        "binary_hash_matches": metadata.get("binary_sha256") == sha256(binary_path),
        "output_hash_matches": metadata.get("output_sha256") == sha256(output_path),
        "commit_recorded": isinstance(metadata.get("git_commit"), str) and len(metadata["git_commit"]) == 40,
        "run_id_recorded": isinstance(metadata.get("github_run_id"), str) and metadata["github_run_id"].isdigit(),
    }
    return {
        "schema_version": 1,
        "integrity_verified": all(checks.values()),
        "checks": checks,
        "git_commit": metadata.get("git_commit"),
        "github_run_id": metadata.get("github_run_id"),
        "limitations": [
            "Hashes prove file consistency relative to this manifest, not the truth of observations.",
            "A hash manifest alone does not authenticate who produced the artifact.",
            "This diagnostic is not a reproduction of historical Profanity or a vulnerability.",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify an exported EVM Key Forensics probe artifact offline.")
    parser.add_argument("artifact_dir", help="Directory containing the four exported probe evidence files")
    args = parser.parse_args(argv)
    try:
        result = verify_artifact(Path(args.artifact_dir))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"integrity_verified": False, "error": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["integrity_verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
