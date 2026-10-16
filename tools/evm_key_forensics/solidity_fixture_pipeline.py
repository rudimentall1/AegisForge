#!/usr/bin/env python3
"""Run the bounded Solidity source fixture through deterministic acceptance stages.

No compiler, EVM, RPC, live network, deployed bytecode, or wallet material is used.
The final review remains INCONCLUSIVE because this fixture does not test runtime
or deployed-contract behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from tools.evm_key_forensics.solidity_source_pattern import (
    PINNED_COMMIT,
    PINNED_GIT_BLOB_SHA1,
    PINNED_PATH,
    PINNED_REPOSITORY,
    inspect_source,
)

SCHEMA_VERSION = "aegisforge-solidity-fixture-pipeline-v1"
ALLOWED_FINAL_STATES = {"REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE", "OUT_OF_SCOPE"}


def synthetic_access_control_controls() -> dict:
    """Exercise a toy authorization predicate, not Solidity or an EVM."""
    synthetic_owner = "synthetic-owner"
    synthetic_other = "synthetic-non-owner"

    def may_call(owner: str | None, caller: str) -> bool:
        return owner is not None and caller == owner

    controls = {
        "owner_allowed": may_call(synthetic_owner, synthetic_owner),
        "non_owner_rejected": not may_call(synthetic_owner, synthetic_other),
        "zero_owner_rejected": not may_call(None, synthetic_owner),
    }
    return {
        "stage": "synthetic_experiment",
        "status": "PASSED" if all(controls.values()) else "FAILED",
        "controls": controls,
        "model": "pure-python-owner-equality-predicate",
        "uses_real_accounts": False,
        "solidity_compiled": False,
        "evm_executed": False,
        "rpc_used": False,
        "wallet_material_used": False,
        "interpretation": "Only the toy predicate was exercised; Solidity runtime behavior was not tested.",
    }


def run_pipeline(source_path: str | Path) -> dict:
    path = Path(source_path)
    try:
        raw = path.read_bytes()
        source = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "final_status": "INCONCLUSIVE",
            "error": f"source_read_failed:{type(exc).__name__}",
            "review": {
                "status": "INCONCLUSIVE",
                "human_review_required": True,
                "automatic_confirmation": False,
            },
        }

    source_observation = inspect_source(source)
    analysis = {
        "stage": "analysis",
        "hypothesis_id": "SOL-OWNABLE-ACCESS-CONTROL-001",
        "status": (
            "ANALYZED"
            if source_observation["conclusion"] == "SOURCE_PATTERN_MATCHED"
            else "INCONCLUSIVE"
        ),
        "hypothesis": "The pinned source routes owner-only authorization through onlyOwner/_checkOwner and _msgSender.",
        "evidence_fields": [
            "owner_modifier_present",
            "modifier_calls_owner_check",
            "owner_compared_with_msg_sender",
            "tx_origin_absent_from_code",
            "zero_address_guard_present",
        ],
        "claims_confirmed": 0,
        "finding_created": False,
    }

    synthetic = synthetic_access_control_controls()

    # Independent consistency checks: recompute both hashes from the exact bytes
    # read by this pipeline and compare stage outputs rather than trusting labels.
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    actual_git_blob = hashlib.sha1(
        f"blob {len(raw)}\0".encode("ascii") + raw
    ).hexdigest()
    validation_checks = {
        "pinned_repository_matches": source_observation.get("repository") == PINNED_REPOSITORY,
        "pinned_commit_matches": source_observation.get("source_commit") == PINNED_COMMIT,
        "pinned_path_matches": source_observation.get("source_path") == PINNED_PATH,
        "git_blob_recomputed": actual_git_blob == PINNED_GIT_BLOB_SHA1
        and actual_git_blob == source_observation.get("source_git_blob_sha1"),
        "sha256_recomputed": actual_sha256 == source_observation.get("source_sha256"),
        "source_observation_passed": source_observation.get("conclusion") == "SOURCE_PATTERN_MATCHED",
        "synthetic_controls_passed": synthetic.get("status") == "PASSED",
        "no_execution_claim": source_observation.get("source_executed") is False
        and synthetic.get("evm_executed") is False,
    }
    validation = {
        "stage": "validator",
        "status": "VALIDATED" if all(validation_checks.values()) else "INCONCLUSIVE",
        "checks": validation_checks,
        "passed_check_count": sum(validation_checks.values()),
        "total_check_count": len(validation_checks),
    }

    # A source-stage fixture and toy predicate cannot establish deployed runtime
    # behavior. Keep the final research conclusion inconclusive by design.
    final_status = "INCONCLUSIVE"
    if final_status not in ALLOWED_FINAL_STATES:
        final_status = "INCONCLUSIVE"
    review = {
        "stage": "human_review",
        "status": final_status,
        "reason": "source_and_synthetic_controls_do_not_establish_runtime_or_deployed_bytecode_behavior",
        "human_review_required": True,
        "automatic_confirmation": False,
        "finding_created": False,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "case": {
            "repository": PINNED_REPOSITORY,
            "commit": PINNED_COMMIT,
            "path": PINNED_PATH,
            "expected_git_blob_sha1": PINNED_GIT_BLOB_SHA1,
            "execution_mode": "local",
        },
        "stages": {
            "source_research": {
                "status": source_observation["conclusion"],
                "observation": source_observation,
            },
            "analysis": analysis,
            "synthetic_experiment": synthetic,
            "validation": validation,
            "review": review,
        },
        "final_status": final_status,
        "evidence": {
            "source_sha256": actual_sha256,
            "source_git_blob_sha1": actual_git_blob,
            "artifact_sha256": hashlib.sha256(
                json.dumps(
                    {
                        "source": source_observation,
                        "analysis": analysis,
                        "synthetic": synthetic,
                        "validation": validation,
                        "review": review,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        },
        "limitations": [
            "No compiler or EVM was used.",
            "The synthetic experiment is a toy predicate, not Solidity execution.",
            "The fixture is upstream source, not evidence of deployed bytecode identity.",
            "No vulnerability or exploitability conclusion is made.",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "source",
        nargs="?",
        default=str(Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "solidity" / "Ownable.sol"),
        help="local pinned source fixture; never executed",
    )
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    result = run_pipeline(args.source)
    print(json.dumps(result, sort_keys=True, indent=2 if args.pretty else None))
    return 0 if result.get("final_status") == "INCONCLUSIVE" and result.get("stages", {}).get("validation", {}).get("status") == "VALIDATED" else 2


if __name__ == "__main__":
    sys.exit(main())
