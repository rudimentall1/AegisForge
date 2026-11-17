#!/usr/bin/env python3
"""Run the pinned Uniswap V2 Factory source case through Round dispatch offline."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.crypto_analyst.agent import CryptoAnalyst
from agents.lab_runner.agent import LabRunner
from agents.source_researcher.agent import SourceResearcher
from agents.validator.agent import Validator
from shared.research_case import ExecutionMode, ResearchCase, RoundSpec
from shared.task import Task
from shared.techniques.registry import TechniqueRegistry
from tools.evm_key_forensics.uniswap_v2_factory_source_pattern import (
    PINNED_COMMIT,
    PINNED_GIT_BLOB_SHA1,
    PINNED_PATH,
    PINNED_REPOSITORY,
    CONTRACT_ADDRESS,
    CHAIN_ID,
    EXPLORER_URL,
)

SCHEMA_VERSION = "aegisforge-uniswap-v2-factory-round-run-v1"


class NoNetworkGitHub:
    """Fail closed if this offline case unexpectedly attempts GitHub access."""
    BASE_URL = "https://api.github.com"

    def get_json(self, *args, **kwargs):
        raise AssertionError("offline Uniswap acceptance runner attempted a GitHub request")


def make_case() -> ResearchCase:
    root = Path(__file__).resolve().parents[2]
    manifest_path = root / "tests" / "fixtures" / "solidity" / "UniswapV2Factory.provenance.json"
    manifest_raw = manifest_path.read_bytes()
    return ResearchCase(
        case_id="uniswap-v2-factory-mainnet-acceptance-001",
        target_repository=PINNED_REPOSITORY,
        target_commit=PINNED_COMMIT,
        scope_url=EXPLORER_URL,
        scope_digest=hashlib.sha256(manifest_raw).hexdigest(),
        scope_reviewed_on="2026-10-16",
        hypothesis=(
            "The pinned Uniswap V2 Factory source requires feeToSetter authorization "
            "before changing feeTo or feeToSetter."
        ),
        attacker_capability="A synthetic unprivileged caller attempts privileged state changes.",
        expected_invariant="Only the synthetic feeToSetter may change feeTo or rotate feeToSetter.",
        falsification_criteria=(
            "The source pin or provenance manifest mismatches, a required source check is absent, "
            "or an unauthorized synthetic caller passes the predicate."
        ),
        execution_mode=ExecutionMode.LOCAL,
        allowed_techniques=("source_pattern",),
        rounds=(
            RoundSpec(
                round_id="uniswap-v2-factory-fee-setter-source-pattern",
                technique="source_pattern",
                hypothesis="Inspect the pinned factory source for feeToSetter authorization.",
                expected_evidence_atoms=(
                    "pinned source Git blob",
                    "feeToSetter authorization before feeTo mutation",
                    "feeToSetter authorization before setter rotation",
                ),
                falsification_criteria=(
                    "Pinned source/provenance fails or either authorization pattern is absent."
                ),
                disclosure_deadline_days=30,
            ),
        ),
    )


def run_case(case: ResearchCase | None = None) -> dict:
    run_started_at = datetime.now(timezone.utc).isoformat()
    case = case or make_case()
    task = Task(
        task_id="uniswap-v2-factory-round-acceptance",
        description="Run the pinned Uniswap V2 Factory source-pattern acceptance case offline.",
        payload={
            "research_case_id": case.case_id,
            "research_case": case,
            "round_spec": case.rounds[0],
            "technique": case.rounds[0].technique,
        },
    )
    registry = TechniqueRegistry()
    dispatches = []
    for role, agent in (
        ("source_researcher", SourceResearcher(github=NoNetworkGitHub())),
        ("crypto_analyst", CryptoAnalyst()),
        ("lab_runner", LabRunner()),
    ):
        routed = registry.dispatch(case.rounds[0].technique, role, task, delegate=agent)
        if not isinstance(routed, Task):
            raise RuntimeError(
                f"technique_dispatch_failed:{role}:"
                f"{routed.get('status', 'invalid_result') if isinstance(routed, dict) else type(routed).__name__}"
            )
        task = routed
        result = task.result if isinstance(task.result, dict) else {}
        dispatches.append({
            "role": role,
            "status": task.status,
            "technique": result.get("technique"),
            "dispatch": result.get("technique_dispatch"),
        })

    validated = Validator().run(task)
    if not isinstance(validated.result, dict):
        raise RuntimeError("validator_result_missing")
    result = validated.result
    run_completed_at = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case.case_id,
        "run_started_at": run_started_at,
        "run_completed_at": run_completed_at,
        "target": {
            "repository": PINNED_REPOSITORY,
            "commit": PINNED_COMMIT,
            "path": PINNED_PATH,
            "expected_git_blob_sha1": PINNED_GIT_BLOB_SHA1,
            "chain_id": CHAIN_ID,
            "contract_address": CONTRACT_ADDRESS,
            "explorer_url": EXPLORER_URL,
            "explorer_reported_status": "Source Code Verified Exact Match",
            "explorer_checked_at_runtime": False,
            "execution_mode": "local",
        },
        "round": {
            "round_id": case.rounds[0].round_id,
            "technique": case.rounds[0].technique,
            "dispatches": dispatches,
        },
        "agent_pipeline_status": validated.status,
        "result": result,
        "safety": {
            "network_access": False,
            "rpc_used": False,
            "evm_executed": False,
            "transactions_sent": False,
            "wallet_material_used": False,
            "private_keys_loaded": False,
            "automatic_confirmation": False,
            "finding_created": False,
            "human_review_required": True,
        },
        "acceptance": {
            "all_round_roles_dispatched": all(
                item["dispatch"] is not None and item["dispatch"]["status"] == "DISPATCHED"
                for item in dispatches
            ),
            "validation_passed": (
                result.get("validation", {}).get("status") == "VALIDATED"
                and all(result.get("validation", {}).get("checks", {}).values())
            ),
            "final_status": result.get("final_status", "INCONCLUSIVE"),
        },
        "limitations": [
            "Explorer exact-match status is recorded from the pinned provenance manifest; no runtime explorer request is made.",
            "The runner does not independently recompile the target or query deployed bytecode.",
            "The synthetic experiment is a pure-Python predicate, not Solidity/EVM execution.",
            "A source pattern match is not a vulnerability finding or a safety certification.",
        ],
    }


def _write_new(path: str, value: dict) -> None:
    target = Path(path)
    if target.is_symlink():
        raise ValueError("output_path_must_not_be_symlink")
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="write a new JSON file; never overwrite existing paths")
    args = parser.parse_args(argv)
    try:
        result = run_case()
        if args.output:
            _write_new(args.output, result)
            print(json.dumps({
                "status": "ACCEPTANCE_RUN_COMPLETED",
                "output": args.output,
                "final_status": result["acceptance"]["final_status"],
                "validation_passed": result["acceptance"]["validation_passed"],
            }, sort_keys=True))
        else:
            print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if (
            result["acceptance"]["all_round_roles_dispatched"]
            and result["acceptance"]["validation_passed"]
            and result["acceptance"]["final_status"] == "INCONCLUSIVE"
            and result["safety"]["automatic_confirmation"] is False
        ) else 2
    except (OSError, ValueError, RuntimeError, AssertionError) as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)[:300]}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
