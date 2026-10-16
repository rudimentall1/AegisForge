#!/usr/bin/env python3
"""Run the pinned Solidity source-pattern case through the Round technique registry.

This is an offline acceptance runner, not a deployed-contract security assessment.
It reads only the checked-in OpenZeppelin Ownable source fixture and uses a toy
Python predicate for the synthetic experiment. No HTTP, RPC, EVM, transaction,
wallet, or private-key access is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
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
from tools.evm_key_forensics.solidity_source_pattern import (
    PINNED_COMMIT,
    PINNED_GIT_BLOB_SHA1,
    PINNED_PATH,
    PINNED_REPOSITORY,
)

SCHEMA_VERSION = "aegisforge-solidity-round-run-v1"


class NoNetworkGitHub:
    """Fail the run if source research unexpectedly tries to use the network."""
    BASE_URL = "https://api.github.com"

    def get_json(self, *args, **kwargs):
        raise AssertionError("offline acceptance runner attempted a GitHub request")


def make_case() -> ResearchCase:
    scope_url = f"https://github.com/{PINNED_REPOSITORY}/blob/{PINNED_COMMIT}/{PINNED_PATH}"
    scope_digest = hashlib.sha256(
        f"{scope_url}\n{PINNED_GIT_BLOB_SHA1}\nlocal-source-fixture".encode("utf-8")
    ).hexdigest()
    return ResearchCase(
        case_id="openzeppelin-ownable-round-acceptance-001",
        target_repository=PINNED_REPOSITORY,
        target_commit=PINNED_COMMIT,
        scope_url=scope_url,
        scope_digest=scope_digest,
        scope_reviewed_on="2026-10-16",
        hypothesis=(
            "The pinned Ownable source routes owner-only authorization through "
            "onlyOwner/_checkOwner and _msgSender."
        ),
        attacker_capability="A synthetic non-owner caller attempts a protected operation.",
        expected_invariant="Only the synthetic owner is accepted by the toy predicate.",
        falsification_criteria=(
            "Pinned source identity fails, an expected source invariant is absent, "
            "or the synthetic non-owner control is accepted."
        ),
        execution_mode=ExecutionMode.LOCAL,
        allowed_techniques=("source_pattern",),
        rounds=(
            RoundSpec(
                round_id="ownable-source-pattern",
                technique="source_pattern",
                hypothesis="Inspect the immutable Ownable source for access-control patterns.",
                expected_evidence_atoms=("pinned Git blob", "owner authorization pattern"),
                falsification_criteria=(
                    "The pinned source identity or expected source patterns do not match."
                ),
                disclosure_deadline_days=30,
            ),
        ),
    )


def run_case() -> dict:
    case = make_case()
    task = Task(
        task_id="solidity-round-acceptance",
        description="Run the pinned offline Solidity source-pattern acceptance case.",
        payload={
            "research_case_id": case.case_id,
            "research_case": case,
            "round_spec": case.rounds[0],
            "technique": case.rounds[0].technique,
        },
    )
    registry = TechniqueRegistry()
    stages = []

    dispatches = (
        ("source_researcher", SourceResearcher(github=NoNetworkGitHub())),
        ("crypto_analyst", CryptoAnalyst()),
        ("lab_runner", LabRunner()),
    )
    for role, agent in dispatches:
        result = registry.dispatch(
            case.rounds[0].technique,
            role,
            task,
            delegate=agent,
        )
        if not isinstance(result, Task):
            raise RuntimeError(
                f"technique_dispatch_failed:{role}:"
                f"{result.get('status', 'invalid_result') if isinstance(result, dict) else type(result).__name__}"
            )
        task = result
        stages.append({
            "role": role,
            "status": task.status,
            "technique": task.result.get("technique") if isinstance(task.result, dict) else None,
            "dispatch": (
                task.result.get("technique_dispatch")
                if isinstance(task.result, dict) else None
            ),
        })

    validated = Validator().run(task)
    if not isinstance(validated.result, dict):
        raise RuntimeError("validator_result_missing")
    result = validated.result
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case.case_id,
        "target": {
            "repository": PINNED_REPOSITORY,
            "commit": PINNED_COMMIT,
            "path": PINNED_PATH,
            "expected_git_blob_sha1": PINNED_GIT_BLOB_SHA1,
            "execution_mode": "local",
            "source_kind": "checked_in_public_source_fixture",
            "deployed_contract_identity_verified": False,
        },
        "round": {
            "round_id": case.rounds[0].round_id,
            "technique": case.rounds[0].technique,
            "dispatches": stages,
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
                stage["dispatch"] is not None
                and stage["dispatch"]["status"] == "DISPATCHED"
                for stage in stages
            ),
            "validation_passed": (
                result.get("validation", {}).get("status") == "VALIDATED"
                and all(result.get("validation", {}).get("checks", {}).values())
            ),
            "final_status": result.get("final_status", "INCONCLUSIVE"),
            "deployed_verified_contract_milestone_complete": False,
        },
        "limitations": [
            "This runner exercises a pinned source fixture, not deployed bytecode.",
            "The synthetic experiment is a pure-Python predicate, not Solidity execution.",
            "A validated evidence package does not establish a vulnerability.",
            "A human must review the evidence and choose any attestation verdict.",
        ],
    }


def _write_new(path: str, value: dict) -> None:
    target = Path(path)
    if target.is_symlink():
        raise ValueError("output_path_must_not_be_symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(target), flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
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
    parser.add_argument("--output", help="write a new JSON result file; existing paths are never overwritten")
    args = parser.parse_args(argv)
    try:
        result = run_case()
        serialized = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True)
        if args.output:
            _write_new(args.output, result)
            print(json.dumps({
                "status": "ACCEPTANCE_RUN_COMPLETED",
                "output": args.output,
                "final_status": result["acceptance"]["final_status"],
                "validation_passed": result["acceptance"]["validation_passed"],
                "deployed_verified_contract_milestone_complete": False,
            }, sort_keys=True))
        else:
            print(serialized)
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
