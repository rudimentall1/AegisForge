#!/usr/bin/env python3
"""Acquire one explicitly authorized EVM contract and enqueue source-only research.

No broad chain crawling, transaction submission, RPC writes, or target execution.
"""
from __future__ import annotations

import argparse
import json
import os
from types import SimpleNamespace
from uuid import uuid4

from scam_intelligence.contract_intake import BlockscoutContractIntake
from shared.onchain_target_store import OnchainTargetStore
from shared.onchain_research_case import OnchainResearchCase
from shared.queue import TaskQueue


NETWORKS = {
    1: "https://eth.blockscout.com/api/v2",
    8453: "https://base.blockscout.com/api/v2",
    42161: "https://arbitrum.blockscout.com/api/v2",
}


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain-id", type=int, required=True, choices=sorted(NETWORKS))
    parser.add_argument("--address", required=True, help="One explicitly in-scope contract address")
    parser.add_argument("--rpc-url", default=os.environ.get("AEGISFORGE_RPC_URL"), required=not bool(os.environ.get("AEGISFORGE_RPC_URL")))
    parser.add_argument("--scope-url", required=True, help="Program scope URL")
    parser.add_argument("--scope-digest", required=True, help="SHA-256 of the reviewed scope snapshot")
    parser.add_argument("--scope-reviewed-on", required=True, help="Review date YYYY-MM-DD")
    parser.add_argument("--authorization-reference", required=True, help="URL identifying the applicable authorization")
    parser.add_argument("--hypothesis", required=True)
    parser.add_argument("--expected-invariant", required=True)
    parser.add_argument("--falsification-criteria", required=True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    intake = BlockscoutContractIntake(
        NETWORKS[args.chain_id],
        chain_id=args.chain_id,
    )
    source = intake.fetch_verified_source(args.address)
    attestation = intake.attest_deployment(args.rpc_url, args.address)
    candidate = SimpleNamespace(chain_id=args.chain_id, address=args.address)
    queue = TaskQueue()
    try:
        target_store = OnchainTargetStore(queue.db)
        target_id = target_store.put_intake_item({
            "candidate": candidate,
            "source": source,
            "deployment_attestation": attestation,
        })
        case = OnchainResearchCase(
            case_id="onchain-" + uuid4().hex,
            target_id=target_id,
            scope_url=args.scope_url,
            scope_digest=args.scope_digest.lower(),
            scope_reviewed_on=args.scope_reviewed_on,
            authorization_reference=args.authorization_reference,
            hypothesis=args.hypothesis,
            expected_invariant=args.expected_invariant,
            falsification_criteria=args.falsification_criteria,
        )
        queue.register_onchain_research_case(case)
        task_id = queue.add(
            description=(
                f"Perform bounded, non-executing Solidity source triage for "
                f"{args.chain_id}:{args.address}. Use the registered on-chain case."
            ),
            role="source_researcher",
            onchain_case_id=case.case_id,
        )
        print(json.dumps({
            "status": "queued",
            "chain_id": args.chain_id,
            "address": args.address.lower(),
            "target_id": target_id,
            "case_id": case.case_id,
            "task_id": task_id,
            "source_sha256": source.source_sha256,
            "standard_json_input_sha256": source.standard_json_input_sha256,
            "runtime_code_sha256": attestation["runtime_code_sha256"],
            "execution": "not_started",
        }, sort_keys=True, indent=2))
        return 0
    finally:
        queue.db.close()


if __name__ == "__main__":
    raise SystemExit(main())
