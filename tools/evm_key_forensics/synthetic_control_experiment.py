#!/usr/bin/env python3
"""Bounded positive/negative controls for a deliberately tiny synthetic state space.

This is a control-harness check, not a Profanity reproduction. It never derives
keys, addresses, or wallet material and has no network access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

SCHEMA_VERSION = 1
EXPERIMENT_ID = "evm-forensics-synthetic-controls-v1"
SEED_BITS = 12
TARGET_SEED = 0xA57
MAX_CANDIDATES = 1 << SEED_BITS


def fingerprint(candidate: int) -> str:
    return hashlib.sha256(
        f"aegisforge-synthetic-control-only:{candidate}".encode("ascii")
    ).hexdigest()


def run_controls() -> dict:
    target = fingerprint(TARGET_SEED)

    # Positive control: the declared candidate space contains the known target.
    positive_match = None
    positive_attempts = 0
    for candidate in range(MAX_CANDIDATES):
        positive_attempts += 1
        if fingerprint(candidate) == target:
            positive_match = candidate
            break

    # Negative control: same predicate, but the bounded range intentionally
    # excludes the known target. A successful match here indicates a harness bug.
    negative_match = None
    negative_attempts = 0
    for candidate in range(TARGET_SEED):
        negative_attempts += 1
        if fingerprint(candidate) == target:
            negative_match = candidate
            break

    positive_passed = positive_match == TARGET_SEED
    negative_passed = negative_match is None
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": EXPERIMENT_ID,
        "purpose": "validate_positive_and_negative_controls_for_a_toy_finite_state_space",
        "model": "sha256_fingerprint_of_synthetic_integer",
        "seed_bits": SEED_BITS,
        "candidate_space": MAX_CANDIDATES,
        "controls": {
            "positive": {
                "control_id": "known-target-included-v1",
                "expected": "target_found",
                "observed": "target_found" if positive_match is not None else "not_found",
                "matched_candidate": positive_match,
                "attempts": positive_attempts,
                "passed": positive_passed,
            },
            "negative": {
                "control_id": "known-target-excluded-v1",
                "expected": "target_not_found",
                "observed": "target_found" if negative_match is not None else "not_found",
                "matched_candidate": negative_match,
                "attempts": negative_attempts,
                "passed": negative_passed,
            },
        },
        "overall_passed": positive_passed and negative_passed,
        "historical_profanity_code_executed": False,
        "historical_vulnerability_reproduced": False,
        "private_keys_derived": False,
        "public_keys_or_addresses_derived": False,
        "wallet_material_used": False,
        "network_access_used": False,
        "interpretation": (
            "A passing result validates only this synthetic control harness; "
            "it provides no evidence of historical Profanity exploitability."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    args = parser.parse_args(argv)
    result = run_controls()
    print(json.dumps(result, sort_keys=True, indent=2 if args.pretty else None))
    return 0 if result["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
