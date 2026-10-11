from __future__ import annotations

import hashlib

from shared.task import Task


class LabRunner:
    """Runs a fixed toy entropy exercise; never executes downloaded source."""

    name = "lab_runner"
    TOY_SEED_BITS = 12
    TOY_TARGET_SEED = 0xA57

    @staticmethod
    def _fingerprint(seed: int) -> str:
        return hashlib.sha256(f"aegisforge-synthetic-seed-only:{seed}".encode("ascii")).hexdigest()

    @classmethod
    def run_synthetic_entropy_demo(cls) -> dict:
        candidate_space = 1 << cls.TOY_SEED_BITS
        target = cls._fingerprint(cls.TOY_TARGET_SEED)
        recovered = None
        attempts = 0
        for candidate in range(candidate_space):
            attempts += 1
            if cls._fingerprint(candidate) == target:
                recovered = candidate
                break
        return {
            "experiment_id": "synthetic-entropy-demo-v1",
            "model": "toy_sha256_fingerprint_over_small_synthetic_seed_space",
            "purpose": "Illustrate the consequences of a deliberately small seed space.",
            "seed_bits": cls.TOY_SEED_BITS,
            "candidate_space": candidate_space,
            "attempts": attempts,
            "synthetic_seed_recovered": recovered == cls.TOY_TARGET_SEED,
            "synthetic_test_only": True,
            "uses_real_private_keys": False,
            "uses_real_wallet_addresses": False,
            "public_wallets_touched": 0,
            "historical_implementation_reproduced": False,
            "result_interpretation": "Toy result only. It does not say anything about a real EVM address or historical generator.",
            "required_next_step": "Pin and reproduce the exact historical implementation with synthetic test vectors before claiming historical reproduction.",
        }

    def run(self, task: Task) -> Task:
        task.status = "running_synthetic_lab"
        result = dict(task.result or {})
        result.update({
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "lab_experiments": [self.run_synthetic_entropy_demo()],
            "lab_summary": {
                "experiments_run": 1,
                "historical_implementation_reproduced": False,
                "real_private_keys_used": False,
                "live_addresses_examined": 0,
                "claim_status": "ILLUSTRATIVE_ONLY",
            },
        })
        task.result = result
        task.status = "lab_completed"
        return task
