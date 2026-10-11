from __future__ import annotations

import hashlib
import json
import subprocess
import sys

from shared.task import Task


class LabRunner:
    """Runs a fixed toy entropy exercise; never executes downloaded source."""

    name = "lab_runner"
    TOY_SEED_BITS = 12
    TOY_TARGET_SEED = 0xA57
    EXECUTION_TIMEOUT_SECONDS = 5

    # Fixed, repository-owned program. This intentionally does not load or execute
    # any source fetched from the internet or any opportunity dossier.
    _SYNTHETIC_EXPERIMENT_SCRIPT = r"""
import hashlib
import json

seed_bits = 12
target_seed = 0xA57

def fingerprint(seed):
    return hashlib.sha256(
        f"aegisforge-synthetic-seed-only:{seed}".encode("ascii")
    ).hexdigest()

target = fingerprint(target_seed)
candidate_space = 1 << seed_bits
recovered = None
attempts = 0
for candidate in range(candidate_space):
    attempts += 1
    if fingerprint(candidate) == target:
        recovered = candidate
        break

print(json.dumps({
    "schema_version": 1,
    "experiment_id": "synthetic-entropy-demo-v1",
    "seed_bits": seed_bits,
    "candidate_space": candidate_space,
    "attempts": attempts,
    "synthetic_seed_recovered": recovered == target_seed,
    "synthetic_test_only": True,
}, sort_keys=True))
"""

    @staticmethod
    def _sha256(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    @classmethod
    def run_synthetic_entropy_demo(cls) -> dict:
        command = [sys.executable, "-c", cls._SYNTHETIC_EXPERIMENT_SCRIPT]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=cls.EXECUTION_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
            stdout_bytes = completed.stdout.encode("utf-8")
            stderr_bytes = completed.stderr.encode("utf-8")
            record = {
                "schema_version": 1,
                "record_kind": "local_subprocess_observation",
                "executor": "python-subprocess",
                "command": command,
                "command_sha256": cls._sha256(
                    json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ),
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stdout_sha256": cls._sha256(stdout_bytes),
                "stderr_sha256": cls._sha256(stderr_bytes),
                "timed_out": False,
            }
            try:
                payload = json.loads(completed.stdout)
            except (TypeError, ValueError):
                payload = None
            passed = (
                completed.returncode == 0
                and isinstance(payload, dict)
                and payload.get("schema_version") == 1
                and payload.get("experiment_id") == "synthetic-entropy-demo-v1"
                and payload.get("synthetic_seed_recovered") is True
                and payload.get("synthetic_test_only") is True
            )
            record["test_passed"] = passed
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            if isinstance(stdout, str):
                stdout = stdout.encode("utf-8")
            if isinstance(stderr, str):
                stderr = stderr.encode("utf-8")
            record = {
                "schema_version": 1,
                "record_kind": "local_subprocess_observation",
                "executor": "python-subprocess",
                "command": command,
                "command_sha256": cls._sha256(
                    json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ),
                "exit_code": None,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stdout_sha256": cls._sha256(stdout),
                "stderr_sha256": cls._sha256(stderr),
                "timed_out": True,
                "test_passed": False,
            }
            payload = None

        payload = payload if isinstance(payload, dict) else {}
        return {
            "experiment_id": "synthetic-entropy-demo-v1",
            "model": "toy_sha256_fingerprint_over_small_synthetic_seed_space",
            "purpose": "Illustrate the consequences of a deliberately small seed space.",
            "seed_bits": payload.get("seed_bits", cls.TOY_SEED_BITS),
            "candidate_space": payload.get("candidate_space", 1 << cls.TOY_SEED_BITS),
            "attempts": payload.get("attempts", 0),
            "synthetic_seed_recovered": payload.get("synthetic_seed_recovered") is True,
            "synthetic_test_only": True,
            "uses_real_private_keys": False,
            "uses_real_wallet_addresses": False,
            "public_wallets_touched": 0,
            "historical_implementation_reproduced": False,
            "execution_record": record,
            "result_interpretation": (
                "Toy result only. The local subprocess record documents this synthetic run; "
                "it does not prove a historical generator was reproduced or provide a signed attestation."
            ),
            "required_next_step": (
                "Build a separately constrained historical-source experiment with synthetic test vectors "
                "and independent verification before claiming historical reproduction."
            ),
        }

    def run(self, task: Task) -> Task:
        task.status = "running_synthetic_lab"
        result = dict(task.result or {})
        experiment = self.run_synthetic_entropy_demo()
        result.update({
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "lab_experiments": [experiment],
            "lab_summary": {
                "experiments_run": 1,
                "historical_implementation_reproduced": False,
                "real_private_keys_used": False,
                "live_addresses_examined": 0,
                "claim_status": "ILLUSTRATIVE_ONLY",
                "synthetic_subprocess_passed": experiment["execution_record"]["test_passed"],
            },
        })
        task.result = result
        task.status = "lab_completed"
        return task
