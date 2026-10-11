from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shared.lab_execution_receipt import build_receipt, receipt_sha256, sign_receipt
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
    "uses_real_private_keys": False,
    "uses_real_wallet_addresses": False,
    "public_wallets_touched": 0,
    "historical_implementation_reproduced": False,
}, sort_keys=True))
"""

    @staticmethod
    def _sha256(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    @classmethod
    def run_synthetic_entropy_demo(cls) -> dict:
        command = [sys.executable, "-c", cls._SYNTHETIC_EXPERIMENT_SCRIPT]
        script_bytes = cls._SYNTHETIC_EXPERIMENT_SCRIPT.encode("utf-8")
        run_id = uuid.uuid4().hex
        payload = None
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
            record = {
                "schema_version": 1,
                "record_kind": "local_subprocess_observation",
                "executor": "python-subprocess",
                "command": command,
                "command_sha256": cls._sha256(
                    json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ),
                "script_source_sha256": cls._sha256(script_bytes),
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stdout_sha256": cls._sha256(stdout_bytes),
                "stderr": completed.stderr,
                "stderr_sha256": cls._sha256(stderr_bytes),
                "timed_out": False,
                "test_passed": passed,
            }
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
                "script_source_sha256": cls._sha256(script_bytes),
                "exit_code": None,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stdout_sha256": cls._sha256(stdout),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "stderr_sha256": cls._sha256(stderr),
                "timed_out": True,
                "test_passed": False,
            }

        payload = payload if isinstance(payload, dict) else {}
        result_payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        receipt = build_receipt(
            run_id=run_id,
            experiment_id="synthetic-entropy-demo-v1",
            inputs={
                "source_kind": "repository_owned_synthetic_demo",
                "source_revision": None,
                "test_vector_id": "synthetic-vector-12bit-v1",
                "argv": command,
                "script_source_sha256": record["script_source_sha256"],
            },
            execution={
                "exit_code": record["exit_code"],
                "timed_out": record["timed_out"],
                "test_passed": record["test_passed"],
                "stdout_sha256": record["stdout_sha256"],
                "stderr_sha256": record["stderr_sha256"],
            },
            artifacts={
                "script_source_sha256": record["script_source_sha256"],
                "result_payload_sha256": cls._sha256(result_payload_bytes),
            },
        )
        receipt_digest = receipt_sha256(receipt)
        receipt_envelope = None
        signing_key_b64 = os.environ.get("AEGISFORGE_LAB_SIGNING_KEY_B64", "").strip()
        signing_key_id = os.environ.get("AEGISFORGE_LAB_SIGNING_KEY_ID", "").strip()
        if signing_key_b64 or signing_key_id:
            # Signing is opt-in. The operator must provision a raw 32-byte Ed25519
            # private key and a stable key ID; no key is generated automatically.
            if not signing_key_b64 or not signing_key_id:
                raise ValueError("lab_signing_key_and_key_id_must_be_configured_together")
            try:
                private_bytes = base64.b64decode(signing_key_b64, validate=True)
                private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
            except (ValueError, TypeError) as exc:
                raise ValueError("invalid_lab_signing_private_key") from exc
            receipt_envelope = sign_receipt(
                receipt, private_key=private_key, key_id=signing_key_id
            )

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
            "execution_receipt": receipt,
            "execution_receipt_sha256": receipt_digest,
            "execution_receipt_envelope": receipt_envelope,
            "execution_receipt_signed": receipt_envelope is not None,
            "execution_receipt_trust": "SIGNATURE_PRESENT_NOT_YET_TRUSTED" if receipt_envelope else "UNSIGNED_INTEGRITY_ONLY",
            "result_interpretation": (
                "Toy result only. The canonical receipt and digest support integrity checks, "
                "not runner authenticity or a claim that historical code was reproduced."
            ),
            "required_next_step": (
                "Validate this receipt in the independent Validator, then build a separately "
                "constrained historical-source experiment with synthetic test vectors."
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
                "receipt_integrity_available": True,
                "receipt_is_signed": experiment["execution_receipt_signed"],
            },
        })
        task.result = result
        task.status = "lab_completed"
        return task
