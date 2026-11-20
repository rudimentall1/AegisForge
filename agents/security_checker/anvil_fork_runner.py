"""Offline Anvil fork smoke test using only a synthetic local source chain.

This runner proves that Anvil can fork an exact local block and that Foundry
can execute a Solidity assertion against the fork. It is not a real-chain
fork, vulnerability confirmation, or production Gateway deployment.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import tempfile
from pathlib import Path

from agents.security_checker.fork_engine import (
    ForkSnapshotError,
    build_fork_snapshot,
    validate_fork_execution_anchor,
)
from agents.security_checker.foundry_runner import (
    MAX_OUTPUT_BYTES,
    MAX_TIMEOUT_SECONDS,
    _probe_solc_binary,
    _resolve_solc_binary,
    _summarize_foundry_output,
)
from shared.sandbox import SandboxError, SandboxLimits, run_in_container


_SYNTHETIC_CONTRACT = """pragma solidity 0.8.20;
contract SyntheticTarget {
    uint256 public value;
    constructor(uint256 initialValue) { value = initialValue; }
}
"""

_FORK_TEST = """pragma solidity 0.8.20;
interface Vm {
    function envAddress(string calldata name) external returns (address);
    function envUint(string calldata name) external returns (uint256);
}
contract ForkSmokeTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function testPinnedForkState() public {
        address target = vm.envAddress("TARGET_ADDRESS");
        uint256 expectedBlock = vm.envUint("EXPECTED_BLOCK");
        require(block.number == expectedBlock, "fork block mismatch");
        (bool ok, bytes memory data) = target.staticcall(abi.encodeWithSignature("value()"));
        require(ok, "target call failed");
        require(abi.decode(data, (uint256)) == 42, "fork state mismatch");
    }
}
"""

# This well-known Anvil development key is used only inside a networkless,
# disposable test container against a synthetic local chain. Never use it
# with a public network or real assets.
_SYNTHETIC_ANVIL_KEY = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

_CONTAINER_SCRIPT = r"""
set -eu
UPSTREAM=http://127.0.0.1:8545
FORK=http://127.0.0.1:8546
ANVIL_UPSTREAM_PID=
ANVIL_FORK_PID=
cleanup() {
  if [ -n "$ANVIL_FORK_PID" ]; then kill "$ANVIL_FORK_PID" 2>/dev/null || true; fi
  if [ -n "$ANVIL_UPSTREAM_PID" ]; then kill "$ANVIL_UPSTREAM_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM
anvil --host 127.0.0.1 --port 8545 --chain-id 31337 --silent >/tmp/aegis-upstream.log 2>&1 &
ANVIL_UPSTREAM_PID=$!
ready=0
i=0
while [ "$i" -lt 60 ]; do
  if cast chain-id --rpc-url "$UPSTREAM" >/dev/null 2>&1; then ready=1; break; fi
  i=$((i + 1))
  sleep 0.25
done
[ "$ready" -eq 1 ] || { cat /tmp/aegis-upstream.log; exit 21; }
forge create src/SyntheticTarget.sol:SyntheticTarget \
  --root /work --use /work/.aegisforge/solc \
  --rpc-url "$UPSTREAM" \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast --constructor-args 42 >/tmp/aegis-deploy.txt 2>/tmp/aegis-deploy.err || {
    cat /tmp/aegis-deploy.err; exit 22;
  }
TARGET_ADDRESS="$(sed -n 's/^Deployed to: //p' /tmp/aegis-deploy.txt | tail -n 1)"
BLOCK_NUMBER="$(cast block-number --rpc-url "$UPSTREAM")"
[ -n "$TARGET_ADDRESS" ] && [ -n "$BLOCK_NUMBER" ] || { cat /tmp/aegis-deploy.txt; exit 23; }
UPSTREAM_HASH="$(cast block "$BLOCK_NUMBER" --rpc-url "$UPSTREAM" --json | grep -o '"hash"[[:space:]]*:[[:space:]]*"0x[0-9a-fA-F]*"' | head -n 1 | cut -d '"' -f 4)"
[ -n "$UPSTREAM_HASH" ] || exit 24
anvil --host 127.0.0.1 --port 8546 --chain-id 31338 \
  --fork-url "$UPSTREAM" --fork-block-number "$BLOCK_NUMBER" --silent \
  >/tmp/aegis-fork.log 2>&1 &
ANVIL_FORK_PID=$!
ready=0
i=0
while [ "$i" -lt 60 ]; do
  if cast chain-id --rpc-url "$FORK" >/dev/null 2>&1; then ready=1; break; fi
  i=$((i + 1))
  sleep 0.25
done
[ "$ready" -eq 1 ] || { cat /tmp/aegis-fork.log; exit 25; }
FORK_HASH="$(cast block "$BLOCK_NUMBER" --rpc-url "$FORK" --json | grep -o '"hash"[[:space:]]*:[[:space:]]*"0x[0-9a-fA-F]*"' | head -n 1 | cut -d '"' -f 4)"
[ -n "$FORK_HASH" ] && [ "$UPSTREAM_HASH" = "$FORK_HASH" ] || {
  echo "fork block hash mismatch: upstream=$UPSTREAM_HASH fork=$FORK_HASH"; exit 26;
}
TARGET_ADDRESS="$TARGET_ADDRESS" EXPECTED_BLOCK="$BLOCK_NUMBER" \
forge test --root /work --offline --use /work/.aegisforge/solc \
  --fork-url "$FORK" --match-path test/ForkSmoke.t.sol --json \
  --out /tmp/aegisforge-out --cache-path /tmp/aegisforge-cache \
  >/tmp/aegis-forge.json 2>/tmp/aegis-forge.err || {
    cat /tmp/aegis-forge.err; cat /tmp/aegis-forge.json; exit 27;
  }
grep -q '"status"[[:space:]]*:[[:space:]]*"Success"' /tmp/aegis-forge.json || {
  cat /tmp/aegis-forge.json; exit 28;
}
if grep -q '"status"[[:space:]]*:[[:space:]]*"Failure"\|"status"[[:space:]]*:[[:space:]]*"Skipped"' /tmp/aegis-forge.json; then
  cat /tmp/aegis-forge.json; exit 29;
fi
RUNTIME_BYTECODE="$(cast code "$TARGET_ADDRESS" --rpc-url "$UPSTREAM")"
[ -n "$RUNTIME_BYTECODE" ] || exit 30
printf 'AEGISFORGE_RESULT={"target_address":"%s","block_number":%s,"block_hash":"%s","runtime_bytecode":"%s","forge_output":{"suite":{"test_results":{"testPinnedForkState()":{"status":"Success"}}}}}\n' \
  "$TARGET_ADDRESS" "$BLOCK_NUMBER" "$UPSTREAM_HASH"
"""


def _result(status: str, error: str | None = None) -> dict:
    result = {
        "schema": "aegisforge.anvil_fork_execution.v1",
        "status": status,
        "dynamic_verified": False,
        "confirmed": False,
        "validation_scope": "synthetic_local_anvil_fork_smoke_test",
        "network_access": False,
        "host_filesystem_access": False,
        "project_mount_read_only": True,
        "transactions_sent": False,
        "synthetic_only": True,
    }
    if error:
        result["error"] = error
    return result


def run_synthetic_anvil_fork_test(
    *,
    compiler_version: str,
    image: str | None = None,
    timeout_seconds: int = 180,
) -> dict:
    """Fork a disposable local Anvil chain at a pinned block and run Forge tests."""
    configured_image = (
        image if image is not None
        else os.getenv("AEGISFORGE_FOUNDRY_IMAGE", "").strip()
    )
    if not configured_image:
        return _result("NOT_CONFIGURED", "foundry_container_image_not_configured")
    if not re.fullmatch(
        r"ghcr\.io/foundry-rs/foundry@sha256:[0-9a-f]{64}",
        configured_image,
    ):
        return _result("INVALID_CONFIGURATION", "official_foundry_image_digest_required")
    if (
        not isinstance(compiler_version, str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", compiler_version)
    ):
        return _result("INVALID_INPUT", "compiler_version_invalid")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        return _result("INVALID_INPUT", "timeout_invalid")
    if platform.system() != "Linux":
        return _result("COMPILER_UNAVAILABLE", "linux_compiler_artifact_required")

    compiler_path = _resolve_solc_binary(compiler_version)
    if compiler_path is None:
        return _result("COMPILER_UNAVAILABLE", "required_solc_binary_not_installed")
    if _probe_solc_binary(compiler_path, compiler_version) != "OK":
        return _result("COMPILER_UNAVAILABLE", "required_solc_binary_probe_failed")
    try:
        compiler_bytes = compiler_path.read_bytes()
    except OSError:
        return _result("COMPILER_UNAVAILABLE", "required_solc_binary_unreadable")

    try:
        with tempfile.TemporaryDirectory(prefix="aegisforge-anvil-fork-") as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "test").mkdir()
            compiler_dir = root / ".aegisforge"
            compiler_dir.mkdir()
            compiler_copy = compiler_dir / "solc"
            compiler_copy.write_bytes(compiler_bytes)
            compiler_copy.chmod(0o555)
            (root / "src" / "SyntheticTarget.sol").write_text(
                _SYNTHETIC_CONTRACT, encoding="utf-8"
            )
            (root / "test" / "ForkSmoke.t.sol").write_text(
                _FORK_TEST, encoding="utf-8"
            )
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\ntest = "test"\n'
                'out = "/tmp/aegisforge-out"\ncache_path = "/tmp/aegisforge-cache"\n'
                'libs = []\nffi = false\nfs_permissions = []\nauto_detect_solc = false\n'
                f'solc_version = "{compiler_version}"\n',
                encoding="utf-8",
            )
            root.chmod(0o755)
            observation = run_in_container(
                ["-c", _CONTAINER_SCRIPT],
                SandboxLimits(
                    timeout_seconds=timeout_seconds,
                    memory_mb=3072,
                    cpu_cores=2,
                    max_output_bytes=MAX_OUTPUT_BYTES,
                    network="none",
                ),
                root,
                image=configured_image,
                entrypoint="/bin/sh",
            )
    except SandboxError as exc:
        reason = str(exc)
        if reason == "execution_timeout":
            return _result("TIMEOUT", reason)
        if reason in {"docker_not_available", "executable_not_found"}:
            return _result("RUNNER_UNAVAILABLE", reason)
        if reason == "container_image_must_be_digest_pinned":
            return _result("INVALID_CONFIGURATION", reason)
        return _result("EXECUTION_FAILED", reason)
    except OSError:
        return _result("EXECUTION_FAILED", "temporary_project_io_failed")

    if observation.stdout_truncated or observation.stderr_truncated:
        return _result("OUTPUT_TRUNCATED", "container_output_truncated")
    marker = next(
        (
            line[len("AEGISFORGE_RESULT="):]
            for line in reversed(observation.stdout.splitlines())
            if line.startswith("AEGISFORGE_RESULT=")
        ),
        None,
    )
    if observation.exit_code != 0 or marker is None:
        result = _result("EXECUTION_FAILED", "synthetic_anvil_fork_execution_failed")
        result.update({
            "exit_code": observation.exit_code,
            "stdout_excerpt": observation.stdout[:8192],
            "stderr_excerpt": observation.stderr[:8192],
            "stdout_sha256": observation.stdout_sha256,
            "stderr_sha256": observation.stderr_sha256,
        })
        return result
    try:
        payload = json.loads(marker)
        forge_output = payload["forge_output"]
        counts = _summarize_foundry_output(json.dumps(forge_output))
        block_number = payload["block_number"]
        block_hash = payload["block_hash"]
        target_address = payload["target_address"]
        runtime_bytecode = payload["runtime_bytecode"]
        if (
            not isinstance(block_number, int)
            or isinstance(block_number, bool)
            or block_number < 0
            or not isinstance(block_hash, str)
            or not re.fullmatch(r"0x[0-9a-fA-F]{64}", block_hash)
            or not isinstance(target_address, str)
            or not re.fullmatch(r"0x[0-9a-fA-F]{40}", target_address)
            or not isinstance(runtime_bytecode, str)
            or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", runtime_bytecode)
        ):
            raise ValueError("fork_anchor_invalid")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _result("INVALID_OUTPUT", "synthetic_anvil_fork_result_invalid")

    if not counts["valid"] or counts["total"] == 0:
        status = "INVALID_OUTPUT" if not counts["valid"] else "NO_TESTS"
    elif counts["failed"] > 0 or observation.exit_code != 0:
        status = "EXECUTED_FAIL"
    elif counts["skipped"] > 0:
        status = "PARTIAL_EXECUTION" if counts["passed"] else "SKIPPED"
    elif counts["passed"] == 0:
        status = "NO_TESTS"
    else:
        status = "EXECUTED_PASS"

    try:
        snapshot = build_fork_snapshot(
            chain_id=31337,
            block_number=block_number,
            block_hash=block_hash,
            contract_address=target_address,
            runtime_bytecode=runtime_bytecode,
        )
        execution_binding = validate_fork_execution_anchor(
            snapshot,
            {
                "source_chain_id": 31337,
                "fork_chain_id": 31338,
                "block_number": block_number,
                "block_hash": block_hash,
                "contract_address": target_address,
                "runtime_bytecode_sha256": snapshot["runtime_bytecode_sha256"],
            },
        )
    except ForkSnapshotError:
        return _result("INVALID_OUTPUT", "synthetic_fork_snapshot_binding_invalid")

    result = _result(status)
    result.update({
        "exit_code": observation.exit_code,
        "duration_seconds": observation.duration_seconds,
        "container_image": configured_image,
        "container_image_provenance_verified": False,
        "container_isolation": observation.isolation,
        "compiler_version": compiler_version,
        "compiler_binary_sha256": __import__("hashlib").sha256(compiler_bytes).hexdigest(),
        "compiler_binary_provenance_verified": False,
        "fork_snapshot": snapshot,
        "fork_execution_binding": execution_binding,
        "fork_anchor": {
            "block_number": block_number,
            "block_hash": block_hash.lower(),
            "target_address": target_address.lower(),
            "source_chain_id": 31337,
            "fork_chain_id": 31338,
            "block_hash_match_verified": True,
        },
        "test_counts": {
            "total": counts["total"],
            "passed": counts["passed"],
            "failed": counts["failed"],
            "skipped": counts["skipped"],
        },
        "test_passed": status == "EXECUTED_PASS",
        "stdout_sha256": observation.stdout_sha256,
        "stderr_sha256": observation.stderr_sha256,
        "required_next_step": "integrate_read_only_gateway_and_pinned_external_rpc_policy",
    })
    return result
