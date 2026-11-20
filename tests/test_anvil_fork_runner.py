import json
import platform

import pytest

from agents.security_checker.anvil_fork_runner import run_synthetic_anvil_fork_test
from shared.sandbox import SandboxResult


IMAGE = "ghcr.io/foundry-rs/foundry@sha256:" + ("c" * 64)


@pytest.fixture
def compiler(monkeypatch, tmp_path):
    import agents.security_checker.anvil_fork_runner as runner

    path = tmp_path / "solc"
    path.write_bytes(b"synthetic-solc")
    path.chmod(0o555)
    monkeypatch.setattr(runner, "_resolve_solc_binary", lambda version: path)
    monkeypatch.setattr(runner, "_probe_solc_binary", lambda path, version: "OK")
    return path


def test_synthetic_anvil_fork_runner_requires_digest_pinned_image(monkeypatch):
    monkeypatch.delenv("AEGISFORGE_FOUNDRY_IMAGE", raising=False)

    result = run_synthetic_anvil_fork_test(
        compiler_version="0.8.20",
        image=None,
    )

    assert result["status"] == "NOT_CONFIGURED"
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False


def test_synthetic_anvil_fork_runner_rejects_invalid_timeout():
    result = run_synthetic_anvil_fork_test(
        compiler_version="0.8.20",
        image=IMAGE,
        timeout_seconds=0,
    )

    assert result["status"] == "INVALID_INPUT"
    assert result["error"] == "timeout_invalid"


def test_synthetic_anvil_fork_runner_executes_inside_networkless_container(
    monkeypatch, compiler
):
    import agents.security_checker.anvil_fork_runner as runner

    observed = {}

    def fake_run_in_container(command, limits, source_root, *, image, entrypoint):
        observed["command"] = command
        observed["limits"] = limits
        observed["image"] = image
        observed["entrypoint"] = entrypoint
        observed["files"] = {
            path.relative_to(source_root).as_posix(): path.read_text(encoding="utf-8")
            for path in source_root.rglob("*")
            if path.is_file() and path.name != "solc"
        }
        return SandboxResult(
            exit_code=0,
            stdout="AEGISFORGE_RESULT=" + json.dumps({
                "target_address": "0x" + "1" * 40,
                "block_number": 7,
                "block_hash": "0x" + "a" * 64,
                "runtime_bytecode": "0x6001600055",
                "forge_output": {
                    "test/ForkSmoke.t.sol:ForkSmokeTest": {
                        "test_results": {
                            "testPinnedForkState()": {"status": "Success"}
                        }
                    }
                },
            }),
            stderr="",
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            stdout_truncated=False,
            stderr_truncated=False,
            duration_seconds=1.0,
            isolation="container",
        )

    monkeypatch.setattr(runner, "run_in_container", fake_run_in_container)
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")

    result = run_synthetic_anvil_fork_test(
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "EXECUTED_PASS"
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False
    assert result["validation_scope"] == "synthetic_local_anvil_fork_smoke_test"
    assert result["network_access"] is False
    assert result["test_counts"] == {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
    }
    assert result["fork_anchor"]["block_number"] == 7
    assert result["fork_anchor"]["block_hash"] == "0x" + "a" * 64
    assert result["fork_snapshot"]["runtime_bytecode_sha256"]
    assert result["fork_execution_binding"]["snapshot_bound"] is True
    assert result["fork_execution_binding"]["source_chain_id"] == 31337
    assert result["fork_execution_binding"]["fork_chain_id"] == 31338
    assert observed["image"] == IMAGE
    assert observed["entrypoint"] == "/bin/sh"
    assert observed["limits"].network == "none"
    assert observed["command"][0] == "-c"
    script = observed["command"][1]
    assert "anvil --host 127.0.0.1 --port 8545" in script
    assert '--fork-url "$UPSTREAM"' in script
    assert "--fork-block-number" in script
    assert "forge test" in script
    assert "python3" not in script
    assert "--private-key" in script
    assert "src/SyntheticTarget.sol" in observed["files"]
    assert "test/ForkSmoke.t.sol" in observed["files"]
    assert "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" in script


def test_synthetic_anvil_fork_runner_requires_exact_compiler_and_linux(
    monkeypatch, compiler
):
    import agents.security_checker.anvil_fork_runner as runner

    monkeypatch.setattr(runner.platform, "system", lambda: "Windows")
    result = run_synthetic_anvil_fork_test(
        compiler_version="latest",
        image=IMAGE,
    )

    assert result["status"] == "INVALID_INPUT"
    assert result["error"] == "compiler_version_invalid"
