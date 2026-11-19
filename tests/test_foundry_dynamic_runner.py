import hashlib

import pytest

from agents.security_checker.foundry_runner import run_foundry_test
from shared.sandbox import SandboxError, SandboxResult


IMAGE = "ghcr.io/foundry-rs/foundry@sha256:" + ("b" * 64)
SOURCES = {
    "Vault.sol": "pragma solidity ^0.8.20; contract Vault {}",
}
TEST_SOURCE = """pragma solidity ^0.8.20;
import {Vault} from "../src/Vault.sol";
contract AegisForgeValidationTest {
    function testSyntheticVaultDeploys() public {
        Vault vault = new Vault();
        require(address(vault) != address(0), "deployment failed");
    }
}
"""


def sandbox_result(exit_code=0, stdout='{"ok":true}', stderr=""):
    return SandboxResult(
        exit_code=exit_code,
        stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),
        stdout_truncated=False,
        stderr_truncated=False,
        duration_seconds=0.25,
        isolation="container",
        stdout=stdout,
        stderr=stderr,
    )


def test_foundry_runner_is_not_configured_without_digest_pinned_image(monkeypatch):
    monkeypatch.delenv("AEGISFORGE_FOUNDRY_IMAGE", raising=False)

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=None,
    )

    assert result["status"] == "NOT_CONFIGURED"
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False


@pytest.mark.parametrize("version", ["latest", "v0.8.20", "0.8", "../0.8.20", ""])
def test_foundry_runner_rejects_non_exact_compiler_version(version):
    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version=version,
        image=IMAGE,
    )

    assert result["status"] == "INVALID_INPUT"
    assert result["error"] == "compiler_version_invalid"


def test_foundry_runner_rejects_source_path_traversal():
    result = run_foundry_test(
        {"../outside.sol": "contract Outside {}"},
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "INVALID_INPUT"
    assert result["error"] == "source_path_invalid"


def test_foundry_runner_executes_only_generated_project_in_container(monkeypatch):
    import agents.security_checker.foundry_runner as runner

    observed = {}

    def fake_run_in_container(command, limits, source_root, *, image, entrypoint):
        observed["command"] = command
        observed["limits"] = limits
        observed["image"] = image
        observed["entrypoint"] = entrypoint
        observed["root_mode"] = source_root.stat().st_mode & 0o777
        observed["source_mode"] = (source_root / "src" / "Vault.sol").stat().st_mode & 0o777
        observed["files"] = {
            path.relative_to(source_root).as_posix(): path.read_text(encoding="utf-8")
            for path in source_root.rglob("*")
            if path.is_file()
        }
        return sandbox_result()

    monkeypatch.setattr(runner, "run_in_container", fake_run_in_container)

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "EXECUTED_PASS"
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False
    assert observed["image"] == IMAGE
    assert observed["entrypoint"] == "forge"
    assert observed["root_mode"] == 0o755
    assert observed["source_mode"] & 0o444 == 0o444
    assert observed["command"][:4] == ["test", "--root", "/work", "--offline"]
    assert "--offline" in observed["command"]
    assert "--match-path" in observed["command"]
    assert "--json" in observed["command"]
    assert observed["files"]["src/Vault.sol"] == SOURCES["Vault.sol"]
    assert observed["files"]["test/AegisForgeValidation.t.sol"] == TEST_SOURCE
    assert "ffi = false" in observed["files"]["foundry.toml"]
    assert "fs_permissions = []" in observed["files"]["foundry.toml"]
    assert result["test_harness_sha256"] == hashlib.sha256(
        TEST_SOURCE.encode()
    ).hexdigest()


def test_foundry_runner_never_marks_a_passing_test_as_confirmed(monkeypatch):
    import agents.security_checker.foundry_runner as runner

    monkeypatch.setattr(
        runner,
        "run_in_container",
        lambda *args, **kwargs: sandbox_result(exit_code=0),
    )

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "EXECUTED_PASS"
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False
    assert result["validation_scope"] == "local_isolated_harness_execution"


def test_foundry_runner_records_failed_test_without_confirmation(monkeypatch):
    import agents.security_checker.foundry_runner as runner

    monkeypatch.setattr(
        runner,
        "run_in_container",
        lambda *args, **kwargs: sandbox_result(exit_code=1, stderr="test failed"),
    )

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "EXECUTED_FAIL"
    assert result["exit_code"] == 1
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False


def test_foundry_runner_maps_timeout_to_bounded_failure(monkeypatch):
    import agents.security_checker.foundry_runner as runner

    def timeout(*args, **kwargs):
        raise SandboxError("execution_timeout")

    monkeypatch.setattr(runner, "run_in_container", timeout)

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "TIMEOUT"
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False


def test_foundry_runner_rejects_non_solidity_source_and_oversized_input():
    non_solidity = run_foundry_test(
        {"foundry.toml": "ffi = true"},
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )
    oversized = run_foundry_test(
        {"Huge.sol": "x" * (4 * 1024 * 1024 + 1)},
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert non_solidity["status"] == "INVALID_INPUT"
    assert oversized["status"] == "INPUT_TOO_LARGE"
