import hashlib
import json

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


def forge_output(status="Success"):
    return json.dumps({
        "test/Vault.t.sol:VaultTest": {
            "test_results": {
                "testSyntheticVaultDeploys()": {"status": status}
            }
        }
    })




@pytest.fixture(autouse=True)
def configured_compiler(monkeypatch, tmp_path):
    import agents.security_checker.foundry_runner as runner

    compiler = tmp_path / "solc"
    compiler.write_bytes(b"synthetic-solidity-compiler-binary")
    compiler.chmod(0o555)
    monkeypatch.setattr(runner, "_resolve_solc_binary", lambda version: compiler)
    monkeypatch.setattr(runner, "_probe_solc_binary", lambda path, version: "OK")


def sandbox_result(exit_code=0, stdout=None, stderr=""):
    if stdout is None:
        stdout = forge_output()
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
        observed["compiler_bytes"] = (source_root / ".aegisforge" / "solc").read_bytes()
        observed["compiler_mode"] = (source_root / ".aegisforge" / "solc").stat().st_mode & 0o777
        observed["files"] = {
            path.relative_to(source_root).as_posix(): path.read_text(encoding="utf-8")
            for path in source_root.rglob("*")
            if path.is_file() and path.name != "solc"
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
    assert result["test_statuses"] == {"testSyntheticVaultDeploys": "Success"}
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False
    assert observed["image"] == IMAGE
    assert observed["entrypoint"] == "forge"
    assert observed["root_mode"] == 0o755
    assert observed["source_mode"] & 0o444 == 0o444
    assert observed["compiler_bytes"] == b"synthetic-solidity-compiler-binary"
    assert observed["compiler_mode"] == 0o555
    assert result["compiler_binary_sha256"] == hashlib.sha256(
        b"synthetic-solidity-compiler-binary"
    ).hexdigest()
    assert result["compiler_installed"] is False
    assert result["compiler_selection_mode"] == "explicit_binary_path_no_global_switch"
    assert result["compiler_binary_provenance_verified"] is False
    assert observed["command"][:4] == ["test", "--root", "/work", "--offline"]
    assert observed["command"][observed["command"].index("--use") + 1] == "/work/.aegisforge/solc"
    assert "--offline" in observed["command"]
    assert "--match-path" in observed["command"]
    assert observed["command"][
        observed["command"].index("--match-test") + 1
    ] == "^test.*$"
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
        lambda *args, **kwargs: sandbox_result(
            exit_code=1,
            stdout=forge_output("Failure"),
            stderr="test failed",
        ),
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


@pytest.mark.parametrize(
    ("exit_code", "expected_status"),
    [(125, "RUNNER_UNAVAILABLE"), (126, "TOOL_UNAVAILABLE"), (127, "TOOL_UNAVAILABLE")],
)
def test_foundry_runner_distinguishes_container_or_tool_start_failure(
    monkeypatch, exit_code, expected_status
):
    import agents.security_checker.foundry_runner as runner

    monkeypatch.setattr(
        runner,
        "run_in_container",
        lambda *args, **kwargs: sandbox_result(
            exit_code=exit_code,
            stderr="container or executable start failed",
        ),
    )

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == expected_status
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False
    assert result["test_passed"] is False



@pytest.mark.parametrize(
    ("stdout", "expected_status"),
    [
        ("{}", "NO_TESTS"),
        (forge_output("Skipped"), "SKIPPED"),
        ("not-json", "INVALID_OUTPUT"),
    ],
)
def test_foundry_runner_requires_machine_readable_executed_test_results(
    monkeypatch, stdout, expected_status
):
    import agents.security_checker.foundry_runner as runner

    monkeypatch.setattr(
        runner,
        "run_in_container",
        lambda *args, **kwargs: sandbox_result(stdout=stdout),
    )

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == expected_status
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False
    assert result["test_passed"] is False


def test_foundry_runner_does_not_pass_when_exit_code_disagrees_with_json(monkeypatch):
    import agents.security_checker.foundry_runner as runner

    monkeypatch.setattr(
        runner,
        "run_in_container",
        lambda *args, **kwargs: sandbox_result(exit_code=1, stdout=forge_output("Success")),
    )

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "EXECUTION_FAILED"
    assert result["test_passed"] is False
    assert result["dynamic_verified"] is False


def test_foundry_runner_rejects_malformed_test_status_type(monkeypatch):
    import agents.security_checker.foundry_runner as runner

    malformed = json.dumps({
        "suite": {
            "test_results": {
                "testBadStatus()": {"status": []}
            }
        }
    })
    monkeypatch.setattr(
        runner,
        "run_in_container",
        lambda *args, **kwargs: sandbox_result(stdout=malformed),
    )

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "INVALID_OUTPUT"
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False


def test_foundry_runner_requires_compiler_binary_when_not_installed(monkeypatch):
    import agents.security_checker.foundry_runner as runner

    monkeypatch.setattr(runner, "_resolve_solc_binary", lambda version: None)
    monkeypatch.delenv("AEGISFORGE_AUTO_INSTALL_SOLC", raising=False)

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "COMPILER_UNAVAILABLE"
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False


def test_foundry_runner_installs_compiler_only_with_explicit_opt_in(
    monkeypatch, tmp_path
):
    import agents.security_checker.foundry_runner as runner

    compiler = tmp_path / "installed" / "solc"
    compiler.parent.mkdir()
    compiler.write_bytes(b"installed-solc")
    compiler.chmod(0o555)
    observed = {"install_commands": []}
    monkeypatch.setenv("AEGISFORGE_AUTO_INSTALL_SOLC", "1")
    monkeypatch.setattr(
        runner,
        "_resolve_solc_binary",
        lambda version: None if not observed["install_commands"] else compiler,
    )
    monkeypatch.setattr(runner, "_probe_solc_binary", lambda path, version: "OK")
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/usr/bin/solc-select")

    def fake_subprocess_run(command, **kwargs):
        observed["install_commands"].append(command)
        return runner.subprocess.CompletedProcess(command, 0, stdout="installed", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(
        runner,
        "run_in_container",
        lambda *args, **kwargs: sandbox_result(),
    )

    result = run_foundry_test(
        SOURCES,
        TEST_SOURCE,
        compiler_version="0.8.20",
        image=IMAGE,
    )

    assert result["status"] == "EXECUTED_PASS"
    assert result["compiler_installed"] is True
    assert observed["install_commands"] == [
        ["/usr/bin/solc-select", "install", "0.8.20"]
    ]
