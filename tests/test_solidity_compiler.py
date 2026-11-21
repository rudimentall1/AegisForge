import hashlib
import json

from shared.sandbox import SandboxResult
from shared.solidity_compiler import compile_standard_json


_IMAGE = "ghcr.io/foundry-rs/foundry@sha256:" + ("a" * 64)


def _input():
    return json.dumps({
        "language": "Solidity",
        "sources": {"src/Vault.sol": {"content": "contract Vault {}"}},
        "settings": {
            "outputSelection": {"*": {"*": ["evm.deployedBytecode"]}},
        },
    })


def test_compiler_runs_exact_standard_json_input_in_networkless_container(monkeypatch, tmp_path):
    import shared.solidity_compiler as compiler

    binary = tmp_path / "solc"
    binary.write_bytes(b"trusted test compiler fixture")
    observed = {}

    monkeypatch.setattr(compiler, "resolve_solc_binary", lambda version: binary)
    monkeypatch.setattr(compiler, "_read_compiler_version", lambda path: "0.8.24+commit.e11b9ed9")

    output = {"contracts": {"src/Vault.sol": {"Vault": {"evm": {"deployedBytecode": {"object": "60016000"}}}}}}

    def fake_run(command, limits, source_root, **kwargs):
        observed["command"] = command
        observed["limits"] = limits
        observed["stdin"] = kwargs["stdin_path"].read_text(encoding="utf-8")
        observed["entrypoint"] = kwargs["entrypoint"]
        return SandboxResult(
            exit_code=0,
            stdout_sha256=hashlib.sha256(json.dumps(output).encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stdout_truncated=False,
            stderr_truncated=False,
            duration_seconds=0.1,
            isolation="container",
            stdout=json.dumps(output),
            stderr="",
        )

    monkeypatch.setattr(compiler, "run_in_container", fake_run)
    raw = _input()
    result = compile_standard_json(raw, "v0.8.24+commit.e11b9ed9", image=_IMAGE)

    assert result.status == "COMPILED"
    assert result.compiler_output == output
    assert result.input_sha256 == hashlib.sha256(raw.encode()).hexdigest()
    assert result.compiler_binary_sha256 == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert result.compiler_version == "0.8.24+commit.e11b9ed9"
    assert observed["stdin"] == raw
    assert observed["command"] == ["--standard-json"]
    assert observed["entrypoint"] == "/work/.aegisforge/solc"
    assert observed["limits"].network == "none"


def test_compiler_rejects_missing_deployed_bytecode_output_before_execution(monkeypatch):
    import shared.solidity_compiler as compiler

    called = []
    monkeypatch.setattr(compiler, "run_in_container", lambda *args, **kwargs: called.append(True))
    payload = json.loads(_input())
    payload["settings"]["outputSelection"] = {"*": {"*": ["abi"]}}
    result = compile_standard_json(json.dumps(payload), "0.8.24", image=_IMAGE)
    assert result.status == "INCOMPLETE"
    assert result.reason == "deployed_bytecode_output_not_requested"
    assert called == []


def test_compiler_rejects_wrong_solc_commit(monkeypatch, tmp_path):
    import shared.solidity_compiler as compiler

    binary = tmp_path / "solc"
    binary.write_bytes(b"compiler fixture")
    monkeypatch.setattr(compiler, "resolve_solc_binary", lambda version: binary)
    monkeypatch.setattr(compiler, "_read_compiler_version", lambda path: "0.8.24+commit.deadbeef")
    monkeypatch.setattr(compiler, "run_in_container", lambda *args, **kwargs: None)
    result = compile_standard_json(_input(), "0.8.24+commit.e11b9ed9", image=_IMAGE)
    assert result.status == "COMPILER_VERSION_MISMATCH"
    assert result.reason == "required_solc_binary_version_mismatch"


def test_compiler_fails_closed_when_compiler_binary_is_missing(monkeypatch):
    import shared.solidity_compiler as compiler

    monkeypatch.setattr(compiler, "resolve_solc_binary", lambda version: None)
    result = compile_standard_json(_input(), "0.8.24", image=_IMAGE)
    assert result.status == "COMPILER_UNAVAILABLE"
    assert result.reason == "required_solc_binary_not_installed"


def test_compiler_rejects_unpinned_container_image():
    result = compile_standard_json(_input(), "0.8.24", image="ghcr.io/foundry-rs/foundry:latest")
    assert result.status == "RUNNER_NOT_CONFIGURED"
    assert result.reason == "digest_pinned_foundry_image_required"


def test_compiler_reports_truncated_output(monkeypatch, tmp_path):
    import shared.solidity_compiler as compiler

    binary = tmp_path / "solc"
    binary.write_bytes(b"compiler fixture")
    monkeypatch.setattr(compiler, "resolve_solc_binary", lambda version: binary)
    monkeypatch.setattr(compiler, "_read_compiler_version", lambda path: "0.8.24")
    monkeypatch.setattr(
        compiler,
        "run_in_container",
        lambda *args, **kwargs: SandboxResult(
            exit_code=0,
            stdout_sha256="0" * 64,
            stderr_sha256="0" * 64,
            stdout_truncated=True,
            stderr_truncated=False,
            duration_seconds=0.1,
            isolation="container",
            stdout="{}",
            stderr="",
        ),
    )
    result = compile_standard_json(_input(), "0.8.24", image=_IMAGE)
    assert result.status == "OUTPUT_TRUNCATED"
    assert result.reason == "compiler_output_truncated"
