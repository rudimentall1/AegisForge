import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from shared.reproduction_contract import REPRODUCTION_CONTRACT_VERSION
from shared.reproduction_runner import ReproductionRunnerError, run_reproduction_contract


def make_contract(output_bytes=b"repro-ok\n"):
    return {
        "schema_version": REPRODUCTION_CONTRACT_VERSION,
        "contract_id": "runner-contract-001",
        "case_id": "runner-case-001",
        "hypothesis_id": "runner-hypothesis-001",
        "target": {
            "repository": "owner/repository",
            "commit_sha": "a" * 40,
            "scope_reference": "https://example.com/security-scope",
            "source_path": "src/target.py",
        },
        "toolchain": {
            "runtime": "python",
            "version": "3.10.12",
            "image_ref": "python:3.10-slim@sha256:" + "b" * 64,
            "image_digest": "sha256:" + "b" * 64,
        },
        "command": ["python", "-m", "pytest", "tests/test_target.py", "-q"],
        "working_directory": ".",
        "environment": {"PYTHONHASHSEED": "0", "LC_ALL": "C.UTF-8"},
        "network_access": "disabled",
        "limits": {
            "timeout_seconds": 10,
            "cpu_cores": 1,
            "memory_mb": 256,
            "max_processes": 16,
            "max_output_bytes": 1024 * 1024,
        },
        "expected_exit_code": 0,
        "expected_outputs": [
            {
                "path": "results/summary.json",
                "sha256": hashlib.sha256(output_bytes).hexdigest(),
            },
        ],
    }


def make_workspace(tmp_path):
    root = tmp_path / "bundle"
    (root / ".git").mkdir(parents=True)
    (root / "src").mkdir(parents=True)
    (root / "src" / "target.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_target.py").write_text("def test_ok(): assert True\n", encoding="utf-8")
    return root


def fake_docker(monkeypatch, *, output_bytes=b"repro-ok\n", exit_code=0, timeout=False):
    calls = []
    observed = {"env_file": None, "docker_env": None, "run_args": None}
    monkeypatch.setattr("shared.reproduction_runner.shutil.which", lambda _binary: "/usr/bin/docker")

    def run(args, **kwargs):
        calls.append((list(args), kwargs))
        operation = args[1]
        if operation == "run":
            observed["run_args"] = list(args)
            observed["docker_env"] = dict(kwargs["env"])
            env_file = Path(args[args.index("--env-file") + 1])
            observed["env_file"] = env_file.read_text(encoding="utf-8")
            return subprocess.CompletedProcess(args, 0, stdout="container-id\n", stderr="")
        if operation == "wait":
            if timeout:
                raise subprocess.TimeoutExpired(args, kwargs["timeout"])
            return subprocess.CompletedProcess(args, 0, stdout=f"{exit_code}\n", stderr="")
        if operation == "stop":
            return subprocess.CompletedProcess(args, 0, stdout="container-id\n", stderr="")
        if operation == "cp":
            output_root = Path(args[-1])
            (output_root / "results").mkdir(parents=True, exist_ok=True)
            (output_root / "results" / "summary.json").write_bytes(output_bytes)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if operation == "rm":
            return subprocess.CompletedProcess(args, 0, stdout="container-id\n", stderr="")
        raise AssertionError(f"unexpected docker operation: {operation}")

    monkeypatch.setattr("shared.reproduction_runner.subprocess.run", run)
    return calls, observed


def test_runner_uses_network_disabled_bounded_container_and_verifies_outputs(tmp_path, monkeypatch):
    root = make_workspace(tmp_path)
    output = tmp_path / "output"
    contract = make_contract()
    os.environ["AegisForge_HOST_SECRET_TEST_SENTINEL"] = "must-not-inherit"
    try:
        calls, observed = fake_docker(monkeypatch)
        result = run_reproduction_contract(contract, root, output)
    finally:
        os.environ.pop("AegisForge_HOST_SECRET_TEST_SENTINEL", None)

    assert result["status"] == "SUCCEEDED"
    assert result["output_validation"]["status"] == "PASS"
    assert result["container_cleanup"] == "REMOVED"
    assert result["finding_verdict"] == "UNCHANGED"
    assert (output / "results" / "summary.json").read_bytes() == b"repro-ok\n"
    args = observed["run_args"]
    assert "--network=none" in args
    assert "--pull=never" in args
    assert "--read-only" in args
    assert "--cap-drop=ALL" in args
    assert "--pids-limit" in args
    assert "--memory" in args
    assert "--cpus" in args
    assert "--log-driver=none" in args
    assert "AegisForge_HOST_SECRET_TEST_SENTINEL" not in observed["docker_env"]
    assert "AegisForge_HOST_SECRET_TEST_SENTINEL" not in observed["env_file"]
    assert "PYTHONHASHSEED=0" in observed["env_file"]
    docker_calls = [call for call in calls if Path(call[0][0]).name == "docker"]
    assert [call[0][1] for call in docker_calls] == ["run", "wait", "cp", "rm"]


def test_runner_fails_when_output_digest_does_not_match(tmp_path, monkeypatch):
    root = make_workspace(tmp_path)
    calls, _ = fake_docker(monkeypatch, output_bytes=b"tampered")

    result = run_reproduction_contract(make_contract(), root, tmp_path / "output")

    assert result["status"] == "FAILED"
    assert result["reason"] == "output_digest_mismatch:results/summary.json"
    assert calls[-1][0][1] == "rm"


def test_runner_fails_when_exit_code_differs_from_contract(tmp_path, monkeypatch):
    root = make_workspace(tmp_path)
    fake_docker(monkeypatch, exit_code=7)

    result = run_reproduction_contract(make_contract(), root, tmp_path / "output")

    assert result["status"] == "FAILED"
    assert result["reason"] == "unexpected_exit_code"


def test_runner_timeout_stops_copies_and_removes_container(tmp_path, monkeypatch):
    root = make_workspace(tmp_path)
    calls, _ = fake_docker(monkeypatch, timeout=True)

    result = run_reproduction_contract(make_contract(), root, tmp_path / "output")

    assert result["status"] == "TIMED_OUT"
    assert result["reason"] == "reproduction_timeout"
    docker_calls = [call for call in calls if Path(call[0][0]).name == "docker"]
    assert [call[0][1] for call in docker_calls] == ["run", "wait", "stop", "cp", "rm"]


def test_runner_returns_not_run_when_docker_is_unavailable(tmp_path, monkeypatch):
    root = make_workspace(tmp_path)
    fake_docker(monkeypatch)
    monkeypatch.setattr(
        "shared.reproduction_runner.shutil.which",
        lambda binary: "/usr/bin/git" if binary == "git" else None,
    )

    result = run_reproduction_contract(make_contract(), root, tmp_path / "output")

    assert result["status"] == "NOT_RUN"
    assert result["reason"] == "docker_binary_not_available"
    assert not (tmp_path / "output").exists()


def test_runner_rejects_symlinks_in_workspace(tmp_path, monkeypatch):
    root = make_workspace(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (root / "src" / "escape").symlink_to(outside)

    with pytest.raises(ReproductionRunnerError, match="workspace_symlink_rejected"):
        run_reproduction_contract(make_contract(), root, tmp_path / "output")


def test_runner_rejects_output_directory_inside_workspace(tmp_path, monkeypatch):
    root = make_workspace(tmp_path)
    fake_docker(monkeypatch)

    with pytest.raises(ReproductionRunnerError, match="output_directory_must_be_disjoint"):
        run_reproduction_contract(make_contract(), root, root / "outputs")



def test_runner_rejects_checkout_at_wrong_commit(tmp_path, monkeypatch):
    root = make_workspace(tmp_path)
    fake_docker(monkeypatch, revision="c" * 40)

    with pytest.raises(ReproductionRunnerError, match="target_git_revision_mismatch"):
        run_reproduction_contract(make_contract(), root, tmp_path / "output")
