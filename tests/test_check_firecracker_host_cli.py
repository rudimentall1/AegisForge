import hashlib
import json
from pathlib import Path

import pytest

from scripts.check_firecracker_host import load_profile, main


def _profile(tmp_path):
    artifacts = {}
    for name, payload, executable in (
        ("firecracker", b"firecracker", True),
        ("jailer", b"jailer", True),
        ("guest_kernel", b"kernel", False),
        ("guest_rootfs", b"rootfs", False),
    ):
        path = tmp_path / name
        path.write_bytes(payload)
        if executable:
            path.chmod(0o755)
        artifacts[name] = {
            "path": str(path),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    return {"version": "1.18.0", "artifacts": artifacts}


def _write_profile(tmp_path, data):
    path = tmp_path / "firecracker-host.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_profile_builds_only_the_four_pinned_artifacts(tmp_path):
    data = _profile(tmp_path)
    profile = load_profile(_write_profile(tmp_path, data))

    assert profile.version == "1.18.0"
    assert profile.firecracker.path == Path(data["artifacts"]["firecracker"]["path"])
    assert profile.jailer.sha256 == data["artifacts"]["jailer"]["sha256"]


@pytest.mark.parametrize("digest", ["<SHA256>", "REPLACE_ME", "a" * 63, ""])
def test_load_profile_rejects_placeholder_or_malformed_digest(tmp_path, digest):
    data = _profile(tmp_path)
    data["artifacts"]["firecracker"]["sha256"] = digest

    with pytest.raises(ValueError):
        load_profile(_write_profile(tmp_path, data))


def test_load_profile_rejects_relative_artifact_paths(tmp_path):
    data = _profile(tmp_path)
    data["artifacts"]["guest_kernel"]["path"] = "artifacts/vmlinux"

    with pytest.raises(ValueError, match="firecracker_artifact_path_invalid"):
        load_profile(_write_profile(tmp_path, data))


def test_load_profile_rejects_unknown_and_missing_keys(tmp_path):
    data = _profile(tmp_path)
    data["unexpected"] = True
    with pytest.raises(ValueError, match="profile_keys_invalid"):
        load_profile(_write_profile(tmp_path, data))

    data = _profile(tmp_path)
    del data["artifacts"]["jailer"]
    with pytest.raises(ValueError, match="artifact_keys_invalid"):
        load_profile(_write_profile(tmp_path, data))


def test_load_profile_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"version":"1.18.0","version":"1.18.0","artifacts":{}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate_json_key"):
        load_profile(path)


def test_main_emits_json_and_zero_only_for_ready_profile(tmp_path, monkeypatch, capsys):
    data = _profile(tmp_path)
    profile_path = _write_profile(tmp_path, data)

    class ReadyReport:
        status = "READY"
        profile_sha256 = "b" * 64
        checks = (("linux_host", True), ("kvm_read_write_access", True))
        failed_checks = ()
        ready = True

    import scripts.check_firecracker_host as cli
    monkeypatch.setattr(cli, "inspect_firecracker_host", lambda *args, **kwargs: ReadyReport())

    assert main(["--profile", str(profile_path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "READY"
    assert output["failed_checks"] == []
    assert output["scope"] == "host_prerequisites_only"


def test_main_returns_nonzero_for_not_ready_host(tmp_path, monkeypatch, capsys):
    data = _profile(tmp_path)
    profile_path = _write_profile(tmp_path, data)

    class NotReadyReport:
        status = "NOT_READY"
        profile_sha256 = "c" * 64
        checks = (("kvm_read_write_access", False),)
        failed_checks = ("kvm_read_write_access",)
        ready = False

    import scripts.check_firecracker_host as cli
    monkeypatch.setattr(cli, "inspect_firecracker_host", lambda *args, **kwargs: NotReadyReport())

    assert main(["--profile", str(profile_path)]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "NOT_READY"
    assert output["failed_checks"] == ["kvm_read_write_access"]


def test_main_reports_invalid_profile_as_json_and_fails_closed(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text('{"version":', encoding="utf-8")

    assert main(["--profile", str(path)]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "INVALID_PROFILE"
    assert output["target_code_executed"] is False
