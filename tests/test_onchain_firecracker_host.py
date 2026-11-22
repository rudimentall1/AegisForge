import hashlib
import os
import stat

import pytest

from shared.onchain_firecracker_host import (
    FirecrackerArtifact,
    FirecrackerHostProfile,
    inspect_firecracker_host,
)


def _artifact(path, payload, *, executable=False):
    path.write_bytes(payload)
    if executable:
        path.chmod(0o755)
    return FirecrackerArtifact(
        path=path,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


@pytest.fixture
def host_profile(tmp_path):
    firecracker = _artifact(tmp_path / "firecracker", b"firecracker-binary", executable=True)
    jailer = _artifact(tmp_path / "jailer", b"jailer-binary", executable=True)
    kernel = _artifact(tmp_path / "vmlinux", b"guest-kernel")
    rootfs = _artifact(tmp_path / "rootfs.ext4", b"guest-rootfs")
    return FirecrackerHostProfile(
        version="1.18.0",
        firecracker=firecracker,
        jailer=jailer,
        guest_kernel=kernel,
        guest_rootfs=rootfs,
    )


def _host(monkeypatch, tmp_path):
    import shared.onchain_firecracker_host as host

    cgroup = tmp_path / "cgroup"
    cgroup.mkdir()
    (cgroup / "cgroup.controllers").write_text("cpuset cpu io memory pids", encoding="ascii")
    kvm = tmp_path / "kvm"
    kvm.write_bytes(b"")
    monkeypatch.setattr(host.platform, "system", lambda: "Linux")
    monkeypatch.setattr(host.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(host.os, "geteuid", lambda: 0)
    monkeypatch.setattr(host.os, "access", lambda path, mode: True)
    monkeypatch.setattr(host, "_is_character_device", lambda path: path == kvm)
    return kvm, cgroup


def test_host_probe_accepts_fully_pinned_firecracker_host(host_profile, monkeypatch, tmp_path):
    kvm, cgroup = _host(monkeypatch, tmp_path)

    report = inspect_firecracker_host(
        host_profile,
        kvm_device=kvm,
        cgroup_root=cgroup,
    )

    assert report.ready is True
    assert report.status == "READY"
    assert report.failed_checks == ()


def test_host_probe_fails_closed_without_kvm_access(host_profile, monkeypatch, tmp_path):
    kvm, cgroup = _host(monkeypatch, tmp_path)
    import shared.onchain_firecracker_host as host
    monkeypatch.setattr(host.os, "access", lambda path, mode: False)

    report = inspect_firecracker_host(host_profile, kvm_device=kvm, cgroup_root=cgroup)

    assert report.ready is False
    assert "kvm_read_write_access" in report.failed_checks


def test_host_probe_rejects_non_linux(host_profile, monkeypatch, tmp_path):
    kvm, cgroup = _host(monkeypatch, tmp_path)
    import shared.onchain_firecracker_host as host
    monkeypatch.setattr(host.platform, "system", lambda: "Darwin")

    report = inspect_firecracker_host(host_profile, kvm_device=kvm, cgroup_root=cgroup)

    assert report.ready is False
    assert "linux_host" in report.failed_checks


def test_host_probe_requires_root_for_jailer_prerequisites(host_profile, monkeypatch, tmp_path):
    kvm, cgroup = _host(monkeypatch, tmp_path)
    import shared.onchain_firecracker_host as host
    monkeypatch.setattr(host.os, "geteuid", lambda: 1000)

    report = inspect_firecracker_host(host_profile, kvm_device=kvm, cgroup_root=cgroup)

    assert report.ready is False
    assert "jailer_privileged_setup" in report.failed_checks


def test_host_probe_requires_cgroup_v2_cpu_memory_and_pids(host_profile, monkeypatch, tmp_path):
    kvm, cgroup = _host(monkeypatch, tmp_path)
    (cgroup / "cgroup.controllers").write_text("cpu io", encoding="ascii")

    report = inspect_firecracker_host(host_profile, kvm_device=kvm, cgroup_root=cgroup)

    assert report.ready is False
    assert "cgroup_v2_controllers" in report.failed_checks


def test_host_probe_rejects_artifact_digest_mismatch(host_profile, monkeypatch, tmp_path):
    kvm, cgroup = _host(monkeypatch, tmp_path)
    host_profile.firecracker.path.write_bytes(b"replaced-firecracker")

    report = inspect_firecracker_host(host_profile, kvm_device=kvm, cgroup_root=cgroup)

    assert report.ready is False
    assert "firecracker_sha256" in report.failed_checks


def test_host_probe_rejects_non_executable_vmm_or_jailer(host_profile, monkeypatch, tmp_path):
    kvm, cgroup = _host(monkeypatch, tmp_path)
    host_profile.jailer.path.chmod(0o644)

    report = inspect_firecracker_host(host_profile, kvm_device=kvm, cgroup_root=cgroup)

    assert report.ready is False
    assert "jailer_executable" in report.failed_checks


def test_profile_rejects_floating_or_malformed_version_and_digest(tmp_path):
    artifact = FirecrackerArtifact(tmp_path / "artifact", "a" * 64)

    with pytest.raises(ValueError, match="firecracker_version_invalid"):
        FirecrackerHostProfile("latest", artifact, artifact, artifact, artifact)
    with pytest.raises(ValueError, match="firecracker_artifact_digest_invalid"):
        FirecrackerArtifact(tmp_path / "artifact", "not-a-digest")


def test_host_probe_rejects_missing_guest_kernel(host_profile, monkeypatch, tmp_path):
    kvm, cgroup = _host(monkeypatch, tmp_path)
    host_profile.guest_kernel.path.unlink()

    report = inspect_firecracker_host(host_profile, kvm_device=kvm, cgroup_root=cgroup)

    assert report.ready is False
    assert "guest_kernel_present" in report.failed_checks


def test_host_probe_hashes_large_artifacts_in_bounded_chunks(host_profile, monkeypatch, tmp_path):
    import shared.onchain_firecracker_host as host

    kvm, cgroup = _host(monkeypatch, tmp_path)
    monkeypatch.setattr(
        host.Path,
        "read_bytes",
        lambda self: (_ for _ in ()).throw(AssertionError("unbounded read_bytes is forbidden")),
    )

    report = inspect_firecracker_host(host_profile, kvm_device=kvm, cgroup_root=cgroup)

    assert report.ready is True


def test_artifact_profile_requires_absolute_operator_paths():
    from shared.onchain_firecracker_host import FirecrackerHostProfileError

    with pytest.raises(FirecrackerHostProfileError, match="firecracker_artifact_path_invalid"):
        FirecrackerArtifact(path=__import__("pathlib").Path("relative/firecracker"), sha256="a" * 64)
