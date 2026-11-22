"""Fail-closed host prerequisite inspection for the Firecracker on-chain runner.

This module never launches Firecracker, jailer, a guest, or target code. A READY
report means only that the inspected host prerequisites and pinned artifact
digests are present; it is not an isolation acceptance result.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_REQUIRED_CGROUP_CONTROLLERS = frozenset({"cpu", "memory", "pids"})


class FirecrackerHostProfileError(ValueError):
    """Invalid immutable Firecracker host artifact profile."""


@dataclass(frozen=True, slots=True)
class FirecrackerArtifact:
    path: Path
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise FirecrackerHostProfileError("firecracker_artifact_path_invalid")
        if not isinstance(self.sha256, str) or not _SHA256_RE.fullmatch(self.sha256):
            raise FirecrackerHostProfileError("firecracker_artifact_digest_invalid")


@dataclass(frozen=True, slots=True)
class FirecrackerHostProfile:
    version: str
    firecracker: FirecrackerArtifact
    jailer: FirecrackerArtifact
    guest_kernel: FirecrackerArtifact
    guest_rootfs: FirecrackerArtifact

    def __post_init__(self) -> None:
        if not isinstance(self.version, str) or not _VERSION_RE.fullmatch(self.version):
            raise FirecrackerHostProfileError("firecracker_version_invalid")
        for name in ("firecracker", "jailer", "guest_kernel", "guest_rootfs"):
            if not isinstance(getattr(self, name), FirecrackerArtifact):
                raise FirecrackerHostProfileError(f"{name}_artifact_invalid")

    @property
    def sha256(self) -> str:
        identity = {
            "version": self.version,
            "firecracker": self.firecracker.sha256,
            "jailer": self.jailer.sha256,
            "guest_kernel": self.guest_kernel.sha256,
            "guest_rootfs": self.guest_rootfs.sha256,
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class FirecrackerHostReport:
    status: str
    profile_sha256: str
    checks: tuple[tuple[str, bool], ...]

    @property
    def ready(self) -> bool:
        return self.status == "READY"

    @property
    def failed_checks(self) -> tuple[str, ...]:
        return tuple(name for name, passed in self.checks if not passed)


def _is_character_device(path: Path) -> bool:
    try:
        return stat.S_ISCHR(path.stat().st_mode)
    except OSError:
        return False


def _artifact_present(artifact: FirecrackerArtifact) -> bool:
    try:
        return artifact.path.is_file() and artifact.path.stat().st_size > 0
    except OSError:
        return False


def _artifact_check(artifact: FirecrackerArtifact) -> bool:
    try:
        if not _artifact_present(artifact):
            return False
        digest = hashlib.sha256()
        with artifact.path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return False
    return digest.hexdigest() == artifact.sha256


def _executable_check(artifact: FirecrackerArtifact) -> bool:
    try:
        mode = artifact.path.stat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and bool(mode & 0o111)


def inspect_firecracker_host(
    profile: FirecrackerHostProfile,
    *,
    kvm_device: Path = Path("/dev/kvm"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> FirecrackerHostReport:
    """Inspect Firecracker prerequisites without starting any process."""
    if not isinstance(profile, FirecrackerHostProfile):
        raise FirecrackerHostProfileError("firecracker_host_profile_required")

    checks: list[tuple[str, bool]] = []
    checks.append(("linux_host", platform.system() == "Linux"))
    checks.append((
        "supported_host_architecture",
        platform.machine().lower() in {"x86_64", "amd64", "aarch64", "arm64"},
    ))
    checks.append(("jailer_privileged_setup", os.geteuid() == 0))
    checks.append(("kvm_character_device", _is_character_device(kvm_device)))
    checks.append((
        "kvm_read_write_access",
        os.access(kvm_device, os.R_OK | os.W_OK),
    ))

    controllers_path = cgroup_root / "cgroup.controllers"
    try:
        with controllers_path.open("r", encoding="ascii") as source:
            controller_text = source.read(4096)
            if len(controller_text) >= 4096:
                raise OSError("cgroup_controller_list_too_large")
        controllers = set(controller_text.split())
        cgroup_ok = _REQUIRED_CGROUP_CONTROLLERS.issubset(controllers)
    except (OSError, UnicodeError):
        cgroup_ok = False
    checks.append(("cgroup_v2_controllers", cgroup_ok))

    for name, artifact in (
        ("firecracker", profile.firecracker),
        ("jailer", profile.jailer),
        ("guest_kernel", profile.guest_kernel),
        ("guest_rootfs", profile.guest_rootfs),
    ):
        checks.append((f"{name}_present", _artifact_present(artifact)))
        checks.append((f"{name}_sha256", _artifact_check(artifact)))
    checks.append(("firecracker_executable", _executable_check(profile.firecracker)))
    checks.append(("jailer_executable", _executable_check(profile.jailer)))

    failed = any(not passed for _, passed in checks)
    return FirecrackerHostReport(
        status="NOT_READY" if failed else "READY",
        profile_sha256=profile.sha256,
        checks=tuple(checks),
    )
