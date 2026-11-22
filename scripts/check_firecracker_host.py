#!/usr/bin/env python3
"""Inspect a dedicated Linux KVM host against an operator-pinned Firecracker profile.

This command is non-executing: it never starts Firecracker, Jailer, a guest,
Foundry, or target code. READY covers host prerequisites and artifact hashes only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from shared.onchain_firecracker_host import (
    FirecrackerArtifact,
    FirecrackerHostProfile,
    FirecrackerHostProfileError,
    inspect_firecracker_host,
)


_ARTIFACT_NAMES = ("firecracker", "jailer", "guest_kernel", "guest_rootfs")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def load_profile(path: Path) -> FirecrackerHostProfile:
    """Load a strict JSON profile; paths and digests must be operator supplied."""
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("profile_json_invalid") from exc
    except OSError as exc:
        raise ValueError("profile_file_unreadable") from exc

    if not isinstance(raw, dict) or set(raw) != {"version", "artifacts"}:
        raise ValueError("profile_keys_invalid")
    if not isinstance(raw["version"], str):
        raise ValueError("firecracker_version_invalid")
    artifacts_raw = raw["artifacts"]
    if not isinstance(artifacts_raw, dict) or set(artifacts_raw) != set(_ARTIFACT_NAMES):
        raise ValueError("artifact_keys_invalid")

    artifacts: dict[str, FirecrackerArtifact] = {}
    for name in _ARTIFACT_NAMES:
        item = artifacts_raw[name]
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError("artifact_entry_keys_invalid")
        if not isinstance(item["path"], str) or not item["path"]:
            raise ValueError("firecracker_artifact_path_invalid")
        if not isinstance(item["sha256"], str):
            raise ValueError("firecracker_artifact_digest_invalid")
        artifact_path = Path(item["path"])
        if not artifact_path.is_absolute():
            raise ValueError("firecracker_artifact_path_invalid")
        artifacts[name] = FirecrackerArtifact(
            path=artifact_path,
            sha256=item["sha256"],
        )

    return FirecrackerHostProfile(
        version=raw["version"],
        firecracker=artifacts["firecracker"],
        jailer=artifacts["jailer"],
        guest_kernel=artifacts["guest_kernel"],
        guest_rootfs=artifacts["guest_rootfs"],
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True, help="Operator-owned JSON artifact profile")
    parser.add_argument("--kvm-device", type=Path, default=Path("/dev/kvm"))
    parser.add_argument("--cgroup-root", type=Path, default=Path("/sys/fs/cgroup"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = load_profile(args.profile)
        report = inspect_firecracker_host(
            profile,
            kvm_device=args.kvm_device,
            cgroup_root=args.cgroup_root,
        )
        payload = {
            "schema_version": "aegisforge-firecracker-host-preflight-v1",
            "status": report.status,
            "profile_sha256": report.profile_sha256,
            "checks": {name: passed for name, passed in report.checks},
            "failed_checks": list(report.failed_checks),
            "scope": "host_prerequisites_only",
            "target_code_executed": False,
            "firecracker_started": False,
            "jailer_started": False,
            "guest_started": False,
        }
        exit_code = 0 if report.ready else 2
    except (FirecrackerHostProfileError, OSError, ValueError) as exc:
        payload = {
            "schema_version": "aegisforge-firecracker-host-preflight-v1",
            "status": "INVALID_PROFILE",
            "error": str(exc)[:200],
            "scope": "host_prerequisites_only",
            "target_code_executed": False,
            "firecracker_started": False,
            "jailer_started": False,
            "guest_started": False,
        }
        exit_code = 2

    sys.stdout.write(json.dumps(payload, sort_keys=True, indent=2) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
