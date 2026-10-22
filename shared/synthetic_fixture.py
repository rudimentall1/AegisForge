"""Fixed, deterministic in-process fixtures for the local-only evidence pipeline.

These fixtures exercise the EvidenceLedger and dossier path without launching a
process, evaluating bundle-supplied commands, using network APIs, or touching a
real protocol. Their output can validate the harness; it cannot establish target
behavior or a vulnerability.
"""
from __future__ import annotations

import json
import sys

FIXTURE_SCHEMA_VERSION = "aegisforge-synthetic-accounting-v1"
_ALLOWED_MODES = frozenset({"control", "countertest"})
_EXPECTED_BALANCE = 100


def _canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def run_synthetic_fixture(mode: str) -> dict:
    """Run one repository-owned state fixture in-process and return raw outputs.

    `argv` is descriptive metadata for the dossier, not a command passed to an
    operating system. Only the fixed modes in this module are accepted.
    """
    if not isinstance(mode, str) or mode not in _ALLOWED_MODES:
        raise ValueError("synthetic_fixture_mode_not_allowed")

    expected_balance = _EXPECTED_BALANCE
    observed_balance = (
        _EXPECTED_BALANCE if mode == "control" else _EXPECTED_BALANCE - 1
    )
    invariant_preserved = observed_balance == expected_balance
    seeded_violation_detected = observed_balance != expected_balance
    passed = (
        invariant_preserved if mode == "control" else seeded_violation_detected
    )

    fixture_input = {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "mode": mode,
        "expected_balance": expected_balance,
        "observed_balance": observed_balance,
        "seeded_violation": mode == "countertest",
    }
    if mode == "control":
        output = (
            "SYNTHETIC_FIXTURE fixture=accounting-v1 mode=control "
            f"invariant_preserved={str(invariant_preserved).lower()} "
            f"expected_balance={expected_balance} observed_balance={observed_balance}\n"
        )
        checks = {"invariant_preserved": invariant_preserved}
    else:
        output = (
            "SYNTHETIC_FIXTURE fixture=accounting-v1 mode=countertest "
            f"seeded_violation_detected={str(seeded_violation_detected).lower()} "
            f"expected_balance={expected_balance} observed_balance={observed_balance}\n"
        )
        checks = {"seeded_violation_detected": seeded_violation_detected}

    return {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "mode": mode,
        "input_bytes": _canonical_bytes(fixture_input),
        "stdout_bytes": output.encode("utf-8"),
        "stderr_bytes": b"",
        "exit_code": 0 if passed else 1,
        "expected_exit_code": 0,
        "argv": ["aegisforge-synthetic-fixture", mode],
        "toolchain": {
            "python": "3.10",
            "fixture": FIXTURE_SCHEMA_VERSION,
        },
        "checks": checks,
        "passed": passed,
        "synthetic_fixture": True,
        "network_access": False,
        "subprocess_started": False,
    }



PROCESS_INPUT_SCHEMA_VERSION = "aegisforge-synthetic-fixture-process-input-v1"
PROCESS_CPU_LIMIT_SECONDS = 2
PROCESS_ADDRESS_SPACE_LIMIT_BYTES = 256 * 1024 * 1024
PROCESS_FILE_SIZE_LIMIT_BYTES = 1024 * 1024
PROCESS_OPEN_FILE_LIMIT = 16
_MAX_PROCESS_INPUT_BYTES = 4096


def _apply_process_resource_limits() -> None:
    """Apply fixed POSIX resource limits before interpreting fixture input."""
    import resource

    for resource_id, soft, hard in (
        (resource.RLIMIT_CPU, PROCESS_CPU_LIMIT_SECONDS, PROCESS_CPU_LIMIT_SECONDS),
        (
            resource.RLIMIT_AS,
            PROCESS_ADDRESS_SPACE_LIMIT_BYTES,
            PROCESS_ADDRESS_SPACE_LIMIT_BYTES,
        ),
        (
            resource.RLIMIT_FSIZE,
            PROCESS_FILE_SIZE_LIMIT_BYTES,
            PROCESS_FILE_SIZE_LIMIT_BYTES,
        ),
        (resource.RLIMIT_NOFILE, PROCESS_OPEN_FILE_LIMIT, PROCESS_OPEN_FILE_LIMIT),
        (resource.RLIMIT_CORE, 0, 0),
    ):
        resource.setrlimit(resource_id, (soft, hard))


def main(argv: list[str] | None = None) -> int:
    """Fixed child-process entry point; accepts only an allowlisted fixture mode.

    The parent runner sends a tiny canonical JSON request over stdin. This CLI
    emits the fixture's actual stdout/stderr bytes rather than a metadata wrapper,
    so the parent can persist genuinely captured process output.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or arguments[0] != "--subprocess-run":
        return 64
    mode = arguments[1]
    if not isinstance(mode, str) or mode not in _ALLOWED_MODES:
        return 64

    try:
        _apply_process_resource_limits()
    except (ImportError, AttributeError, OSError, ValueError):
        return 70

    raw_input = sys.stdin.buffer.read(_MAX_PROCESS_INPUT_BYTES + 1)
    if len(raw_input) > _MAX_PROCESS_INPUT_BYTES:
        return 65
    try:
        request = json.loads(raw_input.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 65
    if (
        not isinstance(request, dict)
        or set(request) != {"schema_version", "mode"}
        or request.get("schema_version") != PROCESS_INPUT_SCHEMA_VERSION
        or request.get("mode") != mode
        or _canonical_bytes(request) != raw_input
    ):
        return 65

    result = run_synthetic_fixture(mode)
    sys.stdout.buffer.write(result["stdout_bytes"])
    sys.stderr.buffer.write(result["stderr_bytes"])
    sys.stdout.buffer.flush()
    sys.stderr.buffer.flush()
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
