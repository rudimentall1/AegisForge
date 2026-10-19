import io
import json
import zipfile

from shared.local_experiment import build_experiment_record
from shared.local_experiment_bundle import (
    BUNDLE_SCHEMA_VERSION,
    export_local_experiment_bundle,
    verify_local_experiment_bundle,
)


def _bundle():
    record, artifacts = build_experiment_record(
        case_id="case-1",
        round_id="round-1",
        task_id="task-1",
        target_repository="example/protocol",
        target_commit="a" * 40,
        argv=["pytest", "-q", "test_control.py"],
        toolchain={"python": "3.12.1", "pytest": "8.3.4"},
        input_bytes=b"fixed input",
        stdout_bytes=b"control: invariant preserved",
        stderr_bytes=b"",
        exit_code=0,
    )
    return export_local_experiment_bundle(record, artifacts), record, artifacts


def test_portable_bundle_round_trip_is_integrity_only():
    bundle, _, _ = _bundle()
    report = verify_local_experiment_bundle(bundle)

    assert report == {
        "status": "PASS",
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "case_id": "case-1",
        "round_id": "round-1",
        "task_id": "task-1",
        "target_repository": "example/protocol",
        "target_commit": "a" * 40,
        "experiment_status": "PASS",
        "checked_artifacts": 3,
        "integrity_only": True,
        "authenticated_execution": False,
        "vulnerability_confirmed": False,
        "errors": [],
    }


def test_bundle_export_rejects_artifact_tampering():
    _, record, artifacts = _bundle()
    changed = dict(artifacts)
    changed["stdout.bin"] = b"forged"
    try:
        export_local_experiment_bundle(record, changed)
    except ValueError as exc:
        assert str(exc) == "local_experiment_record_invalid"
    else:
        raise AssertionError("tampered artifacts must not be exported")


def test_bundle_verifier_rejects_tampered_artifact():
    bundle, _, _ = _bundle()
    source = zipfile.ZipFile(io.BytesIO(bundle))
    changed = io.BytesIO()
    with source, zipfile.ZipFile(changed, "w", zipfile.ZIP_DEFLATED) as output:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "stdout.bin":
                data += b" tampered"
            output.writestr(info.filename, data)

    report = verify_local_experiment_bundle(changed.getvalue())
    assert report["status"] == "FAIL"
    assert report["errors"] == ["local_experiment_record_invalid"]


def test_bundle_verifier_rejects_extra_entry():
    bundle, _, _ = _bundle()
    changed = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(bundle)) as source, zipfile.ZipFile(changed, "w") as output:
        for info in source.infolist():
            output.writestr(info.filename, source.read(info.filename))
        output.writestr("unexpected.txt", b"extra")

    report = verify_local_experiment_bundle(changed.getvalue())
    assert report == {"status": "FAIL", "errors": ["bundle_entry_set_invalid"]}


def test_bundle_verifier_rejects_duplicate_entry_names():
    bundle, _, _ = _bundle()
    changed = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(bundle)) as source, zipfile.ZipFile(changed, "w") as output:
        for info in source.infolist():
            output.writestr(info.filename, source.read(info.filename))
        output.writestr("input.bin", b"duplicate")

    report = verify_local_experiment_bundle(changed.getvalue())
    assert report == {"status": "FAIL", "errors": ["bundle_entry_set_invalid"]}


def test_bundle_verifier_rejects_invalid_input():
    assert verify_local_experiment_bundle(b"not a zip") == {
        "status": "FAIL",
        "errors": ["bundle_malformed_or_unreadable"],
    }
