"""Adversarial offline-verifier cases for portable local-experiment bundles."""
import io
import json
import zipfile

from shared.local_experiment import build_experiment_record
from shared.local_experiment_bundle import (
    BUNDLE_SCHEMA_VERSION,
    export_local_experiment_bundle,
    verify_local_experiment_bundle,
)


def _fixture(*, exit_code=0):
    record, artifacts = build_experiment_record(
        case_id="adversarial-case",
        round_id="adversarial-round",
        task_id="adversarial-task",
        target_repository="example/protocol",
        target_commit="c" * 40,
        argv=["synthetic-fixture", "no-execution"],
        toolchain={"fixture": "adversarial-v1"},
        input_bytes=b"input",
        stdout_bytes=b"synthetic output",
        stderr_bytes=b"",
        exit_code=exit_code,
    )
    return record, artifacts


def _rewrite_bundle(bundle, *, replace_manifest=None, extra_entries=()):
    rewritten = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(bundle), "r") as source:
        with zipfile.ZipFile(rewritten, "w", zipfile.ZIP_DEFLATED) as target:
            for info in source.infolist():
                data = source.read(info.filename)
                if info.filename == "manifest.json" and replace_manifest is not None:
                    data = replace_manifest
                target.writestr(info.filename, data)
            for name, data in extra_entries:
                target.writestr(name, data)
    return rewritten.getvalue()


def test_not_run_record_preserves_not_run_when_bundle_integrity_passes():
    record, artifacts = _fixture(exit_code=None)
    bundle = export_local_experiment_bundle(record, artifacts)

    report = verify_local_experiment_bundle(bundle)

    assert report["status"] == "PASS"
    assert report["experiment_status"] == "NOT_RUN"
    assert report.get("vulnerability_confirmed", False) is False


def test_verifier_rejects_duplicate_manifest_json_keys():
    record, artifacts = _fixture()
    bundle = export_local_experiment_bundle(record, artifacts)
    duplicate_key_manifest = (
        '{"schema_version":"' + BUNDLE_SCHEMA_VERSION + '",'
        '"schema_version":"' + BUNDLE_SCHEMA_VERSION + '",'
        '"record":' + json.dumps(record, sort_keys=True, separators=(",", ":")) + '}'
    ).encode("utf-8")

    report = verify_local_experiment_bundle(
        _rewrite_bundle(bundle, replace_manifest=duplicate_key_manifest)
    )

    assert report["status"] == "FAIL"
    assert report["errors"] == ["bundle_malformed_or_unreadable"]
    assert report.get("vulnerability_confirmed", False) is False


def test_verifier_rejects_path_traversal_entry():
    record, artifacts = _fixture()
    bundle = export_local_experiment_bundle(record, artifacts)

    report = verify_local_experiment_bundle(
        _rewrite_bundle(bundle, extra_entries=(("../outside.txt", b"must not escape"),))
    )

    assert report["status"] == "FAIL"
    assert report["errors"] == ["bundle_entry_set_invalid"]
    assert report.get("vulnerability_confirmed", False) is False


def test_verifier_rejects_malformed_target_revision_in_manifest():
    record, artifacts = _fixture()
    bundle = export_local_experiment_bundle(record, artifacts)
    record["target_commit"] = "not-a-full-git-sha"
    changed_manifest = json.dumps(
        {"schema_version": BUNDLE_SCHEMA_VERSION, "record": record},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    report = verify_local_experiment_bundle(
        _rewrite_bundle(bundle, replace_manifest=changed_manifest)
    )

    assert report["status"] == "FAIL"
    assert report["errors"] == ["local_experiment_record_invalid"]
    assert report.get("vulnerability_confirmed", False) is False


def test_verifier_rejects_symlink_artifact_entry():
    record, artifacts = _fixture()
    bundle = export_local_experiment_bundle(record, artifacts)
    rewritten = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(bundle), "r") as source:
        with zipfile.ZipFile(rewritten, "w", compression=zipfile.ZIP_DEFLATED) as target:
            for info in source.infolist():
                data = source.read(info.filename)
                if info.filename == "input.bin":
                    symlink = zipfile.ZipInfo(info.filename)
                    symlink.create_system = 3
                    symlink.external_attr = (0o120777 << 16)
                    target.writestr(symlink, b"outside-target")
                else:
                    target.writestr(info, data)

    report = verify_local_experiment_bundle(rewritten.getvalue())

    assert report["status"] == "FAIL"
    assert report["errors"] == ["bundle_entry_type_invalid"]
    assert report.get("vulnerability_confirmed", False) is False
