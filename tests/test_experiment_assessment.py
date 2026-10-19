import io
import zipfile

from shared.local_experiment import build_experiment_record
from shared.local_experiment_bundle import export_local_experiment_bundle
from shared.experiment_assessment import assess_local_experiment_pair


CASE_ID = "assessment-case-1"
ROUND_ID = "assessment-round-1"
REPOSITORY = "example/protocol"
COMMIT = "a" * 40


def _bundle(*, task_id, exit_code=0, target_commit=COMMIT):
    record, artifacts = build_experiment_record(
        case_id=CASE_ID,
        round_id=ROUND_ID,
        task_id=task_id,
        target_repository=REPOSITORY,
        target_commit=target_commit,
        argv=["synthetic-fixture", task_id],
        toolchain={"python": "3.12.1", "fixture": "assessment-test"},
        input_bytes=b"fixed input",
        stdout_bytes=b"test output",
        stderr_bytes=b"",
        exit_code=exit_code,
    )
    return export_local_experiment_bundle(record, artifacts)


def _assess(control, counter, *, synthetic_fixture=False):
    return assess_local_experiment_pair(
        control_bundle=control,
        countertest_bundle=counter,
        expected_case_id=CASE_ID,
        expected_round_id=ROUND_ID,
        expected_target_repository=REPOSITORY,
        expected_target_commit=COMMIT,
        synthetic_fixture=synthetic_fixture,
    )


def test_pair_with_missing_both_bundles_is_not_run():
    report = _assess(None, None)
    assert report["status"] == "NOT_RUN"
    assert report["missing_evidence"] == ["control_bundle", "countertest_bundle"]
    assert report["vulnerability_confirmed"] is False


def test_pair_with_one_missing_bundle_is_inconclusive():
    report = _assess(_bundle(task_id="control"), None)
    assert report["status"] == "INCONCLUSIVE"
    assert report["missing_evidence"] == ["countertest_bundle"]


def test_synthetic_fixture_pair_never_confirms_target_behavior():
    report = _assess(
        _bundle(task_id="control"),
        _bundle(task_id="counter"),
        synthetic_fixture=True,
    )
    assert report["status"] == "INCONCLUSIVE"
    assert report["vulnerability_status"] == "INCONCLUSIVE"
    assert report["vulnerability_confirmed"] is False
    assert "synthetic_fixture_cannot_establish_target_behavior" in report["errors"]


def test_valid_non_synthetic_pair_passes_workflow_not_vulnerability():
    report = _assess(_bundle(task_id="control"), _bundle(task_id="counter"))
    assert report["status"] == "PASS"
    assert report["vulnerability_status"] == "INCONCLUSIVE"
    assert report["vulnerability_confirmed"] is False
    assert report["checks"]["identity_match"] is True


def test_bundle_with_unexpected_exit_code_fails_workflow_not_confirm_finding():
    report = _assess(
        _bundle(task_id="control"),
        _bundle(task_id="counter", exit_code=1),
    )
    assert report["status"] == "FAIL"
    assert report["vulnerability_confirmed"] is False
    assert report["errors"] == ["experiment_exit_expectation_not_met"]


def test_target_revision_mismatch_fails_closed():
    report = _assess(
        _bundle(task_id="control", target_commit="b" * 40),
        _bundle(task_id="counter"),
    )
    assert report["status"] == "FAIL"
    assert report["errors"] == ["control_identity_mismatch"]
    assert report["vulnerability_confirmed"] is False


def test_tampered_bundle_fails_closed():
    bundle = _bundle(task_id="control")
    changed = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(bundle)) as source, zipfile.ZipFile(changed, "w") as output:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "stdout.bin":
                data += b"tampered"
            output.writestr(info.filename, data)
    report = _assess(changed.getvalue(), _bundle(task_id="counter"))
    assert report["status"] == "FAIL"
    assert report["errors"] == ["control_bundle_invalid"]
    assert report["vulnerability_confirmed"] is False
