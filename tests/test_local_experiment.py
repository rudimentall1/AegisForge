import copy

from shared.local_experiment import (
    ExperimentRecordError,
    build_experiment_record,
    verify_experiment_record,
)


def _record(exit_code=0):
    return build_experiment_record(
        case_id="case-synthetic-1",
        round_id="round-runtime-1",
        task_id="task-control-1",
        target_commit="a" * 40,
        argv=["pytest", "-q", "tests/test_control.py"],
        toolchain={"python": "3.12.1", "pytest": "8.3.4"},
        input_bytes=b"fixed-input\n",
        stdout_bytes=b"control: invariant-preserved\n",
        stderr_bytes=b"",
        exit_code=exit_code,
        expected_exit_code=0,
    )


def test_local_experiment_record_verifies_raw_artifacts_and_identity():
    record, artifacts = _record()
    report = verify_experiment_record(record, artifacts)

    assert report["status"] == "PASS"
    assert report["experiment_status"] == "PASS"
    assert report["case_id"] == "case-synthetic-1"
    assert report["round_id"] == "round-runtime-1"
    assert report["task_id"] == "task-control-1"
    assert report["checked_artifacts"] == 3


def test_raw_output_tampering_fails_closed():
    record, artifacts = _record()
    changed = dict(artifacts)
    changed["stdout.bin"] = b"control: invariant-PRESERVED\n"

    report = verify_experiment_record(record, changed)

    assert report == {
        "status": "FAIL",
        "errors": ["artifact_digest_mismatch:stdout.bin"],
    }


def test_record_cannot_claim_pass_when_exit_code_fails():
    record, artifacts = _record(exit_code=2)
    assert record["status"] == "FAIL"
    forged = copy.deepcopy(record)
    forged["status"] = "PASS"

    report = verify_experiment_record(forged, artifacts)

    assert report == {
        "status": "FAIL",
        "errors": ["outcome_status_inconsistent"],
    }


def test_not_run_is_preserved_and_not_promoted_to_pass():
    record, artifacts = _record(exit_code=None)

    assert record["status"] == "NOT_RUN"
    report = verify_experiment_record(record, artifacts)
    assert report["status"] == "PASS"
    assert report["experiment_status"] == "NOT_RUN"


def test_missing_artifact_is_not_accepted():
    record, artifacts = _record()
    missing = dict(artifacts)
    del missing["stderr.bin"]

    report = verify_experiment_record(record, missing)

    assert report == {"status": "FAIL", "errors": ["artifact_set_mismatch"]}


def test_invalid_revision_is_rejected_before_record_creation():
    try:
        build_experiment_record(
            case_id="case-1",
            round_id="round-1",
            task_id="task-1",
            target_commit="main",
            argv=["pytest"],
            toolchain={"python": "3.12"},
            input_bytes=b"",
            stdout_bytes=b"",
            stderr_bytes=b"",
            exit_code=0,
        )
    except ExperimentRecordError as exc:
        assert str(exc) == "target_commit_must_be_full_git_sha"
    else:
        raise AssertionError("mutable target revision must be rejected")
