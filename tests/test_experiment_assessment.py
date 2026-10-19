import io
import zipfile

from shared.local_experiment import build_experiment_record
from shared.local_experiment_bundle import export_local_experiment_bundle
from shared.experiment_assessment import assess_local_experiment_pair


CASE_ID = "assessment-case-1"
ROUND_ID = "assessment-round-1"
REPOSITORY = "example/protocol"
COMMIT = "a" * 40


def _bundle(*, task_id, exit_code=0, target_commit=COMMIT, fixture_version="assessment-test", stdout_bytes=None):
    if stdout_bytes is None:
        stdout_bytes = (
            b"control invariant_preserved=true"
            if task_id == "control"
            else b"counter seeded_violation_detected=true"
        )
    record, artifacts = build_experiment_record(
        case_id=CASE_ID,
        round_id=ROUND_ID,
        task_id=task_id,
        target_repository=REPOSITORY,
        target_commit=target_commit,
        argv=["synthetic-fixture", task_id],
        toolchain={"python": "3.12.1", "fixture": fixture_version},
        input_bytes=b"fixed input",
        stdout_bytes=stdout_bytes,
        stderr_bytes=b"",
        exit_code=exit_code,
    )
    return export_local_experiment_bundle(record, artifacts)


def _criteria(**overrides):
    criteria = {
        "case_id": CASE_ID,
        "round_id": ROUND_ID,
        "target_repository": REPOSITORY,
        "target_commit": COMMIT,
        "invariant": "Control must preserve the invariant.",
        "falsification_criteria": "Counter-test must detect the seeded violation.",
        "control": {
            "must_contain": ["invariant_preserved=true"],
            "must_not_contain": ["invariant_preserved=false"],
        },
        "countertest": {
            "must_contain": ["seeded_violation_detected=true"],
            "must_not_contain": ["seeded_violation_detected=false"],
        },
    }
    criteria.update(overrides)
    return criteria


def _assess(control, counter, *, synthetic_fixture=False, semantic_criteria="default"):
    if semantic_criteria == "default":
        semantic_criteria = _criteria()
    return assess_local_experiment_pair(
        control_bundle=control,
        countertest_bundle=counter,
        expected_case_id=CASE_ID,
        expected_round_id=ROUND_ID,
        expected_target_repository=REPOSITORY,
        expected_target_commit=COMMIT,
        semantic_criteria=semantic_criteria,
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
    assert report["execution_provenance"]["status"] == "UNAUTHENTICATED"
    assert report["execution_provenance"]["runner_identity"] == "UNVERIFIED"
    assert report["execution_provenance"]["environment_identity"] == "UNVERIFIED"
    assert report["execution_provenance"]["reproducibility"] == "NOT_ESTABLISHED"


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



def test_reusing_one_bundle_for_both_roles_fails_closed():
    bundle = _bundle(task_id="same-task")
    report = _assess(bundle, bundle)
    assert report["status"] == "FAIL"
    assert report["errors"] == ["control_and_countertest_must_use_distinct_tasks"]
    assert report["vulnerability_confirmed"] is False


def test_control_and_countertest_require_the_same_pinned_toolchain():
    report = _assess(
        _bundle(task_id="control"),
        _bundle(task_id="counter", fixture_version="different-toolchain"),
    )
    assert report["status"] == "FAIL"
    assert report["errors"] == ["control_and_countertest_toolchain_mismatch"]
    assert report["vulnerability_confirmed"] is False


def test_exit_code_success_without_semantic_criteria_is_inconclusive():
    report = _assess(
        _bundle(task_id="control"),
        _bundle(task_id="counter"),
        semantic_criteria=None,
    )
    assert report["status"] == "INCONCLUSIVE"
    assert report["errors"] == ["semantic_criteria_missing"]
    assert report["vulnerability_confirmed"] is False


def test_control_output_must_satisfy_declared_invariant():
    criteria = _criteria()
    criteria["control"]["must_contain"] = ["invariant_preserved=true", "balance_conserved=true"]
    report = _assess(_bundle(task_id="control"), _bundle(task_id="counter"), semantic_criteria=criteria)
    assert report["status"] == "FAIL"
    assert report["errors"] == ["control_semantic_criteria_not_met"]
    assert report["checks"]["control_output_matches_invariant"] is False
    assert report["vulnerability_confirmed"] is False


def test_countertest_output_must_satisfy_falsification_criteria():
    criteria = _criteria()
    criteria["countertest"]["must_contain"] = ["seeded_violation_detected=true", "invariant_broken=true"]
    report = _assess(_bundle(task_id="control"), _bundle(task_id="counter"), semantic_criteria=criteria)
    assert report["status"] == "FAIL"
    assert report["errors"] == ["countertest_semantic_criteria_not_met"]
    assert report["checks"]["countertest_output_matches_falsification_criteria"] is False
    assert report["vulnerability_confirmed"] is False


def test_semantic_criteria_cannot_be_reassigned_to_another_case():
    criteria = _criteria()
    criteria["case_id"] = "different-case"
    report = _assess(_bundle(task_id="control"), _bundle(task_id="counter"), semantic_criteria=criteria)
    assert report["status"] == "FAIL"
    assert report["errors"] == ["semantic_criteria_identity_mismatch"]
    assert report["vulnerability_confirmed"] is False



def test_forbidden_output_token_fails_even_when_required_token_is_present():
    report = _assess(
        _bundle(
            task_id="control",
            stdout_bytes=b"control invariant_preserved=true invariant_preserved=false",
        ),
        _bundle(task_id="counter"),
    )
    assert report["status"] == "FAIL"
    assert report["errors"] == ["control_semantic_criteria_not_met"]
    assert report["checks"]["control_output_matches_invariant"] is False
    assert report["vulnerability_confirmed"] is False
