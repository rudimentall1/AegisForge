from __future__ import annotations

import copy
import json

import pytest

from tools.evm_key_forensics.build_source_evidence_report import build_report, main

PRE = {
    "schema_version": 1,
    "experiment_id": "evm-forensics-historical-source-pattern-v1",
    "upstream_repository": "https://github.com/johguse/profanity",
    "source_revision_role": "pre-disclosure",
    "expected_upstream_commit": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
    "source_sha256": "a" * 64,
    "function_body_sha256": "c" * 64,
    "git_blob_sha1": "c9226fc02a52633a84664cbf3aaf2b4af8a59b25",
    "pinned_source_blob_matches": True,
    "conclusion": "SOURCE_PATTERN_MATCHED",
    "errors": [],
    "historical_code_executed": False,
    "wallet_material_used": False,
    "historical_vulnerability_reproduced": False,
}
POST = {
    **PRE,
    "source_revision_role": "post-disclosure",
    "expected_upstream_commit": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
    "source_sha256": "b" * 64,
    "git_blob_sha1": "884ced30ed6e55794ea5bda0451b52e81ddec1dd",
}


def test_valid_results_build_comparison_but_conclusion_stays_inconclusive():
    report = build_report(copy.deepcopy(PRE), copy.deepcopy(POST))
    assert report["validation_errors"] == []
    assert report["source_comparison"]["pre_disclosure"]["validated"] is True
    assert report["source_comparison"]["post_disclosure_archive"]["validated"] is True
    assert report["source_comparison"]["same_source_sha256"] is False
    assert report["source_comparison"]["same_create_seed_function_body_sha256"] is True
    assert report["overall_conclusion"] == "INCONCLUSIVE"
    assert report["limitations"]["historical_vulnerability_reproduced"] is False


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("expected_upstream_commit", "f" * 40, "pre-disclosure:pinned_commit_mismatch"),
        ("git_blob_sha1", "0" * 40, "pre-disclosure:pinned_source_blob_not_verified"),
        ("source_sha256", "not-a-digest", "pre-disclosure:invalid_source_sha256"),
        ("conclusion", "INCONCLUSIVE", "pre-disclosure:source_pattern_not_matched"),
        ("historical_vulnerability_reproduced", True, "pre-disclosure:unsafe_or_unsubstantiated_flag:historical_vulnerability_reproduced"),
    ],
)
def test_mutated_pre_result_is_rejected(field, value, error):
    data = copy.deepcopy(PRE)
    data[field] = value
    report = build_report(data, copy.deepcopy(POST))
    assert error in report["validation_errors"]
    assert report["overall_conclusion"] == "INCONCLUSIVE"


def test_revision_roles_cannot_be_swapped():
    data = copy.deepcopy(PRE)
    data["source_revision_role"] = "post-disclosure"
    report = build_report(data, copy.deepcopy(POST))
    assert "pre-disclosure:source_revision_role_mismatch" in report["validation_errors"]


def test_cli_rejects_duplicate_json_keys(tmp_path, capsys):
    pre = tmp_path / "pre.json"
    post = tmp_path / "post.json"
    pre.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    post.write_text(json.dumps(POST), encoding="utf-8")
    assert main([str(pre), str(post)]) == 2
    assert "duplicate_json_key:schema_version" in capsys.readouterr().out


def test_cli_writes_report(tmp_path):
    pre = tmp_path / "pre.json"
    post = tmp_path / "post.json"
    output = tmp_path / "report.json"
    pre.write_text(json.dumps(PRE), encoding="utf-8")
    post.write_text(json.dumps(POST), encoding="utf-8")
    assert main([str(pre), str(post), "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["report_id"] == "evm-key-forensics-profanity-source-comparison-v1"
    assert report["overall_conclusion"] == "INCONCLUSIVE"
    reproducibility = report["reproducibility"]
    assert set(reproducibility["input_checker_result_sha256"]) == {"pre_disclosure", "post_disclosure"}
    assert all(len(value) == 64 for value in reproducibility["input_checker_result_sha256"].values())
    assert len(reproducibility["checker_script_sha256"]) == 64
    assert len(reproducibility["report_builder_sha256"]) == 64
    assert reproducibility["hashes_are_authenticity_proof"] is False


def test_function_body_fingerprint_difference_is_reported_without_promoting_conclusion():
    changed = copy.deepcopy(POST)
    changed["function_body_sha256"] = "d" * 64
    report = build_report(copy.deepcopy(PRE), changed)
    assert report["validation_errors"] == []
    assert report["source_comparison"]["same_create_seed_function_body_sha256"] is False
    assert report["overall_conclusion"] == "INCONCLUSIVE"


def test_invalid_function_body_fingerprint_is_rejected():
    changed = copy.deepcopy(PRE)
    changed["function_body_sha256"] = "not-a-digest"
    report = build_report(changed, copy.deepcopy(POST))
    assert "pre-disclosure:invalid_function_body_sha256" in report["validation_errors"]
    assert report["overall_conclusion"] == "INCONCLUSIVE"
