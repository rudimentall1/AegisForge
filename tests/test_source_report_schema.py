from tools.evm_key_forensics.source_report_schema import validate_source_report_schema

def valid_report():
    return {
        "schema_version": 1,
        "report_id": "evm-key-forensics-profanity-source-comparison-v1",
        "experiment_id": "evm-forensics-historical-source-pattern-v1",
        "upstream_repository": "https://github.com/johguse/profanity",
        "evidence_class": "PINNED_SOURCE_PATTERN_INSPECTION",
        "overall_conclusion": "INCONCLUSIVE",
        "source_comparison": {
            "pre_disclosure": {"commit": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6", "git_blob_sha1": "c9226fc02a52633a84664cbf3aaf2b4af8a59b25", "source_sha256": "a"*64, "function_body_sha256": "b"*64, "checker_conclusion": "SOURCE_PATTERN_MATCHED", "validated": True},
            "post_disclosure_archive": {"commit": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e", "git_blob_sha1": "884ced30ed6e55794ea5bda0451b52e81ddec1dd", "source_sha256": "c"*64, "function_body_sha256": "d"*64, "checker_conclusion": "SOURCE_PATTERN_MATCHED", "validated": True},
            "same_source_sha256": False, "same_create_seed_function_body_sha256": True, "same_git_blob_sha1": False,
        },
        "validation_errors": [],
        "interpretation": "The report reconciles source-pattern checker outputs for two pinned source revisions. A matching pattern is source-inspection evidence only; it does not establish runtime entropy, exploitability, key predictability, wallet exposure, or historical vulnerability reproduction.",
        "limitations": {"historical_code_executed": False, "wallet_material_used": False, "historical_vulnerability_reproduced": False, "source_to_binary_provenance": "NOT_ESTABLISHED", "source_review_runner_attestation": "NOT_IMPLEMENTED", "evidence_package_github_attestation": "CHECKED_BY_SEPARATE_WORKFLOW_STEP; DOES_NOT_AUTHENTICATE_SOURCE_CLAIMS", "independent_review": "PENDING"},
    }

def test_accepts_conservative_pinned_report():
    assert validate_source_report_schema(valid_report())

def test_rejects_unknown_top_level_claim_even_if_hashes_are_recomputed():
    report = valid_report(); report["agent_verified_historical_exploit"] = True
    assert not validate_source_report_schema(report)

def test_rejects_unknown_nested_claim():
    report = valid_report(); report["source_comparison"]["pre_disclosure"]["wallet_exposure_confirmed"] = True
    assert not validate_source_report_schema(report)

def test_rejects_promoted_conclusion():
    report = valid_report(); report["overall_conclusion"] = "CONFIRMED"
    assert not validate_source_report_schema(report)

def test_rejects_inconsistent_comparison_flag():
    report = valid_report(); report["source_comparison"]["same_source_sha256"] = True
    assert not validate_source_report_schema(report)


def test_rejects_modified_interpretation_claim():
    report = valid_report(); report["interpretation"] = "Wallet exposure confirmed."
    assert not validate_source_report_schema(report)


def test_rejects_unpinned_revision():
    report = valid_report(); report["source_comparison"]["pre_disclosure"]["commit"] = "f"*40
    assert not validate_source_report_schema(report)

def test_rejects_unsigned_hashes_claimed_as_authenticity():
    report = valid_report(); report["reproducibility"] = {"input_checker_result_sha256": {"pre_disclosure": "a"*64, "post_disclosure": "b"*64}, "checker_script_sha256": "c"*64, "report_builder_sha256": "d"*64, "hashes_are_authenticity_proof": True}
    assert not validate_source_report_schema(report)
