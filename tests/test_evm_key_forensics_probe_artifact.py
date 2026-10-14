from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.evm_key_forensics.verify_probe_artifact import main, verify_artifact


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProbeArtifactVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "probe-source.cpp").write_text("// pinned diagnostic source\n", encoding="utf-8")
        (self.root / "probe-binary").write_bytes(b"synthetic-test-binary")
        (self.root / "probe-binary-repeat").write_bytes(b"synthetic-test-binary")
        output = {
            "schema_version": 1,
            "probe": "std_random_device_environment_diagnostic",
            "historical_profanity_code_executed": False,
            "wallet_material_used": False,
            "observations_are_entropy_proof": False,
            "samples_requested": 64,
            "distinct_values_observed": 63,
            "random_device_result_type_bits": 32,
            "random_device_reported_entropy": 0.0,
        }
        (self.root / "probe-output.json").write_text(json.dumps(output), encoding="utf-8")
        source_report = {
            "schema_version": 1,
            "report_id": "evm-key-forensics-profanity-source-comparison-v1",
            "reproducibility": {
                "input_checker_result_sha256": {"pre_disclosure": "a" * 64, "post_disclosure": "b" * 64},
                "checker_script_sha256": "c" * 64,
                "report_builder_sha256": "d" * 64,
                "hashes_are_authenticity_proof": False,
            },
            "upstream_repository": "https://github.com/johguse/profanity",
            "evidence_class": "PINNED_SOURCE_PATTERN_INSPECTION",
            "source_comparison": {
                "pre_disclosure": {
                    "commit": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
                    "git_blob_sha1": "c9226fc02a52633a84664cbf3aaf2b4af8a59b25",
                    "function_body_sha256": "e" * 64,
                    "checker_conclusion": "SOURCE_PATTERN_MATCHED",
                    "validated": True,
                },
                "post_disclosure_archive": {
                    "commit": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
                    "git_blob_sha1": "884ced30ed6e55794ea5bda0451b52e81ddec1dd",
                    "function_body_sha256": "e" * 64,
                    "checker_conclusion": "SOURCE_PATTERN_MATCHED",
                    "validated": True,
                },
                "same_create_seed_function_body_sha256": True,
            },
            "overall_conclusion": "INCONCLUSIVE",
            "validation_errors": [],
            "limitations": {
                "historical_vulnerability_reproduced": False,
                "source_to_binary_provenance": "NOT_ESTABLISHED",
            },
        }
        (self.root / "source-evidence-report.json").write_text(json.dumps(source_report), encoding="utf-8")
        independent_review = {
            "status": "CHECKED",
            "method": "git_object_identity_plus_direct_function_text_comparison",
            "revisions": [
                {"revision": "pre_disclosure", "git_blob_sha1": "c9226fc02a52633a84664cbf3aaf2b4af8a59b25"},
                {"revision": "post_disclosure_archive", "git_blob_sha1": "884ced30ed6e55794ea5bda0451b52e81ddec1dd"},
            ],
            "same_function_body_bytes": True,
            "conclusion": "INCONCLUSIVE",
            "git_object_pin_verification": {
                "status": "CHECKED",
                "repository_label": "johguse/profanity",
                "checks": [
                    {
                        "revision": "pre_disclosure",
                        "repository": "johguse/profanity",
                        "commit_sha": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
                        "path": "Dispatcher.cpp",
                        "git_blob_sha": "c9226fc02a52633a84664cbf3aaf2b4af8a59b25",
                        "valid": True,
                        "git_object_match": True,
                        "provenance_verified": False,
                    },
                    {
                        "revision": "post_disclosure_archive",
                        "repository": "johguse/profanity",
                        "commit_sha": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
                        "path": "Dispatcher.cpp",
                        "git_blob_sha": "884ced30ed6e55794ea5bda0451b52e81ddec1dd",
                        "valid": True,
                        "git_object_match": True,
                        "provenance_verified": False,
                    },
                ],
                "provenance_verified": False,
                "note": "Local Git object consistency only; independent provenance is not established.",
            },
        }
        (self.root / "independent-source-body-review.json").write_text(json.dumps(independent_review), encoding="utf-8")
        metadata = {
            "schema_version": 1,
            "purpose": "diagnostic_environment_observation_only",
            "git_commit": "a" * 40,
            "github_sha": "a" * 40,
            "github_ref": "refs/pull/32/merge",
            "pull_request_head_sha": "b" * 40,
            "github_run_id": "12345",
            "github_run_attempt": "1",
            "runner_os": "test-runner",
            "compiler_version": "g++ test",
            "build_flags": ["-std=c++11", "-O2"],
            "source_sha256": digest(self.root / "probe-source.cpp"),
            "binary_sha256": digest(self.root / "probe-binary"),
            "repeat_binary_sha256": digest(self.root / "probe-binary-repeat"),
            "repeat_build_matches": True,
            "repeat_build_scope": "same_runner_same_compiler_same_flags",
            "output_sha256": digest(self.root / "probe-output.json"),
            "source_evidence_report_sha256": digest(self.root / "source-evidence-report.json"),
            "independent_source_body_review_sha256": digest(self.root / "independent-source-body-review.json"),
            "historical_vulnerability_reproduced": False,
            "entropy_proven": False,
        }
        (self.root / "probe-run-metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_artifact_passes(self):
        result = verify_artifact(self.root)
        self.assertTrue(result["integrity_verified"])
        self.assertEqual(result["authenticity"], "UNTRUSTED_UNSIGNED")
        self.assertFalse(result["signature_verified_against_trusted_key"])
        self.assertTrue(all(result["checks"].values()))

    def test_hash_consistency_does_not_claim_authenticity(self):
        result = verify_artifact(self.root)
        self.assertTrue(result["integrity_verified"])
        self.assertEqual(result["authenticity"], "UNTRUSTED_UNSIGNED")
        self.assertFalse(result["signature_verified_against_trusted_key"])

    def test_repeat_build_mismatch_is_rejected(self):
        repeat_path = self.root / "probe-binary-repeat"
        repeat_path.write_bytes(b"different-test-binary")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["repeat_binary_sha256"] = digest(repeat_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["repeat_build_is_byte_identical"])

    def test_missing_independent_source_review_is_rejected(self):
        (self.root / "independent-source-body-review.json").unlink()
        with self.assertRaisesRegex(ValueError, "artifact_file_missing_or_not_regular"):
            verify_artifact(self.root)

    def test_independent_source_review_hash_and_claim_are_checked(self):
        review_path = self.root / "independent-source-body-review.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["same_function_body_bytes"] = False
        review_path.write_text(json.dumps(review), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["independent_source_body_review_sha256"] = digest(review_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["independent_source_review_body_match_is_inconclusive"])

    def test_git_object_pin_report_rejects_false_match_even_with_updated_hash(self):
        review_path = self.root / "independent-source-body-review.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["git_object_pin_verification"]["checks"][0]["git_object_match"] = False
        review_path.write_text(json.dumps(review), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["independent_source_body_review_sha256"] = digest(review_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["git_object_pin_verification_matches_pins"])

    def test_git_object_pin_report_rejects_false_valid_flag_even_with_updated_hash(self):
        review_path = self.root / "independent-source-body-review.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["git_object_pin_verification"]["checks"][0]["valid"] = False
        review_path.write_text(json.dumps(review), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["independent_source_body_review_sha256"] = digest(review_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["git_object_pin_verification_matches_pins"])

    def test_git_object_pin_report_rejects_missing_valid_flag_even_with_updated_hash(self):
        review_path = self.root / "independent-source-body-review.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        del review["git_object_pin_verification"]["checks"][0]["valid"]
        review_path.write_text(json.dumps(review), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["independent_source_body_review_sha256"] = digest(review_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["git_object_pin_verification_matches_pins"])

    def test_malformed_git_pin_revision_type_fails_integrity_without_crashing(self):
        review_path = self.root / "independent-source-body-review.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["git_object_pin_verification"]["checks"][0]["revision"] = []
        review_path.write_text(json.dumps(review), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["independent_source_body_review_sha256"] = digest(review_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["git_object_pin_verification_matches_pins"])

    def test_git_object_pin_report_does_not_claim_provenance(self):
        review_path = self.root / "independent-source-body-review.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["git_object_pin_verification"]["provenance_verified"] = True
        review_path.write_text(json.dumps(review), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["independent_source_body_review_sha256"] = digest(review_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["git_object_pin_verification_schema_supported"])

    def test_independent_source_review_rejects_wrong_blob_even_with_updated_hash(self):
        review_path = self.root / "independent-source-body-review.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["revisions"][0]["git_blob_sha1"] = "0" * 40
        review_path.write_text(json.dumps(review), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["independent_source_body_review_sha256"] = digest(review_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["independent_source_review_pins_match"])

    def test_missing_source_report_is_rejected(self):
        (self.root / "source-evidence-report.json").unlink()
        with self.assertRaisesRegex(ValueError, "artifact_file_missing_or_not_regular"):
            verify_artifact(self.root)

    def test_malformed_source_report_limitations_fail_closed(self):
        report_path = self.root / "source-evidence-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["limitations"] = []
        report_path.write_text(json.dumps(report), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["source_evidence_report_sha256"] = digest(report_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["source_report_does_not_claim_reproduction"])
        self.assertFalse(result["checks"]["source_report_does_not_claim_source_binary_provenance"])

    def test_source_report_rejects_wrong_pinned_revision_even_with_updated_hash(self):
        report_path = self.root / "source-evidence-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["source_comparison"]["pre_disclosure"]["commit"] = "f" * 40
        report_path.write_text(json.dumps(report), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["source_evidence_report_sha256"] = digest(report_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["source_report_pre_revision_matches_pin"])

    def test_source_report_rejects_unvalidated_revision_even_with_updated_hash(self):
        report_path = self.root / "source-evidence-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["source_comparison"]["post_disclosure_archive"]["validated"] = False
        report_path.write_text(json.dumps(report), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["source_evidence_report_sha256"] = digest(report_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["source_report_post_revision_matches_pin"])

    def test_source_report_requires_reproducibility_hashes(self):
        report_path = self.root / "source-evidence-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["reproducibility"]["checker_script_sha256"] = "not-a-hash"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["source_evidence_report_sha256"] = digest(report_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["source_report_reproducibility_hashes_well_formed"])

    def test_source_report_is_bound_to_metadata_hash(self):
        report_path = self.root / "source-evidence-report.json"
        report_path.write_text(report_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["source_report_hash_matches"])

    def test_source_report_cannot_claim_historical_reproduction_even_with_updated_hash(self):
        report_path = self.root / "source-evidence-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["limitations"]["historical_vulnerability_reproduced"] = True
        report_path.write_text(json.dumps(report), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["source_evidence_report_sha256"] = digest(report_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["source_report_does_not_claim_reproduction"])

    def test_source_report_cannot_claim_binary_provenance_even_with_updated_hash(self):
        report_path = self.root / "source-evidence-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["limitations"]["source_to_binary_provenance"] = "VERIFIED"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["source_evidence_report_sha256"] = digest(report_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["source_report_does_not_claim_source_binary_provenance"])

    def test_extremely_large_reported_entropy_fails_without_crashing(self):
        output_path = self.root / "probe-output.json"
        raw = output_path.read_text(encoding="utf-8")
        raw = raw.replace(
            '"random_device_reported_entropy": 0.0',
            '"random_device_reported_entropy": ' + ("9" * 4000),
        )
        output_path.write_text(raw, encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["output_sha256"] = digest(output_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["reported_entropy_is_finite_nonnegative"])

    def test_tampered_output_fails(self):
        with (self.root / "probe-output.json").open("a", encoding="utf-8") as stream:
            stream.write(" ")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["output_hash_matches"])

    def test_metadata_cannot_claim_historical_reproduction(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["historical_vulnerability_reproduced"] = True
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["historical_vulnerability_not_claimed"])

    def test_invalid_sample_count_fails_even_with_updated_hash(self):
        output_path = self.root / "probe-output.json"
        output = json.loads(output_path.read_text(encoding="utf-8"))
        output["samples_requested"] = 0
        output_path.write_text(json.dumps(output), encoding="utf-8")

        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["output_sha256"] = digest(output_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["sample_count_in_bounds"])


    def test_non_finite_reported_entropy_fails_even_with_updated_hash(self):
        output_path = self.root / "probe-output.json"
        output = json.loads(output_path.read_text(encoding="utf-8"))
        output["random_device_reported_entropy"] = 0.0
        encoded = json.dumps(output).replace(
            '"random_device_reported_entropy": 0.0',
            '"random_device_reported_entropy": 1e999',
        )
        output_path.write_text(encoded, encoding="utf-8")

        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["output_sha256"] = digest(output_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["reported_entropy_is_finite_nonnegative"])


    def test_duplicate_json_keys_are_rejected(self):
        output_path = self.root / "probe-output.json"
        original = output_path.read_text(encoding="utf-8")
        output_path.write_text(
            original[:-1] + ', "historical_profanity_code_executed": true}',
            encoding="utf-8",
        )
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["output_sha256"] = digest(output_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
            verify_artifact(self.root)

    def test_nonstandard_json_constants_are_rejected(self):
        output_path = self.root / "probe-output.json"
        original = output_path.read_text(encoding="utf-8")
        output_path.write_text(original[:-1] + ', "extra": NaN}', encoding="utf-8")
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["output_sha256"] = digest(output_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "nonstandard_json_constant"):
            verify_artifact(self.root)

    def test_historical_execution_claim_fails_even_with_updated_hash(self):
        output_path = self.root / "probe-output.json"
        output = json.loads(output_path.read_text(encoding="utf-8"))
        output["historical_profanity_code_executed"] = True
        output_path.write_text(json.dumps(output), encoding="utf-8")

        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["output_sha256"] = digest(output_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["probe_does_not_claim_historical_execution"])




    def test_non_hex_commit_record_is_rejected(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["git_commit"] = "g" * 40
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["commit_recorded"])

    def test_boolean_metadata_schema_version_is_rejected(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["schema_version"] = True
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["schema_version_supported"])

    def test_boolean_output_schema_version_is_rejected_even_with_updated_hash(self):
        output_path = self.root / "probe-output.json"
        output = json.loads(output_path.read_text(encoding="utf-8"))
        output["schema_version"] = True
        output_path.write_text(json.dumps(output), encoding="utf-8")

        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["output_sha256"] = digest(output_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["output_schema_supported"])

    def test_oversized_metadata_is_rejected_before_json_decode(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata_path.write_bytes(b" " * (2 * 1024 * 1024 + 1))

        with self.assertRaisesRegex(ValueError, "json_file_exceeds_size_limit"):
            verify_artifact(self.root)

    def test_oversized_output_is_rejected_before_json_decode(self):
        output_path = self.root / "probe-output.json"
        output_path.write_bytes(b" " * (2 * 1024 * 1024 + 1))

        with self.assertRaisesRegex(ValueError, "json_file_exceeds_size_limit"):
            verify_artifact(self.root)


    def test_symlinked_artifact_file_is_rejected(self):
        source_path = self.root / "probe-source.cpp"
        external_source = self.root.parent / (self.root.name + "-external-source.cpp")
        external_source.write_text("// external file\n", encoding="utf-8")
        source_path.unlink()
        try:
            source_path.symlink_to(external_source)
            with self.assertRaisesRegex(ValueError, "artifact_file_must_not_be_symlink"):
                verify_artifact(self.root)
        finally:
            if source_path.is_symlink():
                source_path.unlink()
            external_source.unlink(missing_ok=True)

    def test_metadata_json_root_must_be_object(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata_path.write_text("[]", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "json_root_must_be_object"):
            verify_artifact(self.root)

    def test_output_json_root_must_be_object(self):
        output_path = self.root / "probe-output.json"
        output_path.write_text("null", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "json_root_must_be_object"):
            verify_artifact(self.root)

    def test_excessively_nested_json_is_rejected_cleanly(self):
        output_path = self.root / "probe-output.json"
        output_path.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "json_nesting_limit_exceeded"):
            verify_artifact(self.root)

    def test_non_utf8_json_is_rejected_with_clear_error(self):
        output_path = self.root / "probe-output.json"
        output_path.write_bytes(b"\xff")

        with self.assertRaisesRegex(ValueError, "json_file_invalid_utf8"):
            verify_artifact(self.root)


    def test_symlinked_artifact_directory_is_rejected(self):
        link = self.root.parent / (self.root.name + "-bundle-link")
        try:
            link.symlink_to(self.root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "artifact_directory_must_not_be_symlink"):
                verify_artifact(link)
        finally:
            if link.is_symlink():
                link.unlink()

    def test_non_directory_artifact_root_is_rejected(self):
        not_a_directory = self.root / "not-a-directory"
        not_a_directory.write_text("not a directory", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "artifact_directory_missing_or_not_directory"):
            verify_artifact(not_a_directory)

    def test_oversized_source_is_rejected_during_bounded_hashing(self):
        source_path = self.root / "probe-source.cpp"
        source_path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))

        with self.assertRaisesRegex(ValueError, "artifact_file_exceeds_size_limit"):
            verify_artifact(self.root)

    def test_oversized_binary_is_rejected_during_bounded_hashing(self):
        binary_path = self.root / "probe-binary"
        binary_path.write_bytes(b"x" * (64 * 1024 * 1024 + 1))

        with self.assertRaisesRegex(ValueError, "artifact_file_exceeds_size_limit"):
            verify_artifact(self.root)

    def test_invalid_build_flags_type_fails_integrity(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["build_flags"] = "-O2"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["build_flags_recorded"])

    def test_workflow_checkout_commit_must_match_github_sha(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["github_sha"] = "b" * 40
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["workflow_checkout_commit_matches_github_sha"])

    def test_pull_request_head_sha_must_be_valid_or_null(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["pull_request_head_sha"] = "not-a-commit"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["pull_request_head_sha_valid_or_null"])

    def test_zero_github_run_id_fails_integrity(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["github_run_id"] = "0"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["run_id_recorded"])

    def test_zero_github_run_attempt_fails_integrity(self):
        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["github_run_attempt"] = "0"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["run_attempt_recorded"])


    def test_tampered_source_fails_hash_check(self):
        source_path = self.root / "probe-source.cpp"
        source_path.write_text("// changed after manifest creation\\n", encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["source_hash_matches"])

    def test_tampered_binary_fails_hash_check(self):
        binary_path = self.root / "probe-binary"
        binary_path.write_bytes(b"changed binary")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["binary_hash_matches"])

    def test_cli_success_emits_unsigned_integrity_result(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main([str(self.root)])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertTrue(payload["integrity_verified"])
        self.assertEqual(payload["authenticity"], "UNTRUSTED_UNSIGNED")

    def test_cli_missing_directory_returns_sanitized_error(self):
        missing = self.root / "does-not-exist"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main([str(missing)])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(status, 1)
        self.assertFalse(payload["integrity_verified"])
        self.assertEqual(payload["error"], "ValueError")
        self.assertNotIn(str(missing), stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
