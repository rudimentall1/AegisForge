from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools.evm_key_forensics.verify_attestation import verify_attestation


class VerifyAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / "evm-key-forensics-complete-evidence.zip"
        self.sha = "a" * 40
        self.ref = "refs/pull/42/merge"
        self.run_id = "38520806120"
        self.attempt = "1"
        self.metadata = {
            "git_commit": self.sha,
            "github_sha": self.sha,
            "github_ref": self.ref,
            "github_run_id": self.run_id,
            "github_run_attempt": self.attempt,
        }
        self.write_archive()
        self.report = self.make_report()

    def tearDown(self):
        self.temp.cleanup()

    def write_archive(self, metadata=None):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                json.dumps(self.metadata if metadata is None else metadata),
            )

    def make_report(self, *, sha=None, ref=None, digest=None, repo= "rudimentall1/AegisForge", path=".github/workflows/evm-key-forensics-probe.yml"):
        archive_sha = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        certificate = {
            "githubWorkflowRepository": repo,
            "githubWorkflowName": "EVM Key Forensics Probe",
            "githubWorkflowSHA": sha or self.sha,
            "githubWorkflowRef": ref or self.ref,
        }
        statement = {
            "subject": [{
                "name": self.archive.name,
                "digest": {"sha256": digest or archive_sha},
            }],
            "predicate": {
                "buildDefinition": {
                    "externalParameters": {
                        "workflow": {
                            "path": path,
                            "repository": "https://github.com/rudimentall1/AegisForge",
                            "ref": ref or self.ref,
                        }
                    }
                },
                "runDetails": {
                    "metadata": {
                        "invocationId": (
                            "https://github.com/rudimentall1/AegisForge/actions/runs/"
                            + self.run_id + "/attempts/" + self.attempt
                        )
                    }
                }
            },
        }
        return json.dumps([{"verificationResult": {
            "signature": {"certificate": certificate},
            "statement": statement,
        }}])

    def verify(self, report=None):
        return verify_attestation(
            self.archive,
            expected_sha=self.sha,
            expected_ref=self.ref,
            expected_run_id=self.run_id,
            expected_attempt=self.attempt,
            gh_output=self.report if report is None else report,
        )

    def test_valid_attestation_and_subject_pass(self):
        result = self.verify()
        self.assertEqual(result["conclusion"], "PASS")
        self.assertEqual(result["subject_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(result["historical_vulnerability"], "INCONCLUSIVE")
        self.assertEqual(result["historical_source_to_binary_provenance"], "NOT_ESTABLISHED")

    def test_tampered_archive_subject_digest_fails(self):
        self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
            self.verify, self.make_report(digest="0" * 64),
        )

    def test_wrong_workflow_sha_fails(self):
        self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
            self.verify, self.make_report(sha="b" * 40),
        )

    def test_wrong_workflow_ref_fails(self):
        self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
            self.verify, self.make_report(ref="refs/heads/main"),
        )

    def test_wrong_workflow_path_fails(self):
        self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
            self.verify, self.make_report(path=".github/workflows/other.yml"),
        )

    def test_wrong_attested_run_id_fails(self):
        report = json.loads(self.report)
        report[0]["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = (
            "https://github.com/rudimentall1/AegisForge/actions/runs/999/attempts/1"
        )
        self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
            self.verify, json.dumps(report),
        )

    def test_wrong_attested_run_attempt_fails(self):
        report = json.loads(self.report)
        report[0]["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = (
            "https://github.com/rudimentall1/AegisForge/actions/runs/"
            + self.run_id + "/attempts/2"
        )
        self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
            self.verify, json.dumps(report),
        )

    def test_archive_metadata_mismatch_fails(self):
        changed = dict(self.metadata, github_run_id="999")
        self.write_archive(changed)
        self.assertRaisesRegex(
            ValueError, "archive_metadata_does_not_match_expected_run",
            self.verify,
        )

    def test_empty_attestation_report_fails(self):
        self.assertRaisesRegex(
            ValueError, "github_cli_returned_no_verified_attestations",
            self.verify, "[]",
        )

    @patch("tools.evm_key_forensics.verify_attestation.subprocess.run")
    def test_gh_failure_fails_closed(self, run):
        run.return_value.returncode = 1
        run.return_value.stdout = ""
        run.return_value.stderr = "verification failed"
        with self.assertRaisesRegex(ValueError, "github_cli_attestation_verification_failed"):
            verify_attestation(
                self.archive,
                expected_sha=self.sha,
                expected_ref=self.ref,
                expected_run_id=self.run_id,
                expected_attempt=self.attempt,
            )


    def test_duplicate_archive_member_fails(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                json.dumps(self.metadata),
            )
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                json.dumps(self.metadata),
            )
        with self.assertRaisesRegex(ValueError, "archive_duplicate_member"):
            self.verify()

    def test_archive_member_count_limit_fails(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                json.dumps(self.metadata),
            )
            for index in range(16):
                archive.writestr(f"extra-{index}.txt", "x")
        with self.assertRaisesRegex(ValueError, "archive_member_count_exceeded"):
            self.verify()

    def test_empty_metadata_object_fails(self):
        self.write_archive({})
        with self.assertRaisesRegex(ValueError, "archive_metadata_does_not_match_expected_run"):
            self.verify()

    def test_missing_metadata_member_fails_cleanly(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("unrelated.txt", "no run metadata")
        with self.assertRaisesRegex(ValueError, "probe_metadata_missing"):
            self.verify()

    def test_non_object_metadata_fails(self):
        self.write_archive([])
        with self.assertRaisesRegex(ValueError, "probe_metadata_must_be_object"):
            self.verify()

    def test_malformed_metadata_json_fails(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                "{not valid json",
            )
        with self.assertRaises(json.JSONDecodeError):
            self.verify()

    def test_metadata_size_limit_fails(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                " " * (2 * 1024 * 1024 + 1),
            )
        with self.assertRaisesRegex(ValueError, "probe_metadata_exceeds_size_limit"):
            self.verify()

    def test_symlink_archive_fails(self):
        target = self.root / "real-archive.zip"
        self.archive.replace(target)
        self.archive.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "archive_must_be_regular_file"):
            self.verify()


    def test_duplicate_metadata_json_key_fails(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                '{"git_commit":"' + self.sha + '","git_commit":"' + self.sha + '"}',
            )
        with self.assertRaisesRegex(ValueError, "duplicate_json_key:git_commit"):
            self.verify()

    def test_duplicate_attestation_report_json_key_fails(self):
        report = '[{"verificationResult":{},"verificationResult":{}}]'
        with self.assertRaisesRegex(ValueError, "duplicate_json_key:verificationResult"):
            self.verify(report)


    @patch("tools.evm_key_forensics.verify_attestation.subprocess.run")
    def test_missing_github_cli_fails_closed(self, run):
        run.side_effect = FileNotFoundError("gh")
        with self.assertRaisesRegex(ValueError, "github_cli_not_installed"):
            verify_attestation(
                self.archive,
                expected_sha=self.sha,
                expected_ref=self.ref,
                expected_run_id=self.run_id,
                expected_attempt=self.attempt,
            )

    @patch("tools.evm_key_forensics.verify_attestation.subprocess.run")
    def test_github_cli_timeout_fails_closed(self, run):
        import subprocess
        run.side_effect = subprocess.TimeoutExpired(cmd=["gh"], timeout=120)
        with self.assertRaisesRegex(ValueError, "github_cli_attestation_verification_timed_out"):
            verify_attestation(
                self.archive,
                expected_sha=self.sha,
                expected_ref=self.ref,
                expected_run_id=self.run_id,
                expected_attempt=self.attempt,
            )


if __name__ == "__main__":
    unittest.main()
