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
                json.dumps(metadata or self.metadata),
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
            self.verify("[]"),
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


if __name__ == "__main__":
    unittest.main()
