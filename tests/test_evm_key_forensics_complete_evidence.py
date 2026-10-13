from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools.evm_key_forensics.verify_complete_evidence import (
    EXPECTED_MEMBERS,
    verify_complete_archive,
)


class CompleteEvidenceVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / "complete.zip"
        self.run_id = "12345"
        self.attempt = "1"
        self.sha = "a" * 40
        self.ref = "refs/pull/32/merge"
        self.source_hash = "b" * 64
        self.binary_hash = "c" * 64
        self.metadata = {
            "schema_version": 1,
            "git_commit": self.sha,
            "github_sha": self.sha,
            "github_ref": self.ref,
            "github_run_id": self.run_id,
            "github_run_attempt": self.attempt,
            "source_sha256": self.source_hash,
            "binary_sha256": self.binary_hash,
            "historical_vulnerability_reproduced": False,
        }
        self.rebuild = {
            "check": "independent_clean_runner_rebuild",
            "conclusion": "PASS",
            "github_sha": self.sha,
            "github_ref": self.ref,
            "github_run_id": self.run_id,
            "github_run_attempt": self.attempt,
            "source_matches": True,
            "binary_matches": True,
            "reference_source_sha256": self.source_hash,
            "independent_checkout_source_sha256": self.source_hash,
            "reference_binary_sha256": self.binary_hash,
            "independent_rebuild_binary_sha256": self.binary_hash,
        }
        self.index = {
            "schema_version": 1,
            "conclusion": "PASS",
            "probe_and_rebuild_evidence_consistent": True,
            "historical_profanity_executed": False,
            "historical_vulnerability_reproduced": False,
            "run_id": self.run_id,
            "run_attempt": self.attempt,
            "workflow_sha": self.sha,
            "workflow_ref": self.ref,
            "probe_source_sha256": self.source_hash,
            "independent_rebuild_source_sha256": self.source_hash,
            "probe_binary_sha256": self.binary_hash,
            "independent_rebuild_binary_sha256": self.binary_hash,
        }
        self.members = {
            name: b"synthetic fixture"
            for name in EXPECTED_MEMBERS
        }
        self.members["complete-evidence/probe-evidence/probe-run-metadata.json"] = json.dumps(self.metadata).encode()
        self.members["complete-evidence/independent-rebuild-report.json"] = json.dumps(self.rebuild).encode()
        self.members["complete-evidence/combined-evidence-index.json"] = json.dumps(self.index).encode()
        self.write_archive()

    def tearDown(self):
        self.temp.cleanup()

    def write_archive(self, *, extra=None, duplicate=None, directories=True):
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            if directories:
                zf.writestr("complete-evidence/", b"")
                zf.writestr("complete-evidence/probe-evidence/", b"")
            for name, content in self.members.items():
                zf.writestr(name, content)
            if extra:
                zf.writestr(extra, b"unexpected")
            if duplicate:
                zf.writestr(duplicate, b"second copy")

    def verify_with_stubbed_probe_check(self):
        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact", return_value={"integrity_verified": True}):
            return verify_complete_archive(self.archive)

    def test_valid_combined_archive_passes_cross_link_checks(self):
        result = self.verify_with_stubbed_probe_check()
        self.assertTrue(result["integrity_verified"])
        self.assertEqual(result["authenticity"], "UNTRUSTED_UNSIGNED")
        self.assertEqual(result["github_attestation"], "NOT_CHECKED_OFFLINE")
        self.assertTrue(all(result["checks"].values()))

    def test_mismatched_rebuild_hash_fails_closed(self):
        self.rebuild["independent_rebuild_binary_sha256"] = "d" * 64
        self.members["complete-evidence/independent-rebuild-report.json"] = json.dumps(self.rebuild).encode()
        self.write_archive()
        result = self.verify_with_stubbed_probe_check()
        self.assertFalse(result["integrity_verified"])
        self.assertIn("binary_sha256_cross_run_linkage", result["failed_checks"])

    def test_wrong_run_attempt_fails_closed(self):
        self.rebuild["github_run_attempt"] = "2"
        self.members["complete-evidence/independent-rebuild-report.json"] = json.dumps(self.rebuild).encode()
        self.write_archive()
        result = self.verify_with_stubbed_probe_check()
        self.assertFalse(result["integrity_verified"])
        self.assertIn("index_run_attempt_matches_metadata", result["failed_checks"])

    def test_unexpected_member_is_rejected(self):
        self.write_archive(extra="complete-evidence/extra.txt")
        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_member_set_mismatch"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_duplicate_member_is_rejected(self):
        member = next(iter(self.members))
        self.write_archive(duplicate=member)
        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_duplicate_member"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_path_traversal_member_is_rejected(self):
        self.write_archive(extra="complete-evidence/../outside.json")
        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_member_set_mismatch"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_missing_archive_fails_cleanly(self):
        missing = self.root / "missing.zip"
        with self.assertRaisesRegex(ValueError, "archive_must_be_regular_file"):
            verify_complete_archive(missing)

    def test_zip_directory_entries_are_supported(self):
        self.write_archive(directories=True)
        self.assertTrue(self.verify_with_stubbed_probe_check()["integrity_verified"])


if __name__ == "__main__":
    unittest.main()
