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
        self.ref = "refs/heads/main"
        self.run_id = "38520806120"
        self.attempt = "1"
        self.trigger = "workflow_dispatch"
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

    def make_report(self, *, sha=None, ref=None, digest=None, repo="rudimentall1/AegisForge", path=".github/workflows/evm-key-forensics-probe.yml", trigger=None):
        archive_sha = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        certificate = {
            "githubWorkflowRepository": repo,
            "githubWorkflowName": "EVM Key Forensics Probe",
            "githubWorkflowSHA": sha or self.sha,
            "githubWorkflowRef": ref or self.ref,
            "githubWorkflowTrigger": trigger or self.trigger,
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
            expected_trigger=self.trigger,
            gh_output=self.report if report is None else report,
        )

    @patch("tools.evm_key_forensics.verify_attestation.subprocess.run")
    def test_unsupported_expected_trigger_fails_before_cli(self, run):
        with self.assertRaisesRegex(ValueError, "unsupported_expected_workflow_trigger"):
            verify_attestation(
                self.archive,
                expected_sha=self.sha,
                expected_ref=self.ref,
                expected_run_id=self.run_id,
                expected_attempt=self.attempt,
                expected_trigger="schedule",
            )
        run.assert_not_called()

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
            self.verify, self.make_report(ref="refs/heads/release"),
        )

    def test_wrong_workflow_trigger_fails(self):
        self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
            self.verify, self.make_report(trigger="pull_request"),
        )

    @patch("tools.evm_key_forensics.verify_attestation.subprocess.run")
    def test_pull_request_is_not_an_allowed_expected_trigger(self, run):
        with self.assertRaisesRegex(ValueError, "unsupported_expected_workflow_trigger"):
            verify_attestation(
                self.archive,
                expected_sha=self.sha,
                expected_ref="refs/pull/42/merge",
                expected_run_id=self.run_id,
                expected_attempt=self.attempt,
                expected_trigger="pull_request",
            )
        run.assert_not_called()

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
                expected_trigger=self.trigger,
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

    def test_unsupported_metadata_compression_fails_with_stable_error(self):
        raw = bytearray(self.archive.read_bytes())
        local_header = raw.find(b"PK\\x03\\x04")
        central_header = raw.find(b"PK\\x01\\x02")
        self.assertGreaterEqual(local_header, 0)
        self.assertGreaterEqual(central_header, 0)
        # Compression method 99 is not supported by the Python ZIP reader.
        raw[local_header + 8:local_header + 10] = (99).to_bytes(2, "little")
        raw[central_header + 10:central_header + 12] = (99).to_bytes(2, "little")
        self.archive.write_bytes(raw)

        with self.assertRaisesRegex(
            ValueError, "probe_metadata_unsupported_compression_method"
        ):
            self.verify()

    def test_corrupt_compressed_metadata_fails_with_stable_error(self):
        member = "complete-evidence/probe-evidence/probe-run-metadata.json"
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(member, json.dumps(self.metadata) + (" " * 4096))
        with zipfile.ZipFile(self.archive, "r") as archive:
            info = archive.getinfo(member)
            payload_offset = (
                info.header_offset + 30
                + len(info.filename.encode("utf-8"))
                + len(info.extra)
            )
        with self.archive.open("r+b") as stream:
            stream.seek(payload_offset)
            stream.write(bytes([0xFF]))

        with self.assertRaisesRegex(ValueError, "probe_metadata_invalid_zip_member"):
            self.verify()

    def test_malformed_metadata_json_fails(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                "{not valid json",
            )
        with self.assertRaises(json.JSONDecodeError):
            self.verify()

    def test_nonstandard_json_constant_in_metadata_fails(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                '{"git_commit":"' + self.sha + '","unexpected":NaN}',
            )
        with self.assertRaisesRegex(ValueError, "nonstandard_json_constant:NaN"):
            self.verify()

    def test_invalid_utf8_metadata_fails_cleanly(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                b'{"metadata":"' + bytes([0xFF]) + b'"}',
            )
        with self.assertRaisesRegex(ValueError, "probe_metadata_invalid_utf8"):
            self.verify()

    def test_deeply_nested_metadata_fails_cleanly(self):
        nested = "[" * 2000 + "0" + "]" * 2000
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                nested,
            )
        with self.assertRaisesRegex(ValueError, "probe_metadata_nesting_limit_exceeded"):
            self.verify()

    def test_metadata_size_limit_fails(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(
                "complete-evidence/probe-evidence/probe-run-metadata.json",
                " " * (2 * 1024 * 1024 + 1),
            )
        with self.assertRaisesRegex(ValueError, "probe_metadata_exceeds_size_limit"):
            self.verify()

    def test_archive_hashing_enforces_actual_bytes_read_limit(self):
        from tools.evm_key_forensics import verify_attestation as verifier

        oversized = self.root / "oversized.bin"
        oversized.write_bytes(b"four")
        with patch.object(verifier, "MAX_ARCHIVE_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "archive_exceeds_size_limit"):
                verifier._sha256(oversized)

    def test_symlink_archive_fails_even_if_path_checks_are_raced(self):
        target = self.root / "real-target.zip"
        target.write_bytes(self.archive.read_bytes())
        self.archive.unlink()
        self.archive.symlink_to(target)
        with patch.object(Path, "is_symlink", return_value=False), patch.object(
            Path, "is_file", return_value=True
        ):
            with self.assertRaisesRegex(ValueError, "archive_must_be_regular_file"):
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
                expected_trigger=self.trigger,
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
                expected_trigger=self.trigger,
            )


    def test_missing_invocation_id_fails_closed(self):
        report = json.loads(self.report)
        del report[0]["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"]
        with self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
        ):
            self.verify(json.dumps(report))

    def test_non_string_invocation_id_fails_closed(self):
        report = json.loads(self.report)
        report[0]["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = 123
        with self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
        ):
            self.verify(json.dumps(report))

    def test_malformed_attestation_entries_do_not_mask_missing_valid_match(self):
        report = [
            {"verificationResult": {"statement": {"predicate": []}}},
            {"verificationResult": {"signature": {}, "statement": {}}},
            {"unexpected": "shape"},
        ]
        with self.assertRaisesRegex(
            ValueError, "verified_attestation_identity_or_subject_mismatch",
        ):
            self.verify(json.dumps(report))


    def test_attestation_report_size_limit_fails(self):
        from tools.evm_key_forensics.verify_attestation import MAX_ATTESTATION_REPORT_BYTES
        oversized = " " * (MAX_ATTESTATION_REPORT_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "attestation_report_exceeds_size_limit"):
            self.verify(oversized)

    def test_nonstandard_json_constant_in_attestation_report_fails(self):
        with self.assertRaisesRegex(ValueError, "nonstandard_json_constant:NaN"):
            self.verify("[NaN]")


    def test_attestation_snapshot_enforces_actual_bytes_read_limit(self):
        from tools.evm_key_forensics import verify_attestation as verifier

        with patch.object(verifier, "MAX_ARCHIVE_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "archive_exceeds_size_limit"):
                verifier.verify_attestation(
                    self.archive,
                    expected_sha=self.sha,
                    expected_ref=self.ref,
                    expected_run_id=self.run_id,
                    expected_attempt=self.attempt,
                    expected_trigger=self.trigger,
                    gh_output=self.report,
                )

    def test_bounded_member_reader_rejects_actual_decompressed_size_over_limit(self):
        from tools.evm_key_forensics.verify_attestation import _read_bounded_member

        archive_path = self.root / "oversized-metadata.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("metadata.json", b"four")
        with zipfile.ZipFile(archive_path, "r") as archive:
            info = archive.getinfo("metadata.json")
            with self.assertRaisesRegex(ValueError, "probe_metadata_exceeds_size_limit"):
                _read_bounded_member(archive, info, 3)


    @patch("tools.evm_key_forensics.verify_attestation.subprocess.run")
    def test_real_cli_invocation_is_pinned_and_bounded(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = self.report
        run.return_value.stderr = ""
        result = verify_attestation(
            self.archive,
            expected_sha=self.sha,
            expected_ref=self.ref,
            expected_run_id=self.run_id,
            expected_attempt=self.attempt,
            expected_trigger=self.trigger,
        )
        self.assertEqual(result["conclusion"], "PASS")
        kwargs = run.call_args.kwargs
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["gh", "attestation", "verify"])
        self.assertEqual(command[command.index("--repo") + 1], "rudimentall1/AegisForge")
        self.assertEqual(
            command[command.index("--signer-workflow") + 1],
            "rudimentall1/AegisForge/.github/workflows/evm-key-forensics-probe.yml",
        )
        self.assertEqual(command[command.index("--format") + 1], "json")
        self.assertEqual(kwargs["timeout"], 120)
        self.assertTrue(kwargs["check"] is False)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])


if __name__ == "__main__":
    unittest.main()
