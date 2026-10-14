from __future__ import annotations

import io
import json
import stat
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

    def test_malformed_commit_sha_fails_closed(self):
        self.metadata["git_commit"] = "not-a-commit"
        self.members["complete-evidence/probe-evidence/probe-run-metadata.json"] = json.dumps(self.metadata).encode()
        self.write_archive()
        result = self.verify_with_stubbed_probe_check()
        self.assertFalse(result["integrity_verified"])
        self.assertIn("metadata_commit_sha_format", result["failed_checks"])

    def test_malformed_run_identity_fields_fail_closed(self):
        self.metadata["github_run_id"] = "１２３"
        self.metadata["github_run_attempt"] = "0"
        self.members["complete-evidence/probe-evidence/probe-run-metadata.json"] = json.dumps(self.metadata).encode()
        self.write_archive()
        result = self.verify_with_stubbed_probe_check()
        self.assertFalse(result["integrity_verified"])
        self.assertIn("metadata_run_id_format", result["failed_checks"])
        self.assertIn("metadata_run_attempt_format", result["failed_checks"])

    def test_malformed_git_ref_fails_closed(self):
        self.metadata["github_ref"] = "refs/heads/../main"
        self.rebuild["github_ref"] = self.metadata["github_ref"]
        self.index["workflow_ref"] = self.metadata["github_ref"]
        self.members["complete-evidence/probe-evidence/probe-run-metadata.json"] = json.dumps(self.metadata).encode()
        self.members["complete-evidence/independent-rebuild-report.json"] = json.dumps(self.rebuild).encode()
        self.members["complete-evidence/combined-evidence-index.json"] = json.dumps(self.index).encode()
        self.write_archive()
        result = self.verify_with_stubbed_probe_check()
        self.assertFalse(result["integrity_verified"])
        self.assertIn("metadata_ref_format", result["failed_checks"])

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

    def test_symlink_member_is_rejected(self):
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("complete-evidence/", b"")
            zf.writestr("complete-evidence/probe-evidence/", b"")
            for name, content in self.members.items():
                if name == "complete-evidence/probe-evidence/probe-source.cpp":
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    zf.writestr(info, b"outside.cpp")
                else:
                    zf.writestr(name, content)
        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_non_regular_member"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_fifo_member_is_rejected(self):
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("complete-evidence/", b"")
            zf.writestr("complete-evidence/probe-evidence/", b"")
            for name, content in self.members.items():
                if name == "complete-evidence/probe-evidence/probe-source.cpp":
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFIFO | 0o600) << 16
                    zf.writestr(info, content)
                else:
                    zf.writestr(name, content)
        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_non_regular_member"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_corrupt_compressed_member_fails_with_stable_error(self):
        member = "complete-evidence/probe-evidence/probe-source.cpp"
        with zipfile.ZipFile(self.archive, "r") as zf:
            info = zf.getinfo(member)
            payload_offset = info.header_offset + 30 + len(info.filename.encode("utf-8")) + len(info.extra)

        # Corrupt the compressed payload while preserving the central directory.
        with self.archive.open("r+b") as stream:
            stream.seek(payload_offset)
            stream.write(b"\xff")

        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_invalid_zip_member"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_unsupported_compression_method_fails_with_stable_error(self):
        member = "complete-evidence/probe-evidence/probe-source.cpp"
        with zipfile.ZipFile(self.archive, "r") as zf:
            info = zf.getinfo(member)
            local_header_offset = info.header_offset

        raw = self.archive.read_bytes()
        central_offset = raw.find(b"PK\x01\x02")
        encoded_name = member.encode("utf-8")
        while central_offset >= 0:
            name_length = int.from_bytes(raw[central_offset + 28:central_offset + 30], "little")
            name = raw[central_offset + 46:central_offset + 46 + name_length]
            if name == encoded_name:
                break
            central_offset = raw.find(b"PK\x01\x02", central_offset + 4)
        if central_offset < 0:
            self.fail("central directory entry not found")

        # Keep the archive structure readable, but declare an unsupported
        # compression method in both local and central headers.
        with self.archive.open("r+b") as stream:
            stream.seek(local_header_offset + 8)
            stream.write(b"\x63\x00")
            stream.seek(central_offset + 10)
            stream.write(b"\x63\x00")

        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_unsupported_compression_method"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_local_and_central_compression_mismatch_is_rejected(self):
        member = "complete-evidence/probe-evidence/probe-source.cpp"
        with zipfile.ZipFile(self.archive, "r") as zf:
            info = zf.getinfo(member)
            local_header_offset = info.header_offset

        # Change only the local header; the central directory still says DEFLATE.
        with self.archive.open("r+b") as stream:
            stream.seek(local_header_offset + 8)
            stream.write(b"\x63\x00")

        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_invalid_zip_member"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_local_and_central_flag_mismatch_is_rejected(self):
        member = "complete-evidence/probe-evidence/probe-source.cpp"
        with zipfile.ZipFile(self.archive, "r") as zf:
            info = zf.getinfo(member)
            local_header_offset = info.header_offset

        # Set the data-descriptor flag only in the local header.
        with self.archive.open("r+b") as stream:
            stream.seek(local_header_offset + 6)
            stream.write(b"\x08\x00")

        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_invalid_zip_member"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_local_header_name_mismatch_is_rejected(self):
        member = "complete-evidence/probe-evidence/probe-source.cpp"
        with zipfile.ZipFile(self.archive, "r") as zf:
            info = zf.getinfo(member)
            local_header_offset = info.header_offset
        # The local header filename must agree with the central directory.
        # Change one byte without changing the filename length or central entry.
        with self.archive.open("r+b") as stream:
            stream.seek(local_header_offset + 30)
            stream.write(b"X")
        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_invalid_zip_member"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_local_header_name_mismatch_is_rejected_by_header_validator(self):
        from tools.evm_key_forensics.verify_complete_evidence import (
            _validate_local_compression_method,
        )

        member = "complete-evidence/probe-evidence/probe-source.cpp"
        with zipfile.ZipFile(self.archive, "r") as zf:
            info = zf.getinfo(member)
        with self.archive.open("r+b") as stream:
            stream.seek(info.header_offset + 30)
            stream.write(b"X")
        with self.assertRaisesRegex(ValueError, "archive_invalid_zip_member"):
            _validate_local_compression_method(self.archive, info)

    def test_local_header_payload_bounds_are_checked(self):
        from tools.evm_key_forensics.verify_complete_evidence import (
            _validate_local_compression_method,
        )

        member = "complete-evidence/probe-evidence/probe-source.cpp"
        with zipfile.ZipFile(self.archive, "r") as zf:
            info = zf.getinfo(member)
        with patch.object(info, "compress_size", self.archive.stat().st_size):
            with self.assertRaisesRegex(ValueError, "archive_invalid_zip_member"):
                _validate_local_compression_method(self.archive, info)

    def test_local_payload_cannot_overlap_central_directory(self):
        from tools.evm_key_forensics.verify_complete_evidence import (
            _validate_local_compression_method,
        )

        member = "complete-evidence/probe-evidence/probe-source.cpp"
        with zipfile.ZipFile(self.archive, "r") as zf:
            info = zf.getinfo(member)
            central_directory_offset = zf.start_dir
        with self.assertRaisesRegex(ValueError, "archive_invalid_zip_member"):
            _validate_local_compression_method(
                self.archive,
                info,
                central_directory_offset=info.header_offset + 30 + len(info.filename.encode("cp437")),
            )

    def test_extreme_compression_ratio_is_rejected(self):
        self.members["complete-evidence/probe-evidence/probe-source.cpp"] = b"A" * (2 * 1024 * 1024)
        self.write_archive()
        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
            with self.assertRaisesRegex(ValueError, "archive_compression_ratio_exceeded"):
                verify_complete_archive(self.archive)
            verifier.assert_not_called()

    def test_probe_integrity_failure_propagates(self):
        with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact", return_value={"integrity_verified": False}):
            with self.assertRaisesRegex(ValueError, "probe_artifact_integrity_failed"):
                verify_complete_archive(self.archive)

    def test_archive_hashing_enforces_actual_bytes_read_limit(self):
        from tools.evm_key_forensics import verify_complete_evidence as verifier

        oversized = self.root / "oversized.bin"
        oversized.write_bytes(b"four")
        with patch.object(verifier, "MAX_ARCHIVE_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "archive_exceeds_size_limit"):
                verifier._sha256(oversized)

    def test_corrupt_central_directory_fails_with_stable_error(self):
        raw = self.archive.read_bytes()
        central_offset = raw.find(bytes.fromhex("504b0102"))
        if central_offset < 0:
            self.fail("central directory entry not found")
        with self.archive.open("r+b") as stream:
            stream.seek(central_offset)
            stream.write(bytes.fromhex("58580102"))
        with self.assertRaisesRegex(ValueError, "archive_invalid_zip_structure"):
            verify_complete_archive(self.archive)

    def test_missing_archive_fails_cleanly(self):
        missing = self.root / "missing.zip"
        with self.assertRaisesRegex(ValueError, "archive_must_be_regular_file"):
            verify_complete_archive(missing)

    def test_symlink_archive_fails_even_if_preliminary_checks_are_raced(self):
        from tools.evm_key_forensics import verify_complete_evidence as verifier

        real_archive = self.root / "real-archive.zip"
        real_archive.write_bytes(self.archive.read_bytes())
        symlink_archive = self.root / "archive-link.zip"
        try:
            symlink_archive.symlink_to(real_archive)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")

        with patch.object(Path, "is_symlink", return_value=False), patch.object(
            Path, "is_file", return_value=True
        ):
            with self.assertRaisesRegex(ValueError, "archive_must_be_regular_file"):
                verifier.verify_complete_archive(symlink_archive)

    def test_zip_directory_entries_are_supported(self):
        self.write_archive(directories=True)
        self.assertTrue(self.verify_with_stubbed_probe_check()["integrity_verified"])


    def test_archive_snapshot_enforces_actual_bytes_read_limit(self):
        from tools.evm_key_forensics import verify_complete_evidence as verifier

        with patch.object(verifier, "MAX_ARCHIVE_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "archive_exceeds_size_limit"):
                verifier.verify_complete_archive(self.archive)

    def test_data_descriptor_fields_are_validated(self):
        from tools.evm_key_forensics.verify_complete_evidence import (
            _validate_local_compression_method,
        )

        class NonSeekableBuffer(io.BytesIO):
            def seekable(self):
                return False

            def seek(self, *args, **kwargs):
                raise io.UnsupportedOperation("non-seekable test stream")

        fields = (
            ("CRC", 4),
            ("compressed size", 8),
            ("uncompressed size", 12),
        )
        for label, descriptor_field_offset in fields:
            with self.subTest(field=label):
                buffer = NonSeekableBuffer()
                with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("probe-source.cpp", b"synthetic fixture payload")
                archive_path = self.root / "descriptor.zip"
                archive_path.write_bytes(buffer.getvalue())

                with zipfile.ZipFile(archive_path, "r") as zf:
                    info = zf.getinfo("probe-source.cpp")
                    central_directory_offset = zf.start_dir
                    self.assertTrue(info.flag_bits & 0x08)
                    _validate_local_compression_method(
                        archive_path, info, central_directory_offset=central_directory_offset
                    )
                    descriptor_offset = (
                        info.header_offset + 30 + len(info.filename.encode("cp437"))
                        + len(info.extra) + info.compress_size
                    )

                # Python's writer emits the optional descriptor signature before CRC.
                with archive_path.open("r+b") as stream:
                    stream.seek(descriptor_offset)
                    self.assertEqual(stream.read(4), b"PK\x07\x08")
                    stream.seek(descriptor_offset + descriptor_field_offset)
                    stream.write(b"\x00\x00\x00\x00")

                with zipfile.ZipFile(archive_path, "r") as zf:
                    info = zf.getinfo("probe-source.cpp")
                    with self.assertRaisesRegex(ValueError, "archive_invalid_zip_member"):
                        _validate_local_compression_method(
                            archive_path, info, central_directory_offset=zf.start_dir
                        )

    def test_unsigned_data_descriptor_is_supported(self):
        from tools.evm_key_forensics.verify_complete_evidence import (
            _validate_local_compression_method,
        )

        class NonSeekableBuffer(io.BytesIO):
            def seekable(self):
                return False

            def seek(self, *args, **kwargs):
                raise io.UnsupportedOperation("non-seekable test stream")

        buffer = NonSeekableBuffer()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("probe-source.cpp", b"synthetic fixture payload")
        archive_path = self.root / "unsigned-descriptor.zip"
        archive_path.write_bytes(buffer.getvalue())

        with zipfile.ZipFile(archive_path, "r") as zf:
            info = zf.getinfo("probe-source.cpp")
            descriptor_offset = (
                info.header_offset + 30 + len(info.filename.encode("cp437"))
                + len(info.extra) + info.compress_size
            )
            crc = info.CRC.to_bytes(4, "little")
            compressed_size = info.compress_size.to_bytes(4, "little")
            file_size = info.file_size.to_bytes(4, "little")
            central_directory_offset = zf.start_dir

        # Replace the signed descriptor with the unsigned 12-byte form while
        # retaining the same space before the central directory.
        with archive_path.open("r+b") as stream:
            stream.seek(descriptor_offset)
            self.assertEqual(stream.read(4), b"PK\x07\x08")
            stream.seek(descriptor_offset)
            stream.write(crc + compressed_size + file_size + b"\x00\x00\x00\x00")

        with zipfile.ZipFile(archive_path, "r") as zf:
            info = zf.getinfo("probe-source.cpp")
            _validate_local_compression_method(
                archive_path, info, central_directory_offset=central_directory_offset
            )

    def test_local_crc_and_size_fields_must_match_central_directory(self):
        member = "complete-evidence/probe-evidence/probe-source.cpp"
        fields = (
            ("CRC", 14, b"\x00\x00\x00\x00"),
            ("compressed size", 18, b"\x01\x00\x00\x00"),
            ("uncompressed size", 22, b"\x01\x00\x00\x00"),
        )
        for label, offset, replacement in fields:
            with self.subTest(field=label):
                self.write_archive()
                with zipfile.ZipFile(self.archive, "r") as zf:
                    info = zf.getinfo(member)
                    original = self.archive.read_bytes()
                    current = original[info.header_offset + offset:info.header_offset + offset + 4]
                if current == replacement:
                    replacement = b"\x02\x00\x00\x00"
                with self.archive.open("r+b") as stream:
                    stream.seek(info.header_offset + offset)
                    stream.write(replacement)
                with patch("tools.evm_key_forensics.verify_complete_evidence.verify_artifact") as verifier:
                    with self.assertRaisesRegex(ValueError, "archive_invalid_zip_member"):
                        verify_complete_archive(self.archive)
                    verifier.assert_not_called()


if __name__ == "__main__":
    unittest.main()
