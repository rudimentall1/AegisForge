from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.evm_key_forensics.verify_probe_artifact import verify_artifact


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProbeArtifactVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "probe-source.cpp").write_text("// pinned diagnostic source\n", encoding="utf-8")
        (self.root / "probe-binary").write_bytes(b"synthetic-test-binary")
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
        metadata = {
            "schema_version": 1,
            "purpose": "diagnostic_environment_observation_only",
            "git_commit": "a" * 40,
            "github_run_id": "12345",
            "github_run_attempt": "1",
            "runner_os": "test-runner",
            "compiler_version": "g++ test",
            "build_flags": ["-std=c++11", "-O2"],
            "source_sha256": digest(self.root / "probe-source.cpp"),
            "binary_sha256": digest(self.root / "probe-binary"),
            "output_sha256": digest(self.root / "probe-output.json"),
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
        output["random_device_reported_entropy"] = float("inf")
        output_path.write_text(json.dumps(output), encoding="utf-8")

        metadata_path = self.root / "probe-run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["output_sha256"] = digest(output_path)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        result = verify_artifact(self.root)
        self.assertFalse(result["integrity_verified"])
        self.assertFalse(result["checks"]["reported_entropy_is_finite_nonnegative"])

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


if __name__ == "__main__":
    unittest.main()
