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
            "historical_profanity_code_executed": False,
            "wallet_material_used": False,
            "observations_are_entropy_proof": False,
        }
        (self.root / "probe-output.json").write_text(json.dumps(output), encoding="utf-8")
        metadata = {
            "schema_version": 1,
            "purpose": "diagnostic_environment_observation_only",
            "git_commit": "a" * 40,
            "github_run_id": "12345",
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
        self.assertTrue(all(result["checks"].values()))

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


if __name__ == "__main__":
    unittest.main()
