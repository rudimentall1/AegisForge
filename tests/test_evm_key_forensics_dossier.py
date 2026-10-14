from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.evm_key_forensics.validate_source_dossier import main, validate_dossier


DOSSIER = {
    "schema_version": 1,
    "dossier_id": "evm-key-forensics-profanity-source-evidence-v1",
    "status": "SOURCE_REVIEW_ONLY",
    "generated_for_branch": "feat/evm-git-object-source-verifier",
    "reviewed_upstream": {
        "repository": "https://github.com/johguse/profanity",
        "files": [
            {
                "role": "pre-disclosure",
                "commit": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
                "path": "Dispatcher.cpp",
                "url": "https://github.com/johguse/profanity/blob/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/Dispatcher.cpp",
                "git_blob_sha1": "c9226fc02a52633a84664cbf3aaf2b4af8a59b25",
            },
            {
                "role": "post-disclosure-archive",
                "commit": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
                "path": "Dispatcher.cpp",
                "url": "https://github.com/johguse/profanity/blob/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/Dispatcher.cpp",
                "git_blob_sha1": "884ced30ed6e55794ea5bda0451b52e81ddec1dd",
            },
        ],
        "supporting_references": [],
    },
    "claim_register": [
        {"id": "SRC-001", "claim": "source claim", "evidence_level": "E0_SOURCE_INSPECTION",
         "status": "SUPPORTED_BY_PINNED_SOURCE_PATTERN_CHECK", "does_not_establish": ["entropy", "exploitability"]},
        {"id": "SRC-002", "claim": "identity claim", "evidence_level": "SOURCE_IDENTITY",
         "status": "CHECKED_BY_SOURCE_PATTERN_CLI", "does_not_establish": ["authorship", "binary provenance"]},
    ],
    "verification_contract": {
        "checker": "tools/evm_key_forensics/check_historical_source_pattern.py",
        "checker_behavior": ["bounded reads", "pinned blob", "sha256"],
        "independent_retrieval_recommended": True,
        "source_to_binary_provenance": "NOT_ESTABLISHED",
        "source_review_runner_attestation": "NOT_IMPLEMENTED",
        "evidence_package_github_attestation": "PUBLISHED_BY_SEPARATE_WORKFLOW; DOES_NOT_AUTHENTICATE_SOURCE_CLAIMS",
        "signed_dossier": False,
    },
    "experiment_state": {
        "source_review": "COMPLETE",
        "historical_code_executed": False,
        "wallet_material_used": False,
        "historical_vulnerability_reproduced": False,
        "independent_review": "PENDING",
        "overall_conclusion": "INCONCLUSIVE",
    },
    "promotion_rules": ["Do not infer entropy", "Do not overstate source evidence", "Never include wallet material"],
}


class SourceDossierValidatorTests(unittest.TestCase):
    def test_valid_dossier_passes(self):
        self.assertEqual(validate_dossier(copy.deepcopy(DOSSIER)), [])

    def test_checked_in_dossier_passes(self):
        dossier_path = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "research"
            / "evm-key-forensics"
            / "SOURCE_EVIDENCE_DOSSIER.json"
        )
        data = json.loads(dossier_path.read_text(encoding="utf-8"))
        self.assertEqual(validate_dossier(data), [])

    def test_commit_or_blob_mutation_fails_closed(self):
        data = copy.deepcopy(DOSSIER)
        data["reviewed_upstream"]["files"][0]["commit"] = "f" * 40
        data["reviewed_upstream"]["files"][1]["git_blob_sha1"] = "0" * 40
        errors = validate_dossier(data)
        self.assertIn("pinned_commit_mismatch:pre-disclosure", errors)
        self.assertIn("pinned_blob_mismatch:post-disclosure-archive", errors)

    def test_claim_promotion_is_rejected(self):
        data = copy.deepcopy(DOSSIER)
        data["experiment_state"]["historical_vulnerability_reproduced"] = True
        data["experiment_state"]["overall_conclusion"] = "ESTABLISHED"
        errors = validate_dossier(data)
        self.assertIn("unsafe_or_unsubstantiated_state:historical_vulnerability_reproduced", errors)
        self.assertIn("overall_conclusion_must_remain_inconclusive", errors)

    def test_attestation_or_binary_provenance_cannot_be_claimed(self):
        data = copy.deepcopy(DOSSIER)
        data["verification_contract"]["source_to_binary_provenance"] = "VERIFIED"
        data["verification_contract"]["source_review_runner_attestation"] = "IMPLEMENTED"
        errors = validate_dossier(data)
        self.assertIn("source_to_binary_provenance_must_not_be_overstated", errors)
        self.assertIn("source_review_runner_attestation_must_remain_not_implemented", errors)

    def test_evidence_package_attestation_scope_cannot_be_overstated(self):
        data = copy.deepcopy(DOSSIER)
        data["verification_contract"]["evidence_package_github_attestation"] = "VERIFIED"
        errors = validate_dossier(data)
        self.assertIn("evidence_package_attestation_scope_must_be_explicit", errors)

    def test_duplicate_claim_ids_fail(self):
        data = copy.deepcopy(DOSSIER)
        data["claim_register"][1]["id"] = "SRC-001"
        self.assertIn("claim_register_ids_mismatch", validate_dossier(data))

    def test_cli_rejects_oversized_dossier(self):
        from tools.evm_key_forensics.validate_source_dossier import MAX_DOSSIER_BYTES
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dossier.json"
            path.write_bytes(b" " * (MAX_DOSSIER_BYTES + 1))
            self.assertEqual(main([str(path)]), 2)

    def test_cli_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dossier.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            self.assertEqual(main([str(path)]), 2)


    def test_unhashable_source_role_returns_validation_error(self):
        data = copy.deepcopy(DOSSIER)
        data["reviewed_upstream"]["files"][0]["role"] = ["pre-disclosure"]
        errors = validate_dossier(data)
        self.assertIn("unknown_source_role", errors)

    def test_unhashable_claim_id_returns_validation_error(self):
        data = copy.deepcopy(DOSSIER)
        data["claim_register"][0]["id"] = {"id": "SRC-001"}
        errors = validate_dossier(data)
        self.assertIn("claim_register_ids_mismatch", errors)

    def test_claim_text_cannot_be_changed_while_retaining_known_id(self):
        data = copy.deepcopy(DOSSIER)
        data["claim_register"][0]["claim"] = "The historical vulnerability is proven exploitable."
        errors = validate_dossier(data)
        self.assertIn("claim_content_mismatch:SRC-001:claim", errors)

    def test_claim_boundary_entries_must_be_nonempty_strings(self):
        data = copy.deepcopy(DOSSIER)
        data["claim_register"][0]["does_not_establish"] = [{"entropy": "unknown"}]
        errors = validate_dossier(data)
        self.assertIn("claim_boundaries_required:SRC-001", errors)


if __name__ == "__main__":
    unittest.main()
