"""Contract tests for the EVM Key Forensics evidence dossier.

These tests guard the research boundary: source identity and pattern checks must
not silently become runtime-reproduction or individual-wallet claims.
"""
import json
from pathlib import Path

from tools.evm_key_forensics.check_historical_source_pattern import PINNED_REVISIONS
from tools.evm_key_forensics.known_vulnerability_benchmark import run_benchmark


ROOT = Path(__file__).resolve().parents[1]
DOSSIER_PATH = ROOT / "docs/research/evm-key-forensics/SOURCE_EVIDENCE_DOSSIER.json"


def load_dossier():
    return json.loads(DOSSIER_PATH.read_text(encoding="utf-8"))


def test_dossier_pinned_source_identities_match_checker_contract():
    dossier = load_dossier()
    files = dossier["reviewed_upstream"]["files"]

    by_role = {item["role"]: item for item in files}
    assert by_role["pre-disclosure"]["commit"] == PINNED_REVISIONS["pre-disclosure"]["commit"]
    assert by_role["pre-disclosure"]["git_blob_sha1"] == PINNED_REVISIONS["pre-disclosure"]["git_blob_sha1"]
    assert by_role["post-disclosure-archive"]["commit"] == PINNED_REVISIONS["post-disclosure"]["commit"]
    assert by_role["post-disclosure-archive"]["git_blob_sha1"] == PINNED_REVISIONS["post-disclosure"]["git_blob_sha1"]

    for item in files:
        assert item["path"] == "Dispatcher.cpp"
        assert item["url"].endswith(
            f"/blob/{item['commit']}/Dispatcher.cpp"
        )


def test_dossier_does_not_promote_source_review_to_runtime_or_wallet_claim():
    dossier = load_dossier()
    state = dossier["experiment_state"]

    assert dossier["status"] == "SOURCE_REVIEW_ONLY"
    assert state["historical_code_executed"] is False
    assert state["wallet_material_used"] is False
    assert state["historical_vulnerability_reproduced"] is False
    assert state["independent_review"] == "PENDING"
    assert state["overall_conclusion"] == "INCONCLUSIVE"

    for claim in dossier["claim_register"]:
        exclusions = " ".join(claim.get("does_not_establish", []))
        assert "wallet" in exclusions.lower() or "runtime" in exclusions.lower() or "authenticity" in exclusions.lower()


def test_dossier_explicitly_marks_provenance_and_attestation_unestablished():
    contract = load_dossier()["verification_contract"]

    assert contract["source_to_binary_provenance"] == "NOT_ESTABLISHED"
    assert contract["source_review_runner_attestation"] == "NOT_IMPLEMENTED"
    assert contract["signed_dossier"] is False
    assert contract["independent_retrieval_recommended"] is True


def test_classification_benchmark_keeps_runtime_and_wallet_exposure_unestablished():
    report = run_benchmark()

    assert report["status"] == "PASS"
    assert report["scope"] == "source_classification_only"
    assert report["historical_runtime_reproduction"] == "NOT_ESTABLISHED"
    assert report["individual_wallet_exposure"] == "NOT_ESTABLISHED"
    assert all(
        item["classification"]["historical_runtime_reproduction"] == "NOT_ESTABLISHED"
        and item["classification"]["individual_wallet_exposure"] == "NOT_ESTABLISHED"
        for item in report["results"]
    )
