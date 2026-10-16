import json
from pathlib import Path

from tools.evm_key_forensics.uniswap_v2_factory_source_pattern import (
    PINNED_GIT_BLOB_SHA1,
    inspect_source,
    git_blob_sha1,
)

ROOT = Path(__file__).parent / "fixtures" / "solidity"
SOURCE = ROOT / "UniswapV2Factory.sol"
PROVENANCE = ROOT / "UniswapV2Factory.provenance.json"


def test_pinned_factory_source_matches_expected_git_blob_and_patterns():
    raw = SOURCE.read_bytes()
    result = inspect_source(raw.decode("utf-8"))

    assert git_blob_sha1(raw) == PINNED_GIT_BLOB_SHA1
    assert result["source_git_blob_sha1"] == PINNED_GIT_BLOB_SHA1
    assert result["conclusion"] == "SOURCE_PATTERN_MATCHED"
    assert all(result["checks"].values())
    assert result["finding"] is False
    assert result["vulnerability_confirmed"] is False
    assert result["rpc_used"] is False
    assert result["explorer_checked_at_runtime"] is False


def test_factory_source_mutation_fails_closed():
    source = SOURCE.read_text(encoding="utf-8")
    mutated = source.replace(
        "require(msg.sender == feeToSetter, 'UniswapV2: FORBIDDEN');",
        "/* require(msg.sender == feeToSetter, 'UniswapV2: FORBIDDEN'); */",
        1,
    )
    result = inspect_source(mutated)

    assert result["conclusion"] == "INCONCLUSIVE"
    assert "pinned_git_blob_mismatch" in result["errors"]
    assert result["checks"]["set_fee_to_authorized_before_assignment"] is False
    assert result["finding"] is False


def test_comments_and_strings_cannot_supply_authorization_evidence():
    source = """
    // contract UniswapV2Factory { address public feeToSetter; }
    string memory decoy = "require(msg.sender == feeToSetter, 'FORBIDDEN')";
    function setFeeTo(address _feeTo) external { feeTo = _feeTo; }
    function setFeeToSetter(address _feeToSetter) external {
        feeToSetter = _feeToSetter;
    }
    """
    result = inspect_source(source)

    assert result["conclusion"] == "INCONCLUSIVE"
    assert result["checks"]["factory_contract_present"] is False
    assert result["checks"]["set_fee_to_authorized_before_assignment"] is False
    assert result["checks"]["set_fee_to_setter_authorized_before_assignment"] is False


def test_provenance_manifest_pins_public_verified_target_without_claiming_formal_verification():
    manifest = json.loads(PROVENANCE.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == "aegisforge-verified-source-provenance-v1"
    assert manifest["chain_id"] == 1
    assert manifest["contract_address"] == "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
    assert manifest["explorer"]["reported_status"] == "Source Code Verified Exact Match"
    assert manifest["upstream_source"]["commit"] == "4dd59067c76dea4a0e8e4bfdda41877a6b16dedc"
    assert manifest["upstream_source"]["git_blob_sha1"] == PINNED_GIT_BLOB_SHA1
    assert manifest["constraints"]["runtime_rpc_used"] is False
    assert manifest["constraints"]["verification_claim_means_explorer_reported_exact_match_not_formal_verification"] is True
