from pathlib import Path

from tools.evm_key_forensics.solidity_source_pattern import (
    PINNED_COMMIT,
    PINNED_GIT_BLOB_SHA1,
    PINNED_PATH,
    inspect_source,
)

FIXTURE = Path(__file__).parent / "fixtures" / "solidity" / "Ownable.sol"
SOURCE = FIXTURE.read_text(encoding="utf-8")


def test_pinned_openzeppelin_source_matches_expected_access_control_patterns():
    result = inspect_source(SOURCE)

    assert result["conclusion"] == "SOURCE_PATTERN_MATCHED"
    assert result["errors"] == []
    assert result["source_git_blob_sha1"] == PINNED_GIT_BLOB_SHA1
    assert result["checks"]["owner_modifier_present"] is True
    assert result["checks"]["modifier_calls_owner_check"] is True
    assert result["checks"]["owner_compared_with_msg_sender"] is True
    assert result["checks"]["tx_origin_absent_from_code"] is True
    assert result["checks"]["zero_address_guard_present"] is True
    assert result["finding"] is False
    assert result["vulnerability_confirmed"] is False
    assert result["deployed_contract_verified"] is False
    assert result["source_executed"] is False


def test_comment_cannot_supply_access_control_pattern():
    mutated = SOURCE.replace(
        "modifier onlyOwner()",
        "// modifier onlyOwner()",
    ).replace(
        "modifier onlyOwner() {",
        "modifier onlyOwner() {",
    )
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "pinned_git_blob_mismatch" in result["errors"]


def test_changed_source_fails_closed_even_if_patterns_remain():
    mutated = SOURCE + "\\n// harmless source change"
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "pinned_git_blob_mismatch" in result["errors"]


def test_mutable_revision_and_path_are_rejected():
    result = inspect_source(
        SOURCE,
        source_commit="main",
        source_path="contracts/Unknown.sol",
    )
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "source_commit_not_allowlisted" in result["errors"]
    assert "source_path_not_allowlisted" in result["errors"]


def test_tx_origin_in_code_is_not_misclassified_as_safe():
    mutated = SOURCE.replace(
        "if (owner() != _msgSender()) {",
        "if (owner() != tx.origin) {",
    )
    result = inspect_source(mutated)
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "pinned_git_blob_mismatch" in result["errors"]
    assert "expected_access_control_invariant_not_observed" in result["errors"]


def test_tx_origin_in_comment_does_not_trigger_code_check_but_hash_still_pins():
    result = inspect_source(SOURCE.replace(
        "pragma solidity ^0.8.20;",
        "pragma solidity ^0.8.20; // tx.origin is not used here",
    ))
    assert result["conclusion"] == "INCONCLUSIVE"
    assert "pinned_git_blob_mismatch" in result["errors"]
