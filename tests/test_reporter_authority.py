import json

import pytest

from reporter import generate_whitehat_report


TX_HASH = "0x" + "ab" * 32


def test_report_does_not_claim_rescue_without_verified_authorized_receipt(tmp_path):
    report_path = generate_whitehat_report(
        "incident-1",
        "base",
        "0x1234567890abcdef1234567890abcdef12345678",
        "reentrancy",
        "critical",
        1000,
        TX_HASH,
        reports_dir=tmp_path,
    )
    data = json.loads((tmp_path / "incident_incident-1.json").read_text())

    assert data["status"] == "INCIDENT_DETECTED_RESPONSE_PENDING"
    assert data["proof_of_rescue_tx"] is None
    assert data["metrics"]["verified_rescued_usd"] == 0
    assert data["metrics"]["proposed_bounty_usd"] is None
    assert data["metrics"]["return_amount_usd"] == 0
    assert "No rescue is claimed" in open(report_path, encoding="utf-8").read()


def test_verified_rescue_proposes_bounty_without_automatic_deduction(tmp_path):
    generate_whitehat_report(
        "incident-2",
        "base",
        "0x1234567890abcdef1234567890abcdef12345678",
        "access_control",
        "critical",
        1000,
        TX_HASH,
        reports_dir=tmp_path,
        rescue_receipt_verified=True,
        owner_authorized=True,
    )
    data = json.loads((tmp_path / "incident_incident-2.json").read_text())

    assert data["status"] == "RESCUED_AND_SECURED"
    assert data["proof_of_rescue_tx"] == TX_HASH
    assert data["metrics"]["verified_rescued_usd"] == 1000
    assert data["metrics"]["proposed_bounty_usd"] == 75
    assert data["metrics"]["bounty_settlement_usd"] == 0
    assert data["metrics"]["return_amount_usd"] == 1000
    assert data["metrics"]["bounty_agreed"] is False


def test_agreed_bounty_is_deducted_only_after_verified_rescue(tmp_path):
    generate_whitehat_report(
        "incident-3",
        "base",
        "0x1234567890abcdef1234567890abcdef12345678",
        "access_control",
        "critical",
        1000,
        TX_HASH,
        reports_dir=tmp_path,
        rescue_receipt_verified=True,
        owner_authorized=True,
        bounty_agreed=True,
    )
    data = json.loads((tmp_path / "incident_incident-3.json").read_text())

    assert data["metrics"]["bounty_settlement_usd"] == 75
    assert data["metrics"]["return_amount_usd"] == 925


def test_report_rejects_bounty_agreement_without_verified_authority(tmp_path):
    with pytest.raises(ValueError, match="bounty_requires_verified_authorized_rescue"):
        generate_whitehat_report(
            "incident-4",
            "base",
            "0x1234567890abcdef1234567890abcdef12345678",
            "access_control",
            "critical",
            1000,
            TX_HASH,
            reports_dir=tmp_path,
            bounty_agreed=True,
        )


def test_report_rejects_bounty_rate_outside_negotiation_range(tmp_path):
    with pytest.raises(ValueError, match="bounty_rate_out_of_range"):
        generate_whitehat_report(
            "incident-5",
            "base",
            "0x1234567890abcdef1234567890abcdef12345678",
            "access_control",
            "critical",
            1000,
            TX_HASH,
            reports_dir=tmp_path,
            rescue_receipt_verified=True,
            owner_authorized=True,
            bounty_rate=0.15,
        )
