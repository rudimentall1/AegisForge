from types import SimpleNamespace

import pytest

from shared.trust_authority import (
    AUTHORITY_CONTINUE,
    AUTHORITY_RESTRICT,
    EXPIRED,
    RE_ATTEST_REQUIRED,
    TRUSTED,
    UNTRUSTED,
    TrustAuthorityError,
    trust_to_authority,
)


def _decision(status, reason="reason"):
    return SimpleNamespace(
        status=status,
        reason=reason,
        proof_id="proof_123",
        attestor_id="attestor_1",
        registry_id="registry_1",
    )


def test_trusted_continues_authority():
    result = trust_to_authority(
        _decision(TRUSTED, "authorized_active_attestor")
    )

    assert result.status == TRUSTED
    assert result.decision == AUTHORITY_CONTINUE
    assert result.reason == "trusted_attested_outcome"
    assert result.proof_id == "proof_123"


def test_untrusted_restricts_authority():
    result = trust_to_authority(
        _decision(UNTRUSTED, "attestation_missing")
    )

    assert result.status == UNTRUSTED
    assert result.decision == AUTHORITY_RESTRICT
    assert result.reason == "attestation_missing"


def test_expired_requires_reattestation():
    result = trust_to_authority(
        _decision(EXPIRED, "attestation_outside_attestor_validity")
    )

    assert result.status == EXPIRED
    assert result.decision == RE_ATTEST_REQUIRED
    assert result.reason == "attestation_expired"


def test_missing_decision_rejected():
    with pytest.raises(TrustAuthorityError, match="trust_decision_required"):
        trust_to_authority(None)


def test_missing_proof_identity_rejected():
    decision = _decision(TRUSTED)
    decision = SimpleNamespace(
        status=decision.status,
        reason=decision.reason,
        proof_id="",
        attestor_id=decision.attestor_id,
        registry_id=decision.registry_id,
    )

    with pytest.raises(TrustAuthorityError, match="proof_id_required"):
        trust_to_authority(decision)


def test_unknown_status_rejected():
    with pytest.raises(TrustAuthorityError, match="unknown_trust_status"):
        trust_to_authority(_decision("UNKNOWN"))
