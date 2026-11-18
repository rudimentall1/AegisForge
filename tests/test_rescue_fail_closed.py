import rescue
from agents.config import RESCUE_WALLET_ADDRESS


def test_rescue_destination_matches_owner_approved_multisig():
    assert RESCUE_WALLET_ADDRESS == "0xF462A261266C543A31Ef43A94bb48d7575299B97"


def test_legacy_rescue_path_fails_closed_until_protocol_adapter_exists(monkeypatch):
    monkeypatch.setenv("RESCUE_PRIVATE_KEY", "0x" + "11" * 32)

    assert not hasattr(rescue, "PRIVATE_KEY")
    assert rescue.execute_rescue(
        "base",
        "0x1234567890abcdef1234567890abcdef12345678",
    ) is False
