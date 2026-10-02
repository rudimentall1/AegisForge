import pytest


@pytest.fixture(autouse=True)
def agent_identity_key_dir(tmp_path, monkeypatch):
    """Keep cryptographic test identities isolated and writable in CI."""
    key_dir = tmp_path / "agent-identities"
    monkeypatch.setenv("AEGISFORGE_AGENT_IDENTITY_KEY_DIR", str(key_dir))
    return key_dir
