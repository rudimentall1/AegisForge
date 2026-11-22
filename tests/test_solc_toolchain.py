from pathlib import Path

from shared.solc_toolchain import resolve_solc_binary


def test_resolves_explicit_executable_solc_binary(monkeypatch, tmp_path):
    binary = tmp_path / "solc"
    binary.write_bytes(b"compiler")
    binary.chmod(0o755)
    monkeypatch.setenv("AEGISFORGE_SOLC_BINARY", str(binary))
    assert resolve_solc_binary("0.8.24") == binary


def test_rejects_missing_or_non_executable_configured_solc(monkeypatch, tmp_path):
    binary = tmp_path / "solc"
    binary.write_text("compiler", encoding="utf-8")
    binary.chmod(0o644)
    monkeypatch.setenv("AEGISFORGE_SOLC_BINARY", str(binary))
    assert resolve_solc_binary("0.8.24") is None


def test_rejects_invalid_version_before_artifact_lookup(monkeypatch):
    monkeypatch.delenv("AEGISFORGE_SOLC_BINARY", raising=False)
    assert resolve_solc_binary("") is None
