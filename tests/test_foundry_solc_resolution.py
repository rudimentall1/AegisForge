from shared.solc_toolchain import resolve_solc_binary


def test_solc_resolver_accepts_explicit_binary_path_without_solc_select(
    monkeypatch, tmp_path
):
    compiler = tmp_path / "solc-0.8.24"
    compiler.write_bytes(b"solc")
    compiler.chmod(0o755)
    monkeypatch.setenv("AEGISFORGE_SOLC_BINARY", str(compiler))
    assert resolve_solc_binary("0.8.24") == compiler


def test_solc_resolver_rejects_non_executable_explicit_binary(
    monkeypatch, tmp_path
):
    compiler = tmp_path / "solc-not-executable"
    compiler.write_bytes(b"not executable")
    compiler.chmod(0o644)
    monkeypatch.setenv("AEGISFORGE_SOLC_BINARY", str(compiler))
    assert resolve_solc_binary("0.8.24") is None
