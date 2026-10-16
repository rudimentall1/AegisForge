import base64
import hashlib
import json
import os
import stat
from pathlib import Path

from shared.attestation_cli import main


def input_payload(artifact=None, verdict="INCONCLUSIVE"):
    artifacts = []
    if artifact is not None:
        path, content = artifact
        artifacts.append({
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        })
    return {
        "case_ref": {
            "case_id": "case-cli-001",
            "case_digest": hashlib.sha256(b"case").hexdigest(),
            "target_repository": "example/project",
            "target_commit": "a" * 40,
            "scope_url": "https://example.invalid/scope",
            "scope_digest": hashlib.sha256(b"scope").hexdigest(),
        },
        "finding_ref": {
            "finding_id": "finding-cli-001",
            "claim": "A bounded test claim",
            "affected_component": "fixture",
            "source_locations": [],
            "impact_path": "synthetic-only",
        },
        "reproduction": {
            "reproduction_contract_sha256": hashlib.sha256(b"contract").hexdigest(),
            "commands": [["python", "-V"]],
            "environment": {"python": "3.x"},
            "network_access": False,
            "artifacts": artifacts,
            "started_at": "2026-10-16T10:00:00+00:00",
            "completed_at": "2026-10-16T10:00:01+00:00",
            "exit_code": 0,
        },
        "verdict": verdict,
        "verdict_rationale": "Synthetic test only; no vulnerability claim.",
        "issued_at": "2026-10-16T10:00:02+00:00",
    }


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def create_signed(tmp_path, monkeypatch, *, artifact=None, verdict="INCONCLUSIVE"):
    private_path = tmp_path / "private.key"
    trusted_path = tmp_path / "trusted-keys.json"
    attestation_path = tmp_path / "attestation.json"
    input_path = tmp_path / "input.json"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    if artifact is not None:
        rel, content = artifact
        target = artifact_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    assert main([
        "attest", "keygen",
        "--private-key-file", str(private_path),
        "--public-key-file", str(trusted_path),
        "--key-id", "cli-test-key",
    ]) == 0
    input_path.write_text(json.dumps(input_payload(artifact, verdict)), encoding="utf-8")
    assert main([
        "attest", "create",
        "--input", str(input_path),
        "--private-key-file", str(private_path),
        "--key-id", "cli-test-key",
        "--organization", "AegisForge CLI tests",
        "--output", str(attestation_path),
    ]) == 0
    return private_path, trusted_path, attestation_path, input_path, artifact_root


def test_cli_keygen_create_and_verify_all_three_tiers(tmp_path, capsys):
    artifact = ("evidence.txt", b"bounded evidence\n")
    _, trusted_path, attestation_path, _, artifact_root = create_signed(
        tmp_path, None, artifact=artifact
    )
    payload = read_json(attestation_path)
    trusted = read_json(trusted_path)

    assert main(["verify", str(attestation_path), "--level", "1"]) == 0
    tier1 = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert tier1["status"] == "STRUCTURE_VALID"
    assert "signer_not_verified" in tier1["reason"]

    assert main([
        "verify", str(attestation_path), "--level", "2",
        "--trusted-keys", str(trusted_path),
    ]) == 0
    tier2 = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert tier2["status"] == "VALID"
    assert tier2["checks"]["signature_valid"] is True

    assert main([
        "verify", str(attestation_path), "--level", "3",
        "--trusted-keys", str(trusted_path),
        "--expected-case-digest", payload["case_ref"]["case_digest"],
        "--artifact-root", str(artifact_root),
    ]) == 0
    tier3 = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert tier3["status"] == "VALID"
    assert tier3["checks"]["case_digest_matches"] is True
    assert tier3["checks"]["artifacts_valid"] is True
    assert trusted["cli-test-key"] == payload["signer"]["public_key"]


def test_cli_refuses_to_overwrite_key_files(tmp_path, capsys):
    private_path = tmp_path / "private.key"
    public_path = tmp_path / "trusted.json"
    assert main([
        "attest", "keygen", "--private-key-file", str(private_path),
        "--public-key-file", str(public_path), "--key-id", "owner-key",
    ]) == 0
    assert main([
        "attest", "keygen", "--private-key-file", str(private_path),
        "--public-key-file", str(public_path), "--key-id", "owner-key",
    ]) == 3
    assert "refusing_to_overwrite_existing_key_file" in capsys.readouterr().err


def test_cli_rejects_private_key_with_open_permissions(tmp_path, capsys):
    private_path, trusted_path, _, input_path, _ = create_signed(tmp_path, None)
    if os.name == "nt":
        return
    private_path.chmod(0o644)
    output = tmp_path / "should-not-exist.json"
    assert main([
        "attest", "create", "--input", str(input_path),
        "--private-key-file", str(private_path), "--key-id", "cli-test-key",
        "--organization", "AegisForge CLI tests", "--output", str(output),
    ]) == 3
    assert "private_key_permissions_too_open" in capsys.readouterr().err
    assert not output.exists()


def test_cli_tampering_and_untrusted_signer_have_distinct_exit_codes(tmp_path, capsys):
    _, trusted_path, attestation_path, _, _ = create_signed(tmp_path, None)
    payload = read_json(attestation_path)
    payload["verdict_rationale"] = "tampered"
    attestation_path.write_text(json.dumps(payload), encoding="utf-8")
    assert main([
        "verify", str(attestation_path), "--level", "2",
        "--trusted-keys", str(trusted_path),
    ]) == 1
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert result["status"] == "TAMPERED"

    empty_trusted = tmp_path / "empty-trusted.json"
    empty_trusted.write_text("{}", encoding="utf-8")
    payload["verdict_rationale"] = "Synthetic test only; no vulnerability claim."
    # Restore a valid attestation for the unknown-signer test by creating another one.
    private_path = tmp_path / "private2.key"
    public_path = tmp_path / "trusted2.json"
    fresh_attestation = tmp_path / "fresh.json"
    fresh_input = tmp_path / "fresh-input.json"
    assert main([
        "attest", "keygen", "--private-key-file", str(private_path),
        "--public-key-file", str(public_path), "--key-id", "other-key",
    ]) == 0
    fresh_input.write_text(json.dumps(input_payload()), encoding="utf-8")
    assert main([
        "attest", "create", "--input", str(fresh_input),
        "--private-key-file", str(private_path), "--key-id", "other-key",
        "--organization", "AegisForge CLI tests", "--output", str(fresh_attestation),
    ]) == 0
    assert main([
        "verify", str(fresh_attestation), "--level", "2",
        "--trusted-keys", str(empty_trusted),
    ]) == 2
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert result["status"] == "UNTRUSTED"


def test_cli_never_accepts_confirmed_verdict(tmp_path, capsys):
    private_path = tmp_path / "private.key"
    public_path = tmp_path / "trusted.json"
    input_path = tmp_path / "input.json"
    output = tmp_path / "attestation.json"
    assert main([
        "attest", "keygen", "--private-key-file", str(private_path),
        "--public-key-file", str(public_path), "--key-id", "owner-key",
    ]) == 0
    input_path.write_text(json.dumps(input_payload(verdict="CONFIRMED")), encoding="utf-8")
    assert main([
        "attest", "create", "--input", str(input_path),
        "--private-key-file", str(private_path), "--key-id", "owner-key",
        "--organization", "AegisForge CLI tests", "--output", str(output),
    ]) == 3
    assert "verdict_not_allowed" in capsys.readouterr().err
    assert not output.exists()
