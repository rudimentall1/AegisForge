import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation import sign_attestation
from shared.attestation_registry import (
    AttestationRegistryError,
    build_inclusion_proof,
    build_registry,
    checkpoint_for,
    entry_from_attestation,
    verify_inclusion_proof,
    verify_registry,
    verify_registry_chain,
)
from shared.attestation_registry_cli import main


def signed_attestation(key, finding_id="finding-registry-001"):
    case = {
        "case_id": "case-registry-001",
        "case_digest": hashlib.sha256(b"case-registry").hexdigest(),
        "target_repository": "example/project",
        "target_commit": "a" * 40,
        "scope_url": "https://example.invalid/scope",
        "scope_digest": hashlib.sha256(b"scope-registry").hexdigest(),
    }
    finding = {
        "finding_id": finding_id,
        "claim": "Synthetic registry test",
        "affected_component": "fixture",
        "source_locations": [],
        "impact_path": "synthetic-only",
    }
    reproduction = {
        "reproduction_contract_sha256": hashlib.sha256(b"contract").hexdigest(),
        "commands": [["python", "-V"]],
        "environment": {"python": "3.x"},
        "network_access": False,
        "artifacts": [],
        "started_at": "2026-10-16T10:00:00+00:00",
        "completed_at": "2026-10-16T10:00:01+00:00",
        "exit_code": 0,
    }
    return sign_attestation(
        case_ref=case,
        finding_ref=finding,
        reproduction=reproduction,
        verdict="INCONCLUSIVE",
        verdict_rationale="Synthetic-only registry test.",
        private_key=key,
        key_id="registry-test-key",
        organization="AegisForge registry tests",
        issued_at="2026-10-16T10:00:02+00:00",
    ).to_dict()


def write_json(path, payload):
    Path(path).write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def test_merkle_registry_and_inclusion_proof_round_trip():
    key = Ed25519PrivateKey.generate()
    first = signed_attestation(key, "finding-registry-001")
    second = signed_attestation(key, "finding-registry-002")
    registry = build_registry([
        entry_from_attestation(first),
        entry_from_attestation(second),
    ])
    assert verify_registry(registry)["valid"] is True
    proof = build_inclusion_proof(registry, first["attestation_id"])
    result = verify_inclusion_proof(
        proof, expected_root=registry["merkle_root"], expected_size=2
    )
    assert result["valid"] is True
    assert result["attestation_id"] == first["attestation_id"]


def test_registry_detects_tampered_entry_and_root():
    key = Ed25519PrivateKey.generate()
    attestation = signed_attestation(key)
    registry = build_registry([entry_from_attestation(attestation)])
    registry["entries"][0]["verdict"] = "REPRODUCED"
    try:
        verify_registry(registry)
    except AttestationRegistryError as exc:
        assert str(exc) == "registry_merkle_root_mismatch"
    else:
        raise AssertionError("tampered registry unexpectedly verified")


def test_previous_checkpoint_proves_append_only_prefix():
    key = Ed25519PrivateKey.generate()
    first = signed_attestation(key, "finding-registry-001")
    second = signed_attestation(key, "finding-registry-002")
    previous = build_registry([entry_from_attestation(first)])
    current = build_registry(
        [*previous["entries"], entry_from_attestation(second)],
        previous_checkpoint=checkpoint_for(previous),
    )
    chain = verify_registry_chain(current, previous)
    assert chain["valid"] is True
    assert chain["append_only"] is True
    assert current["entries"][0] == previous["entries"][0]


def test_registry_chain_rejects_modified_prefix():
    key = Ed25519PrivateKey.generate()
    first = signed_attestation(key, "finding-registry-001")
    second = signed_attestation(key, "finding-registry-002")
    previous = build_registry([entry_from_attestation(first)])
    current = build_registry(
        [*previous["entries"], entry_from_attestation(second)],
        previous_checkpoint=checkpoint_for(previous),
    )
    current["entries"][0]["verdict"] = "OUT_OF_SCOPE"
    current["merkle_root"] = build_registry(current["entries"])["merkle_root"]
    try:
        verify_registry_chain(current, previous)
    except AttestationRegistryError as exc:
        assert str(exc) in {"previous_checkpoint_mismatch", "registry_prefix_changed"}
    else:
        raise AssertionError("modified prefix unexpectedly verified")


def test_cli_add_verify_proof_and_verify_proof(tmp_path, capsys):
    key = Ed25519PrivateKey.generate()
    attestation = signed_attestation(key)
    attestation_path = tmp_path / "attestation.json"
    trusted_path = tmp_path / "trusted.json"
    registry_path = tmp_path / "registry.json"
    proof_path = tmp_path / "proof.json"
    write_json(attestation_path, attestation)
    public = key.public_key().public_bytes_raw()
    write_json(trusted_path, {"registry-test-key": base64.b64encode(public).decode("ascii")})

    assert main([
        "add", "--attestation", str(attestation_path),
        "--trusted-keys", str(trusted_path), "--output", str(registry_path),
    ]) == 0
    added = json.loads(capsys.readouterr().out.strip())
    assert added["status"] == "APPENDED"
    assert added["root_trust"] == "UNANCHORED"

    assert main(["verify", "--registry", str(registry_path)]) == 0
    verified = json.loads(capsys.readouterr().out.strip())
    assert verified["valid"] is True
    assert verified["root_trust"] == "UNANCHORED"

    assert main([
        "proof", "--registry", str(registry_path),
        "--attestation-id", attestation["attestation_id"],
        "--output", str(proof_path),
    ]) == 0
    proof_output = json.loads(capsys.readouterr().out.strip())
    assert proof_output["status"] == "PROOF_CREATED"

    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    assert main([
        "verify-proof", "--proof", str(proof_path),
        "--attestation", str(attestation_path), "--trusted-keys", str(trusted_path),
        "--expected-root", registry["merkle_root"], "--expected-size", "1",
    ]) == 0
    proof_result = json.loads(capsys.readouterr().out.strip())
    assert proof_result["status"] == "VALID"
    assert proof_result["root_trust"] == "EXTERNALLY_PINNED"


def test_cli_rejects_untrusted_attestation(tmp_path, capsys):
    key = Ed25519PrivateKey.generate()
    attestation = signed_attestation(key)
    attestation_path = tmp_path / "attestation.json"
    trusted_path = tmp_path / "trusted.json"
    output_path = tmp_path / "registry.json"
    write_json(attestation_path, attestation)
    write_json(trusted_path, {})

    assert main([
        "add", "--attestation", str(attestation_path),
        "--trusted-keys", str(trusted_path), "--output", str(output_path),
    ]) == 2
    result = json.loads(capsys.readouterr().out.strip())
    assert result["status"] == "UNTRUSTED"
    assert not output_path.exists()


def test_inclusion_proof_rejects_wrong_root():
    key = Ed25519PrivateKey.generate()
    attestation = signed_attestation(key)
    registry = build_registry([entry_from_attestation(attestation)])
    proof = build_inclusion_proof(registry, attestation["attestation_id"])
    try:
        verify_inclusion_proof(proof, expected_root="0" * 64)
    except AttestationRegistryError as exc:
        assert str(exc) == "expected_root_mismatch"
    else:
        raise AssertionError("proof accepted an incorrect external root")
