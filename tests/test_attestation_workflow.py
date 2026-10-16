import base64
from contextlib import contextmanager
import json
from pathlib import Path
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation import verify_attestation
from shared.attestation_cli import main
from shared.attestation_registry import (
    verify_inclusion_proof,
    verify_registry,
    verify_registry_chain,
    verify_signed_checkpoint,
)
from shared.attestation_signer import make_server
from tools.evm_key_forensics.run_uniswap_v2_factory_round_case import run_case

TOKEN = "workflow-test-token-at-least-32-characters-long"
KEY_ID = "workflow-test-key"


@contextmanager
def running_signer(key):
    server = make_server(
        "127.0.0.1",
        0,
        private_key=key,
        key_id=KEY_ID,
        organization="AegisForge workflow tests",
        token=TOKEN,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def write_evidence(path: Path, *, valid=True):
    payload = run_case()
    if not valid:
        payload["acceptance"]["validation_passed"] = False
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return payload


def write_trusted_keys(path: Path, key):
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    path.write_text(
        json.dumps({KEY_ID: base64.b64encode(public).decode("ascii")}),
        encoding="utf-8",
    )


def invoke_workflow(evidence, trusted, output_dir, *, previous=None):
    args = [
        "attest", "workflow",
        "--evidence", str(evidence),
        "--verdict", "INCONCLUSIVE",
        "--rationale", "Human review: source-only evidence does not establish runtime behavior.",
        "--trusted-keys", str(trusted),
        "--output-dir", str(output_dir),
    ]
    if previous is not None:
        args.extend(["--previous-registry", str(previous)])
    return main(args)


def test_workflow_signs_verifies_and_registers_source_only_evidence(tmp_path, monkeypatch, capsys):
    key = Ed25519PrivateKey.generate()
    evidence = tmp_path / "evidence.json"
    trusted = tmp_path / "trusted-keys.json"
    output = tmp_path / "workflow-output"
    output.mkdir()
    write_evidence(evidence)
    write_trusted_keys(trusted, key)

    with running_signer(key) as url:
        monkeypatch.setenv("AEGISFORGE_SIGNER_URL", url)
        monkeypatch.setenv("AEGISFORGE_SIGNER_TOKEN", TOKEN)
        assert invoke_workflow(evidence, trusted, output) == 0

    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert summary["status"] == "ATTESTED_AND_REGISTERED_LOCALLY"
    assert summary["verdict"] == "INCONCLUSIVE"
    assert summary["signature_status"] == "VALID"
    assert summary["registry_size"] == 1
    assert summary["inclusion_proof_valid"] is True
    assert summary["published_remotely"] is False
    assert summary["automatic_confirmation"] is False
    assert summary["finding_created"] is False

    attestation = json.loads((output / "attestation.json").read_text(encoding="utf-8"))
    registry = json.loads((output / "registry.json").read_text(encoding="utf-8"))
    checkpoint = json.loads((output / "checkpoint.json").read_text(encoding="utf-8"))
    proof = json.loads((output / "inclusion-proof.json").read_text(encoding="utf-8"))
    assert attestation["verdict"] == "INCONCLUSIVE"
    assert "No vulnerability finding" in attestation["finding_ref"]["claim"]
    assert verify_attestation(
        attestation,
        trusted_keys=json.loads(trusted.read_text(encoding="utf-8")),
        expected_case_digest=attestation["case_ref"]["case_digest"],
        artifact_root=tmp_path,
    ).status == "VALID"
    assert verify_registry(registry)["valid"] is True
    assert verify_signed_checkpoint(
        checkpoint,
        trusted_keys=json.loads(trusted.read_text(encoding="utf-8")),
        registry=registry,
    )["size"] == 1
    assert verify_inclusion_proof(
        proof, expected_root=registry["merkle_root"], expected_size=1
    )["valid"] is True


def test_workflow_appends_to_previous_registry(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    evidence = tmp_path / "evidence.json"
    trusted = tmp_path / "trusted-keys.json"
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    first_output.mkdir()
    second_output.mkdir()
    write_evidence(evidence)
    write_trusted_keys(trusted, key)

    with running_signer(key) as url:
        monkeypatch.setenv("AEGISFORGE_SIGNER_URL", url)
        monkeypatch.setenv("AEGISFORGE_SIGNER_TOKEN", TOKEN)
        assert invoke_workflow(evidence, trusted, first_output) == 0
        assert invoke_workflow(
            evidence, trusted, second_output, previous=first_output / "registry.json"
        ) == 0

    first_registry = json.loads((first_output / "registry.json").read_text(encoding="utf-8"))
    second_registry = json.loads((second_output / "registry.json").read_text(encoding="utf-8"))
    assert second_registry["size"] == 2
    assert verify_registry_chain(second_registry, first_registry)["append_only"] is True


def test_workflow_rejects_unvalidated_evidence_before_signing(tmp_path, capsys):
    key = Ed25519PrivateKey.generate()
    evidence = tmp_path / "invalid-evidence.json"
    trusted = tmp_path / "trusted-keys.json"
    output = tmp_path / "workflow-output"
    output.mkdir()
    write_evidence(evidence, valid=False)
    write_trusted_keys(trusted, key)

    assert main([
        "attest", "workflow",
        "--evidence", str(evidence),
        "--verdict", "INCONCLUSIVE",
        "--rationale", "Human review required.",
        "--trusted-keys", str(trusted),
        "--output-dir", str(output),
    ]) == 3
    assert "evidence_must_be_validated_and_remain_INCONCLUSIVE" in capsys.readouterr().err
    assert not list(output.iterdir())


def test_workflow_refuses_to_overwrite_any_output_file(tmp_path, capsys):
    key = Ed25519PrivateKey.generate()
    evidence = tmp_path / "evidence.json"
    trusted = tmp_path / "trusted-keys.json"
    output = tmp_path / "workflow-output"
    output.mkdir()
    write_evidence(evidence)
    write_trusted_keys(trusted, key)
    sentinel = output / "registry.json"
    sentinel.write_text("keep", encoding="utf-8")

    assert main([
        "attest", "workflow",
        "--evidence", str(evidence),
        "--verdict", "INCONCLUSIVE",
        "--rationale", "Human review required.",
        "--trusted-keys", str(trusted),
        "--output-dir", str(output),
    ]) == 3
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert "refusing_to_overwrite_workflow_output" in capsys.readouterr().err
