import json
import subprocess
import sys

from shared.outcome_proof import write_outcome_proof
from tests.test_outcome_proof import _proof
from shared.proof_bundle import export_bundle


def test_bundle_is_self_contained_and_verifies(tmp_path):
    proof = _proof()
    proof_path = tmp_path / "outcome-proof.json"
    write_outcome_proof(proof, proof_path)
    bundle = tmp_path / "bundle"
    export_bundle(proof_path, bundle)
    result = subprocess.run(
        [sys.executable, str(bundle / "verify_bundle.py")],
        cwd=bundle,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "VALID" in result.stdout
    metadata = json.loads((bundle / "bundle.json").read_text())
    assert metadata["proof_id"] == proof["proof_id"]
    assert (bundle / "evidence-manifest.json").exists()
    assert (bundle / "public-key.txt").read_text().strip() == proof["public_key"]


def test_bundle_rejects_tampered_public_key(tmp_path):
    proof = _proof()
    proof_path = tmp_path / "outcome-proof.json"
    write_outcome_proof(proof, proof_path)
    bundle = tmp_path / "bundle"
    export_bundle(proof_path, bundle)
    (bundle / "public-key.txt").write_text("tampered\n")
    result = subprocess.run(
        [sys.executable, str(bundle / "verify_bundle.py")],
        cwd=bundle,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert "public_key_mismatch" in result.stdout


def test_bundle_rejects_tampered_proof(tmp_path):
    proof = _proof()
    proof_path = tmp_path / "outcome-proof.json"
    write_outcome_proof(proof, proof_path)
    bundle = tmp_path / "bundle"
    export_bundle(proof_path, bundle)
    data = json.loads((bundle / "outcome-proof.json").read_text())
    data["receipt"]["status"] = "FAILED"
    (bundle / "outcome-proof.json").write_text(json.dumps(data))
    result = subprocess.run(
        [sys.executable, str(bundle / "verify_bundle.py")],
        cwd=bundle,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert "proof_id_mismatch" in result.stdout or "proof_signature_invalid" in result.stdout


def test_bundle_with_attestation_and_registry_verifies(tmp_path):
    from datetime import datetime, timedelta, timezone
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from shared.attestor_registry import AttestorRecord, attest_outcome, create_registry
    proof = _proof()
    proof_path = tmp_path / "outcome-proof.json"
    write_outcome_proof(proof, proof_path)
    key = Ed25519PrivateKey.generate()
    public = base64.urlsafe_b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
    now = datetime.now(timezone.utc)
    record = AttestorRecord("attestor-1", "attestor-key-1", public, ("artifact_independent_v1",), "ACTIVE", now.isoformat(), (now + timedelta(days=1)).isoformat())
    registry = create_registry([record], Ed25519PrivateKey.generate()).to_dict()
    attestation = attest_outcome(proof, key, "attestor-1", "attestor-key-1", "artifact_independent_v1")
    bundle = tmp_path / "bundle"
    export_bundle(proof_path, bundle, attestation=attestation, registry=registry)
    result = subprocess.run([sys.executable, str(bundle / "verify_bundle.py")], cwd=bundle, text=True, capture_output=True, check=False)
    assert result.returncode == 0
    assert "VALID" in result.stdout


def test_bundle_rejects_revoked_attestor(tmp_path):
    from datetime import datetime, timedelta, timezone
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from shared.attestor_registry import AttestorRecord, attest_outcome, create_registry
    proof = _proof(); proof_path = tmp_path / "outcome-proof.json"; write_outcome_proof(proof, proof_path)
    key = Ed25519PrivateKey.generate(); public = base64.urlsafe_b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
    now=datetime.now(timezone.utc); record=AttestorRecord("attestor-1","attestor-key-1",public,("artifact_independent_v1",),"ACTIVE",now.isoformat(),(now+timedelta(days=1)).isoformat())
    registry=create_registry([record],Ed25519PrivateKey.generate()).to_dict(); attestation=attest_outcome(proof,key,"attestor-1","attestor-key-1","artifact_independent_v1")
    bundle=tmp_path/"bundle"; export_bundle(proof_path,bundle,attestation=attestation,registry=registry)
    data=json.loads((bundle/"attestor-registry.json").read_text()); data["attestors"][0]["status"]="REVOKED"; (bundle/"attestor-registry.json").write_text(json.dumps(data))
    result=subprocess.run([sys.executable,str(bundle/"verify_bundle.py")],cwd=bundle,text=True,capture_output=True,check=False)
    assert result.returncode == 1
    assert "registry" in result.stdout or "signature" in result.stdout
