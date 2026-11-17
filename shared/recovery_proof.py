import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from shared.recovery_evidence import RecoveryEvidenceChain
from shared.recovery_trust import RecoveryAttestorRegistry, RecoveryTrustError


SCHEMA_VERSION = "recovery-proof-v1"
ALGORITHM = "Ed25519"


class RecoveryProofError(ValueError):
    pass


def canonical_json(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _integrity_payload(proof):
    return {
        "schema_version": proof["schema_version"],
        "algorithm": proof["algorithm"],
        "key_id": proof["key_id"],
        "public_key": proof["public_key"],
        "recovery_artifact": proof["recovery_artifact"],
    }


def _signature_payload(proof):
    return {
        **_integrity_payload(proof),
        "proof_id": proof["proof_id"],
    }


def _decode(value, field):
    try:
        return base64.urlsafe_b64decode(str(value).encode("ascii"))
    except Exception as exc:
        raise RecoveryProofError(f"invalid_base64:{field}") from exc


def _validate_shape(proof):
    if not isinstance(proof, dict):
        raise RecoveryProofError("proof_object_required")
    required = (
        "schema_version",
        "algorithm",
        "key_id",
        "public_key",
        "proof_id",
        "recovery_artifact",
        "signature",
    )
    for field in required:
        if field not in proof:
            raise RecoveryProofError(f"proof_field_missing:{field}")
    if proof["schema_version"] != SCHEMA_VERSION:
        raise RecoveryProofError("unsupported_proof_schema")
    if proof["algorithm"] != ALGORITHM:
        raise RecoveryProofError("unsupported_proof_algorithm")
    if not isinstance(proof["recovery_artifact"], dict):
        raise RecoveryProofError("recovery_artifact_required")
    result = RecoveryEvidenceChain.verify_artifact(proof["recovery_artifact"])
    if not result["valid"]:
        raise RecoveryProofError(f"recovery_artifact_invalid:{result['error']}")


def sign_recovery_proof(recovery_artifact, signer):
    if not isinstance(recovery_artifact, dict):
        raise RecoveryProofError("recovery_artifact_required")
    result = RecoveryEvidenceChain.verify_artifact(recovery_artifact)
    if not result["valid"]:
        raise RecoveryProofError(f"recovery_artifact_invalid:{result['error']}")
    if not all(hasattr(signer, attr) for attr in ("sign_payload", "key_id", "public_key")):
        raise RecoveryProofError("signer_payload_api_required")

    proof = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "key_id": signer.key_id,
        "public_key": signer.public_key,
        "proof_id": "",
        "recovery_artifact": recovery_artifact,
    }
    proof["proof_id"] = hashlib.sha256(
        canonical_json(_integrity_payload(proof)).encode("utf-8")
    ).hexdigest()
    signature = signer.sign_payload(_signature_payload(proof))
    proof["signature"] = base64.urlsafe_b64encode(signature).decode("ascii")
    return proof


def verify_recovery_proof(proof, trusted_attestors=None):
    _validate_shape(proof)

    expected_id = hashlib.sha256(
        canonical_json(_integrity_payload(proof)).encode("utf-8")
    ).hexdigest()
    if proof["proof_id"] != expected_id:
        raise RecoveryProofError("proof_id_mismatch")

    public_raw = _decode(proof["public_key"], "public_key")
    if len(public_raw) != 32:
        raise RecoveryProofError("invalid_ed25519_public_key")
    expected_key_id = "ed25519-" + hashlib.sha256(public_raw).hexdigest()[:16]
    if proof["key_id"] != expected_key_id:
        raise RecoveryProofError("key_id_public_key_mismatch")

    signature = _decode(proof["signature"], "signature")
    if len(signature) != 64:
        raise RecoveryProofError("invalid_ed25519_signature")

    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature,
            canonical_json(_signature_payload(proof)).encode("utf-8"),
        )
    except Exception as exc:
        raise RecoveryProofError("proof_signature_invalid") from exc

    if trusted_attestors is not None:
        if not isinstance(trusted_attestors, RecoveryAttestorRegistry):
            raise RecoveryProofError("attestor_registry_required")
        try:
            trusted_attestors.require(proof["key_id"], proof["public_key"])
        except RecoveryTrustError as exc:
            raise RecoveryProofError(str(exc)) from exc

    artifact = proof["recovery_artifact"]
    result = RecoveryEvidenceChain.verify_artifact(artifact)
    return {
        "valid": True,
        "proof_id": proof["proof_id"],
        "key_id": proof["key_id"],
        "algorithm": proof["algorithm"],
        "recovery_id": artifact["recovery_id"],
        "attempt_id": artifact.get("attempt_id"),
        "events": result["events"],
        "head_hash": result["head_hash"],
    }


def write_recovery_proof(proof, path):
    _validate_shape(proof)
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(proof, handle, sort_keys=True, indent=2, ensure_ascii=True)
        handle.write("\n")
    os.replace(temp, path)
    return path


def read_recovery_proof(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryProofError("proof_file_invalid") from exc


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(prog="aegisforge verify-recovery")
    parser.add_argument("proof", help="path to recovery-proof.json")
    args = parser.parse_args(argv)

    try:
        result = verify_recovery_proof(read_recovery_proof(args.proof))
    except RecoveryProofError as exc:
        print(f"INVALID: {exc}")
        return 1

    print("VALID")
    print(f"proof_id={result['proof_id']}")
    print(f"key_id={result['key_id']}")
    print(f"recovery_id={result['recovery_id']}")
    print(f"attempt_id={result['attempt_id']}")
    print(f"events={result['events']}")
    print(f"head_hash={result['head_hash']}")
    return 0
