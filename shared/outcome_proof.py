import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from shared.evidence_manifest import verify_manifest


class OutcomeProofError(ValueError):
    pass


SCHEMA_VERSION = "outcome-proof-v1"
ALGORITHM = "Ed25519"


def canonical_json(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _b64decode(value, field):
    try:
        return base64.urlsafe_b64decode(str(value).encode("ascii"))
    except Exception as exc:
        raise OutcomeProofError(f"invalid_base64:{field}") from exc


def _integrity_payload(proof):
    return {
        "schema_version": proof["schema_version"],
        "algorithm": proof["algorithm"],
        "key_id": proof["key_id"],
        "public_key": proof["public_key"],
        "grant": proof["grant"],
        "receipt": proof["receipt"],
        "outcome_contract": proof["outcome_contract"],
        "outcome": proof["outcome"],
        "evidence": proof["evidence"],
        "evidence_manifest": proof["evidence_manifest"],
    }


def _signature_payload(proof):
    payload = dict(_integrity_payload(proof))
    payload["proof_id"] = proof["proof_id"]
    return payload


def _validate_shape(proof):
    if not isinstance(proof, dict):
        raise OutcomeProofError("proof_object_required")
    required = (
        "schema_version", "algorithm", "key_id", "public_key", "proof_id",
        "grant", "receipt", "outcome_contract", "outcome", "evidence", "signature",
    )
    for field in required:
        if field not in proof:
            raise OutcomeProofError(f"proof_field_missing:{field}")
    if proof["schema_version"] != SCHEMA_VERSION:
        raise OutcomeProofError("unsupported_proof_schema")
    if proof["algorithm"] != ALGORITHM:
        raise OutcomeProofError("unsupported_proof_algorithm")
    if not isinstance(proof["grant"], dict) or not isinstance(proof["receipt"], dict):
        raise OutcomeProofError("proof_binding_objects_required")
    if not isinstance(proof["outcome_contract"], dict):
        raise OutcomeProofError("proof_outcome_contract_required")
    if not isinstance(proof["outcome"], dict):
        raise OutcomeProofError("proof_outcome_required")
    if not isinstance(proof["evidence"], dict):
        raise OutcomeProofError("proof_evidence_required")
    if not isinstance(proof["evidence_manifest"], dict):
        raise OutcomeProofError("proof_evidence_manifest_required")
    try:
        verify_manifest(proof["evidence_manifest"])
    except Exception as exc:
        raise OutcomeProofError(str(exc)) from exc
    if proof["outcome"].get("status") != "PROVEN":
        raise OutcomeProofError("proof_outcome_not_proven")
    if proof["outcome"].get("verifier") != proof["outcome_contract"].get("verifier"):
        raise OutcomeProofError("proof_verifier_mismatch")


def build_outcome_proof_payload(grant, receipt, outcome_contract, outcome, evidence, evidence_manifest):
    if not isinstance(grant, dict) or not isinstance(receipt, dict):
        raise OutcomeProofError("grant_and_receipt_required")
    if not isinstance(outcome_contract, dict) or not isinstance(outcome, dict):
        raise OutcomeProofError("contract_and_outcome_required")
    if not isinstance(evidence, dict):
        raise OutcomeProofError("evidence_required")
    if not isinstance(evidence_manifest, dict):
        raise OutcomeProofError("evidence_manifest_required")
    try:
        verify_manifest(evidence_manifest)
    except Exception as exc:
        raise OutcomeProofError(str(exc)) from exc
    if outcome.get("status") != "PROVEN":
        raise OutcomeProofError("only_proven_outcomes_can_be_exported")
    if outcome.get("verifier") != outcome_contract.get("verifier"):
        raise OutcomeProofError("outcome_verifier_contract_mismatch")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "key_id": "",
        "public_key": "",
        "proof_id": "",
        "grant": grant,
        "receipt": receipt,
        "outcome_contract": outcome_contract,
        "outcome": outcome,
        "evidence": evidence,
        "evidence_manifest": evidence_manifest,
    }
    return payload


def sign_outcome_proof(payload, signer):
    if not hasattr(signer, "sign_payload"):
        raise OutcomeProofError("signer_payload_api_required")
    proof = dict(payload)
    proof["key_id"] = signer.key_id
    proof["public_key"] = signer.public_key
    proof["proof_id"] = hashlib.sha256(
        canonical_json(_integrity_payload(proof)).encode("utf-8")
    ).hexdigest()
    signature = signer.sign_payload(_signature_payload(proof))
    proof["signature"] = base64.urlsafe_b64encode(signature).decode("ascii")
    return proof


def verify_outcome_proof(proof):
    _validate_shape(proof)
    expected_id = hashlib.sha256(
        canonical_json(_integrity_payload(proof)).encode("utf-8")
    ).hexdigest()
    if proof["proof_id"] != expected_id:
        raise OutcomeProofError("proof_id_mismatch")
    public_bytes = _b64decode(proof["public_key"], "public_key")
    if len(public_bytes) != 32:
        raise OutcomeProofError("invalid_ed25519_public_key")
    signature = _b64decode(proof["signature"], "signature")
    if len(signature) != 64:
        raise OutcomeProofError("invalid_ed25519_signature")
    public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
    try:
        public_key.verify(
            signature,
            canonical_json(_signature_payload(proof)).encode("utf-8"),
        )
    except Exception as exc:
        raise OutcomeProofError("proof_signature_invalid") from exc
    grant = proof["grant"]
    if grant.get("algorithm") != ALGORITHM:
        raise OutcomeProofError("grant_signature_algorithm_invalid")
    if grant.get("key_id") != proof["key_id"]:
        raise OutcomeProofError("grant_signer_key_mismatch")
    grant_signature = _b64decode(grant.get("signature", ""), "grant_signature")
    grant_payload = {
        "algorithm": grant["algorithm"],
        "key_id": grant["key_id"],
        "grant": grant.get("grant"),
    }
    try:
        public_key.verify(
            grant_signature,
            canonical_json(grant_payload).encode("utf-8"),
        )
    except Exception as exc:
        raise OutcomeProofError("grant_signature_invalid") from exc
    grant_body = grant.get("grant") or {}
    receipt = proof["receipt"]
    if grant_body.get("grant_id") != receipt.get("grant_id"):
        raise OutcomeProofError("grant_receipt_binding_mismatch")
    if grant_body.get("task_id") != receipt.get("task_id"):
        raise OutcomeProofError("grant_receipt_task_mismatch")
    if receipt.get("intent_hash") and grant_body.get("intent_hash") != receipt.get("intent_hash"):
        raise OutcomeProofError("grant_receipt_intent_mismatch")
    if grant_body.get("outcome_contract") != proof["outcome_contract"]:
        raise OutcomeProofError("grant_contract_mismatch")
    if proof["outcome"].get("outcome_id") != proof["evidence"].get("outcome_id"):
        raise OutcomeProofError("outcome_evidence_binding_mismatch")
    return {
        "valid": True,
        "proof_id": proof["proof_id"],
        "key_id": proof["key_id"],
        "algorithm": proof["algorithm"],
        "verifier": proof["outcome"]["verifier"],
        "outcome_id": proof["outcome"].get("outcome_id"),
        "grant_id": grant_body.get("grant_id"),
        "task_id": grant_body.get("task_id"),
    }


def write_outcome_proof(proof, path):
    _validate_shape(proof)
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(proof, handle, sort_keys=True, indent=2, ensure_ascii=True)
        handle.write("\n")
    os.replace(temp, path)
    return path


def read_outcome_proof(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise OutcomeProofError("proof_file_invalid") from exc


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="aegisforge")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify a portable outcome proof offline")
    verify.add_argument("proof", help="path to outcome-proof.json")
    bundle = sub.add_parser("bundle", help="export a portable offline proof bundle")
    bundle.add_argument("proof", help="path to outcome-proof.json")
    bundle.add_argument("output", help="directory to create")
    args = parser.parse_args(argv)
    if args.command == "bundle":
        from shared.proof_bundle import export_bundle
        try:
            output = export_bundle(args.proof, args.output)
        except (OutcomeProofError, OSError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(f"BUNDLE: {output}")
        return 0
    if args.command == "verify":
        try:
            result = verify_outcome_proof(read_outcome_proof(args.proof))
        except OutcomeProofError as exc:
            print(f"INVALID: {exc}")
            return 1
        print("VALID")
        print(f"proof_id={result['proof_id']}")
        print(f"key_id={result['key_id']}")
        print(f"verifier={result['verifier']}")
        print(f"outcome_id={result['outcome_id']}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
