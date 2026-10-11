import copy
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.lab_execution_receipt import (
    LabExecutionReceiptError,
    build_receipt,
    canonical_json,
    receipt_sha256,
    sign_receipt,
    verify_signed_receipt,
)


def _public_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _receipt():
    return build_receipt(
        run_id="synthetic-run-0001",
        experiment_id="synthetic-entropy-demo-v1",
        inputs={
            "source_kind": "repository_owned_synthetic_demo",
            "source_revision": None,
            "test_vector_id": "synthetic-vector-001",
            "argv": ["python", "-c", "print('synthetic-only')"],
        },
        execution={
            "exit_code": 0,
            "timed_out": False,
            "test_passed": True,
            "stdout_sha256": hashlib.sha256(b"synthetic-only\n").hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        },
        artifacts={"result_sha256": hashlib.sha256(b"result").hexdigest()},
    )


def test_canonical_json_is_stable_across_key_order():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})

    receipt = _receipt()
    reordered = dict(reversed(list(receipt.items())))
    reordered["execution"] = dict(reversed(list(receipt["execution"].items())))
    assert receipt_sha256(receipt) == receipt_sha256(reordered)


def test_canonical_json_rejects_non_finite_numbers():
    with pytest.raises(LabExecutionReceiptError, match="receipt_not_canonicalizable"):
        canonical_json({"value": float("nan")})


def test_signed_receipt_verifies_against_explicit_trusted_key():
    private_key = Ed25519PrivateKey.generate()
    receipt = _receipt()
    envelope = sign_receipt(receipt, private_key=private_key, key_id="test-runner-1")

    result = verify_signed_receipt(
        envelope,
        trusted_public_keys={"test-runner-1": _public_bytes(private_key)},
    )
    assert result["valid"] is True
    assert result["run_id"] == "synthetic-run-0001"
    assert result["receipt_sha256"] == receipt_sha256(receipt)


def test_signed_receipt_rejects_unknown_key_id():
    private_key = Ed25519PrivateKey.generate()
    envelope = sign_receipt(_receipt(), private_key=private_key, key_id="runner-a")

    with pytest.raises(LabExecutionReceiptError, match="untrusted_runner_key"):
        verify_signed_receipt(envelope, trusted_public_keys={})


def test_signed_receipt_rejects_tampered_receipt_even_if_digest_is_recomputed():
    private_key = Ed25519PrivateKey.generate()
    envelope = sign_receipt(_receipt(), private_key=private_key, key_id="runner-a")
    changed = copy.deepcopy(envelope)
    changed["receipt"]["execution"]["exit_code"] = 0
    changed["receipt"]["execution"]["test_passed"] = False
    changed["receipt_sha256"] = receipt_sha256(changed["receipt"])

    with pytest.raises(LabExecutionReceiptError, match="receipt_signature_invalid"):
        verify_signed_receipt(
            changed,
            trusted_public_keys={"runner-a": _public_bytes(private_key)},
        )


def test_signed_receipt_rejects_tampered_digest_and_key_mismatch():
    private_key = Ed25519PrivateKey.generate()
    envelope = sign_receipt(_receipt(), private_key=private_key, key_id="runner-a")
    changed_digest = copy.deepcopy(envelope)
    changed_digest["receipt_sha256"] = "0" * 64

    with pytest.raises(LabExecutionReceiptError, match="receipt_digest_mismatch"):
        verify_signed_receipt(
            changed_digest,
            trusted_public_keys={"runner-a": _public_bytes(private_key)},
        )

    other_key = Ed25519PrivateKey.generate()
    with pytest.raises(LabExecutionReceiptError, match="signer_key_fingerprint_mismatch"):
        verify_signed_receipt(
            envelope,
            trusted_public_keys={"runner-a": _public_bytes(other_key)},
        )


def test_receipt_requires_nonempty_run_and_experiment_ids():
    with pytest.raises(LabExecutionReceiptError, match="run_id_required"):
        build_receipt(
            run_id=" ",
            experiment_id="demo",
            inputs={},
            execution={},
        )


def test_signing_rejects_receipt_missing_required_fields():
    private_key = Ed25519PrivateKey.generate()
    with pytest.raises(LabExecutionReceiptError, match="run_id_required"):
        sign_receipt(
            {"schema_version": 1, "receipt_type": "aegisforge.lab_execution"},
            private_key=private_key,
            key_id="runner-a",
        )
