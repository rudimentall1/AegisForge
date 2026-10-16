import base64
import http.client
import json
import threading
from contextlib import contextmanager

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation import verify_attestation
from shared.attestation_signer import MAX_BODY_BYTES, make_server
from shared.attestation_signer_client import (
    SignerClientError,
    request_attestation,
    request_registry_checkpoint,
)
from shared.attestation_registry import build_registry, verify_signed_checkpoint


TOKEN = "test-only-token-that-is-long-enough-123456"


def payload(verdict="INCONCLUSIVE"):
    import hashlib

    return {
        "case_ref": {
            "case_id": "signer-case-001",
            "case_digest": hashlib.sha256(b"case").hexdigest(),
            "target_repository": "example/project",
            "target_commit": "a" * 40,
            "scope_url": "https://example.invalid/scope",
            "scope_digest": hashlib.sha256(b"scope").hexdigest(),
        },
        "finding_ref": {
            "finding_id": "signer-finding-001",
            "claim": "Synthetic acceptance claim",
            "affected_component": "test-fixture",
            "source_locations": [],
            "impact_path": "synthetic-only",
        },
        "reproduction": {
            "reproduction_contract_sha256": hashlib.sha256(b"contract").hexdigest(),
            "commands": [["python", "-V"]],
            "environment": {"python": "3.x"},
            "network_access": False,
            "artifacts": [],
            "started_at": "2026-10-16T10:00:00+00:00",
            "completed_at": "2026-10-16T10:00:01+00:00",
            "exit_code": 0,
        },
        "verdict": verdict,
        "verdict_rationale": "Synthetic test only; no vulnerability claim.",
    }


@contextmanager
def running_signer():
    key = Ed25519PrivateKey.generate()
    server = make_server(
        "127.0.0.1", 0, private_key=key, key_id="test-signer",
        organization="AegisForge signer tests", token=TOKEN,
    )
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server, key, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def direct_request(url, *, path="/v1/attest", body=None, token=None, content_type="application/json"):
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2)
    headers = {"Content-Type": content_type, "Connection": "close"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    conn.request("POST", path, body=body or b"{}", headers=headers)
    response = conn.getresponse()
    raw = response.read()
    status = response.status
    conn.close()
    return status, json.loads(raw.decode("utf-8"))


def test_master_client_requests_attestation_without_private_key_access():
    with running_signer() as (_, key, url):
        attestation = request_attestation(payload(), base_url=url, token=TOKEN)
        verified = verify_attestation(
            attestation,
            trusted_keys={"test-signer": key.public_key()},
        )
        assert verified.status == "VALID"
        assert attestation["verdict"] == "INCONCLUSIVE"
        assert "private_key" not in attestation
        assert attestation["signer"]["key_id"] == "test-signer"


def test_signer_requires_bearer_token_and_rejects_wrong_token():
    with running_signer() as (_, __, url):
        status, body = direct_request(url, token=None)
        assert status == 401 and body["error"] == "unauthorized"
        status, body = direct_request(url, token="wrong-token")
        assert status == 401 and body["error"] == "unauthorized"


def test_signer_rejects_confirmed_and_extra_fields():
    with running_signer() as (_, __, url):
        status, body = direct_request(
            url, body=json.dumps(payload("CONFIRMED")).encode(), token=TOKEN
        )
        assert status == 400
        assert body["error"] == "verdict_not_allowed"

        extra = payload()
        extra["private_key"] = "must-not-be-accepted"
        status, body = direct_request(url, body=json.dumps(extra).encode(), token=TOKEN)
        assert status == 400
        assert body["error"] == "unexpected_request_fields"


def test_signer_rejects_duplicate_json_keys_and_wrong_content_type():
    with running_signer() as (_, __, url):
        status, body = direct_request(
            url,
            body=b'{"verdict":"INCONCLUSIVE","verdict":"REPRODUCED"}',
            token=TOKEN,
        )
        assert status == 400
        assert body["error"] == "duplicate_json_key"

        status, body = direct_request(
            url, body=b"{}", token=TOKEN, content_type="text/plain"
        )
        assert status == 415
        assert body["error"] == "application_json_required"


def test_signer_enforces_body_limit_before_parsing():
    with running_signer() as (_, __, url):
        status, body = direct_request(
            url, body=b"x" * (MAX_BODY_BYTES + 1), token=TOKEN
        )
        assert status == 413
        assert body["error"] == "request_body_too_large"


def test_client_refuses_non_loopback_or_non_http_urls():
    with pytest.raises(SignerClientError, match="signer_url_must_be_plain_http_loopback"):
        request_attestation(payload(), base_url="http://192.0.2.10:8765", token=TOKEN)
    with pytest.raises(SignerClientError, match="signer_url_must_be_plain_http_loopback"):
        request_attestation(payload(), base_url="https://127.0.0.1:8765", token=TOKEN)


def test_public_key_and_health_endpoints_do_not_expose_private_material():
    with running_signer() as (_, key, url):
        import urllib.request

        with urllib.request.urlopen(url + "/healthz", timeout=2) as response:
            health = json.loads(response.read().decode("utf-8"))
            assert response.status == 200
            assert health["status"] == "ok"
        with urllib.request.urlopen(url + "/v1/public-key", timeout=2) as response:
            public = json.loads(response.read().decode("utf-8"))
            assert response.status == 200
            assert public["key_id"] == "test-signer"
            assert len(base64.b64decode(public["public_key"])) == 32
            assert "private_key" not in public


def test_master_client_requests_signed_registry_checkpoint():
    import hashlib

    registry = build_registry([{
        "attestation_id": hashlib.sha256(b"attestation-id").hexdigest(),
        "attestation_sha256": hashlib.sha256(b"signed-attestation").hexdigest(),
        "case_digest": hashlib.sha256(b"case-digest").hexdigest(),
        "verdict": "INCONCLUSIVE",
        "issued_at": "2026-10-16T10:00:00+00:00",
        "key_id": "test-signer",
    }])
    with running_signer() as (_, key, url):
        checkpoint = request_registry_checkpoint(registry, base_url=url, token=TOKEN)
        verified = verify_signed_checkpoint(
            checkpoint,
            trusted_keys={"test-signer": key.public_key()},
            registry=registry,
        )
        assert verified["valid"] is True
        assert verified["root_trust"] == "SIGNED_CHECKPOINT"
        assert checkpoint["registry"]["merkle_root"] == registry["merkle_root"]


def test_signer_rejects_malformed_registry_checkpoint_request():
    with running_signer() as (_, __, url):
        status, body = direct_request(
            url,
            path="/v1/registry-checkpoint",
            body=json.dumps({
                "schema_version": "wrong-schema",
                "registry": {},
            }).encode(),
            token=TOKEN,
        )
        assert status == 400
        assert body["error"] == "registry_checkpoint_request_invalid"
