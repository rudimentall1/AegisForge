"""Master-side HTTP client for the loopback-only AegisForge signer service."""
from __future__ import annotations

import http.client
import json
import os
from urllib.parse import urlsplit


MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 512 * 1024


class SignerClientError(RuntimeError):
    """Raised when the signer service cannot safely return an attestation."""


def request_attestation(
    payload: dict,
    *,
    base_url: str | None = None,
    token: str | None = None,
    timeout: float = 3.0,
) -> dict:
    """Request a signature without loading private key material into the caller."""
    url = base_url or os.environ.get("AEGISFORGE_SIGNER_URL", "http://127.0.0.1:8765")
    secret = token if token is not None else os.environ.get("AEGISFORGE_SIGNER_TOKEN", "")
    if not isinstance(secret, str) or len(secret) < 32:
        raise SignerClientError("signer_token_missing_or_too_short")
    if not isinstance(payload, dict):
        raise SignerClientError("attestation_payload_must_be_object")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise SignerClientError("signer_url_must_be_plain_http_loopback")
    try:
        port = parsed.port or 80
        body = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SignerClientError("attestation_payload_not_json_serializable") from exc
    if len(body) > MAX_REQUEST_BYTES:
        raise SignerClientError("attestation_payload_too_large")

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(
            "POST",
            "/v1/attest",
            body=body,
            headers={
                "Authorization": "Bearer " + secret,
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise SignerClientError("signer_response_too_large")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SignerClientError("signer_returned_invalid_json") from exc
        if response.status != 200:
            code = decoded.get("error", "request_rejected") if isinstance(decoded, dict) else "request_rejected"
            raise SignerClientError(f"signer_request_rejected:{response.status}:{str(code)[:100]}")
        if (
            not isinstance(decoded, dict)
            or not isinstance(decoded.get("attestation"), dict)
            or not isinstance(decoded.get("attestation_id"), str)
            or decoded["attestation"].get("attestation_id") != decoded["attestation_id"]
        ):
            raise SignerClientError("signer_response_contract_invalid")
        return decoded["attestation"]
    except (OSError, http.client.HTTPException) as exc:
        raise SignerClientError("signer_service_unavailable") from exc
    finally:
        connection.close()
