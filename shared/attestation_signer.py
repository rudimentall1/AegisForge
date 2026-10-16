"""Loopback-only Ed25519 signing service for the AegisForge master process.

Workers never receive the private key. The signer accepts only bounded JSON
attestation inputs and delegates schema/verdict validation to shared.attestation.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import json
import os
import stat
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared.attestation import AttestationError, SIGNATURE_ALGORITHM, sign_attestation
from shared.attestation_registry import (
    AttestationRegistryError,
    CHECKPOINT_REQUEST_SCHEMA_VERSION,
    sign_registry_checkpoint,
)

MAX_BODY_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
REQUIRED_INPUT_FIELDS = {
    "case_ref", "finding_ref", "reproduction", "verdict", "verdict_rationale"
}
OPTIONAL_INPUT_FIELDS = {"issued_at"}


class SignerServiceError(ValueError):
    """Raised for invalid signer configuration or requests."""


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SignerServiceError("duplicate_json_key")
        result[key] = value
    return result


def _decode_request(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda item: (_ for _ in ()).throw(
                SignerServiceError(f"nonstandard_json_constant:{item}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SignerServiceError("invalid_json") from exc
    if not isinstance(value, dict):
        raise SignerServiceError("json_object_required")
    keys = set(value)
    if not REQUIRED_INPUT_FIELDS.issubset(keys):
        raise SignerServiceError("required_fields_missing")
    if keys - REQUIRED_INPUT_FIELDS - OPTIONAL_INPUT_FIELDS:
        raise SignerServiceError("unexpected_request_fields")
    return value




def _decode_checkpoint_request(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda item: (_ for _ in ()).throw(
                SignerServiceError(f"nonstandard_json_constant:{item}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SignerServiceError("invalid_json") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "registry"}
        or value.get("schema_version") != CHECKPOINT_REQUEST_SCHEMA_VERSION
        or not isinstance(value.get("registry"), dict)
    ):
        raise SignerServiceError("registry_checkpoint_request_invalid")
    return value


def load_private_key(path: str | os.PathLike[str]) -> Ed25519PrivateKey:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise SignerServiceError("private_key_path_must_be_regular_file")
    metadata = target.stat()
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SignerServiceError("private_key_permissions_too_open")
    raw = target.read_bytes()
    if len(raw) != 32:
        raise SignerServiceError("private_key_must_be_32_raw_bytes")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise SignerServiceError("private_key_invalid") from exc


def _public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def make_server(
    host: str,
    port: int,
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
    organization: str,
    token: str,
) -> ThreadingHTTPServer:
    if host != "127.0.0.1":
        raise SignerServiceError("signer_must_bind_loopback_only")
    if type(port) is not int or not 0 <= port <= 65535:
        raise SignerServiceError("signer_port_invalid")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SignerServiceError("ed25519_private_key_required")
    if not isinstance(key_id, str) or not key_id.strip():
        raise SignerServiceError("signer_key_id_required")
    if not isinstance(organization, str) or not organization.strip():
        raise SignerServiceError("signer_organization_required")
    if not isinstance(token, str) or len(token) < 32:
        raise SignerServiceError("signer_token_must_be_at_least_32_characters")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AegisForgeSigner/1"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Do not log credentials, request bodies, or attestation contents.
            return

        def _send(self, status: int, payload: dict) -> None:
            raw = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)

        def _authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "")
            expected = "Bearer " + token
            return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))

        def do_GET(self):
            if self.path == "/healthz":
                self._send(200, {"status": "ok", "service": "aegisforge-signer-v1"})
                return
            if self.path == "/v1/public-key":
                self._send(200, {
                    "algorithm": SIGNATURE_ALGORITHM,
                    "key_id": key_id,
                    "organization": organization,
                    "public_key": _public_key_b64(private_key),
                })
                return
            self._send(404, {"error": "not_found"})

        def do_POST(self):
            if self.path not in {"/v1/attest", "/v1/registry-checkpoint"}:
                self._send(404, {"error": "not_found"})
                return
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                self._send(415, {"error": "application_json_required"})
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 0:
                self._send(411, {"error": "content_length_required"})
                return
            if length > MAX_BODY_BYTES:
                self._send(413, {"error": "request_body_too_large"})
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                self._send(400, {"error": "request_body_truncated"})
                return
            try:
                if self.path == "/v1/attest":
                    inputs = _decode_request(raw)
                    attestation = sign_attestation(
                        case_ref=inputs["case_ref"],
                        finding_ref=inputs["finding_ref"],
                        reproduction=inputs["reproduction"],
                        verdict=inputs["verdict"],
                        verdict_rationale=inputs["verdict_rationale"],
                        private_key=private_key,
                        key_id=key_id,
                        organization=organization,
                        issued_at=inputs.get("issued_at"),
                    ).to_dict()
                    response = {
                        "attestation_id": attestation["attestation_id"],
                        "attestation": attestation,
                    }
                else:
                    inputs = _decode_checkpoint_request(raw)
                    checkpoint = sign_registry_checkpoint(
                        registry=inputs["registry"],
                        private_key=private_key,
                        key_id=key_id,
                        organization=organization,
                    )
                    response = {
                        "checkpoint_id": checkpoint["checkpoint_id"],
                        "checkpoint": checkpoint,
                    }
            except (SignerServiceError, AttestationError, AttestationRegistryError, TypeError, ValueError) as exc:
                reason = str(exc)
                if not reason or len(reason) > 120:
                    reason = "invalid_signing_request"
                self._send(400, {"error": reason})
                return
            encoded = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_RESPONSE_BYTES:
                self._send(413, {"error": "signer_response_too_large"})
                return
            self._send(200, response)

        def do_PUT(self):
            self._send(405, {"error": "method_not_allowed"})

        def do_DELETE(self):
            self._send(405, {"error": "method_not_allowed"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        host = os.environ.get("AEGISFORGE_SIGNER_HOST", "127.0.0.1")
        port = int(os.environ.get("AEGISFORGE_SIGNER_PORT", "8765"))
        if port == 0:
            raise SignerServiceError("signer_port_invalid")
        token = os.environ.get("AEGISFORGE_SIGNER_TOKEN", "")
        key_path = os.environ.get("AEGISFORGE_ATTESTATION_KEY_PATH", "")
        key_id = os.environ.get("AEGISFORGE_ATTESTATION_KEY_ID", "")
        organization = os.environ.get("AEGISFORGE_ATTESTATION_ORGANIZATION", "")
        if not key_path:
            raise SignerServiceError("AEGISFORGE_ATTESTATION_KEY_PATH_required")
        private_key = load_private_key(key_path)
        server = make_server(
            host, port, private_key=private_key, key_id=key_id,
            organization=organization, token=token,
        )
    except (OSError, ValueError, SignerServiceError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)[:200]}), file=sys.stderr)
        return 2
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
