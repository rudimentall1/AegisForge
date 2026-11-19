"""Strict validation primitives for a read-only EVM JSON-RPC gateway.

This module deliberately does not start a listener or choose an upstream. The
caller must bind its HTTP server to an isolated interface and configure an
explicit hostname allowlist before forwarding requests.
"""
from __future__ import annotations

import ipaddress
import json
from urllib.parse import urlsplit


MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576
MAX_REQUEST_ID_LENGTH = 128

DEFAULT_READ_ONLY_METHODS = frozenset(
    {
        "eth_chainId",
        "eth_blockNumber",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getBlockTransactionCountByHash",
        "eth_getBlockTransactionCountByNumber",
        "eth_getTransactionByHash",
        "eth_getTransactionByBlockHashAndIndex",
        "eth_getTransactionByBlockNumberAndIndex",
        "eth_getTransactionReceipt",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_call",
        "eth_getLogs",
        "eth_feeHistory",
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
        "eth_getProof",
        "net_version",
        "web3_clientVersion",
    }
)


class RpcGatewayError(ValueError):
    """A request or upstream response violates the gateway boundary."""


def _reject_constant(value: str):
    raise RpcGatewayError("json_constant_not_allowed")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RpcGatewayError("duplicate_json_key")
        result[key] = value
    return result


def parse_rpc_request(
    body: bytes,
    *,
    allowed_methods=frozenset(DEFAULT_READ_ONLY_METHODS),
) -> dict:
    """Parse one bounded JSON-RPC request and enforce an explicit method allowlist."""
    if not isinstance(body, bytes):
        raise RpcGatewayError("request_body_invalid")
    if not body or len(body) > MAX_REQUEST_BYTES:
        raise RpcGatewayError("request_body_size_invalid")
    try:
        payload = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RpcGatewayError("request_json_invalid") from exc

    if not isinstance(payload, dict):
        raise RpcGatewayError("single_request_object_required")
    if set(payload) - {"jsonrpc", "id", "method", "params"}:
        raise RpcGatewayError("request_fields_invalid")
    if payload.get("jsonrpc") != "2.0":
        raise RpcGatewayError("jsonrpc_version_invalid")
    if "id" not in payload:
        raise RpcGatewayError("request_id_invalid")
    request_id = payload["id"]
    if isinstance(request_id, bool) or not (
        request_id is None
        or isinstance(request_id, int)
        or isinstance(request_id, str)
    ):
        raise RpcGatewayError("request_id_invalid")
    if isinstance(request_id, int) and not -(2**53) < request_id < 2**53:
        raise RpcGatewayError("request_id_invalid")
    if isinstance(request_id, str) and (
        not request_id or len(request_id) > MAX_REQUEST_ID_LENGTH
    ):
        raise RpcGatewayError("request_id_invalid")

    method = payload.get("method")
    if not isinstance(method, str) or method not in allowed_methods:
        raise RpcGatewayError("method_not_allowed")
    params = payload.get("params", [])
    if not isinstance(params, (list, dict)):
        raise RpcGatewayError("request_params_invalid")

    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def validate_upstream_url(url: str, *, allowed_hosts: set[str]) -> str:
    """Accept only an explicitly allowlisted HTTPS origin without URL credentials."""
    if not isinstance(url, str) or not isinstance(allowed_hosts, set) or not allowed_hosts:
        raise RpcGatewayError("upstream_configuration_invalid")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise RpcGatewayError("upstream_url_invalid") from exc

    normalized_hosts = {
        host.strip().lower().rstrip(".")
        for host in allowed_hosts
        if isinstance(host, str) and host.strip()
    }
    if (
        parsed.scheme != "https"
        or not hostname
        or hostname.lower().rstrip(".") not in normalized_hosts
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise RpcGatewayError("upstream_url_not_allowlisted")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
    ):
        raise RpcGatewayError("upstream_ip_not_public")

    return url


def validate_rpc_response(
    *,
    status_code: int,
    body: bytes,
    expected_id,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> dict:
    """Validate a bounded upstream response and bind it to the request ID."""
    if (
        isinstance(max_response_bytes, bool)
        or not isinstance(max_response_bytes, int)
        or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES
    ):
        raise RpcGatewayError("response_limit_invalid")
    if status_code != 200:
        raise RpcGatewayError("upstream_http_status_rejected")
    if not isinstance(body, bytes) or not body or len(body) > max_response_bytes:
        raise RpcGatewayError("upstream_response_size_invalid")
    try:
        payload = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RpcGatewayError("upstream_response_invalid") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("jsonrpc") != "2.0"
        or "id" not in payload
        or set(payload) - {"jsonrpc", "id", "result", "error"}
        or ("result" in payload) == ("error" in payload)
    ):
        raise RpcGatewayError("upstream_response_invalid")
    if payload.get("id") != expected_id or isinstance(payload.get("id"), bool):
        raise RpcGatewayError("upstream_response_id_mismatch")
    if "error" in payload and (
        not isinstance(payload["error"], dict)
        or not isinstance(payload["error"].get("code"), int)
        or isinstance(payload["error"].get("code"), bool)
        or not isinstance(payload["error"].get("message"), str)
    ):
        raise RpcGatewayError("upstream_response_invalid")
    return payload


def forward_rpc_request(
    upstream_url: str,
    allowed_hosts: set[str],
    body: bytes,
    *,
    transport=None,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> dict:
    """Forward one allowlisted request with bounded streaming and no redirects.

    The caller remains responsible for exposing this function only behind a
    separately isolated listener. No caller-supplied headers or URL are passed
    through from the untrusted RPC request.
    """
    import requests

    validated_url = validate_upstream_url(
        upstream_url,
        allowed_hosts=allowed_hosts,
    )
    request = parse_rpc_request(body)
    if transport is None:
        transport = requests.post
    if (
        isinstance(max_response_bytes, bool)
        or not isinstance(max_response_bytes, int)
        or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES
    ):
        raise RpcGatewayError("response_limit_invalid")

    encoded_request = json.dumps(
        request,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    response = None
    try:
        response = transport(
            validated_url,
            data=encoded_request,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=(3.0, 15.0),
            allow_redirects=False,
            stream=True,
        )
        status_code = response.status_code
        if status_code != 200:
            return validate_rpc_response(
                status_code=status_code,
                body=b"",
                expected_id=request["id"],
                max_response_bytes=max_response_bytes,
            )

        chunks = []
        total_bytes = 0
        for chunk in response.iter_content(chunk_size=65536):
            if not isinstance(chunk, bytes):
                raise RpcGatewayError("upstream_response_invalid")
            total_bytes += len(chunk)
            if total_bytes > max_response_bytes:
                raise RpcGatewayError("upstream_response_size_invalid")
            if chunk:
                chunks.append(chunk)
        return validate_rpc_response(
            status_code=status_code,
            body=b"".join(chunks),
            expected_id=request["id"],
            max_response_bytes=max_response_bytes,
        )
    except requests.RequestException as exc:
        raise RpcGatewayError("upstream_transport_failed") from exc
    finally:
        if response is not None:
            response.close()
