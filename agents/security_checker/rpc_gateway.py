"""Authenticated, bounded HTTP gateway for an allowlisted read-only EVM RPC upstream.

The listener defaults to loopback. Binding it to a container interface requires
an isolated Docker network and an egress policy that permits only the configured
upstream. This module does not create or enforce those network policies.
"""
from __future__ import annotations

import ipaddress
import json
import re
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
        isinstance(request_id, int)
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
    if (
        not isinstance(url, str)
        or any(ord(char) <= 32 or ord(char) == 127 for char in url)
        or "\\\\" in url
        or not isinstance(allowed_hosts, set)
        or not allowed_hosts
    ):
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
    session = None
    if transport is None:
        session = requests.Session()
        session.trust_env = False
        transport = session.post
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
        if session is not None:
            session.close()


def validate_fork_anchor(
    *,
    chain_response: dict,
    block_response: dict,
    expected_chain_id: int,
    expected_block_number: int,
    expected_block_hash: str,
) -> dict:
    """Bind a fork target to one configured chain, height, and block hash."""
    if (
        isinstance(expected_chain_id, bool)
        or not isinstance(expected_chain_id, int)
        or expected_chain_id <= 0
        or isinstance(expected_block_number, bool)
        or not isinstance(expected_block_number, int)
        or expected_block_number < 0
        or not isinstance(expected_block_hash, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]{64}", expected_block_hash)
    ):
        raise RpcGatewayError("fork_anchor_configuration_invalid")

    if (
        not isinstance(chain_response, dict)
        or chain_response.get("jsonrpc") != "2.0"
        or not isinstance(block_response, dict)
        or block_response.get("jsonrpc") != "2.0"
        or "result" not in chain_response
        or not isinstance(chain_response["result"], str)
        or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", chain_response["result"])
    ):
        raise RpcGatewayError("fork_chain_identity_invalid")
    try:
        observed_chain_id = int(chain_response["result"], 16)
    except ValueError as exc:
        raise RpcGatewayError("fork_chain_identity_invalid") from exc
    if observed_chain_id != expected_chain_id:
        raise RpcGatewayError("fork_chain_id_mismatch")

    block = block_response.get("result")
    if not isinstance(block, dict):
        raise RpcGatewayError("fork_block_identity_invalid")
    number = block.get("number")
    block_hash = block.get("hash")
    if (
        not isinstance(number, str)
        or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", number)
        or not isinstance(block_hash, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]{64}", block_hash)
    ):
        raise RpcGatewayError("fork_block_identity_invalid")
    observed_block_number = int(number, 16)
    if observed_block_number != expected_block_number:
        raise RpcGatewayError("fork_block_number_mismatch")
    if block_hash.lower() != expected_block_hash.lower():
        raise RpcGatewayError("fork_block_hash_mismatch")

    return {
        "chain_id": observed_chain_id,
        "block_number": observed_block_number,
        "block_hash": block_hash.lower(),
        "anchor_verified": True,
    }


def create_rpc_gateway_server(
    upstream_url: str,
    allowed_hosts: set[str],
    bearer_token: str,
    *,
    bind_host: str = "127.0.0.1",
    port: int = 8545,
    max_concurrent_requests: int = 8,
):
    """Create a bounded authenticated HTTP listener for the read-only RPC gateway.

    The default bind address is loopback. Deployments that bind to a container
    interface must additionally isolate that interface at the network layer.
    The bearer token authenticates the research-side caller; it is never sent
    to the upstream RPC provider.
    """
    import hmac
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    if (
        not isinstance(bearer_token, str)
        or len(bearer_token) < 32
        or not bearer_token.isascii()
        or not isinstance(max_concurrent_requests, int)
        or isinstance(max_concurrent_requests, bool)
        or not 1 <= max_concurrent_requests <= 64
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 0 <= port <= 65535
        or not isinstance(bind_host, str)
        or not bind_host
    ):
        raise RpcGatewayError("gateway_listener_configuration_invalid")

    validate_upstream_url(upstream_url, allowed_hosts=allowed_hosts)
    slots = threading.BoundedSemaphore(max_concurrent_requests)

    class BoundedThreadingHTTPServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = False

        def process_request(self, request, client_address):
            if not slots.acquire(blocking=False):
                try:
                    request.sendall(
                        b"HTTP/1.1 503 Service Unavailable\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                except OSError:
                    pass
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                slots.release()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(10)
        server_version = "AegisForgeRPC"
        sys_version = ""

        def log_message(self, format, *args):
            # Avoid logging bearer tokens, provider URLs, and RPC payloads.
            return

        def _reply(self, status: int, payload: dict | None = None):
            body = b"" if payload is None else json.dumps(
                payload, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            if payload is not None:
                self.send_header("Content-Type", "application/json")
            self.end_headers()
            if body:
                self.wfile.write(body)
            self.close_connection = True

        def do_GET(self):
            self._reply(405, {"error": "method_not_allowed"})

        def do_PUT(self):
            self._reply(405, {"error": "method_not_allowed"})

        def do_DELETE(self):
            self._reply(405, {"error": "method_not_allowed"})

        def do_POST(self):
            if self.path != "/rpc":
                self._reply(404, {"error": "route_not_found"})
                return
            if self.headers.get("Transfer-Encoding") is not None:
                self._reply(400, {"error": "transfer_encoding_not_supported"})
                return
            if self.headers.get_content_type() != "application/json":
                self._reply(415, {"error": "content_type_must_be_json"})
                return
            auth = self.headers.get("Authorization", "")
            expected = "Bearer " + bearer_token
            if not hmac.compare_digest(auth, expected):
                self._reply(401, {"error": "unauthorized"})
                return
            raw_length = self.headers.get("Content-Length")
            if raw_length is None or not raw_length.isascii() or not raw_length.isdecimal():
                self._reply(411, {"error": "content_length_required"})
                return
            length = int(raw_length)
            if length < 1 or length > MAX_REQUEST_BYTES:
                self._reply(413, {"error": "request_body_size_invalid"})
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self._reply(400, {"error": "request_body_incomplete"})
                return
            try:
                result = forward_rpc_request(
                    upstream_url,
                    allowed_hosts,
                    body,
                )
            except RpcGatewayError as exc:
                status = 403 if str(exc) == "method_not_allowed" else 502
                self._reply(status, {"error": str(exc)})
                return
            self._reply(200, result)

    try:
        server = BoundedThreadingHTTPServer((bind_host, port), Handler)
    except OSError as exc:
        raise RpcGatewayError("gateway_listener_bind_failed") from exc
    return server
