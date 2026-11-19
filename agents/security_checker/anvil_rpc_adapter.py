"""Narrow RPC adapter for Anvil-to-AegisForge-Gateway traffic.

The adapter injects the Gateway bearer token from process memory rather than
placing it in Anvil command-line arguments. It does not create or enforce
Docker network isolation or egress policy; deployment must do that separately.
"""
from __future__ import annotations

import http.client
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from agents.security_checker.rpc_gateway import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    RpcGatewayError,
    parse_rpc_request,
    validate_rpc_response,
)


ANVIL_READ_ONLY_METHODS = frozenset(
    {
        "eth_chainId",
        "eth_blockNumber",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_call",
        "eth_getLogs",
        "eth_getProof",
        "net_version",
        "web3_clientVersion",
    }
)


class AnvilRpcAdapterError(ValueError):
    """An Anvil RPC request or adapter configuration violates policy."""


def validate_gateway_url(url: str) -> tuple[str, int, str]:
    """Accept only an HTTP endpoint on a single-label internal service name."""
    if (
        not isinstance(url, str)
        or any(ord(char) <= 32 or ord(char) == 127 for char in url)
        or "\\\\" in url
    ):
        raise AnvilRpcAdapterError("gateway_url_invalid")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise AnvilRpcAdapterError("gateway_url_invalid") from exc
    if (
        parsed.scheme != "http"
        or not hostname
        or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/rpc"
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1 <= port <= 65535
    ):
        raise AnvilRpcAdapterError("gateway_target_not_internal_service")
    return hostname, port, parsed.path


def build_gateway_headers(bearer_token: str) -> dict[str, str]:
    """Build fixed headers; credentials are never copied into the RPC payload."""
    if (
        not isinstance(bearer_token, str)
        or len(bearer_token) < 32
        or not bearer_token.isascii()
        or any(ord(char) <= 32 or ord(char) == 127 for char in bearer_token)
    ):
        raise AnvilRpcAdapterError("gateway_token_invalid")
    return {
        "Authorization": "Bearer " + bearer_token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "close",
    }


def prepare_gateway_request(
    body: bytes,
    *,
    bearer_token: str,
) -> tuple[dict, dict[str, str]]:
    """Validate a single Anvil read-only JSON-RPC request and prepare auth."""
    try:
        request = parse_rpc_request(
            body,
            allowed_methods=ANVIL_READ_ONLY_METHODS,
        )
    except RpcGatewayError as exc:
        raise AnvilRpcAdapterError(str(exc)) from exc
    return request, build_gateway_headers(bearer_token)


def _post_gateway(
    host: str,
    port: int,
    path: str,
    body: bytes,
    headers: dict[str, str],
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=15)
    try:
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            return response.status, b""
        chunks = []
        total = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise AnvilRpcAdapterError("gateway_response_size_invalid")
            chunks.append(chunk)
        return response.status, b"".join(chunks)
    except (OSError, http.client.HTTPException) as exc:
        raise AnvilRpcAdapterError("gateway_transport_failed") from exc
    finally:
        connection.close()


def create_anvil_rpc_adapter_server(
    gateway_url: str,
    bearer_token: str,
    *,
    bind_host: str = "127.0.0.1",
    port: int = 8546,
    transport=None,
):
    """Create a bounded adapter listener; network isolation is external policy."""
    host, gateway_port, gateway_path = validate_gateway_url(gateway_url)
    if (
        not isinstance(bind_host, str)
        or not bind_host
        or isinstance(port, bool)
        or not isinstance(port, int)
        or not 0 <= port <= 65535
    ):
        raise AnvilRpcAdapterError("listener_configuration_invalid")
    forward = transport or _post_gateway
    slots = threading.BoundedSemaphore(8)

    class BoundedServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = False

        def process_request(self, request, client_address):
            if not slots.acquire(blocking=False):
                request.close()
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
        server_version = "AegisForgeAnvilAdapter"
        sys_version = ""

        def log_message(self, format, *args):
            return

        def _reply(self, status: int, body: bytes = b""):
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            if body:
                self.send_header("Content-Type", "application/json")
            self.end_headers()
            if body:
                self.wfile.write(body)
            self.close_connection = True

        def do_GET(self):
            self._reply(405)

        def do_PUT(self):
            self._reply(405)

        def do_DELETE(self):
            self._reply(405)

        def do_POST(self):
            if self.path != "/rpc":
                self._reply(404)
                return
            if self.headers.get("Transfer-Encoding") is not None:
                self._reply(400)
                return
            if self.headers.get_content_type() != "application/json":
                self._reply(415)
                return
            raw_length = self.headers.get("Content-Length")
            if (
                raw_length is None
                or not raw_length.isascii()
                or not raw_length.isdecimal()
                or len(raw_length) > 10
            ):
                self._reply(411)
                return
            length = int(raw_length)
            if not 1 <= length <= MAX_REQUEST_BYTES:
                self._reply(413)
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self._reply(400)
                return
            try:
                request, headers = prepare_gateway_request(
                    body,
                    bearer_token=bearer_token,
                )
            except AnvilRpcAdapterError:
                self._reply(403)
                return

            try:
                encoded = json.dumps(
                    request,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
                status, response_body = forward(
                    host,
                    gateway_port,
                    gateway_path,
                    encoded,
                    headers,
                )
                validate_rpc_response(
                    status_code=status,
                    body=response_body,
                    expected_id=request["id"],
                )
            except (AnvilRpcAdapterError, RpcGatewayError, OSError, TimeoutError):
                self._reply(502)
                return
            except Exception:
                # Do not expose transport/client exception details to Anvil.
                self._reply(502)
                return
            self._reply(200, response_body)

    try:
        return BoundedServer((bind_host, port), Handler)
    except OSError as exc:
        raise AnvilRpcAdapterError("listener_bind_failed") from exc
