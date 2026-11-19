import json

import pytest

from agents.security_checker.anvil_rpc_adapter import (
    AnvilRpcAdapterError,
    build_gateway_headers,
    prepare_gateway_request,
    validate_gateway_url,
)


def test_gateway_url_accepts_only_single_label_internal_service():
    assert validate_gateway_url("http://rpc-gateway:8545/rpc") == (
        "rpc-gateway",
        8545,
        "/rpc",
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://rpc-gateway:8545/rpc",
        "http://rpc.example.com:8545/rpc",
        "http://127.0.0.1:8545/rpc",
        "http://user:pass@rpc-gateway:8545/rpc",
        "http://rpc-gateway:8545/other",
        "http://rpc-gateway:8545/rpc?token=secret",
        "http://rpc-gateway:8545/rpc#fragment",
    ],
)
def test_gateway_url_rejects_non_internal_or_ambiguous_targets(url):
    with pytest.raises(AnvilRpcAdapterError):
        validate_gateway_url(url)


def test_gateway_headers_keep_bearer_token_out_of_rpc_payload():
    headers = build_gateway_headers("x" * 40)

    assert headers == {
        "Authorization": "Bearer " + "x" * 40,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "close",
    }


@pytest.mark.parametrize("token", ["", "short", "x" * 32 + "\n", None])
def test_gateway_headers_reject_invalid_bearer_token(token):
    with pytest.raises(AnvilRpcAdapterError):
        build_gateway_headers(token)


def test_adapter_allows_required_read_only_fork_methods():
    request = {
        "jsonrpc": "2.0",
        "id": "fork-1",
        "method": "eth_getCode",
        "params": ["0x" + "ab" * 20, "0x100"],
    }

    parsed, headers = prepare_gateway_request(
        json.dumps(request).encode(),
        bearer_token="x" * 40,
    )

    assert parsed == request
    assert headers["Authorization"] == "Bearer " + "x" * 40


@pytest.mark.parametrize(
    "method",
    ["eth_sendRawTransaction", "eth_sendTransaction", "personal_unlockAccount", "debug_traceCall"],
)
def test_adapter_rejects_methods_outside_fork_read_only_surface(method):
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": [],
    }

    with pytest.raises(AnvilRpcAdapterError, match="method_not_allowed"):
        prepare_gateway_request(
            json.dumps(request).encode(),
            bearer_token="x" * 40,
        )


def test_adapter_rejects_oversized_rpc_body():
    with pytest.raises(AnvilRpcAdapterError, match="request_body_size_invalid"):
        prepare_gateway_request(
            b" " * (1_048_577),
            bearer_token="x" * 40,
        )


def test_adapter_server_injects_gateway_auth_and_returns_validated_response():
    import http.client
    import threading

    from agents.security_checker.anvil_rpc_adapter import (
        create_anvil_rpc_adapter_server,
    )

    observed = {}

    def fake_transport(host, port, path, body, headers):
        observed["target"] = (host, port, path)
        observed["headers"] = headers
        observed["request"] = json.loads(body)
        response = {
            "jsonrpc": "2.0",
            "id": observed["request"]["id"],
            "result": "0xa4b1",
        }
        return 200, json.dumps(response).encode()

    server = create_anvil_rpc_adapter_server(
        "http://rpc-gateway:8545/rpc",
        "x" * 40,
        bind_host="127.0.0.1",
        port=0,
        transport=fake_transport,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            server.server_address[1],
            timeout=3,
        )
        request = {
            "jsonrpc": "2.0",
            "id": "adapter-test",
            "method": "eth_chainId",
            "params": [],
        }
        connection.request(
            "POST",
            "/rpc",
            body=json.dumps(request).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer attacker-controlled",
            },
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert response.status == 200
    assert payload["id"] == "adapter-test"
    assert payload["result"] == "0xa4b1"
    assert observed["target"] == ("rpc-gateway", 8545, "/rpc")
    assert observed["headers"]["Authorization"] == "Bearer " + "x" * 40
    assert observed["request"] == request


def test_adapter_server_rejects_write_method_before_gateway_forwarding():
    import http.client
    import threading

    from agents.security_checker.anvil_rpc_adapter import (
        create_anvil_rpc_adapter_server,
    )

    forwarded = []
    server = create_anvil_rpc_adapter_server(
        "http://rpc-gateway:8545/rpc",
        "x" * 40,
        bind_host="127.0.0.1",
        port=0,
        transport=lambda *args: forwarded.append(args),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            server.server_address[1],
            timeout=3,
        )
        connection.request(
            "POST",
            "/rpc",
            body=json.dumps({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "eth_sendRawTransaction",
                "params": ["0xdead"],
            }).encode(),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert response.status == 403
    assert forwarded == []
