import json

import pytest

from agents.security_checker.rpc_gateway import (
    DEFAULT_READ_ONLY_METHODS,
    RpcGatewayError,
    parse_rpc_request,
    validate_rpc_response,
    validate_upstream_url,
)


def test_accepts_single_read_only_json_rpc_request():
    request = parse_rpc_request(
        b'{"jsonrpc":"2.0","id":7,"method":"eth_getBlockByNumber","params":["latest",false]}'
    )

    assert request["id"] == 7
    assert request["method"] == "eth_getBlockByNumber"
    assert request["params"] == ["latest", False]


@pytest.mark.parametrize(
    "body",
    [
        b"not-json",
        b"[]",
        b'[{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}]',
        b'{"jsonrpc":"1.0","id":1,"method":"eth_chainId","params":[]}',
        b'{"jsonrpc":"2.0","id":true,"method":"eth_chainId","params":[]}',
        b'{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x00"]}',
        b'{"jsonrpc":"2.0","id":1,"method":"debug_traceTransaction","params":["0x00",{}]}',
        b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[],"extra":true}',
    ],
)
def test_rejects_malformed_batch_or_mutating_rpc_requests(body):
    with pytest.raises(RpcGatewayError):
        parse_rpc_request(body)


def test_rejects_unknown_read_method_even_if_its_name_looks_safe():
    with pytest.raises(RpcGatewayError, match="method_not_allowed"):
        parse_rpc_request(
            b'{"jsonrpc":"2.0","id":1,"method":"eth_unknownReadMethod","params":[]}'
        )


def test_read_only_allowlist_is_explicit_and_excludes_mutating_methods():
    assert "eth_chainId" in DEFAULT_READ_ONLY_METHODS
    assert "eth_call" in DEFAULT_READ_ONLY_METHODS
    assert "eth_sendTransaction" not in DEFAULT_READ_ONLY_METHODS
    assert "eth_sendRawTransaction" not in DEFAULT_READ_ONLY_METHODS
    assert not any(method.startswith(("debug_", "anvil_", "personal_")) for method in DEFAULT_READ_ONLY_METHODS)


@pytest.mark.parametrize(
    "url",
    [
        "http://rpc.example.test",
        "https://user:pass@rpc.example.test",
        "https://rpc.example.test/path?token=secret",
        "https://rpc.example.test/path#fragment",
        "https://attacker.example.test",
        "https://rpc.example.test:8546",
    ],
)
def test_rejects_untrusted_or_ambiguous_upstream_urls(url):
    with pytest.raises(RpcGatewayError):
        validate_upstream_url(url, allowed_hosts={"rpc.example.test"})


def test_accepts_exact_allowlisted_https_upstream():
    assert validate_upstream_url(
        "https://rpc.example.test/",
        allowed_hosts={"rpc.example.test"},
    ) == "https://rpc.example.test/"


def test_rejects_upstream_redirect_status():
    with pytest.raises(RpcGatewayError, match="upstream_http_status_rejected"):
        validate_rpc_response(
            status_code=307,
            body=b'{"jsonrpc":"2.0","id":1,"result":"0x1"}',
            expected_id=1,
        )


def test_rejects_response_with_mismatched_id_or_invalid_json():
    with pytest.raises(RpcGatewayError, match="upstream_response_id_mismatch"):
        validate_rpc_response(
            status_code=200,
            body=b'{"jsonrpc":"2.0","id":2,"result":"0x1"}',
            expected_id=1,
        )

    with pytest.raises(RpcGatewayError, match="upstream_response_invalid"):
        validate_rpc_response(status_code=200, body=b"{", expected_id=1)


def test_accepts_valid_bounded_json_rpc_response():
    result = validate_rpc_response(
        status_code=200,
        body=json.dumps({"jsonrpc": "2.0", "id": "req-1", "result": "0x1"}).encode(),
        expected_id="req-1",
    )

    assert result["result"] == "0x1"


@pytest.mark.parametrize(
    "body",
    [
        b'{"jsonrpc":"2.0","method":"eth_chainId","params":[]}',
        b'{"jsonrpc":"2.0","id":1,"id":2,"method":"eth_chainId","params":[]}',
    ],
)
def test_rejects_missing_or_duplicate_request_id(body):
    with pytest.raises(RpcGatewayError):
        parse_rpc_request(body)


def test_rejects_oversized_request_and_response():
    with pytest.raises(RpcGatewayError, match="request_body_size_invalid"):
        parse_rpc_request(b" " * (1_048_576 + 1))

    with pytest.raises(RpcGatewayError, match="upstream_response_size_invalid"):
        validate_rpc_response(
            status_code=200,
            body=b'{"jsonrpc":"2.0","id":1,"result":"' + b"x" * 64 + b'"}',
            expected_id=1,
            max_response_bytes=32,
        )


class FakeResponse:
    def __init__(self, status_code, chunks):
        self.status_code = status_code
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size):
        assert chunk_size == 65536
        yield from self._chunks

    def close(self):
        self.closed = True


def test_gateway_forwards_only_normalized_read_request_without_redirects():
    from agents.security_checker.rpc_gateway import forward_rpc_request

    observed = {}
    response = FakeResponse(
        200,
        [b'{"jsonrpc":"2.0","id":4,"result":"0x1"}'],
    )

    def transport(url, **kwargs):
        observed["url"] = url
        observed.update(kwargs)
        return response

    result = forward_rpc_request(
        "https://rpc.example.test/",
        {"rpc.example.test"},
        b'{"jsonrpc":"2.0","id":4,"method":"eth_chainId","params":[]}',
        transport=transport,
    )

    assert result["result"] == "0x1"
    assert observed["url"] == "https://rpc.example.test/"
    assert observed["allow_redirects"] is False
    assert observed["stream"] is True
    assert observed["timeout"] == (3.0, 15.0)
    assert observed["headers"] == {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    assert json.loads(observed["data"])["method"] == "eth_chainId"
    assert response.closed is True


def test_gateway_closes_response_and_rejects_oversized_upstream_body():
    from agents.security_checker.rpc_gateway import forward_rpc_request

    response = FakeResponse(200, [b"x" * 20])

    def transport(url, **kwargs):
        return response

    with pytest.raises(RpcGatewayError, match="upstream_response_size_invalid"):
        forward_rpc_request(
            "https://rpc.example.test/",
            {"rpc.example.test"},
            b'{"jsonrpc":"2.0","id":4,"method":"eth_chainId","params":[]}',
            transport=transport,
            max_response_bytes=10,
        )

    assert response.closed is True


def test_gateway_never_follows_upstream_redirects():
    from agents.security_checker.rpc_gateway import forward_rpc_request

    response = FakeResponse(307, [])

    def transport(url, **kwargs):
        assert kwargs["allow_redirects"] is False
        return response

    with pytest.raises(RpcGatewayError, match="upstream_http_status_rejected"):
        forward_rpc_request(
            "https://rpc.example.test/",
            {"rpc.example.test"},
            b'{"jsonrpc":"2.0","id":4,"method":"eth_chainId","params":[]}',
            transport=transport,
        )

    assert response.closed is True


def test_fork_anchor_requires_expected_chain_height_and_hash():
    from agents.security_checker.rpc_gateway import validate_fork_anchor

    result = validate_fork_anchor(
        chain_response={"jsonrpc": "2.0", "id": 1, "result": "0x1"},
        block_response={
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "number": "0x2a",
                "hash": "0x" + "a" * 64,
            },
        },
        expected_chain_id=1,
        expected_block_number=42,
        expected_block_hash="0x" + "a" * 64,
    )

    assert result == {
        "chain_id": 1,
        "block_number": 42,
        "block_hash": "0x" + "a" * 64,
        "anchor_verified": True,
    }


@pytest.mark.parametrize(
    ("chain_id", "block_number", "block_hash"),
    [
        ("0x2", 42, "0x" + "a" * 64),
        ("0x1", 43, "0x" + "a" * 64),
        ("0x1", 42, "0x" + "b" * 64),
        ("0x01", 42, "0x" + "a" * 64),
    ],
)
def test_fork_anchor_fails_closed_on_chain_height_or_hash_mismatch(
    chain_id, block_number, block_hash
):
    from agents.security_checker.rpc_gateway import validate_fork_anchor

    with pytest.raises(RpcGatewayError):
        validate_fork_anchor(
            chain_response={"jsonrpc": "2.0", "id": 1, "result": chain_id},
            block_response={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "number": hex(block_number),
                    "hash": block_hash,
                },
            },
            expected_chain_id=1,
            expected_block_number=42,
            expected_block_hash="0x" + "a" * 64,
        )


def test_fork_anchor_rejects_unvalidated_response_envelopes():
    from agents.security_checker.rpc_gateway import validate_fork_anchor

    with pytest.raises(RpcGatewayError, match="fork_chain_identity_invalid"):
        validate_fork_anchor(
            chain_response={"jsonrpc": "1.0", "id": 1, "result": "0x1"},
            block_response={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"number": "0x2a", "hash": "0x" + "a" * 64},
            },
            expected_chain_id=1,
            expected_block_number=42,
            expected_block_hash="0x" + "a" * 64,
        )


def test_default_transport_ignores_environment_proxy_configuration(monkeypatch):
    import requests
    from agents.security_checker.rpc_gateway import forward_rpc_request

    response = FakeResponse(
        200,
        [b'{"jsonrpc":"2.0","id":4,"result":"0x1"}'],
    )
    observed = {}

    class FakeSession:
        def __init__(self):
            self.trust_env = True

        def post(self, url, **kwargs):
            observed["trust_env"] = self.trust_env
            observed["url"] = url
            return response

        def close(self):
            observed["session_closed"] = True

    monkeypatch.setattr(requests, "Session", FakeSession)

    result = forward_rpc_request(
        "https://rpc.example.test/",
        {"rpc.example.test"},
        b'{"jsonrpc":"2.0","id":4,"method":"eth_chainId","params":[]}',
    )

    assert result["result"] == "0x1"
    assert observed["trust_env"] is False
    assert observed["session_closed"] is True
    assert response.closed is True


def _start_test_gateway(monkeypatch, *, forward_result=None):
    import threading
    import agents.security_checker.rpc_gateway as gateway

    calls = []

    def fake_forward(upstream_url, allowed_hosts, body):
        calls.append((upstream_url, allowed_hosts, body))
        if forward_result is not None:
            return forward_result
        return {"jsonrpc": "2.0", "id": 9, "result": "0x1"}

    monkeypatch.setattr(gateway, "forward_rpc_request", fake_forward)
    server = gateway.create_rpc_gateway_server(
        "https://rpc.example.test/",
        {"rpc.example.test"},
        "t" * 40,
        port=0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, calls


def test_http_listener_authenticates_and_forwards_only_rpc_post(monkeypatch):
    import http.client

    server, thread, calls = _start_test_gateway(monkeypatch)
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
        body = b'{"jsonrpc":"2.0","id":9,"method":"eth_chainId","params":[]}'
        connection.request(
            "POST",
            "/rpc",
            body=body,
            headers={
                "Authorization": "Bearer " + "t" * 40,
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == 200
        assert payload == {"jsonrpc": "2.0", "id": 9, "result": "0x1"}
        assert calls == [
            (
                "https://rpc.example.test/",
                {"rpc.example.test"},
                body,
            )
        ]
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_http_listener_rejects_missing_or_invalid_bearer_token(monkeypatch):
    import http.client

    server, thread, calls = _start_test_gateway(monkeypatch)
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
        connection.request(
            "POST",
            "/rpc",
            body=b'{"jsonrpc":"2.0","id":9,"method":"eth_chainId","params":[]}',
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == 401
        assert payload["error"] == "unauthorized"
        assert calls == []
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_http_listener_rejects_wrong_route_and_non_post_methods(monkeypatch):
    import http.client

    server, thread, calls = _start_test_gateway(monkeypatch)
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
        connection.request("GET", "/")
        response = connection.getresponse()
        assert response.status == 405
        response.read()
        connection.close()

        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
        connection.request(
            "POST",
            "/admin",
            body=b"{}",
            headers={
                "Authorization": "Bearer " + "t" * 40,
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        assert response.status == 404
        response.read()
        connection.close()
        assert calls == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_http_listener_rejects_oversized_body_before_reading(monkeypatch):
    import http.client

    server, thread, calls = _start_test_gateway(monkeypatch)
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
        connection.putrequest("POST", "/rpc")
        connection.putheader("Authorization", "Bearer " + "t" * 40)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(1_048_577))
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 413
        response.read()
        connection.close()
        assert calls == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"bearer_token": "short"},
        {"bearer_token": "x" * 32, "max_concurrent_requests": 0},
        {"bearer_token": "x" * 32, "max_concurrent_requests": 65},
        {"bearer_token": "x" * 32, "port": -1},
        {"bearer_token": "x" * 32, "port": 65536},
    ],
)
def test_http_listener_rejects_unsafe_configuration(kwargs):
    from agents.security_checker.rpc_gateway import create_rpc_gateway_server

    values = {
        "upstream_url": "https://rpc.example.test/",
        "allowed_hosts": {"rpc.example.test"},
        "bearer_token": "x" * 32,
    }
    values.update(kwargs)
    with pytest.raises(RpcGatewayError, match="gateway_listener_configuration_invalid"):
        create_rpc_gateway_server(**values)
