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
