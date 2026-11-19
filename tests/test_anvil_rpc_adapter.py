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
