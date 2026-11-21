import json

import pytest

from scam_intelligence.contract_intake import (
    ContractIntakeError,
    BlockscoutContractIntake,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def read(self, _size=-1):
        return self.payload


def test_discovery_paginates_verified_contracts_and_filters_low_activity():
    pages = [
        {
            "items": [
                {"address": {"hash": "0x" + "1" * 40, "is_verified": True, "name": "Vault"},
                 "transactions_count": 120, "coin_balance": "1000",
                 "verified_at": "2026-11-20T00:00:00Z"},
                {"address": {"hash": "0x" + "2" * 40, "is_verified": True, "name": "Dust"},
                 "transactions_count": 1},
            ],
            "next_page_params": {"items_count": 50, "smart_contract_id": 50},
        },
        {
            "items": [
                {"address": {"hash": "0x" + "3" * 40, "is_verified": True, "name": "Lending"},
                 "transactions_count": 250}
            ],
            "next_page_params": None,
        },
    ]
    urls = []

    def opener(request, timeout):
        urls.append((request.full_url, timeout))
        return FakeResponse(pages.pop(0))

    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2", chain_id=8453, opener=opener
    )
    found = intake.discover_verified_contracts(limit=2, min_transactions=10)

    assert [item.address for item in found] == ["0x" + "1" * 40, "0x" + "3" * 40]
    assert found[0].chain_id == 8453
    assert found[0].name == "Vault"
    assert len(urls) == 2
    assert "smart_contract_id=50" in urls[1][0]


def test_source_acquisition_normalizes_multifile_verified_source():
    address = "0x" + "a" * 40
    calls = []

    def opener(request, timeout):
        calls.append(request.full_url)
        return FakeResponse({
            "is_verified": True,
            "name": "Pool",
            "compiler_version": "v0.8.24+commit.e11b9ed9",
            "optimization_enabled": True,
            "evm_version": "cancun",
            "source_code": {
                "contracts/Pool.sol": {"content": "pragma solidity ^0.8.24; contract Pool {}"},
                "contracts/Math.sol": {"content": "library Math {}"},
            },
            "abi": "[]",
            "implementations": [],
        })

    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2", chain_id=8453, opener=opener
    )
    source = intake.fetch_verified_source(address)

    assert source.chain_id == 8453
    assert source.address == address
    assert source.contract_name == "Pool"
    assert source.compiler_version == "v0.8.24+commit.e11b9ed9"
    assert source.source_files["contracts/Pool.sol"].startswith("pragma")
    assert source.source_files["contracts/Math.sol"] == "library Math {}"
    assert len(source.source_sha256) == 64
    assert calls == [f"https://base.blockscout.com/api/v2/smart-contracts/{address}"]


def test_source_acquisition_rejects_unverified_or_empty_source():
    address = "0x" + "b" * 40
    responses = iter([
        {"is_verified": False, "source_code": "contract Fake {}"},
        {"is_verified": True, "source_code": ""},
    ])
    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2",
        chain_id=8453,
        opener=lambda *_args, **_kwargs: FakeResponse(next(responses)),
    )
    with pytest.raises(ContractIntakeError, match="contract_source_not_verified"):
        intake.fetch_verified_source(address)
    with pytest.raises(ContractIntakeError, match="contract_source_empty"):
        intake.fetch_verified_source(address)


def test_discovery_rejects_malformed_addresses_and_non_verified_entries():
    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2",
        chain_id=8453,
        opener=lambda *_args, **_kwargs: FakeResponse({
            "items": [
                {"address": {"hash": "not-an-address", "is_verified": True}, "transactions_count": 99},
                {"address": {"hash": "0x" + "c" * 40, "is_verified": False}, "transactions_count": 99},
            ]
        }),
    )
    assert intake.discover_verified_contracts(limit=10) == []


def test_rpc_attestation_checks_chain_and_nonempty_deployed_code():
    calls = []

    def opener(request, timeout):
        payload = json.loads(request.data.decode())
        calls.append(payload["method"])
        result = hex(8453) if payload["method"] == "eth_chainId" else "0x6001600055"
        return FakeResponse({"jsonrpc": "2.0", "id": payload["id"], "result": result})

    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2", chain_id=8453, opener=opener
    )
    attestation = intake.attest_deployment("https://rpc.example", "0x" + "d" * 40)

    assert attestation["chain_id"] == 8453
    assert attestation["deployed"] is True
    assert len(attestation["runtime_code_sha256"]) == 64
    assert calls == ["eth_chainId", "eth_getCode"]


def test_rpc_attestation_fails_closed_on_wrong_chain_or_empty_code():
    def opener(request, timeout):
        payload = json.loads(request.data.decode())
        return FakeResponse({"jsonrpc": "2.0", "id": payload["id"], "result": hex(1)})

    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2", chain_id=8453, opener=opener
    )
    with pytest.raises(ContractIntakeError, match="rpc_chain_id_mismatch"):
        intake.attest_deployment("https://rpc.example", "0x" + "e" * 40)


def test_intake_targets_only_accepts_verified_source_with_rpc_deployment_proof():
    address = "0x" + "f" * 40
    calls = []

    def opener(request, timeout):
        if request.data:
            rpc = json.loads(request.data.decode())
            calls.append(rpc["method"])
            result = hex(8453) if rpc["method"] == "eth_chainId" else "0x6001600055"
            return FakeResponse({"jsonrpc": "2.0", "id": rpc["id"], "result": result})
        calls.append(request.full_url)
        if request.full_url.endswith("/smart-contracts?items_count=1"):
            return FakeResponse({
                "items": [{
                    "address": {"hash": address, "is_verified": True, "name": "RealVault"},
                    "transactions_count": 500,
                }],
                "next_page_params": None,
            })
        return FakeResponse({
            "is_verified": True,
            "name": "RealVault",
            "compiler_version": "v0.8.24+commit.e11b9ed9",
            "source_code": "pragma solidity ^0.8.24; contract RealVault {}",
            "file_path": "src/RealVault.sol",
        })

    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2", chain_id=8453, opener=opener
    )
    result = intake.intake_targets(
        "https://rpc.example", limit=1, min_transactions=100
    )

    assert result["discovered"] == 1
    assert len(result["accepted"]) == 1
    assert result["rejected"] == []
    accepted = result["accepted"][0]
    assert accepted["candidate"].address == address
    assert accepted["source"].source_files["src/RealVault.sol"].startswith("pragma")
    assert accepted["deployment_attestation"]["deployed"] is True
    assert calls[1:3] == ["eth_chainId", "eth_getCode"]


def test_source_acquisition_rejects_path_traversal():
    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2",
        chain_id=8453,
        opener=lambda *_args, **_kwargs: FakeResponse({
            "is_verified": True,
            "source_code": {"../outside.sol": {"content": "contract Outside {}"}},
        }),
    )
    with pytest.raises(ContractIntakeError, match="contract_source_path_invalid"):
        intake.fetch_verified_source("0x" + "9" * 40)


def test_source_acquisition_parses_standard_json_input_string():
    standard_json = json.dumps({
        "language": "Solidity",
        "sources": {
            "src/Router.sol": {"content": "contract Router {}"},
            "src/Pair.sol": {"content": "contract Pair {}"},
        },
        "settings": {"optimizer": {"enabled": True, "runs": 200}},
    })
    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2",
        chain_id=8453,
        opener=lambda *_args, **_kwargs: FakeResponse({
            "is_verified": True,
            "source_code": standard_json,
        }),
    )

    source = intake.fetch_verified_source("0x" + "8" * 40)

    assert set(source.source_files) == {"src/Router.sol", "src/Pair.sol"}


def test_rpc_attestation_rejects_empty_runtime_code():
    responses = iter([hex(8453), "0x"])

    def opener(request, timeout):
        payload = json.loads(request.data.decode())
        return FakeResponse({
            "jsonrpc": "2.0",
            "id": payload["id"],
            "result": next(responses),
        })

    intake = BlockscoutContractIntake(
        "https://base.blockscout.com/api/v2", chain_id=8453, opener=opener
    )
    with pytest.raises(ContractIntakeError, match="rpc_contract_code_empty_or_invalid"):
        intake.attest_deployment("https://rpc.example", "0x" + "7" * 40)
