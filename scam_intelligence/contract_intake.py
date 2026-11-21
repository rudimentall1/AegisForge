"""Read-only discovery and acquisition of verified, deployed EVM contracts.

Blockscout supplies candidate metadata and verified source. A separately configured
RPC endpoint attests the chain and confirms non-empty runtime bytecode before a
candidate is treated as a deployed target. This module never submits transactions
or executes downloaded source.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable


_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_BYTES = 4 * 1024 * 1024
_DEFAULT_TIMEOUT = 15


class ContractIntakeError(ValueError):
    """Discovery or source intake failed closed."""


@dataclass(frozen=True, slots=True)
class DiscoveredContract:
    chain_id: int
    address: str
    name: str
    transactions_count: int
    coin_balance: str = "0"
    verified_at: str = ""
    proxy_type: str | None = None
    implementations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VerifiedContractSource:
    chain_id: int
    address: str
    contract_name: str
    compiler_version: str
    optimization_enabled: bool | None
    evm_version: str | None
    source_files: dict[str, str]
    abi: Any = None
    proxy_type: str | None = None
    implementations: tuple[str, ...] = ()
    source_sha256: str = field(default="")

    def __post_init__(self):
        if not self.source_sha256:
            canonical = json.dumps(
                self.source_files,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            object.__setattr__(
                self, "source_sha256", hashlib.sha256(canonical).hexdigest()
            )


class BlockscoutContractIntake:
    """Paginated Blockscout v2 verified-contract discovery and source intake."""

    def __init__(
        self,
        base_url: str,
        *,
        chain_id: int,
        timeout: int = _DEFAULT_TIMEOUT,
        opener: Callable[..., Any] | None = None,
    ):
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ContractIntakeError("blockscout_base_url_invalid")
        if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
            raise ContractIntakeError("chain_id_invalid")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 60:
            raise ContractIntakeError("timeout_invalid")
        self.base_url = base_url.rstrip("/")
        self.chain_id = chain_id
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen

    @staticmethod
    def _validate_address(address: str) -> str:
        if not isinstance(address, str) or not _ADDRESS_RE.fullmatch(address):
            raise ContractIntakeError("contract_address_invalid")
        return address

    def _read_json(self, url: str, *, data: bytes | None = None) -> dict:
        headers = {"Accept": "application/json", "User-Agent": "AegisForge/1.0"}
        request = urllib.request.Request(url, data=data, headers=headers)
        try:
            with self._opener(request, timeout=self.timeout) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except Exception as exc:
            raise ContractIntakeError("upstream_request_failed") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ContractIntakeError("upstream_response_too_large")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContractIntakeError("upstream_json_invalid") from exc
        if not isinstance(payload, dict):
            raise ContractIntakeError("upstream_response_invalid")
        return payload

    @staticmethod
    def _address_entry(item: dict) -> dict:
        value = item.get("address") or item.get("address_hash") or {}
        return value if isinstance(value, dict) else {}

    def discover_verified_contracts(
        self,
        *,
        limit: int = 100,
        min_transactions: int = 1,
        cursor: dict | None = None,
    ) -> list[DiscoveredContract]:
        """Return verified contracts, paging until limit or explorer exhaustion."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ContractIntakeError("discovery_limit_invalid")
        if (
            not isinstance(min_transactions, int)
            or isinstance(min_transactions, bool)
            or min_transactions < 0
        ):
            raise ContractIntakeError("min_transactions_invalid")
        if cursor is not None and not isinstance(cursor, dict):
            raise ContractIntakeError("discovery_cursor_invalid")

        found: list[DiscoveredContract] = []
        seen: set[str] = set()
        page_cursor = dict(cursor or {})
        pages = 0
        while len(found) < limit and pages < 20:
            params = {"items_count": min(50, limit - len(found)), **page_cursor}
            url = self.base_url + "/smart-contracts?" + urllib.parse.urlencode(params)
            payload = self._read_json(url)
            items = payload.get("items")
            if not isinstance(items, list):
                raise ContractIntakeError("blockscout_contract_list_invalid")
            for item in items:
                if not isinstance(item, dict):
                    continue
                address_info = self._address_entry(item)
                address = address_info.get("hash")
                if not isinstance(address, str) or not _ADDRESS_RE.fullmatch(address):
                    continue
                if address.lower() in seen:
                    continue
                # Blockscout v2 returns verified contracts from this endpoint;
                # reject explicit false flags if a provider adds them.
                if address_info.get("is_verified") is False or item.get("is_verified") is False:
                    continue
                try:
                    tx_count = int(item.get("transactions_count") or 0)
                except (TypeError, ValueError):
                    continue
                if tx_count < min_transactions:
                    continue
                implementations = address_info.get("implementations") or item.get("implementations") or []
                implementation_addresses = []
                if isinstance(implementations, list):
                    for implementation in implementations:
                        if isinstance(implementation, dict):
                            candidate = implementation.get("address") or implementation.get("address_hash")
                            if isinstance(candidate, dict):
                                candidate = candidate.get("hash")
                            if isinstance(candidate, str) and _ADDRESS_RE.fullmatch(candidate):
                                implementation_addresses.append(candidate)
                found.append(DiscoveredContract(
                    chain_id=self.chain_id,
                    address=address,
                    name=str(address_info.get("name") or item.get("name") or ""),
                    transactions_count=tx_count,
                    coin_balance=str(item.get("coin_balance") or "0"),
                    verified_at=str(item.get("verified_at") or ""),
                    proxy_type=address_info.get("proxy_type") or item.get("proxy_type"),
                    implementations=tuple(implementation_addresses),
                ))
                seen.add(address.lower())
                if len(found) >= limit:
                    break
            next_cursor = payload.get("next_page_params")
            if not items or not isinstance(next_cursor, dict) or not next_cursor:
                break
            page_cursor = next_cursor
            pages += 1
        return found

    @staticmethod
    def _normalize_sources(payload: dict) -> dict[str, str]:
        source = payload.get("source_code")
        file_path = payload.get("file_path") or payload.get("file_name") or "Contract.sol"
        files: dict[str, str] = {}

        if isinstance(source, str):
            if source.strip():
                files[str(file_path)] = source
        elif isinstance(source, dict):
            # Blockscout may expose standard-json source objects or a path map.
            nested = source.get("sources") if isinstance(source.get("sources"), dict) else source
            for path, value in nested.items():
                if not isinstance(path, str):
                    continue
                if isinstance(value, str):
                    text = value
                elif isinstance(value, dict):
                    text = value.get("content")
                else:
                    continue
                if isinstance(text, str) and text.strip():
                    files[path] = text
        elif isinstance(source, list):
            for item in source:
                if not isinstance(item, dict):
                    continue
                path = item.get("file_path") or item.get("name")
                text = item.get("source_code") or item.get("content")
                if isinstance(path, str) and isinstance(text, str) and text.strip():
                    files[path] = text

        additional = payload.get("additional_sources") or []
        if isinstance(additional, list):
            for item in additional:
                if not isinstance(item, dict):
                    continue
                path = item.get("file_path") or item.get("name")
                text = item.get("source_code") or item.get("content")
                if isinstance(path, str) and isinstance(text, str) and text.strip():
                    files[path] = text

        total = sum(len(text.encode("utf-8")) for text in files.values())
        if total > _MAX_SOURCE_BYTES:
            raise ContractIntakeError("contract_source_too_large")
        return files

    def fetch_verified_source(self, address: str) -> VerifiedContractSource:
        address = self._validate_address(address)
        payload = self._read_json(
            f"{self.base_url}/smart-contracts/{urllib.parse.quote(address, safe='')}"
        )
        if payload.get("is_verified") is False:
            raise ContractIntakeError("contract_source_not_verified")
        files = self._normalize_sources(payload)
        if not files:
            raise ContractIntakeError("contract_source_empty")

        implementations = payload.get("implementations") or []
        implementation_addresses = []
        if isinstance(implementations, list):
            for implementation in implementations:
                if isinstance(implementation, dict):
                    candidate = implementation.get("address") or implementation.get("address_hash")
                    if isinstance(candidate, dict):
                        candidate = candidate.get("hash")
                    if isinstance(candidate, str) and _ADDRESS_RE.fullmatch(candidate):
                        implementation_addresses.append(candidate)

        optimization = payload.get("optimization_enabled")
        if optimization is not None:
            optimization = bool(optimization)
        return VerifiedContractSource(
            chain_id=self.chain_id,
            address=address,
            contract_name=str(payload.get("name") or payload.get("contract_name") or ""),
            compiler_version=str(payload.get("compiler_version") or ""),
            optimization_enabled=optimization,
            evm_version=payload.get("evm_version"),
            source_files=files,
            abi=payload.get("abi"),
            proxy_type=payload.get("proxy_type"),
            implementations=tuple(implementation_addresses),
        )

    def attest_deployment(self, rpc_url: str, address: str) -> dict:
        """Independently verify chain ID and non-empty runtime code via configured RPC."""
        address = self._validate_address(address)
        parsed = urllib.parse.urlsplit(rpc_url)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ContractIntakeError("rpc_url_invalid")

        def rpc_call(method: str, params: list) -> Any:
            body = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params
            }).encode("utf-8")
            request = urllib.request.Request(
                rpc_url,
                data=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            try:
                with self._opener(request, timeout=self.timeout) as response:
                    raw = response.read(1024 * 1024 + 1)
            except Exception as exc:
                raise ContractIntakeError("rpc_request_failed") from exc
            if len(raw) > 1024 * 1024:
                raise ContractIntakeError("rpc_response_too_large")
            try:
                result = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ContractIntakeError("rpc_json_invalid") from exc
            if not isinstance(result, dict) or result.get("error") or "result" not in result:
                raise ContractIntakeError("rpc_result_invalid")
            return result["result"]

        chain_hex = rpc_call("eth_chainId", [])
        try:
            actual_chain_id = int(chain_hex, 16)
        except (TypeError, ValueError) as exc:
            raise ContractIntakeError("rpc_chain_id_invalid") from exc
        if actual_chain_id != self.chain_id:
            raise ContractIntakeError("rpc_chain_id_mismatch")

        code = rpc_call("eth_getCode", [address, "latest"])
        if not isinstance(code, str) or not code.startswith("0x") or len(code) <= 2 or len(code) % 2 != 0:
            raise ContractIntakeError("rpc_contract_code_empty_or_invalid")
        try:
            code_bytes = bytes.fromhex(code[2:])
        except ValueError as exc:
            raise ContractIntakeError("rpc_contract_code_invalid") from exc
        if not code_bytes:
            raise ContractIntakeError("rpc_contract_code_empty_or_invalid")
        return {
            "chain_id": actual_chain_id,
            "address": address,
            "deployed": True,
            "runtime_code_bytes": len(code_bytes),
            "runtime_code_sha256": hashlib.sha256(code_bytes).hexdigest(),
            "attestation_source": "configured_evm_rpc_eth_getCode_latest",
        }


    def intake_targets(
        self,
        rpc_url: str,
        *,
        limit: int = 25,
        min_transactions: int = 10,
    ) -> dict:
        """Discover, source, and RPC-attest a bounded batch of real targets.

        Rejected candidates are returned with a machine-readable reason; one
        bad explorer record never aborts the remaining batch. Only accepted
        entries contain source files and a positive deployment attestation.
        """
        candidates = self.discover_verified_contracts(
            limit=limit,
            min_transactions=min_transactions,
        )
        accepted = []
        rejected = []
        for candidate in candidates:
            try:
                attestation = self.attest_deployment(rpc_url, candidate.address)
                source = self.fetch_verified_source(candidate.address)
                accepted.append({
                    "candidate": candidate,
                    "source": source,
                    "deployment_attestation": attestation,
                })
            except ContractIntakeError as exc:
                rejected.append({
                    "chain_id": self.chain_id,
                    "address": candidate.address,
                    "reason": str(exc),
                })
        return {
            "chain_id": self.chain_id,
            "discovered": len(candidates),
            "accepted": accepted,
            "rejected": rejected,
            "source_provider": "blockscout_v2",
            "deployment_verifier": "configured_evm_rpc",
        }
