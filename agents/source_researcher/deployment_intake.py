from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests
from web3 import Web3

from agents.config import CHAIN_IDS, EXPLORER_URLS, RPC_ENDPOINTS
from shared.discovery import FINDING_SCHEMA


_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
MAX_DISCOVERY_DESCRIPTION_BYTES = 64 * 1024
MAX_VERIFIED_SOURCE_BYTES = 4 * 1024 * 1024
ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"


class DeploymentResearchError(ValueError):
    """A bounded, machine-readable deployment research failure."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _default_web3_factory(endpoint: str):
    return Web3(
        Web3.HTTPProvider(
            endpoint,
            request_kwargs={"timeout": 15},
        )
    )


class DeploymentIntakeResearcher:
    """Read-only EVM deployment research with durable bytecode provenance."""

    def __init__(
        self,
        *,
        rpc_endpoints=None,
        chain_ids=None,
        explorer_urls=None,
        evidence_dir=None,
        web3_factory=None,
        http_get=None,
    ):
        self.rpc_endpoints = dict(RPC_ENDPOINTS if rpc_endpoints is None else rpc_endpoints)
        self.chain_ids = dict(CHAIN_IDS if chain_ids is None else chain_ids)
        self.explorer_urls = dict(EXPLORER_URLS if explorer_urls is None else explorer_urls)
        configured_dir = evidence_dir or os.getenv(
            "AEGISFORGE_EVIDENCE_DIR",
            str(Path(__file__).resolve().parents[2] / "data" / "evidence" / "deployments"),
        )
        self.evidence_dir = Path(configured_dir)
        self.web3_factory = web3_factory or _default_web3_factory
        self.http_get = http_get or requests.get

    @staticmethod
    def _parse_finding(description: str) -> dict:
        if not isinstance(description, str):
            raise DeploymentResearchError("discovery_description_invalid")
        if len(description.encode("utf-8")) > MAX_DISCOVERY_DESCRIPTION_BYTES:
            raise DeploymentResearchError("discovery_description_exceeds_limit")
        try:
            envelope = json.loads(description)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DeploymentResearchError("discovery_description_invalid_json") from exc
        if not isinstance(envelope, dict) or envelope.get("task_type") != "deep_research_intake":
            raise DeploymentResearchError("discovery_task_type_invalid")
        finding = envelope.get("discovery_finding")
        if not isinstance(finding, dict) or finding.get("schema") != FINDING_SCHEMA:
            raise DeploymentResearchError("discovery_finding_schema_invalid")

        chain = finding.get("chain")
        address = finding.get("contract_address")
        finding_type = finding.get("finding_type")
        block_number = finding.get("observed_block")
        if not isinstance(chain, str) or not re.fullmatch(r"[a-z0-9_-]{1,32}", chain.lower()):
            raise DeploymentResearchError("discovery_chain_invalid")
        if not isinstance(address, str) or not _ADDRESS_RE.fullmatch(address):
            raise DeploymentResearchError("discovery_contract_address_invalid")
        if not isinstance(finding_type, str) or not finding_type.strip():
            raise DeploymentResearchError("discovery_finding_type_invalid")
        if not isinstance(finding.get("evidence"), dict):
            raise DeploymentResearchError("discovery_evidence_invalid")
        if not isinstance(block_number, int) or isinstance(block_number, bool) or block_number < 0:
            raise DeploymentResearchError("discovery_observed_block_invalid")

        transaction_hash = finding.get("transaction_hash")
        if transaction_hash is not None and (
            not isinstance(transaction_hash, str) or not _TX_HASH_RE.fullmatch(transaction_hash)
        ):
            raise DeploymentResearchError("discovery_transaction_hash_invalid")

        identity = {
            "chain": chain.lower(),
            "contract_address": address.lower(),
            "finding_type": finding_type.lower(),
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        expected_fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if finding.get("fingerprint") != expected_fingerprint:
            raise DeploymentResearchError("discovery_fingerprint_mismatch")
        return finding

    def _lookup_verified_source(self, chain: str, chain_id: int, address: str, directory: Path) -> dict:
        explorer_base = self.explorer_urls.get(chain)
        explorer_url = (
            f"{explorer_base.rstrip('/')}/address/{address}#code"
            if explorer_base
            else None
        )
        api_key = os.getenv("ETHERSCAN_API_KEY", "").strip()
        if not api_key:
            return {
                "status": "NOT_CONFIGURED",
                "provider": "etherscan_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "error": "etherscan_api_key_not_configured",
            }

        try:
            response = self.http_get(
                ETHERSCAN_V2_API,
                params={
                    "chainid": chain_id,
                    "module": "contract",
                    "action": "getsourcecode",
                    "address": address,
                    "apikey": api_key,
                },
                timeout=15,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            return {
                "status": "LOOKUP_FAILED",
                "provider": "etherscan_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "error": f"explorer_request_failed:{type(exc).__name__}",
            }

        entries = payload.get("result") if isinstance(payload, dict) else None
        source_code = (
            entries[0].get("SourceCode")
            if isinstance(entries, list) and entries and isinstance(entries[0], dict)
            else None
        )
        if not isinstance(source_code, str) or not source_code.strip():
            return {
                "status": "NOT_VERIFIED",
                "provider": "etherscan_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "error": "verified_source_not_available",
            }

        source_bytes = source_code.encode("utf-8")
        if len(source_bytes) > MAX_VERIFIED_SOURCE_BYTES:
            return {
                "status": "SOURCE_TOO_LARGE",
                "provider": "etherscan_v2",
                "explorer_url": explorer_url,
                "source_sha256": _sha256(source_bytes),
                "source_path": None,
                "error": "verified_source_exceeds_size_limit",
            }

        source_path = directory / "verified-source.txt"
        _atomic_write(source_path, source_bytes)
        return {
            "status": "VERIFIED",
            "provider": "etherscan_v2",
            "explorer_url": explorer_url,
            "source_sha256": _sha256(source_bytes),
            "source_path": str(source_path),
            "error": None,
        }

    def run(self, task):
        try:
            finding = self._parse_finding(task.description)
            chain = finding["chain"].lower()
            endpoint = self.rpc_endpoints.get(chain)
            if not isinstance(endpoint, str) or not endpoint.strip():
                raise DeploymentResearchError("rpc_endpoint_not_configured")

            address = Web3.to_checksum_address(finding["contract_address"])
            block_number = finding["observed_block"]
            try:
                web3 = self.web3_factory(endpoint)
                if not web3.is_connected():
                    raise DeploymentResearchError("rpc_disconnected")
                chain_id = int(web3.eth.chain_id)
                expected_chain_id = self.chain_ids.get(chain)
                if expected_chain_id is not None and chain_id != int(expected_chain_id):
                    raise DeploymentResearchError("rpc_chain_id_mismatch")
                runtime_code = web3.eth.get_code(
                    address,
                    block_identifier=block_number,
                )
                if isinstance(runtime_code, str):
                    raw_bytecode = bytes.fromhex(runtime_code.removeprefix("0x"))
                else:
                    raw_bytecode = bytes(runtime_code)
            except DeploymentResearchError:
                raise
            except Exception as exc:
                raise DeploymentResearchError(
                    f"rpc_request_failed:{type(exc).__name__}"
                ) from exc

            observed_at = datetime.now(timezone.utc).isoformat()
            contract_dir = self.evidence_dir / chain / address.lower() / str(block_number)
            bytecode_path = contract_dir / "runtime-bytecode.bin"
            _atomic_write(bytecode_path, raw_bytecode)

            bytecode_sha256 = _sha256(raw_bytecode)
            bytecode_keccak256 = Web3.keccak(raw_bytecode).hex()
            if not bytecode_keccak256.startswith("0x"):
                bytecode_keccak256 = "0x" + bytecode_keccak256

            source_verification = self._lookup_verified_source(
                chain,
                chain_id,
                address,
                contract_dir,
            )
            endpoint_host = urlsplit(endpoint).hostname or "configured_rpc"
            metadata = {
                "schema": "aegisforge.deployment_evidence.v1",
                "chain": chain,
                "chain_id": chain_id,
                "contract_address": address,
                "observed_block": block_number,
                "transaction_hash": finding.get("transaction_hash"),
                "deployer": (finding.get("evidence") or {}).get("deployer"),
                "observed_at": observed_at,
                "rpc_endpoint_host": endpoint_host,
                "runtime_bytecode_file": bytecode_path.name,
                "runtime_bytecode_size_bytes": len(raw_bytecode),
                "runtime_bytecode_sha256": bytecode_sha256,
                "runtime_bytecode_keccak256": bytecode_keccak256,
                "source_verification": source_verification,
                "vulnerability_confirmed": False,
                "transactions_sent": False,
            }
            metadata_bytes = json.dumps(
                metadata,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            metadata_path = contract_dir / "evidence.json"
            _atomic_write(metadata_path, metadata_bytes)

            evidence_summary = {
                "chain": chain,
                "chain_id": chain_id,
                "contract_address": address,
                "observed_block": block_number,
                "transaction_hash": finding.get("transaction_hash"),
                "runtime_bytecode_size_bytes": len(raw_bytecode),
                "runtime_bytecode_sha256": bytecode_sha256,
                "runtime_bytecode_keccak256": bytecode_keccak256,
                "source_verification_status": source_verification["status"],
                "source_sha256": source_verification["source_sha256"],
                "metadata_sha256": _sha256(metadata_bytes),
            }
            task.result = {
                "agent": "source_researcher",
                "research_track": "evm_deployment_deep_research",
                "stage": "runtime_evidence",
                "status": "BYTECODE_RETRIEVED" if raw_bytecode else "NO_RUNTIME_BYTECODE",
                "discovery_finding": finding,
                "discovery_evidence": evidence_summary,
                "source_verification": source_verification,
                "evidence_artifact": {
                    "metadata_path": str(metadata_path.relative_to(self.evidence_dir)),
                    "bytecode_path": str(bytecode_path.relative_to(self.evidence_dir)),
                    "metadata_sha256": _sha256(metadata_bytes),
                    "bytecode_sha256": bytecode_sha256,
                },
                "scope_guards": {
                    "read_only_rpc": True,
                    "transactions_sent": False,
                    "private_keys_accessed": False,
                    "vulnerability_confirmed": False,
                },
                "observed_at": observed_at,
            }
            task.status = "source_researched"
        except DeploymentResearchError as exc:
            task.status = "source_research_failed"
            task.result = {
                "agent": "source_researcher",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "transactions_sent": False,
            }
        except Exception as exc:
            task.status = "source_research_failed"
            task.result = {
                "agent": "source_researcher",
                "error_type": type(exc).__name__,
                "error": "deployment_research_internal_error",
                "transactions_sent": False,
            }
        return task
