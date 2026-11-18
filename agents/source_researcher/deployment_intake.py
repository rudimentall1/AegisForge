from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import requests
from web3 import Web3

from agents.config import CHAIN_IDS, EXPLORER_URLS, RPC_ENDPOINTS
from agents.deep_researcher.slither_analysis import analyze_source
from agents.deep_researcher.analysis_verifier import verify_analysis_evidence
from shared.discovery import FINDING_SCHEMA


_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
MAX_DISCOVERY_DESCRIPTION_BYTES = 64 * 1024
MAX_VERIFIED_SOURCE_BYTES = 4 * 1024 * 1024
ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"
SOURCIFY_V2_API = "https://sourcify.dev/server/v2/contract"
SOURCIFY_FIELDS = "sources,compilation,metadata,match,matchId,creationMatch,runtimeMatch,runtimeBytecode"
SOURCIFY_USER_AGENT = "AegisForge/0.1 (+https://github.com/rudimentall1/AegisForge)"


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

    def _lookup_sourcify_source(
        self,
        chain_id: int,
        address: str,
        directory: Path,
        explorer_url: str | None,
        runtime_bytecode_keccak256: str,
    ) -> dict:
        if not isinstance(runtime_bytecode_keccak256, str) or not _TX_HASH_RE.fullmatch(
            runtime_bytecode_keccak256
        ):
            return {
                "status": "SOURCE_BYTECODE_UNVERIFIABLE",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "runtime_bytecode_match": "UNVERIFIABLE",
                "error": "observed_runtime_bytecode_hash_invalid",
            }
        cache_path = (
            self.evidence_dir
            / "_cache"
            / "sourcify_v2"
            / str(chain_id)
            / address.lower()
            / runtime_bytecode_keccak256.removeprefix("0x").lower()
            / "contract.json"
        )
        cache_hit = False
        payload = None
        if cache_path.is_file():
            try:
                cache_bytes = cache_path.read_bytes()
                if len(cache_bytes) <= MAX_VERIFIED_SOURCE_BYTES * 3:
                    cached = json.loads(cache_bytes)
                    if isinstance(cached, dict) and isinstance(cached.get("payload"), dict):
                        payload = cached["payload"]
                        cache_hit = True
            except (OSError, ValueError, json.JSONDecodeError):
                payload = None
                cache_hit = False

        if payload is None:
            url = f"{SOURCIFY_V2_API}/{chain_id}/{address}"
            try:
                response = self.http_get(
                    url,
                    params={"fields": SOURCIFY_FIELDS},
                    headers={"User-Agent": SOURCIFY_USER_AGENT},
                    timeout=15,
                )
                status_code = getattr(response, "status_code", 200)
                if status_code == 404:
                    return {
                        "status": "NOT_VERIFIED",
                        "provider": "sourcify_v2",
                        "explorer_url": explorer_url,
                        "source_sha256": None,
                        "source_path": None,
                        "cache_hit": False,
                        "error": "sourcify_contract_not_found",
                    }
                if status_code == 429:
                    headers = getattr(response, "headers", {}) or {}
                    return {
                        "status": "RATE_LIMITED",
                        "provider": "sourcify_v2",
                        "explorer_url": explorer_url,
                        "source_sha256": None,
                        "source_path": None,
                        "retry_after": headers.get("Retry-After"),
                        "error": "sourcify_rate_limited",
                    }
                response.raise_for_status()
                payload = response.json()
            except Exception as exc:
                return {
                    "status": "LOOKUP_FAILED",
                    "provider": "sourcify_v2",
                    "explorer_url": explorer_url,
                    "source_sha256": None,
                    "source_path": None,
                    "cache_hit": False,
                    "error": f"sourcify_request_failed:{type(exc).__name__}",
                }

        if not isinstance(payload, dict):
            return {
                "status": "LOOKUP_FAILED",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "cache_hit": cache_hit,
                "error": "sourcify_response_invalid",
            }

        if (
            str(payload.get("chainId", "")) != str(chain_id)
            or str(payload.get("address", "")).lower() != address.lower()
        ):
            return {
                "status": "SOURCE_IDENTITY_MISMATCH",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "cache_hit": cache_hit,
                "error": "sourcify_chain_or_address_mismatch",
            }

        runtime_bytecode = payload.get("runtimeBytecode")
        onchain_bytecode = (
            runtime_bytecode.get("onchainBytecode")
            if isinstance(runtime_bytecode, dict)
            else None
        )
        if not isinstance(onchain_bytecode, str) or not onchain_bytecode.strip():
            return {
                "status": "SOURCE_BYTECODE_UNVERIFIABLE",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "runtime_bytecode_match": "UNVERIFIABLE",
                "observed_runtime_bytecode_keccak256": runtime_bytecode_keccak256,
                "cache_hit": cache_hit,
                "error": "sourcify_runtime_bytecode_missing",
            }
        try:
            onchain_bytes = bytes.fromhex(onchain_bytecode.removeprefix("0x"))
        except ValueError:
            onchain_bytes = None
        if onchain_bytes is None:
            return {
                "status": "SOURCE_BYTECODE_UNVERIFIABLE",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "runtime_bytecode_match": "UNVERIFIABLE",
                "observed_runtime_bytecode_keccak256": runtime_bytecode_keccak256,
                "cache_hit": cache_hit,
                "error": "sourcify_runtime_bytecode_invalid",
            }
        sourcify_bytecode_hash = Web3.keccak(onchain_bytes).hex().lower()
        if not sourcify_bytecode_hash.startswith("0x"):
            sourcify_bytecode_hash = "0x" + sourcify_bytecode_hash
        if sourcify_bytecode_hash != runtime_bytecode_keccak256.lower():
            return {
                "status": "SOURCE_BYTECODE_MISMATCH",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "runtime_bytecode_match": "MISMATCH",
                "observed_runtime_bytecode_keccak256": runtime_bytecode_keccak256,
                "sourcify_runtime_bytecode_keccak256": sourcify_bytecode_hash,
                "cache_hit": cache_hit,
                "error": "sourcify_runtime_bytecode_does_not_match_observed_block",
            }

        match_quality = payload.get("match")
        if match_quality not in {"exact_match", "match"}:
            return {
                "status": "NOT_VERIFIED",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "match_quality": match_quality,
                "cache_hit": cache_hit,
                "error": "sourcify_match_not_available",
            }

        compilation = payload.get("compilation")
        if not isinstance(compilation, dict):
            compilation = {}
        language = compilation.get("language", "Solidity")
        if language != "Solidity":
            return {
                "status": "UNSUPPORTED_LANGUAGE",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "language": language,
                "cache_hit": cache_hit,
                "error": "verified_source_language_unsupported",
            }

        sources = payload.get("sources")
        if not isinstance(sources, dict) or not sources or len(sources) > 1000:
            return {
                "status": "SOURCE_INVALID",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": None,
                "source_path": None,
                "cache_hit": cache_hit,
                "error": "sourcify_sources_invalid",
            }

        metadata = payload.get("metadata")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (TypeError, ValueError, json.JSONDecodeError):
                metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        metadata_sources = metadata.get("sources")
        if not isinstance(metadata_sources, dict):
            metadata_sources = {}

        normalized_sources = {}
        total_source_bytes = 0
        verified_hashes = 0
        unavailable_hashes = 0
        for source_name, source_entry in sources.items():
            if (
                not isinstance(source_name, str)
                or not source_name
                or "\\" in source_name
            ):
                return {
                    "status": "SOURCE_INVALID",
                    "provider": "sourcify_v2",
                    "explorer_url": explorer_url,
                    "source_sha256": None,
                    "source_path": None,
                    "cache_hit": cache_hit,
                    "error": "sourcify_source_path_invalid",
                }
            relative = PurePosixPath(source_name)
            if (
                relative.is_absolute()
                or not relative.parts
                or any(part in ("", ".", "..") for part in relative.parts)
                or ":" in relative.parts[0]
                or relative.suffix.lower() != ".sol"
                or relative.as_posix() in normalized_sources
            ):
                return {
                    "status": "SOURCE_INVALID",
                    "provider": "sourcify_v2",
                    "explorer_url": explorer_url,
                    "source_sha256": None,
                    "source_path": None,
                    "cache_hit": cache_hit,
                    "error": "sourcify_source_path_invalid",
                }

            content = source_entry.get("content") if isinstance(source_entry, dict) else None
            if not isinstance(content, str):
                return {
                    "status": "SOURCE_INVALID",
                    "provider": "sourcify_v2",
                    "explorer_url": explorer_url,
                    "source_sha256": None,
                    "source_path": None,
                    "cache_hit": cache_hit,
                    "error": "sourcify_source_content_missing",
                }

            content_bytes = content.encode("utf-8")
            total_source_bytes += len(content_bytes)
            if total_source_bytes > MAX_VERIFIED_SOURCE_BYTES:
                return {
                    "status": "SOURCE_TOO_LARGE",
                    "provider": "sourcify_v2",
                    "explorer_url": explorer_url,
                    "source_sha256": None,
                    "source_path": None,
                    "cache_hit": cache_hit,
                    "error": "verified_source_exceeds_size_limit",
                }

            metadata_entry = metadata_sources.get(source_name)
            expected_keccak = (
                metadata_entry.get("keccak256")
                if isinstance(metadata_entry, dict)
                else None
            )
            if isinstance(expected_keccak, str) and expected_keccak:
                actual_keccak = Web3.keccak(text=content).hex().lower().removeprefix("0x")
                if actual_keccak != expected_keccak.lower().removeprefix("0x"):
                    return {
                        "status": "SOURCE_INTEGRITY_MISMATCH",
                        "provider": "sourcify_v2",
                        "explorer_url": explorer_url,
                        "source_sha256": None,
                        "source_path": None,
                        "cache_hit": cache_hit,
                        "error": "sourcify_source_keccak_mismatch",
                    }
                verified_hashes += 1
            else:
                unavailable_hashes += 1

            normalized_sources[relative.as_posix()] = {"content": content}

        compiler_settings = compilation.get("compilerSettings")
        if not isinstance(compiler_settings, dict):
            compiler_settings = {}
        source_payload = {
            "language": "Solidity",
            "sources": normalized_sources,
            "settings": compiler_settings,
        }
        source_bytes = json.dumps(
            source_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if len(source_bytes) > MAX_VERIFIED_SOURCE_BYTES:
            return {
                "status": "SOURCE_TOO_LARGE",
                "provider": "sourcify_v2",
                "explorer_url": explorer_url,
                "source_sha256": _sha256(source_bytes),
                "source_path": None,
                "cache_hit": cache_hit,
                "error": "verified_source_exceeds_size_limit",
            }

        source_path = directory / "verified-source.json"
        _atomic_write(source_path, source_bytes)
        metadata_bytes = json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        metadata_path = directory / "sourcify-metadata.json"
        _atomic_write(metadata_path, metadata_bytes)

        if not cache_hit:
            cache_payload = {
                "payload": payload,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }
            cache_bytes = json.dumps(
                cache_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            if len(cache_bytes) <= MAX_VERIFIED_SOURCE_BYTES * 3:
                _atomic_write(cache_path, cache_bytes)

        optimizer = compiler_settings.get("optimizer")
        if not isinstance(optimizer, dict):
            optimizer = {}
        compiler_version_value = compilation.get("compilerVersion")
        compiler_version = (
            compiler_version_value[:128]
            if isinstance(compiler_version_value, str)
            else None
        )
        return {
            "status": "VERIFIED",
            "provider": "sourcify_v2",
            "explorer_url": explorer_url,
            "match_quality": match_quality,
            "match_id": payload.get("matchId"),
            "runtime_bytecode_match": "MATCHED_AT_OBSERVED_BLOCK",
            "observed_runtime_bytecode_keccak256": runtime_bytecode_keccak256,
            "source_files_count": len(normalized_sources),
            "source_integrity": {
                "verified_files": verified_hashes,
                "hashes_unavailable": unavailable_hashes,
            },
            "source_sha256": _sha256(source_bytes),
            "source_path": str(source_path),
            "metadata_path": str(metadata_path),
            "metadata_sha256": _sha256(metadata_bytes),
            "contract_name": compilation.get("name"),
            "compiler_version": compiler_version,
            "optimization_used": optimizer.get("enabled"),
            "runs": optimizer.get("runs"),
            "evm_version": compiler_settings.get("evmVersion"),
            "license_type": None,
            "cache_hit": cache_hit,
            "error": None,
        }

    def _lookup_verified_source(
        self,
        chain: str,
        chain_id: int,
        address: str,
        directory: Path,
        runtime_bytecode_keccak256: str,
    ) -> dict:
        explorer_base = self.explorer_urls.get(chain)
        explorer_url = (
            f"{explorer_base.rstrip('/')}/address/{address}#code"
            if explorer_base
            else None
        )
        api_key = os.getenv("ETHERSCAN_API_KEY", "").strip()
        etherscan_status = "NOT_CONFIGURED"
        if api_key:
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
                entries = payload.get("result") if isinstance(payload, dict) else None
                source_entry = (
                    entries[0]
                    if isinstance(entries, list) and entries and isinstance(entries[0], dict)
                    else {}
                )
                source_code = source_entry.get("SourceCode")
                compiler_version_value = source_entry.get("CompilerVersion")
                compiler_version = (
                    compiler_version_value[:128]
                    if isinstance(compiler_version_value, str)
                    else None
                )
                compiler_metadata = {
                    "contract_name": source_entry.get("ContractName"),
                    "compiler_version": compiler_version,
                    "optimization_used": source_entry.get("OptimizationUsed"),
                    "runs": source_entry.get("Runs"),
                    "evm_version": source_entry.get("EVMVersion"),
                    "license_type": source_entry.get("LicenseType"),
                }
                if isinstance(source_code, str) and source_code.strip():
                    source_bytes = source_code.encode("utf-8")
                    if len(source_bytes) <= MAX_VERIFIED_SOURCE_BYTES:
                        source_path = directory / "verified-source.txt"
                        _atomic_write(source_path, source_bytes)
                        return {
                            "status": "VERIFIED",
                            "provider": "etherscan_v2",
                            "explorer_url": explorer_url,
                            "match_quality": "explorer_verified",
                            "runtime_bytecode_match": "NOT_CHECKED",
                            "observed_runtime_bytecode_keccak256": runtime_bytecode_keccak256,
                            "source_sha256": _sha256(source_bytes),
                            "source_path": str(source_path),
                            "source_files_count": 1,
                            "cache_hit": False,
                            **compiler_metadata,
                            "error": None,
                        }
                    etherscan_status = "SOURCE_TOO_LARGE"
                else:
                    etherscan_status = "NOT_VERIFIED"
            except Exception as exc:
                etherscan_status = f"LOOKUP_FAILED:{type(exc).__name__}"

        sourcify_result = self._lookup_sourcify_source(
            chain_id,
            address,
            directory,
            explorer_url,
            runtime_bytecode_keccak256,
        )
        sourcify_result["provider_attempts"] = (
            ["etherscan_v2", "sourcify_v2"] if api_key else ["sourcify_v2"]
        )
        if api_key:
            sourcify_result["etherscan_fallback_status"] = etherscan_status
        return sourcify_result

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
                bytecode_keccak256,
            )
            verified_source = None
            source_analysis = {
                "schema": "aegisforge.slither_analysis.v1",
                "status": "NOT_RUN",
                "findings": [],
                "finding_count": 0,
                "vulnerabilities_confirmed": False,
                "reason": "verified_source_unavailable",
            }
            if source_verification["status"] == "VERIFIED":
                try:
                    verified_source = Path(source_verification["source_path"]).read_text(
                        encoding="utf-8"
                    )
                    source_analysis = analyze_source(
                        verified_source,
                        compiler_version=source_verification.get("compiler_version"),
                    )
                except (OSError, UnicodeError):
                    source_analysis = {
                        "schema": "aegisforge.slither_analysis.v1",
                        "status": "SOURCE_READ_FAILED",
                        "findings": [],
                        "finding_count": 0,
                        "vulnerabilities_confirmed": False,
                        "error": "verified_source_read_failed",
                    }

            analysis_bytes = json.dumps(
                source_analysis,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            analysis_path = contract_dir / "slither-analysis.json"
            _atomic_write(analysis_path, analysis_bytes)

            if verified_source is not None:
                analysis_validation = verify_analysis_evidence(
                    source_bytes=verified_source.encode("utf-8"),
                    analysis_bytes=analysis_path.read_bytes(),
                    expected_source_sha256=source_verification["source_sha256"],
                    expected_analysis_sha256=_sha256(analysis_bytes),
                )
            else:
                analysis_validation = {
                    "schema": "aegisforge.analysis_validation.v1",
                    "status": "NOT_APPLICABLE",
                    "validation_scope": "artifact_integrity_only",
                    "reason": "verified_source_unavailable",
                    "checks": {},
                    "vulnerabilities_confirmed": False,
                }

            validation_bytes = json.dumps(
                analysis_validation,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            validation_path = contract_dir / "analysis-validation.json"
            _atomic_write(validation_path, validation_bytes)

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
                "static_analysis": {
                    "status": source_analysis["status"],
                    "finding_count": source_analysis.get("finding_count", 0),
                    "vulnerabilities_confirmed": False,
                },
                "static_analysis_sha256": _sha256(analysis_bytes),
                "analysis_validation_sha256": _sha256(validation_bytes),
                "analysis_validation_status": analysis_validation["status"],
                "analysis_validation": {
                    "status": analysis_validation["status"],
                    "validation_scope": "artifact_integrity_only",
                    "vulnerabilities_confirmed": False,
                },
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
                "static_analysis_status": source_analysis["status"],
                "static_analysis_finding_count": source_analysis.get("finding_count", 0),
                "analysis_validation_status": analysis_validation["status"],
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
                "static_analysis": source_analysis,
                "analysis_validation": analysis_validation,
                "evidence_artifact": {
                    "metadata_path": str(metadata_path.relative_to(self.evidence_dir)),
                    "bytecode_path": str(bytecode_path.relative_to(self.evidence_dir)),
                    "analysis_path": str(analysis_path.relative_to(self.evidence_dir)),
                    "validation_path": str(validation_path.relative_to(self.evidence_dir)),
                    "metadata_sha256": _sha256(metadata_bytes),
                    "bytecode_sha256": bytecode_sha256,
                    "analysis_sha256": _sha256(analysis_bytes),
                    "validation_sha256": _sha256(validation_bytes),
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
