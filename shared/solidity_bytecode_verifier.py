"""Fail-closed comparison of compiler-produced and deployed Solidity runtime bytecode.

This module verifies bytecode identity only. It does not compile source, attest the
RPC response, resolve constructor immutables, or establish proxy implementation
identity; those are separate provenance and execution gates.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any


_VERSION_RE = re.compile(
    r"^v?(\d+\.\d+\.\d+)(?:\+commit\.([0-9a-fA-F]+))?"
)
_HEX_RE = re.compile(r"^(?:0x)?(?:[0-9a-fA-F]{2})+$")


@dataclass(frozen=True, slots=True)
class CompilerRuntimeVerification:
    status: str
    reason: str
    compiled_runtime_sha256: str = ""
    deployed_runtime_sha256: str = ""
    compiler_version: str = ""
    compiler_binary_sha256: str = ""
    standard_json_input_sha256: str = ""
    compiler_image: str = ""
    isolation: str = ""


def _incomplete(reason: str) -> CompilerRuntimeVerification:
    return CompilerRuntimeVerification("INCOMPLETE", reason)


def _version_identity(value: object) -> tuple[str, str | None] | None:
    if not isinstance(value, str):
        return None
    match = _VERSION_RE.fullmatch(value.strip())
    if match is None:
        return None
    return match.group(1), match.group(2).lower() if match.group(2) else None


def _requests_deployed_bytecode(standard_input: dict[str, Any], file_name: str, contract_name: str) -> bool:
    settings = standard_input.get("settings")
    if not isinstance(settings, dict):
        return False
    selection = settings.get("outputSelection")
    if not isinstance(selection, dict):
        return False
    file_selectors = (file_name, "*")
    output_names = {
        "evm.deployedBytecode",
        "evm.deployedBytecode.object",
        "evm.deployedBytecode.*",
        "*",
    }
    for file_selector in file_selectors:
        contracts = selection.get(file_selector)
        if not isinstance(contracts, dict):
            continue
        for contract_selector in (contract_name, "*"):
            outputs = contracts.get(contract_selector)
            if isinstance(outputs, list) and any(item in output_names for item in outputs):
                return True
    return False


def _runtime_bytes(value: object) -> bytes | None:
    if not isinstance(value, str):
        return None
    normalized = value[2:] if value.startswith("0x") else value
    if not _HEX_RE.fullmatch(normalized):
        return None
    try:
        return bytes.fromhex(normalized)
    except ValueError:
        return None


def verify_compiler_runtime_match(
    *,
    standard_json_input: str | None,
    source_files: dict[str, str] | None,
    compiled_input_sha256: str | None,
    compiler_output: dict[str, Any] | None,
    deployed_runtime_code: str | None,
    expected_compiler_version: str | None,
    actual_compiler_version: str | None,
    contract_file: str,
    contract_name: str,
    proxy_type: str | None = None,
    implementations: tuple[str, ...] = (),
) -> CompilerRuntimeVerification:
    """Return VERIFIED only for exact, fully attributable runtime bytecode.

    Metadata bytes are intentionally compared as part of the runtime. Link and
    immutable references are not masked: until their deployed values can be
    independently reconstructed, the result remains INCOMPLETE.
    """
    if proxy_type or implementations:
        return _incomplete("proxy_implementation_verification_required")
    if not isinstance(standard_json_input, str) or not standard_json_input:
        return _incomplete("standard_json_input_missing")
    try:
        standard_input = json.loads(standard_json_input)
    except (TypeError, json.JSONDecodeError):
        return _incomplete("standard_json_input_invalid")
    if (
        not isinstance(standard_input, dict)
        or standard_input.get("language") != "Solidity"
        or not isinstance(standard_input.get("sources"), dict)
        or not isinstance(standard_input.get("settings"), dict)
    ):
        return _incomplete("standard_json_input_incomplete")
    if not isinstance(source_files, dict) or not source_files:
        return _incomplete("source_file_mapping_missing")
    standard_sources = standard_input["sources"]
    normalized_sources = {}
    for path, entry in standard_sources.items():
        if not isinstance(path, str) or not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
            return _incomplete("standard_json_source_content_missing")
        normalized_sources[path] = entry["content"]
    if normalized_sources != source_files:
        return _incomplete("standard_json_source_mapping_mismatch")
    if not isinstance(compiled_input_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", compiled_input_sha256):
        return _incomplete("compiled_input_digest_missing")
    expected_input_digest = hashlib.sha256(standard_json_input.encode("utf-8")).hexdigest()
    if compiled_input_sha256 != expected_input_digest:
        return _incomplete("compiler_input_digest_mismatch")
    if not isinstance(contract_file, str) or not contract_file or not isinstance(contract_name, str) or not contract_name:
        return _incomplete("contract_identity_missing")
    if not _requests_deployed_bytecode(standard_input, contract_file, contract_name):
        return _incomplete("deployed_bytecode_output_not_requested")

    expected_version = _version_identity(expected_compiler_version)
    actual_version = _version_identity(actual_compiler_version)
    if expected_version is None or actual_version is None:
        return _incomplete("compiler_version_metadata_missing")
    if expected_version[0] != actual_version[0] or (
        expected_version[1] is not None and expected_version[1] != actual_version[1]
    ):
        return _incomplete("compiler_version_mismatch")

    if not isinstance(compiler_output, dict):
        return _incomplete("compiler_output_missing")
    errors = compiler_output.get("errors", [])
    if not isinstance(errors, list):
        return _incomplete("compiler_output_errors_invalid")
    if any(
        isinstance(item, dict) and item.get("severity") == "error"
        for item in errors
    ):
        return _incomplete("compiler_reported_errors")

    contracts = compiler_output.get("contracts")
    if not isinstance(contracts, dict):
        return _incomplete("compiler_contract_output_missing")
    file_output = contracts.get(contract_file)
    if not isinstance(file_output, dict):
        return _incomplete("compiler_contract_file_missing")
    contract_output = file_output.get(contract_name)
    if not isinstance(contract_output, dict):
        return _incomplete("compiler_contract_name_missing")
    evm_output = contract_output.get("evm")
    deployed_output = evm_output.get("deployedBytecode") if isinstance(evm_output, dict) else None
    if not isinstance(deployed_output, dict):
        return _incomplete("compiler_deployed_bytecode_missing")

    immutable_references = deployed_output.get("immutableReferences", {})
    if not isinstance(immutable_references, dict):
        return _incomplete("immutable_references_invalid")
    if immutable_references:
        return _incomplete("immutable_references_require_constructor_reconstruction")

    link_references = deployed_output.get("linkReferences", {})
    if not isinstance(link_references, dict):
        return _incomplete("library_link_references_invalid")
    if link_references:
        return _incomplete("library_link_references_require_address_resolution")

    compiled = _runtime_bytes(deployed_output.get("object"))
    deployed = _runtime_bytes(deployed_runtime_code)
    if compiled is None:
        return _incomplete("compiler_runtime_bytecode_invalid")
    if deployed is None:
        return _incomplete("deployed_runtime_bytecode_invalid")

    compiled_digest = hashlib.sha256(compiled).hexdigest()
    deployed_digest = hashlib.sha256(deployed).hexdigest()
    if compiled != deployed:
        return CompilerRuntimeVerification(
            "MISMATCH",
            "runtime_bytecode_mismatch",
            compiled_digest,
            deployed_digest,
        )
    return CompilerRuntimeVerification(
        "VERIFIED",
        "runtime_bytecode_exact_match",
        compiled_digest,
        deployed_digest,
    )
