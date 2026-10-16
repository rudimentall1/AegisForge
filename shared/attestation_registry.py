"""Portable Merkle registry for signed AegisForge attestations.

The registry stores privacy-minimized public metadata and the digest of each
complete signed attestation. It does not by itself authenticate a registry root:
verifiers must pin the expected root out of band.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from shared.attestation import ALLOWED_VERDICTS, canonical_json, sha256_hex

SCHEMA_VERSION = "aegisforge-attestation-registry-v1"
PROOF_SCHEMA_VERSION = "aegisforge-attestation-inclusion-proof-v1"
HASH_ALGORITHM = "SHA-256"
TREE_ALGORITHM = "domain-separated-sha256-duplicate-last-v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EMPTY_ROOT = hashlib.sha256(b"AegisForge attestation registry empty root v1").hexdigest()
ENTRY_FIELDS = {
    "index", "attestation_id", "attestation_sha256", "case_digest",
    "verdict", "issued_at", "key_id",
}
ENTRY_METADATA_FIELDS = ENTRY_FIELDS - {"index"}


class AttestationRegistryError(ValueError):
    """Raised for invalid registry snapshots or inclusion proofs."""


def _valid_hash(value: Any) -> bool:
    return isinstance(value, str) and bool(SHA256_RE.fullmatch(value))


def _leaf_hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(b"\x00" + canonical_json(entry).encode("utf-8")).hexdigest()


def _parent_hash(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _root_from_entries(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return EMPTY_ROOT
    level = [_leaf_hash(entry) for entry in entries]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            _parent_hash(level[index], level[index + 1])
            for index in range(0, len(level), 2)
        ]
    return level[0]


def _normalize_entry(entry: Any, index: int) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise AttestationRegistryError("registry_entry_must_be_object")
    keys = set(entry)
    if keys != ENTRY_FIELDS and keys != ENTRY_METADATA_FIELDS:
        raise AttestationRegistryError("registry_entry_fields_invalid")
    if "index" in entry:
        supplied_index = entry["index"]
        if type(supplied_index) is not int or supplied_index != index:
            raise AttestationRegistryError("registry_entry_index_invalid")
    normalized = {
        "index": index,
        "attestation_id": entry.get("attestation_id"),
        "attestation_sha256": entry.get("attestation_sha256"),
        "case_digest": entry.get("case_digest"),
        "verdict": entry.get("verdict"),
        "issued_at": entry.get("issued_at"),
        "key_id": entry.get("key_id"),
    }
    if not _valid_hash(normalized["attestation_id"]):
        raise AttestationRegistryError("registry_attestation_id_invalid")
    if not _valid_hash(normalized["attestation_sha256"]):
        raise AttestationRegistryError("registry_attestation_digest_invalid")
    if not _valid_hash(normalized["case_digest"]):
        raise AttestationRegistryError("registry_case_digest_invalid")
    if (
        not isinstance(normalized["verdict"], str)
        or normalized["verdict"] not in ALLOWED_VERDICTS
    ):
        raise AttestationRegistryError("registry_verdict_not_allowed")
    if not isinstance(normalized["issued_at"], str) or not normalized["issued_at"]:
        raise AttestationRegistryError("registry_issued_at_invalid")
    if not isinstance(normalized["key_id"], str) or not normalized["key_id"]:
        raise AttestationRegistryError("registry_key_id_invalid")
    return normalized


def entry_from_attestation(attestation: dict[str, Any]) -> dict[str, Any]:
    """Extract only public registry metadata from a signed attestation payload."""
    if not isinstance(attestation, dict):
        raise AttestationRegistryError("attestation_payload_must_be_object")
    case = attestation.get("case_ref")
    signer = attestation.get("signer")
    if not isinstance(case, dict) or not isinstance(signer, dict):
        raise AttestationRegistryError("attestation_case_or_signer_missing")
    metadata = {
        "attestation_id": attestation.get("attestation_id"),
        "attestation_sha256": sha256_hex(canonical_json(attestation)),
        "case_digest": case.get("case_digest"),
        "verdict": attestation.get("verdict"),
        "issued_at": attestation.get("issued_at"),
        "key_id": signer.get("key_id"),
    }
    normalized = _normalize_entry(metadata, 0)
    return {key: value for key, value in normalized.items() if key != "index"}


def build_registry(
    entries: list[dict[str, Any]],
    *,
    previous_checkpoint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(entries, list):
        raise AttestationRegistryError("registry_entries_must_be_list")
    normalized = [_normalize_entry(entry, index) for index, entry in enumerate(entries)]
    ids = [entry["attestation_id"] for entry in normalized]
    if len(ids) != len(set(ids)):
        raise AttestationRegistryError("duplicate_attestation_id")
    if previous_checkpoint is not None:
        _validate_checkpoint(previous_checkpoint)
    return {
        "schema_version": SCHEMA_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "tree_algorithm": TREE_ALGORITHM,
        "size": len(normalized),
        "entries": normalized,
        "merkle_root": _root_from_entries(normalized),
        "previous_checkpoint": previous_checkpoint,
    }


def registry_sha256(registry: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(registry))


def checkpoint_for(registry: dict[str, Any]) -> dict[str, Any]:
    verify_registry(registry)
    return {
        "size": registry["size"],
        "merkle_root": registry["merkle_root"],
        "registry_sha256": registry_sha256(registry),
    }


def _validate_checkpoint(checkpoint: Any) -> None:
    if (
        not isinstance(checkpoint, dict)
        or set(checkpoint) != {"size", "merkle_root", "registry_sha256"}
        or type(checkpoint.get("size")) is not int
        or checkpoint["size"] < 0
        or not _valid_hash(checkpoint.get("merkle_root"))
        or not _valid_hash(checkpoint.get("registry_sha256"))
    ):
        raise AttestationRegistryError("previous_checkpoint_invalid")


def verify_registry(registry: Any) -> dict[str, Any]:
    if not isinstance(registry, dict):
        raise AttestationRegistryError("registry_must_be_object")
    if set(registry) != {"schema_version", "hash_algorithm", "tree_algorithm", "size", "entries", "merkle_root", "previous_checkpoint"}:
        raise AttestationRegistryError("registry_fields_invalid")
    if registry.get("schema_version") != SCHEMA_VERSION:
        raise AttestationRegistryError("unsupported_registry_schema")
    if registry.get("hash_algorithm") != HASH_ALGORITHM:
        raise AttestationRegistryError("unsupported_registry_hash_algorithm")
    if registry.get("tree_algorithm") != TREE_ALGORITHM:
        raise AttestationRegistryError("unsupported_registry_tree_algorithm")
    entries = registry.get("entries")
    if not isinstance(entries, list) or type(registry.get("size")) is not int:
        raise AttestationRegistryError("registry_entries_or_size_invalid")
    if registry["size"] != len(entries):
        raise AttestationRegistryError("registry_size_mismatch")
    normalized = [_normalize_entry(entry, index) for index, entry in enumerate(entries)]
    ids = [entry["attestation_id"] for entry in normalized]
    if len(ids) != len(set(ids)):
        raise AttestationRegistryError("duplicate_attestation_id")
    expected_root = _root_from_entries(normalized)
    if registry.get("merkle_root") != expected_root:
        raise AttestationRegistryError("registry_merkle_root_mismatch")
    previous = registry.get("previous_checkpoint")
    if previous is not None:
        _validate_checkpoint(previous)
    return {
        "valid": True,
        "size": len(entries),
        "merkle_root": expected_root,
        "registry_sha256": registry_sha256(registry),
        "root_trust": "UNANCHORED",
    }


def verify_registry_chain(
    registry: dict[str, Any], previous_registry: dict[str, Any]
) -> dict[str, Any]:
    current_result = verify_registry(registry)
    previous_result = verify_registry(previous_registry)
    expected = checkpoint_for(previous_registry)
    if registry.get("previous_checkpoint") != expected:
        raise AttestationRegistryError("previous_checkpoint_mismatch")
    previous_size = previous_registry["size"]
    if registry["size"] <= previous_size:
        raise AttestationRegistryError("registry_did_not_append")
    if registry["entries"][:previous_size] != previous_registry["entries"]:
        raise AttestationRegistryError("registry_prefix_changed")
    return {
        "valid": True,
        "previous_size": previous_size,
        "current_size": registry["size"],
        "previous_root": previous_result["merkle_root"],
        "current_root": current_result["merkle_root"],
        "append_only": True,
    }


def build_inclusion_proof(
    registry: dict[str, Any], attestation_id: str
) -> dict[str, Any]:
    verify_registry(registry)
    matches = [
        (index, entry) for index, entry in enumerate(registry["entries"])
        if entry["attestation_id"] == attestation_id
    ]
    if len(matches) != 1:
        raise AttestationRegistryError("attestation_id_not_found")
    leaf_index, entry = matches[0]
    level = [_leaf_hash(item) for item in registry["entries"]]
    index = leaf_index
    siblings = []
    while len(level) > 1:
        sibling_index = index - 1 if index % 2 else min(index + 1, len(level) - 1)
        siblings.append(level[sibling_index])
        if len(level) % 2:
            level.append(level[-1])
        level = [
            _parent_hash(level[position], level[position + 1])
            for position in range(0, len(level), 2)
        ]
        index //= 2
    return {
        "schema_version": PROOF_SCHEMA_VERSION,
        "tree_size": registry["size"],
        "leaf_index": leaf_index,
        "entry": entry,
        "siblings": siblings,
        "merkle_root": registry["merkle_root"],
    }


def verify_inclusion_proof(
    proof: Any,
    *,
    expected_root: str,
    expected_size: int | None = None,
) -> dict[str, Any]:
    if not isinstance(proof, dict) or proof.get("schema_version") != PROOF_SCHEMA_VERSION:
        raise AttestationRegistryError("unsupported_inclusion_proof_schema")
    if set(proof) != {"schema_version", "tree_size", "leaf_index", "entry", "siblings", "merkle_root"}:
        raise AttestationRegistryError("inclusion_proof_fields_invalid")
    if not _valid_hash(expected_root):
        raise AttestationRegistryError("expected_root_invalid")
    if proof.get("merkle_root") != expected_root:
        raise AttestationRegistryError("expected_root_mismatch")
    tree_size = proof.get("tree_size")
    leaf_index = proof.get("leaf_index")
    if type(tree_size) is not int or tree_size < 1:
        raise AttestationRegistryError("proof_tree_size_invalid")
    if expected_size is not None and (type(expected_size) is not int or expected_size != tree_size):
        raise AttestationRegistryError("expected_tree_size_mismatch")
    if type(leaf_index) is not int or not 0 <= leaf_index < tree_size:
        raise AttestationRegistryError("proof_leaf_index_invalid")
    entry = _normalize_entry(proof.get("entry"), leaf_index)
    siblings = proof.get("siblings")
    if not isinstance(siblings, list) or any(not _valid_hash(item) for item in siblings):
        raise AttestationRegistryError("proof_siblings_invalid")

    current = _leaf_hash(entry)
    index = leaf_index
    width = tree_size
    sibling_position = 0
    while width > 1:
        if sibling_position >= len(siblings):
            raise AttestationRegistryError("proof_sibling_missing")
        sibling = siblings[sibling_position]
        if index % 2 == 0:
            if index + 1 >= width and sibling != current:
                raise AttestationRegistryError("proof_duplicate_last_mismatch")
            current = _parent_hash(current, sibling)
        else:
            current = _parent_hash(sibling, current)
        index //= 2
        width = (width + 1) // 2
        sibling_position += 1
    if sibling_position != len(siblings):
        raise AttestationRegistryError("proof_has_extra_siblings")
    if current != expected_root:
        raise AttestationRegistryError("inclusion_proof_invalid")
    return {
        "valid": True,
        "attestation_id": entry["attestation_id"],
        "leaf_index": leaf_index,
        "tree_size": tree_size,
        "merkle_root": current,
    }
