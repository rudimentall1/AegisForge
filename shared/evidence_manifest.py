import hashlib
import json


class EvidenceManifestError(ValueError):
    pass


SCHEMA_VERSION = "evidence-manifest-v1"

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _leaf(entry):
    if not isinstance(entry, dict) or set(entry) != {"id", "type", "digest"}:
        raise EvidenceManifestError("invalid_manifest_entry")
    if not all(isinstance(entry[k], str) and entry[k] for k in entry):
        raise EvidenceManifestError("invalid_manifest_entry_values")
    return hashlib.sha256((entry["id"] + "\0" + entry["type"] + "\0" + entry["digest"]).encode()).hexdigest()


def merkle_root(entries):
    if not entries:
        raise EvidenceManifestError("manifest_entries_required")
    level = [_leaf(e) for e in sorted(entries, key=lambda x: (x["id"], x["type"]))]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest() for i in range(0, len(level), 2)]
    return level[0]


def build_manifest(entries, agent_id=None):
    normalized = [dict(e) for e in entries]
    if len({(e.get("id"), e.get("type")) for e in normalized}) != len(normalized):
        raise EvidenceManifestError("duplicate_manifest_entry")
    root = merkle_root(normalized)
    manifest = {"schema_version": SCHEMA_VERSION, "entry_count": len(normalized), "entries": sorted(normalized, key=lambda x: (x["id"], x["type"])), "merkle_root": root}
    if agent_id is not None:
        if not isinstance(agent_id, str) or not agent_id:
            raise EvidenceManifestError("invalid_manifest_agent_id")
        manifest["agent_id"] = agent_id
    return manifest


def verify_manifest(manifest):
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceManifestError("unsupported_manifest_schema")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or manifest.get("entry_count") != len(entries):
        raise EvidenceManifestError("manifest_entry_count_mismatch")
    if "agent_id" in manifest and (not isinstance(manifest["agent_id"], str) or not manifest["agent_id"]):
        raise EvidenceManifestError("invalid_manifest_agent_id")
    expected = merkle_root(entries)
    if manifest.get("merkle_root") != expected:
        raise EvidenceManifestError("manifest_root_mismatch")
    return {"valid": True, "merkle_root": expected, "entry_count": len(entries)}


def verify_artifact_bindings(manifest, artifacts):
    """Verify that manifest digests correspond to the exact embedded artifacts."""
    verify_manifest(manifest)
    if not isinstance(artifacts, dict):
        raise EvidenceManifestError("artifact_bindings_required")
    by_key = {(entry["id"], entry["type"]): entry for entry in manifest["entries"]}
    required = {
        "grant": "capability_grant",
        "receipt": "execution_receipt",
        "contract": "outcome_contract",
        "outcome": "verified_outcome",
        "evidence": "outcome_evidence",
    }
    for artifact_id, artifact_type in required.items():
        entry = by_key.get((artifact_id, artifact_type))
        if entry is None:
            raise EvidenceManifestError(f"manifest_entry_missing:{artifact_id}")
        if artifact_id not in artifacts:
            raise EvidenceManifestError(f"artifact_missing:{artifact_id}")
        if digest(artifacts[artifact_id]) != entry["digest"]:
            raise EvidenceManifestError(f"manifest_artifact_mismatch:{artifact_id}")
    return {"valid": True, "checked": tuple(required)}
