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
    if len({(entry["id"], entry["type"]) for entry in entries}) != len(entries):
        raise EvidenceManifestError("duplicate_manifest_entry")
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


# Source-coordinate records complement the artifact Merkle manifest above.
# Hashes establish byte identity, not authenticity or independent origin.
import re

_SOURCE_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def source_excerpt_digest(excerpt):
    """Hash exact UTF-8 excerpt bytes without whitespace normalization."""
    if not isinstance(excerpt, str):
        raise TypeError("excerpt_must_be_text")
    return hashlib.sha256(excerpt.encode("utf-8")).hexdigest()


def build_source_record(repository, commit_sha, path, start_line, end_line, blob_sha, excerpt):
    """Build and validate a record identifying an excerpt at a pinned revision."""
    record = {
        "repository": repository, "commit_sha": commit_sha, "path": path,
        "start_line": start_line, "end_line": end_line, "git_blob_sha": blob_sha,
        "excerpt_sha256": source_excerpt_digest(excerpt), "excerpt": excerpt,
        "limitations": [
            "Hashes establish byte identity, not source authenticity.",
            "Pinned source text does not establish independent provenance.",
            "This record alone does not establish exploitability, runtime reproduction, or individual wallet exposure.",
        ],
    }
    validate_source_record(record)
    return record


def validate_source_record(record):
    """Validate source coordinates and digest without inferring authenticity."""
    if not isinstance(record, dict):
        raise EvidenceManifestError("source_record_must_be_object")
    if not isinstance(record.get("repository"), str) or not _SOURCE_REPOSITORY_RE.fullmatch(record["repository"]):
        raise EvidenceManifestError("source_repository_must_be_owner_repo")
    if not isinstance(record.get("commit_sha"), str) or not _SOURCE_SHA1_RE.fullmatch(record["commit_sha"]):
        raise EvidenceManifestError("source_commit_sha_invalid")
    path = record.get("path")
    if (
        not isinstance(path, str)
        or not path.strip()
        or path != path.strip()
        or path.startswith("/")
        or "\\" in path
        or ":" in path
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise EvidenceManifestError("source_path_invalid")
    start_line, end_line = record.get("start_line"), record.get("end_line")
    if type(start_line) is not int or type(end_line) is not int or start_line < 1 or end_line < start_line:
        raise EvidenceManifestError("source_line_range_invalid")
    if not isinstance(record.get("git_blob_sha"), str) or not _SOURCE_SHA1_RE.fullmatch(record["git_blob_sha"]):
        raise EvidenceManifestError("source_git_blob_sha_invalid")
    excerpt = record.get("excerpt")
    if not isinstance(excerpt, str) or not excerpt:
        raise EvidenceManifestError("source_excerpt_required")
    digest_value = record.get("excerpt_sha256")
    if not isinstance(digest_value, str) or not _SOURCE_SHA256_RE.fullmatch(digest_value):
        raise EvidenceManifestError("source_excerpt_sha256_invalid")
    if source_excerpt_digest(excerpt) != digest_value:
        raise EvidenceManifestError("source_excerpt_sha256_mismatch")
    limitations = record.get("limitations")
    if not isinstance(limitations, list) or not all(isinstance(item, str) and item.strip() for item in limitations):
        raise EvidenceManifestError("source_limitations_required")
    combined = " ".join(limitations).lower()
    if "source authenticity" not in combined or "independent provenance" not in combined:
        raise EvidenceManifestError("source_limitations_must_distinguish_integrity_from_provenance")
    overclaims = (
        "proves source authenticity",
        "proves independent provenance",
        "establishes source authenticity",
        "establishes independent provenance",
        "confirms source authenticity",
        "confirms independent provenance",
    )
    if any(claim in combined for claim in overclaims):
        raise EvidenceManifestError("source_limitations_must_distinguish_integrity_from_provenance")
