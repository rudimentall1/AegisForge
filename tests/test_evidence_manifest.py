import pytest

from shared.evidence_manifest import EvidenceManifestError, build_manifest, digest, verify_manifest


def test_manifest_merkle_root_verifies():
    manifest = build_manifest([
        {"id": "a", "type": "claim", "digest": digest({"value": 1})},
        {"id": "b", "type": "claim", "digest": digest({"value": 2})},
        {"id": "c", "type": "claim", "digest": digest({"value": 3})},
    ])
    assert verify_manifest(manifest)["valid"] is True
    assert manifest["entry_count"] == 3


def test_manifest_tampering_changes_root():
    manifest = build_manifest([
        {"id": "a", "type": "claim", "digest": digest({"value": 1})},
        {"id": "b", "type": "claim", "digest": digest({"value": 2})},
    ])
    manifest["entries"][0]["digest"] = digest({"value": 99})
    with pytest.raises(EvidenceManifestError, match="manifest_root_mismatch"):
        verify_manifest(manifest)
