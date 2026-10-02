import hashlib
import sqlite3
from types import SimpleNamespace

from shared.capability_grant import issue_capability_grant as _issue_capability_grant
from shared.authority_state import AuthorityState
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.capability_signing import CapabilitySigner
from shared.evidence_ledger import EvidenceLedger
from shared.artifact_executor import SafeArtifactPublisher
from shared.outcome_verifier import ArtifactOutcomeVerifier
from shared.executor_registry import ExecutorRegistry
from shared.execution_gate import ExecutionGate


def issue_capability_grant(*args, **kwargs):
    state = kwargs.setdefault("authority_state", AuthorityState.STANDARD)
    kwargs.setdefault("authority_context", SimpleNamespace(
        agent_id="test-agent",
        authority_epoch=1,
        state=state,
        policy_version=kwargs.get("policy_version", args[2] if len(args) > 2 else "policy-v1"),
    ))
    return _issue_capability_grant(*args, **kwargs)


def _intent(content, target="release/demo.txt"):
    return ActionIntent(
        role="developer",
        action="publish",
        target=target,
        resource="staging_artifact_store",
        destination="staging",
        data_scope="source_code",
        requires_filesystem=True,
        read_only=False,
        evidence_required=True,
        parameters={
            "content": content,
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "outcome_contract": {"type": "artifact_exists", "verifier": "artifact_independent_v1", "path": target, "expected_exists": True},
        },
    )


def test_artifact_publish_is_authorized_and_independently_proven(tmp_path):
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    root = tmp_path / "artifacts"
    content = "AegisForge artifact v1\n"
    intent = _intent(content)
    signer = CapabilitySigner.generate()
    grant = signer.sign(
        issue_capability_grant(
            "publish-task",
            intent,
            CapabilityPolicy.VERSION,
            ["artifact-integrity-1"],
            "staging",
        )
    )

    registry = ExecutorRegistry(
        ExecutionGate(db=db, signer=signer),
        evidence_ledger=ledger,
        role="executor",
    )
    registry.register(
        "staging_publish",
        "publish",
        "staging_artifact_store",
        SafeArtifactPublisher(root).publish,
    )
    result = registry.execute(grant, intent, evidence_ids=["artifact-integrity-1"])

    target = root / "release" / "demo.txt"
    assert target.read_text(encoding="utf-8") == content
    assert result["receipt"].status == "EXECUTED"

    outcome = ArtifactOutcomeVerifier(root).verify(intent, result["receipt"])
    assert outcome["status"] == "PROVEN"
    assert outcome["observed_state"] == "PRESENT"
    assert outcome["sha256"] == intent.parameters["sha256"]
    assert "artifact_hash" in outcome["checks"]


def test_artifact_publish_rejects_content_hash_tampering(tmp_path):
    signer = CapabilitySigner.generate()
    content = "original"
    intent = _intent(content)
    intent.parameters["content"] = "tampered"
    root = tmp_path / "artifacts"

    try:
        SafeArtifactPublisher(root).publish(intent)
    except Exception as exc:
        assert str(exc) == "artifact_content_hash_mismatch"
    else:
        raise AssertionError("tampered content was accepted")


def test_artifact_verifier_detects_post_execution_tampering(tmp_path):
    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    root = tmp_path / "artifacts"
    content = "immutable claim"
    intent = _intent(content)
    signer = CapabilitySigner.generate()
    grant = signer.sign(
        issue_capability_grant(
            "tamper-task",
            intent,
            CapabilityPolicy.VERSION,
            ["artifact-integrity-1"],
            "staging",
        )
    )
    registry = ExecutorRegistry(
        ExecutionGate(db=db, signer=signer),
        evidence_ledger=ledger,
        role="executor",
    )
    registry.register(
        "staging_publish",
        "publish",
        "staging_artifact_store",
        SafeArtifactPublisher(root).publish,
    )
    result = registry.execute(grant, intent, evidence_ids=["artifact-integrity-1"])
    (root / intent.target).write_text("tampered", encoding="utf-8")

    import pytest
    with pytest.raises(Exception, match="artifact_hash_mismatch"):
        ArtifactOutcomeVerifier(root).verify(intent, result["receipt"])
