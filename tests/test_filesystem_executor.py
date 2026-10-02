import sqlite3
from pathlib import Path

import pytest
from types import SimpleNamespace

from shared.capability_grant import issue_capability_grant as _issue_capability_grant
from shared.authority_state import AuthorityState
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.capability_signing import CapabilitySigner
from shared.evidence_ledger import EvidenceLedger
from shared.execution_gate import ExecutionGate
from shared.agent_authority import AgentAuthorityRegistry
from shared.trust_evaluation import TrustDecision
from shared.executor_registry import ExecutorRegistry
from shared.filesystem_executor import FilesystemExecutorError, SafeFilesystemExecutor


def issue_capability_grant(*args, **kwargs):
    state = kwargs.setdefault("authority_state", AuthorityState.STANDARD)
    kwargs.setdefault("authority_context", SimpleNamespace(
        agent_id="test-agent",
        authority_epoch=2,
        state=state,
        policy_version=kwargs.get("policy_version", args[2] if len(args) > 2 else "policy-v1"),
    ))
    return _issue_capability_grant(*args, **kwargs)


def _intent(target):
    return ActionIntent(
        role="developer",
        action="delete",
        target=target,
        resource="staging_filesystem",
        destination="staging",
        data_scope="source_code",
        irreversible=True,
        requires_filesystem=True,
        read_only=False,
        evidence_required=True,
        parameters={"outcome_contract": {"type": "state_match", "verifier": "filesystem_independent_v1", "expected_state": "ABSENT"}},
    )


def test_authorized_delete_executes_and_records_receipt(tmp_path):
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("remove me")

    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    signer = CapabilitySigner.generate()
    authority = AgentAuthorityRegistry(db)
    authority.register("test-agent")
    authority.record_trust("test-agent", TrustDecision("TRUSTED", "test", "proof-filesystem", "test"))
    registry = ExecutorRegistry(ExecutionGate(db=db, signer=signer, authority_registry=authority), evidence_ledger=ledger)
    adapter = SafeFilesystemExecutor(tmp_path)
    registry.register("staging_delete", "delete", "staging_filesystem", adapter.delete)
    intent = _intent("workspace/obsolete.txt")
    grant = issue_capability_grant("task-1", intent, CapabilityPolicy.VERSION, ["recovery-1"], "staging")
    signed_grant = signer.sign(grant)

    result = registry.execute(signed_grant, intent, ["recovery-1"])

    assert not target.exists()
    assert result["receipt"].status == "EXECUTED"
    assert result["evidence"]["status"] == "EXECUTED"


def test_path_escape_is_failed_and_cannot_delete_outside_root(tmp_path):
    outside = tmp_path.parent / "protected.txt"
    outside.write_text("keep")
    adapter = SafeFilesystemExecutor(tmp_path / "root")
    intent = _intent("../protected.txt")

    with pytest.raises(FilesystemExecutorError, match="filesystem_path_escape"):
        adapter.delete(intent)

    assert outside.exists()


def test_root_and_directory_deletion_are_protected(tmp_path):
    adapter = SafeFilesystemExecutor(tmp_path)
    directory = tmp_path / "dir"
    directory.mkdir()

    with pytest.raises(FilesystemExecutorError, match="filesystem_root_protected"):
        adapter.delete(_intent("."))
    with pytest.raises(FilesystemExecutorError, match="directory_delete_not_supported"):
        adapter.delete(_intent("dir"))
