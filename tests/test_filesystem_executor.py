import sqlite3
from pathlib import Path

import pytest

from shared.capability_grant import issue_capability_grant
from shared.capability_policy import ActionIntent, CapabilityPolicy
from shared.capability_signing import CapabilitySigner
from shared.evidence_ledger import EvidenceLedger
from shared.execution_gate import ExecutionGate
from shared.executor_registry import ExecutorRegistry
from shared.filesystem_executor import FilesystemExecutorError, SafeFilesystemExecutor


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
    )


def test_authorized_delete_executes_and_records_receipt(tmp_path):
    target = tmp_path / "workspace" / "obsolete.txt"
    target.parent.mkdir()
    target.write_text("remove me")

    db = sqlite3.connect(":memory:")
    ledger = EvidenceLedger(db)
    signer = CapabilitySigner.generate()
    registry = ExecutorRegistry(ExecutionGate(db=db, signer=signer), evidence_ledger=ledger)
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
