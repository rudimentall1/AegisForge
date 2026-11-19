import json
import os

import pytest

from agents.security_checker.anvil_fork_runner import run_synthetic_anvil_fork_test


pytestmark = pytest.mark.skipif(
    os.getenv("AEGISFORGE_ANVIL_FORK_INTEGRATION") != "1",
    reason="requires Docker, a digest-pinned Foundry image, and solc 0.8.20",
)


def test_real_anvil_forks_exact_local_block_and_foundry_reads_contract_state():
    result = run_synthetic_anvil_fork_test(
        compiler_version="0.8.20",
        timeout_seconds=240,
    )

    assert result["status"] == "EXECUTED_PASS", json.dumps(result, indent=2)
    assert result["validation_scope"] == "synthetic_local_anvil_fork_smoke_test"
    assert result["synthetic_only"] is True
    assert result["fork_anchor"]["block_hash_match_verified"] is True
    assert result["test_counts"] == {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
    }
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False
    assert result["network_access"] is False
    assert result["project_mount_read_only"] is True
