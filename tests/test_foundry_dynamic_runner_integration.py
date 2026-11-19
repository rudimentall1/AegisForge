import os

import pytest

from agents.security_checker.foundry_runner import run_foundry_test


pytestmark = pytest.mark.skipif(
    os.getenv("AEGISFORGE_FOUNDRY_INTEGRATION") != "1",
    reason="requires Docker, a digest-pinned Foundry image, and opt-in solc installation",
)


def test_real_foundry_container_executes_one_offline_solidity_test():
    source_files = {
        "Vault.sol": (
            "pragma solidity 0.8.20; "
            "contract Vault { uint256 public value; "
            "function set(uint256 next) external { value = next; } }"
        )
    }
    test_source = """pragma solidity 0.8.20;
import {Vault} from "../src/Vault.sol";

contract AegisForgeValidationTest {
    function testVaultStateChange() public {
        Vault vault = new Vault();
        vault.set(42);
        require(vault.value() == 42, "state transition failed");
    }
}
"""

    result = run_foundry_test(
        source_files,
        test_source,
        compiler_version="0.8.20",
        timeout_seconds=120,
    )

    assert result["status"] == "EXECUTED_PASS", result
    assert result["test_counts"] == {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
    }
    assert result["test_passed"] is True
    assert result["dynamic_verified"] is False
    assert result["confirmed"] is False
    assert result["network_access"] is False
    assert result["project_mount_read_only"] is True
    assert result["compiler_selection_mode"] == "explicit_binary_path_no_global_switch"
