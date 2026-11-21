// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../src/ReentrancyVault.sol";

/// Minimal Foundry cheatcode surface: keeps this benchmark dependency-free.
interface Vm {
    function deal(address account, uint256 newBalance) external;
}

contract ReentrancyBenchmarkTest {
    Vm private constant vm =
        Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    VulnerableVault private vulnerable;
    SafeVault private safe;

    function setUp() public {
        vulnerable = new VulnerableVault();
        safe = new SafeVault();
        vm.deal(address(this), 100 ether);
        vulnerable.deposit{value: 10 ether}();
        safe.deposit{value: 10 ether}();
    }

    function test_positive_control_reentrancy_drains_vulnerable_vault() public {
        ReentrantAttacker attacker = new ReentrantAttacker(address(vulnerable));
        attacker.attack{value: 1 ether}();

        require(address(vulnerable).balance == 0, "vulnerable vault should be drained");
        require(address(attacker).balance == 11 ether, "attacker should recover victim funds");
        require(
            vulnerable.credit(address(attacker)) == 1 ether,
            "stale credit demonstrates broken accounting"
        );
    }

    function test_negative_control_safe_vault_resists_same_attack() public {
        ReentrantAttacker attacker = new ReentrantAttacker(address(safe));
        attacker.attack{value: 1 ether}();

        require(address(safe).balance == 10 ether, "victim funds must remain");
        require(address(attacker).balance == 1 ether, "attacker must only recover own deposit");
        require(safe.credit(address(attacker)) == 0, "attacker credit must be consumed");
    }
}
