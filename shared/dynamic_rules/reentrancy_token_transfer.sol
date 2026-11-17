// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Rule: Token Transfer Reentrancy (Checks-Effects-Interactions Violation)
contract TokenReentrancyRule {
    mapping(address => uint256) public balances;

    // Vulnerability pattern: External call before state update
    function withdrawTokens(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Unsafe external call before reducing balance (Classic Reentrancy)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    function detectTokenReentrancyPattern(bool stateUpdatedBeforeCall) external pure returns (bool) {
        // Trigger alert if state update happens AFTER external interaction
        if (!stateUpdatedBeforeCall) {
            return true;
        }
        return false;
    }
}
