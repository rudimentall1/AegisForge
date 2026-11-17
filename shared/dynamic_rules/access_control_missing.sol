// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Rule: Missing Access Control / Unprotected Initializer / Owner Transfer
contract AccessControlMissingRule {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Vulnerability pattern: State-changing function without onlyOwner or access modifier
    function changeOwner(address newOwner) external {
        // Missing require(msg.sender == owner, "Unauthorized");
        owner = newOwner;
    }

    function detectUnprotectedAdminFunction(address caller, address currentOwner) external pure returns (bool) {
        // Trigger alert if administrative function lacks sender validation
        if (caller != currentOwner) {
            return true;
        }
        return false;
    }
}
