// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract VulnerableTest {
    address public owner;
    function withdraw() public {
        // Уязвимость reentrancy для проверки Slither
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success);
    }
}
