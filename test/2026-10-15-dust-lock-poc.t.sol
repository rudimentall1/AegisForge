// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IEscrowV1 {
    function createEscrow(address seller, uint256 amount, uint64 deliveryWindowSec, uint64 reviewWindowSec, string calldata verificationURI) external returns (uint256);
    function markDelivered(uint256 id, bytes32 deliveryHash) external;
    function dispute(uint256 id, string calldata reason) external;
    function resolve(uint256 id, uint16 buyerBps, uint16 sellerBps, bytes32 verdictHash) external;
    function arbiter() external view returns (address);
}

contract ArbitovaResolveTest is Test {
    address constant ESCROW = 0xA8a031bcaD2f840b451c19db8e43CEAF86a088fC;
    address constant USDC   = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;

    IEscrowV1 escrow;
    IERC20 usdc;

    address buyer  = address(0xB0B);
    address seller = address(0x5E11E);

    function setUp() public {
        vm.createSelectFork(vm.envString("RPC_BASE_SEPOLIA"));
        escrow = IEscrowV1(ESCROW);
        usdc = IERC20(USDC);
        deal(USDC, buyer, 1);
        vm.prank(buyer);
        usdc.approve(ESCROW, 1);
    }

    function testResolveDustLocked() public {
        vm.prank(buyer);
        uint256 escrowId = escrow.createEscrow(seller, 1, 86400, 86400, "ipfs://test");

        vm.prank(seller);
        escrow.markDelivered(escrowId, keccak256("test"));

        vm.prank(buyer);
        escrow.dispute(escrowId, "not delivered");

        address arbiter = escrow.arbiter();
        vm.prank(arbiter);
        escrow.resolve(escrowId, 5000, 5000, keccak256("verdict"));

        uint256 contractBalance = usdc.balanceOf(ESCROW);
        emit log_named_uint("Contract balance after resolve (wei)", contractBalance);

        if (contractBalance > 0) {
            emit log_string("=== DUST LOCKED IN CONTRACT ===");
        } else {
            emit log_string("=== NO DUST LOCKED ===");
        }
    }
}
