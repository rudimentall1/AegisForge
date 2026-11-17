// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Rule: Flash Loan Price Manipulation Detection Pattern
contract FlashLoanPriceManipulationRule {
    bool private investigating;

    modifier checkFlashLoanImpact() {
        investigating = true;
        _;
        investigating = false;
    }

    function detectPriceDeviation(uint256 spotPrice, uint256 twapPrice) external view returns (bool) {
        // Trigger alert if spot price deviates significantly from TWAP during low liquidity
        if (spotPrice > twapPrice * 2 || spotPrice < twapPrice / 2) {
            return true;
        }
        return false;
    }
}
