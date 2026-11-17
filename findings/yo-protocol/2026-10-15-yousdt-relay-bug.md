# YO Protocol — yoUSDT._deposit relays 95% of deposits to yoUSD via naked ERC20 transfer without minting shares

**Date found:** 2026-10-15
**Date submitted:** 2026-10-15
**Submission channel:** Immunefi — https://bugs.immunefi.com/dashboard/submission/96055
**Severity (reported):** Low (researcher-assessed; not independently validated)
**Status:** Submitted; awaiting triage
**Component:** src/yoUSDT.sol → _deposit()
**Repository:** https://github.com/yoprotocol/core
**Commit tested:** ab57083 ("feat: add yoUSDT contract for USDT integration", 2026-02-09)
**Current HEAD at report time:** 9820b0f
**Asset selected on Immunefi:** Other (affected contract not deployed; URL to source file)
**PoC type:** Source-level (contract not deployed; no fork test possible)

---

## Summary

The not-yet-deployed yoUSDT vault is designed to relay 95% of every deposit into the yoUSD vault while retaining a 5% liquidity buffer. The implementation performs the relay as a bare ERC20 transfer() to the yoUSD proxy address, without calling yoUSD.deposit() and without minting any yoUSD shares to yoUSDT. No on-chain record is created that yoUSDT is entitled to those assets. Because yoUSD counts the relayed USDT as available liquidity, any yoUSD holder can withdraw those funds via instant redemption. If deployed as written, yoUSDT is insolvent from the first deposit and depositor funds can be drained by unrelated yoUSD holders.

---

## Technical details

Buggy function (src/yoUSDT.sol):

    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {
        uint256 feeAmount = _feeOnTotal(assets, feeOnDeposit);
        super._deposit(caller, receiver, assets, shares);
        uint256 assetsAfterFee = assets - feeAmount;
        uint256 relayAmount = assetsAfterFee.mulDiv(RELAY_PERCENTAGE, DENOMINATOR, Math.Rounding.Floor);
        if (relayAmount > 0) {
            IERC20(asset()).safeTransfer(YO_USD_ADDRESS, relayAmount);
        }
    }

Constant definition:

    address public constant YO_USD_ADDRESS = 0x0000000f2eB9f69274678c76222B35eEc7588a65;

0x0000000f2eB9f69274678c76222B35eEc7588a65 is the yoUSD vault proxy address, not the underlying USDC token. A safeTransfer of USDT to the vault proxy does not invoke any ERC-4626 deposit logic. It increases yoUSD's raw ERC20 balance, which yoUSD counts directly as liquid assets:

    function _getAvailableBalance() internal view returns (uint256) {
        uint256 balance = IERC20(asset()).balanceOf(address(this));
        return balance > totalPendingAssets ? balance - totalPendingAssets : 0;
    }

Since no yoUSD shares are minted to yoUSDT for the relayed funds, yoUSDT shares have no claim on the 95% portion.

---

## Impact

If yoUSDT is deployed as-is the exploit is permissionless and atomic:

1. Alice deposits 1000 USDT into yoUSDT; receives yoUSDT shares.
2. yoUSDT keeps 50 USDT, transfers 950 USDT to the yoUSD proxy.
3. yoUSD has no record that this 950 USDT belongs to yoUSDT.
4. Bob (any yoUSD holder) calls yoUSD.requestRedeem(). The vault has enough liquid balance; _withdraw executes instantly using Alice's 950 USDT.
5. When Alice later redeems yoUSDT shares, only the 5% buffer remains.

Net effect: Direct theft of user funds (Critical impact category). Even ignoring theft, yoUSDT is insolvent from the first relay.

Current real-world impact (as of 2026-10-15): $0 — src/yoUSDT.sol has no on-chain deployment on Base mainnet. Severity reported as Low for that reason; would become Critical on deployment without a fix.

---

## Why this is likely unintentional

- The doc comment in yoUSDT.sol says the contract "relays 95% of deposits to yoUSD" and calls yoUSD a "relay destination and oracle pricing reference." Neither phrasing matches a bare ERC20 transfer.
- _oracleAsset() override prices yoUSDT shares against the yoUSD oracle entry — implying yoUSDT shares are meant to be backed by yoUSD value. That only makes sense if shares are minted to yoUSDT.
- A donation-style relay would not need the _oracleAsset() override at all.

---

## Recommendation

Option 1 — deposit into yoUSD and hold the shares:

    IERC20(asset()).forceApprove(YO_USD_ADDRESS, relayAmount);
    uint256 yoUSDshares = IERC4626(YO_USD_ADDRESS).deposit(relayAmount, address(this));

Track yoUSDshares as part of yoUSDT backing. Update totalAssets() in yoUSDT to include their value.

Option 2 — if the relay is intentionally a one-way donation, remove the misleading comment, remove the _oracleAsset() override, and document the loss-of-funds behavior explicitly.

Option 3 — if the relay is temporary deployment scaffolding, gate it behind a one-time migration that runs before any user deposit.

---

## Proof of Concept

Source-level PoC only. yoUSDT is not deployed on any network. The bug is visible by reading two source files at commit ab57083.

Step 1 — relayed funds are moved via bare ERC20 transfer. The relay is a plain ERC20 transfer to the yoUSD proxy. There is no IERC4626(YO_USD_ADDRESS).deposit(...) call, and no yoUSDshares are recorded as belonging to yoUSDT.

Static confirmation:

    $ grep -n "IERC4626\|deposit(" src/yoUSDT.sol
    (no matches)

Step 2 — yoUSD counts those funds as available liquidity. balanceOf(address(this)) in YoVault_V2._getAvailableBalance() counts the whole ERC20 balance of the yoUSD proxy, which now includes the relayed USDT.

Step 3 — drain scenario (conceptual trace):

1. Alice calls yoUSDT.deposit(1000e6, alice) with 1000 USDT.
2. _deposit calls super._deposit (mints yoUSDT shares to Alice).
3. relayAmount = 950e6.
4. USDT.safeTransfer(0x0000000f2eB9f69274678c76222B35eEc7588a65, 950e6).
5. yoUSDT on-chain USDT balance: 50e6.
6. Bob, any unrelated yoUSD holder, calls yoUSD.requestRedeem(bobShares, bob, bob).
7. _getAvailableBalance() >= assetsWithFee (because balanceOf includes Alice's 950e6 USDT).
8. super._withdraw transfers USDT to Bob in full.
9. Alice later calls yoUSDT.requestRedeem(aliceShares, alice, alice).
10. _getAvailableBalance() for yoUSDT returns at most 50e6.
11. The remainder of Alice's redemption stays pending indefinitely with no assets to fulfil it.

Reproduce in a fork (once yoUSDT is deployed):

    forge test --fork-url $BASE_RPC --match-test testYousdtDrain

Because the affected contract has no address yet, no on-chain artifact is available for triage. The source trace above is the full PoC.

---

## Audit coverage note

- yoUSDT.sol is not covered by any of the 7 audit reports in /audits: grep for yoUSDT, relay, and YO_USD in the extracted audit text returns zero hits.
- yoUSDT.sol was added in commit ab57083 (2026-02-09) — after the latest audit (Paladin report dated 2025-11-21).

---

## Timeline

- 2026-10-15 — Bug identified during code review of yoprotocol/core at commit ab57083.
- 2026-10-15 — Submitted to YO Protocol via Immunefi. Submission ID: 96055.
- Status: Awaiting triage. Check for response on 2026-10-22.
