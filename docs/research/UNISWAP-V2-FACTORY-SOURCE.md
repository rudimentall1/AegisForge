# Uniswap V2 Factory pinned-source acceptance target

## Target identity

- Contract: `UniswapV2Factory`
- Network: Ethereum mainnet, chain ID 1
- Address: `0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f`
- Explorer: https://etherscan.io/address/0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f
- Explorer status recorded on 2026-10-16: **Source Code Verified Exact Match**
- Upstream repository: https://github.com/Uniswap/v2-core
- Pinned commit: `4dd59067c76dea4a0e8e4bfdda41877a6b16dedc`
- Source path: `contracts/UniswapV2Factory.sol`
- Expected Git blob SHA-1: `a66ad8247b88cbd4e547b0f9dee8fceede51a358`

The exact source file is checked into `tests/fixtures/solidity/UniswapV2Factory.sol`. The provenance metadata is checked into the adjacent JSON file. Tests do not fetch the explorer, upstream repository, or any RPC endpoint.

## Source-pattern check

The checker verifies the pinned source bytes and checks that:
- the `feeToSetter` state variable exists;
- the constructor initializes `feeToSetter`;
- `setFeeTo` checks `msg.sender == feeToSetter` before changing `feeTo`;
- `setFeeToSetter` checks the same authorization before changing the setter;
- executable source does not contain `tx.origin`.

Run locally:

```bash
python -m tools.evm_key_forensics.uniswap_v2_factory_source_pattern
pytest -q tests/test_uniswap_v2_factory_source_pattern.py
```

## Interpretation and limits

A successful result means only that the checked-in source has the expected Git blob identity and the listed source-level patterns. The provenance manifest records the explorer's reported exact-match status, but this command does not independently recompile the contract, query the chain, or verify deployed bytecode. Source-code verification is not formal verification and does not prove the contract is safe.

No EVM execution, RPC request, transaction, wallet material, private key, or automatic vulnerability verdict is involved. This is a negative-control source target; a source-pattern match is not a finding.
