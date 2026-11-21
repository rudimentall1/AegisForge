# On-chain contract intake

This module is the first real-target acquisition adapter for AegisForge. It uses
Blockscout v2 to discover recently verified contracts and retrieve their source,
then uses a separately configured EVM JSON-RPC endpoint to independently check
the expected chain ID, pin a block number/hash, and read runtime bytecode at that block.

## Supported initial networks

Use the Blockscout v2 instance and matching chain ID explicitly:

| Network | Blockscout API base | Chain ID |
|---|---|---:|
| Ethereum | `https://eth.blockscout.com/api/v2` | 1 |
| Base | `https://base.blockscout.com/api/v2` | 8453 |
| Arbitrum One | `https://arbitrum.blockscout.com/api/v2` | 42161 |

## Minimal use

```python
from scam_intelligence.contract_intake import BlockscoutContractIntake

intake = BlockscoutContractIntake(
    "https://base.blockscout.com/api/v2",
    chain_id=8453,
)
batch = intake.intake_targets(
    rpc_url="https://YOUR_BASE_RPC",
    limit=25,
    min_transactions=100,
)

for item in batch["accepted"]:
    candidate = item["candidate"]
    source = item["source"]
    attestation = item["deployment_attestation"]
    print(candidate.address, source.contract_name, source.source_sha256)
    print(attestation["runtime_code_sha256"])
```

The intake returns a bounded batch with:
- explorer-discovered verified contract metadata;
- normalized Solidity source files and a deterministic SHA-256 source digest;
- compiler version, optimizer flag, EVM version, ABI and proxy implementation metadata when supplied by Blockscout;
- RPC chain-ID and deployed-runtime-code attestation pinned to a specific block number and block hash;
- per-address rejection reasons for candidates that fail source or RPC checks.

## Security and evidence boundaries

- Read-only only: no transaction submission, wallet access, or target execution.
- Explorer metadata is untrusted input. Source file paths and response sizes are bounded.
- RPC attestation proves the configured endpoint reports the expected chain and non-empty
  runtime bytecode at the recorded block number/hash; it does not prove the explorer's source matches that bytecode.
- A source digest identifies the acquired bytes; it is not a cryptographic proof of
  explorer authenticity or compiler reproducibility.
- Proxy implementation addresses are recorded as metadata but are not recursively
  acquired by this first adapter.
- Unverified contracts are not silently treated as source-available targets.

## Current integration status

This adapter establishes the missing discovery/source-acquisition boundary. It is
not yet wired into the Worker queue or the SecurityChecker/LabRunner task graph.
That integration must preserve the complete source bundle outside the queue's
small capability-intent field, register immutable chain/address/block/source
provenance, and hand the resulting target to the existing research-case and
evidence workflow. Until that is implemented and exercised end-to-end, AegisForge
must not claim autonomous on-chain vulnerability discovery.
