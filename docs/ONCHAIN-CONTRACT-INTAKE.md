# On-chain contract intake

This module is the first real-target acquisition adapter for AegisForge. It uses
Blockscout v2 to discover recently verified contracts and retrieve their source,
then uses a separately configured EVM JSON-RPC endpoint to independently check
the expected chain ID, pin a block number/hash, and read runtime bytecode using an
EIP-1898 block-hash selector with `requireCanonical: true`.

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

## Immutable target persistence

Acquisition results can be persisted separately from queue task payloads:

```python
from shared.queue import TaskQueue
from shared.onchain_target_store import OnchainTargetStore

queue = TaskQueue()
targets = OnchainTargetStore(queue.db)

for item in batch["accepted"]:
    target_id = targets.put_intake_item(item)
    stored = targets.get(target_id)
    print(stored.chain_id, stored.address, stored.block_hash, stored.source_sha256)
```

The store is insert-only and content-addresses each snapshot from its chain/address,
block, runtime-code digest, source digest, provider, and compiler/proxy metadata.
A second, conflicting source snapshot for the same chain/address/block hash is
rejected. Source maps are immutable after record construction. The source bundle
is stored in dedicated SQLite columns, not in the queue's bounded
`capability_intent` field.

This does not yet make the record a ResearchCase or enqueue agent work. The current
ResearchCase contract is Git-repository/commit-centric; a separate explicit
on-chain case binding is still required before Worker integration.

## Security and evidence boundaries

- Read-only only: no transaction submission, wallet access, or target execution.
- Explorer metadata is untrusted input. Source file paths and response sizes are bounded.
- RPC attestation proves the configured endpoint reports the expected chain and non-empty
  runtime bytecode at the recorded canonical block hash via EIP-1898; it does not prove the explorer's source matches that bytecode.
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


## Worker integration contract (next implementation slice)

Do not attach an `OnchainTargetRecord` directly to a Git `ResearchCase`. The latter requires a repository and full commit SHA, and its admission path resolves pinned Git objects. An EVM contract is identified by chain/address/block/runtime-code hash and acquired source digest; fabricating Git identity would corrupt provenance.

The next slice must introduce a separate immutable `OnchainResearchCase` that references `target_id` and records explicit authorization/scope evidence. A verified public contract is a research candidate, not permission to test it. Queue tasks must bind to either a Git ResearchCase or an on-chain research case, never both; parent/child task inheritance must preserve that binding.

At the Worker boundary, resolve the on-chain case and target record from the existing SQLite database, then pass a typed read-only target context to source-research agents. Do not put source bytes in queue descriptions, capability intent, or task result payloads. Do not route this context into the Git-only target execution admission or Foundry runner. Initial integration is non-executing source research only; any future fork/harness execution requires its own explicit admission contract and reviewed isolation backend.


## Working source-research pipeline

The current branch now includes a separate `OnchainResearchCase` contract. It binds an immutable `target_id` to a reviewed scope URL/digest, review date, authorization reference, hypothesis, invariant, and falsification criteria. Registration fails unless the referenced immutable target already exists in `OnchainTargetStore`.

Queue tasks carry a dedicated `onchain_case_id` column. Git and on-chain case IDs are mutually exclusive; child tasks inherit the same on-chain case; cross-case rebinding is rejected. Evidence observations inherit the on-chain case ID. The Git `ResearchCase` and its Foundry admission remain unchanged.

Worker resolves both the case and full target record from SQLite and passes the read-only source bundle to agents. The automatic on-chain path is:

1. `source_researcher`: bounded lexical triage of all stored Solidity files; records source-file digests and line-level signals.
2. `crypto_analyst`: converts signals into falsifiable review hypotheses; does not mark findings confirmed.
3. `security_checker`: independently applies its source-pattern rules to the persisted source bundle and records potential risks.

All three stages are offline/read-only. The on-chain case cannot be assigned to `lab_runner`; no Foundry, Anvil, shell, RPC writes, or transactions are invoked. Pattern matches are leads, not confirmed vulnerabilities.

## Explicit-address CLI

To start a source-only case for one contract that is already within the reviewed program scope:

```bash
export AEGISFORGE_RPC_URL="https://YOUR_CHAIN_RPC"
python scripts/aegisforge_onchain_research.py \
  --chain-id 8453 \
  --address 0xYOUR_IN_SCOPE_CONTRACT \
  --scope-url "https://YOUR_PROGRAM_SCOPE_URL" \
  --scope-digest YOUR_REVIEWED_SCOPE_SHA256 \
  --scope-reviewed-on 2026-11-21 \
  --authorization-reference "https://YOUR_PROGRAM_AUTHORIZATION_URL" \
  --hypothesis "Describe a falsifiable security hypothesis" \
  --expected-invariant "Describe the invariant that must always hold" \
  --falsification-criteria "Describe what would disprove the hypothesis"
```

The CLI intentionally accepts one explicit address instead of crawling a chain and treating arbitrary public contracts as authorized targets. It persists the acquired source/provenance, registers the case, and queues the first Worker task. It prints the target, case, and task IDs. Run it from the repository root with the normal AegisForge Python environment and configured database path.

## Verification boundary

New coverage was added for case validation/tamper detection, target-backed registration, queue/Worker binding, child inheritance, evidence lineage, agent source triage, hypothesis generation, independent SecurityChecker review, and role-scoped offline capabilities. CI runner assignment remains unreliable; do not treat these tests as passing until a runner executes them.
