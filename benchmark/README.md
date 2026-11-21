# First executable EVM benchmark: reentrancy

This is a self-contained real-EVM execution gate, not yet an automatic AegisForge detector.

## What it proves

- Positive control: the attacker drains a deliberately vulnerable vault through recursive withdraw calls.
- Negative control: the same attacker cannot drain the safe vault; the victim's 10 ETH remains.
- Both cases compile with Solidity 0.8.24 and execute in Foundry's local EVM. The test harness uses Foundry's documented cheatcode address directly and has no forge-std dependency.
- Assertions check balances and accounting state, not suggestive log messages.

## Run

```bash
forge test --match-contract ReentrancyBenchmarkTest -vvv
```

The GitHub Actions workflow at .github/workflows/foundry-benchmark.yml runs these tests on relevant pushes and pull requests.

## Acceptance boundary

This is exploit reproduction, not source-code detection, not integration into Research Case orchestration, and not evidence about any third-party contract. Those remain subsequent engineering steps.


## Using this benchmark as a planned ResearchCase round

The same source and harness can be passed through the case-bound Foundry adapter.
The source path is repository-root-relative, while the generated Foundry project
uses the declared source root:

```python
from pathlib import Path
from shared.research_case import RoundSpec

round_spec = RoundSpec(
    round_id="reentrancy-foundry-round",
    technique="runtime_probe",
    hypothesis="A reentrant callback can withdraw a vault credit more than once.",
    expected_evidence_atoms=("positive_control", "negative_control"),
    falsification_criteria="The safe vault retains victim funds under the same attack.",
    target_source_paths=("benchmark/src/ReentrancyVault.sol",),
    foundry_source_root="benchmark/src",
    test_harness_source=Path(
        "benchmark/test/ReentrancyBenchmark.t.sol"
    ).read_text(encoding="utf-8"),
    solc_version="0.8.24",
    foundry_image=PINNED_FOUNDRY_IMAGE_DIGEST,
    positive_control_test="test_positive_control_reentrancy_drains_vulnerable_vault",
    negative_control_test="test_negative_control_safe_vault_resists_same_attack",
)
```

`PINNED_FOUNDRY_IMAGE_DIGEST` must be the exact digest of the Foundry image
preloaded on the LabRunner host. Do not substitute a mutable image tag. The
ResearchCase must also pin the commit containing these benchmark files and
carry a reviewed scope envelope. This example is a local benchmark only; it
does not authorize testing any third-party target.
