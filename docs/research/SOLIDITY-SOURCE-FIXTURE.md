# Pinned Solidity source-pattern acceptance fixture

This fixture pins the upstream OpenZeppelin Contracts source for
`contracts/access/Ownable.sol` at commit
`dbb6104ce834628e473d2173bbc9d47f81a9eec3`. The expected Git blob SHA-1 is
`bd96f6661dcbf7b2d4948823ac0e7bfb4ba31fb1`.

The source is included under `tests/fixtures/solidity/Ownable.sol` so CI does
not fetch mutable remote content. The checker verifies the exact Git blob
identity and then checks a small set of source-level access-control invariants.
It does not compile or execute Solidity, connect to an RPC endpoint, inspect
deployed bytecode, or claim that this abstract source is a deployed/verified
contract.

A matching result is a **negative-control source observation**, not a finding:
it confirms that the pinned source contains `onlyOwner`, calls `_checkOwner()`,
compares the owner with `_msgSender()`, guards the zero address, and has no
`tx.origin` token in executable source text. It does not prove runtime security.

Run locally:

```bash
python -m tools.evm_key_forensics.solidity_source_pattern tests/fixtures/solidity/Ownable.sol
pytest -q tests/test_solidity_source_pattern.py
```

This is the first bounded source-stage fixture for the Solidity acceptance
workflow. It is not yet the full Source Researcher → Crypto Analyst → Lab Runner
→ Validator → human-review flow. That integration must preserve the same
pinned-source and no-finding boundaries before the fixture can count as a
release acceptance case.


## Agent-level acceptance flow

The agent integration test runs the actual `SourceResearcher`, `CryptoAnalyst`,
`LabRunner`, and `Validator` against this local fixture, preserving a stage history.
The validator recomputes the source identity and synthetic control outcomes. A
changed case commit or tampered control result remains `INCONCLUSIVE`.

This is still a negative-control acceptance fixture, not a live/deployed-contract
investigation. The lab stage exercises a pure-Python owner-equality predicate; it
does not compile Solidity or execute the EVM. The validator may report its evidence
checks as validated while the research conclusion remains `INCONCLUSIVE`. Human
review is required, and automatic confirmation remains disabled.
