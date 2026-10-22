# Local Experiment Evidence and Portable Case Packages

This document describes the current evidence path and its trust limits. The data packages are offline, deterministic integrity transports; they are not signatures, execution attestations, or vulnerability verdicts.

## Evidence layers

1. `shared/local_experiment.py` builds a canonical record and exact raw `input.bin`, `stdout.bin`, and `stderr.bin` bytes from output supplied by a caller. Record schema v2 includes both the planned `round_spec_id` and runtime `round_id`. Schema v1 records remain readable. The record builder never executes `argv`.
2. `EvidenceLedger.record_local_experiment()` accepts a record only for a terminal queue task. It checks the registered case and pinned target revision, the task's case/runtime/planned identities, and the authoritative runtime-round registry for planned cases. Count and raw-byte budgets are checked under a SQLite write reservation.
3. `shared/local_experiment_bundle.py` creates and verifies a strict ZIP containing the canonical record and raw artifact bytes. A PASS means the record and bytes are internally consistent. The verifier exposes the canonical record digest so dossier evidence can link to it.
4. `shared/research_case_bundle.py` exports a portable case dossier. Schema v3 includes `rounds.json`, which records the runtime-round registry separately from the case's planned RoundSpecs. The offline verifier checks task-parent, evidence, case, root-task, runtime-round, and planned-round relationships. Schema v1/v2 compatibility remains explicit.
5. `shared/experiment_assessment.py` checks a control and a falsification counter-test against caller-specified byte-string criteria. Both artifacts must have matching case, round, planned round, repository and commit identities, with separate tasks and distinct commands. This is explicit byte matching, not a proof of general program behavior.
6. `shared/research_case_evidence_package.py` combines the case dossier and all local-experiment ZIPs referenced by its evidence observations into one deterministic archive. It verifies the nested archives, cross-checks each record digest against exactly one task-bound evidence observation, and rejects packages that omit a referenced experiment.

## CLI

Build a combined package after exporting the case dossier and persisted experiment bundles:

```bash
python -m shared.research_case_evidence_package build \
  --case-dossier case-dossier.zip \
  --experiment control-experiment.zip \
  --experiment counter-experiment.zip \
  --output case-evidence-package.zip
```

Verify it offline:

```bash
python -m shared.research_case_evidence_package verify case-evidence-package.zip
```

The verifier returns a machine-readable report. A successful report includes case ID/digest, task IDs, record digests, runtime and planned round IDs, and the explicit status `UNSIGNED_INTEGRITY_ONLY`. Input ZIPs are treated as untrusted bytes, and the CLI reads only bounded files. It does not execute any command from a bundle.

Every `local_experiment_record:<digest>` evidence reference in the case dossier must be accompanied by the corresponding experiment bundle. A package containing only a subset of those records is rejected. The package manifest and all nested hashes are unsigned; a party capable of rewriting the whole package can recompute them. The package therefore does not authenticate who created the evidence.

## Attestation and verdict boundaries

Detached Ed25519 execution attestations and SQLite nonce replay protection are separate layers. Signature verification depends on a trusted public key supplied out of band; freshness is opt-in, and the SQLite replay registry is shared-database scoped rather than distributed. None of these mechanisms, alone or together, proves the runner was uncompromised or that a claimed experiment truly occurred.

The included `shared/synthetic_fixture.py` is a fixed in-process fixture for testing evidence plumbing. It computes a control invariant and detects a deliberately seeded counter-test mismatch. It does not launch a subprocess, use the network, or accept user-provided commands. This fixture is not an isolated execution runner for arbitrary target code.

Synthetic outputs remain `INCONCLUSIVE` for target vulnerability status. No verifier automatically promotes a finding to `CONFIRMED`.

## Release gate

RC gate #158 remains open until a clean-runner acceptance path demonstrates bounded execution/reproduction from a clean checkout, exact evidence persistence, portable export and offline verification, and clear failure behavior for missing or mismatched evidence. The deterministic in-process fixture proves the data plumbing only; it does not by itself close that gate.
