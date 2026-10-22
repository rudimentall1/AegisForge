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

A package may additionally embed detached Ed25519 execution attestations associated with exact experiment-record digests:

```bash
python -m shared.research_case_evidence_package build \
  --case-dossier case-dossier.zip \
  --experiment control-experiment.zip \
  --experiment counter-experiment.zip \
  --attestation control-attestation.json \
  --attestation counter-attestation.json \
  --output case-evidence-package.zip
```

Verify the package structure, nested bundles, and evidence links offline:

```bash
python -m shared.research_case_evidence_package verify case-evidence-package.zip
```

Without an external trust policy, this verifies package integrity and structurally binds each included attestation to an exact experiment record, but reports `attestation_verification_status=NOT_CHECKED`. If a caller supplies a trust store, the package must contain at least one attestation and every included signature must pass; otherwise overall verification fails instead of treating a stripped/unsigned package as authenticated. Requesting freshness with `--max-attestation-age-seconds` also requires a trusted key store: timestamps on unsigned or unchecked claims are not verified. To verify the signatures, supply each trusted raw Ed25519 public key out of band as a 32-byte hexadecimal value:

```bash
python -m shared.research_case_evidence_package verify case-evidence-package.zip \
  --trusted-key ci-runner-key-1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --max-attestation-age-seconds 3600
```

To also enforce one-time nonce consumption for every embedded attestation, add a durable replay database:

```bash
python -m shared.research_case_evidence_package verify case-evidence-package.zip \
  --trusted-key ci-runner-key-1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --max-attestation-age-seconds 3600 \
  --replay-database ./attestation-replay.sqlite3
```

The first successful verification consumes the package's signer/nonce pairs atomically. Re-verifying the same package under the same registry returns failure with `replay_protection_status=FAIL`. If replay protection is explicitly requested for a package with no embedded attestations, verification also fails rather than returning success with nothing protected. Invalid signatures are rejected before nonce consumption; duplicate or previously consumed signer/nonce pairs reject the entire batch without partial consumption.

Replay protection requires a trusted key policy and a durable, shared registry across all verifiers in the same replay domain. A local SQLite file is not a distributed replay service when workers use separate files or hosts.

Replace the example key with the actual public key from your independently managed trust store. Never treat a key or public-key label supplied only by the package itself as trusted. The verifier reports separate `package_integrity_status` and `attestation_verification_status` values (`NOT_PRESENT`, `NOT_CHECKED`, `PASS`, or `FAIL`), as well as a separate `replay_protection_status`. When a trust store is provided, any missing/untrusted signer, invalid signature, record mismatch, or requested freshness failure makes the overall verification fail. A valid signature still does not establish execution truth or rule out a compromised runner.

The verifier returns a machine-readable report with case ID/digest, task IDs, record digests, runtime and planned round IDs, and the explicit package status `UNSIGNED_INTEGRITY_ONLY`. The outer package remains unsigned even when it contains signed claims. Input ZIPs are treated as untrusted bytes, and the CLI reads only bounded files. It never executes any command from a bundle.

Every `local_experiment_record:<digest>` evidence reference in the case dossier must be accompanied by the corresponding experiment bundle. A package containing only a subset of those records is rejected. Schema v2 carries optional detached attestations; the verifier retains compatibility with packages using schema v1. The package manifest and nested hashes are unsigned; a party capable of rewriting the whole package can recompute them. Signatures can authenticate claims under a separately trusted public key, but they do not authenticate arbitrary package metadata or prove the runner told the truth.

## Attestation and verdict boundaries

Detached Ed25519 execution attestations and SQLite nonce replay protection are separate layers. Signature verification depends on a trusted public key supplied out of band; freshness is opt-in, and the SQLite replay registry is shared-database scoped rather than distributed. None of these mechanisms, alone or together, proves the runner was uncompromised or that a claimed experiment truly occurred.

The fixture logic in `shared/synthetic_fixture.py` computes a control invariant and detects a deliberately seeded counter-test mismatch. The end-to-end evidence path invokes it through `shared.synthetic_fixture_runner.run_synthetic_fixture_subprocess`, which launches only the fixed repository script with Python isolated mode and two allowlisted modes. It records the child's actual captured stdout/stderr, exit code, canonical stdin request, and command metadata. The runner uses a capped wall timeout, output-capture limits, a minimal environment, a temporary working directory, and POSIX CPU, address-space, file-size, open-file, and core-dump limits.

This is a bounded subprocess adapter for the fixed synthetic fixture, **not a security sandbox**. It does not create a network namespace, deny network syscalls, isolate the filesystem, or safely run arbitrary target code. Its `network_access=false` fixture result means this fixed code path does not request network access; it is not evidence that network access was technically blocked. The runner rejects bundle-provided commands, executable paths, and environment variables.

Synthetic outputs remain `INCONCLUSIVE` for target vulnerability status. No verifier automatically promotes a finding to `CONFIRMED`.

## Release gate

RC gate #158 remains open until a clean-runner acceptance path demonstrates bounded execution/reproduction from a clean checkout, exact evidence persistence, portable export and offline verification, and clear failure behavior for missing or mismatched evidence. The fixed-fixture subprocess exercises actual process output capture and resource-limit wiring, but the missing network and filesystem isolation mean it does not by itself close that gate.
