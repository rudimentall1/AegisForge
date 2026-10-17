# Verifier Level 2: Workflow Provenance Trust Contract

**Status:** design proposal; not implemented and not an approval to claim level 2 verification.
**Related:** issues #80 and #88; `docs/ARCHITECTURE.md` §3.8–3.9.
**Scope:** workflow provenance only. Experiment execution (level 3) is explicitly out of scope.

## Decision proposal

Use GitHub Artifact Attestations with a Sigstore/in-toto attestation bundle as the supported provenance format. Do not accept a self-declared JSON file, a manifest hash, a Merkle root, or an unsigned workflow metadata file as provenance.

The verifier must consume a detached attestation bundle plus an independently configured trust policy. The evidence bundle itself must not be able to choose or weaken that policy.

This is a proposal for review, not a statement that the current verifier supports these checks.

## Existing implementation inventory (reviewed 2026-10-17)

The repository already has a narrower, EVM Key Forensics-specific implementation:

- `.github/workflows/evm-key-forensics-probe.yml` mints an attestation only for a manual run on `refs/heads/main`, after the probe and independent clean-runner rebuild jobs succeed. The attestation-writing job has `id-token: write` and `attestations: write`; the pull-request job does not.
- `tools/evm_key_forensics/verify_attestation.py` invokes `gh attestation verify` with a pinned repository and signer-workflow path, then checks subject SHA-256, workflow repository/name/path/ref/trigger/SHA, and run ID/attempt against independently supplied expectations.
- `tests/test_evm_key_forensics_verify_attestation.py` exercises identity and digest mismatches, malformed reports, missing CLI, bounded timeouts, and archive safety.
- `shared/verify_bundle.py` does not call that verifier. It correctly leaves generic Level 2 `INCONCLUSIVE` even if an unsigned `workflow-attestation.json` file is present.

This is useful prior art, not yet the generic Level 2 contract. The existing wrapper is archive/workflow-specific, relies on the installed GitHub CLI and its verification environment, and expects caller-supplied run metadata. Do not describe it as a portable offline verifier or reuse it for arbitrary bundles without redesigning its policy interface. The next implementation should either adapt the established wrapper behind an explicit, externally supplied policy or extract a tested shared interface without weakening its hard-coded trust constraints.

The first integration target is a sanitized fixture/report from a successful `workflow_dispatch` run on `main`. A pull-request run cannot provide the required attestation by design. Keep Level 2 `INCONCLUSIVE` in the generic verifier until the integration is covered by adversarial tests and the generic report preserves the exact verified identity and subject digest.

## Claims level 2 may make

A successful check may say that an accepted identity issued an attestation binding a specific artifact digest to a specific GitHub Actions workflow/run, under the configured trust policy.

It must not claim that:
- the workflow or runner was honest or uncompromised;
- the source repository or target revision is benign or authentic beyond the verified provenance fields;
- the artifact was built reproducibly unless a separate reproducible-build check establishes that;
- the experiment is scientifically valid or its output proves a vulnerability;
- the finding is confirmed.

Level 2 is provenance evidence, not a vulnerability verdict.

## Trust policy

The verifier configuration, supplied independently of the bundle, must pin:
- accepted OIDC issuer (for GitHub-hosted Actions, the expected GitHub Actions issuer);
- repository owner/name;
- exact workflow identity/path, not only a display name;
- permitted source ref policy and expected source commit where the case requires one;
- expected artifact subject digest;
- accepted predicate type and schema version;
- trusted Sigstore roots and transparency-log verification policy, including a documented refresh/rotation process.

Do not accept wildcards for repository or workflow identity by default. Any opt-in wildcard policy must be explicit and visible in the verification report.

The verifier must compare the attested subject digest to the digest of the artifact being verified, and compare the attested repository, workflow, source revision, run identity, and predicate type against the external policy and case binding. A valid signature with the wrong subject or identity is a failure.

## Verification result contract

Keep each check independently visible. At minimum:
- `PASS`: cryptographic verification succeeded and all required identity/digest/predicate bindings matched policy.
- `FAIL`: a present attestation is malformed, has an invalid signature/proof, or conflicts with a required identity/digest/policy field.
- `INCONCLUSIVE`: verification cannot complete because a required trust root, proof, policy, or verifier capability is unavailable or unsupported.
- `NOT_RUN`: level 2 was not requested.

Missing attestation is not a pass. Under a required-provenance policy it is `FAIL`; when provenance is optional or no policy was supplied, report `INCONCLUSIVE` with a precise reason. Never silently downgrade to level 1 and label the overall result verified.

The report should include the verifier version, policy identifier/digest, attestation digest, subject digest, verified issuer, repository/workflow identity, source commit, run ID/attempt when present, and individual check outcomes. Do not print secrets or trust material that should remain private.

## Offline and dependency behavior

The desired verifier is deterministic and offline when supplied with a complete attestation bundle, inclusion proof, and pinned trust-root material. It must fail closed if the bundle lacks required proof material or the trust policy cannot be evaluated.

Before implementation, compare:
1. invoking a pinned `gh attestation verify` binary with explicit repository/workflow constraints; and
2. verifying the Sigstore/in-toto envelope in-process using an established verifier library.

Do not add a runtime dependency or assume offline support until the chosen implementation and its trust-root/proof behavior are validated against real GitHub-generated fixtures. Do not write a bespoke signature or certificate verifier. Record tool/library versions and test fixtures.

If the selected supported verifier requires network access for trust-root or transparency-log lookup, it must report that requirement explicitly. It must not describe the result as offline verification.

## Required adversarial tests

- Missing attestation and missing trust policy.
- Malformed envelope, unsupported predicate, missing or empty identity fields.
- Invalid signature or transparency-log proof.
- Wrong issuer, repository, workflow path, source ref, source commit, subject digest, and predicate type.
- A valid attestation from a different repository or workflow.
- A valid signature over a statement whose subject digest does not match the supplied artifact.
- Expired/revoked or otherwise untrusted signing material where the selected trust model supports those checks.
- Trust-root absent, malformed, or unsupported version.
- Multiple attestations where none matches policy; no “first item wins” behavior.
- Level 2 failure/inconclusive must never promote a research finding to `CONFIRMED`.

Use real, non-secret fixture attestations generated by a dedicated test workflow or checked-in sanitized fixtures. Tests must not require production credentials, access private keys, or contact live chains.

## Rollout gates

1. Approve this trust model and the exact identity policy.
2. Capture and verify a real GitHub-generated attestation fixture from a dedicated workflow without changing the reserved `.github/workflows/ci.yml`.
3. Implement the verifier behind an explicit level-2 option; keep current level-2 status `INCONCLUSIVE` until cryptographic verification is complete.
4. Add adversarial tests and a report that distinguishes signature validity, identity binding, artifact integrity, experiment reproduction, and finding status.
5. Update architecture and user documentation only after the implementation is proven against the fixture.
6. Keep level 3 `NOT_RUN` unless a separately reviewed, isolated reproduction runner is explicitly invoked.

## Security boundary

A trusted workflow attestation records a workflow's statement about an artifact. It is not a substitute for independent source review, deterministic rebuilds, a controlled experiment, impact validation, or human review. The bundle must never be allowed to supply the trust root that validates its own claims.
