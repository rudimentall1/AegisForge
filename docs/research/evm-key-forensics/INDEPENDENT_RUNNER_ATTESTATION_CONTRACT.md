# Independent Runner Attestation Contract

Status: **specification only; no independent attestation provider is implemented**.

This document defines the minimum evidence required before an EVM Key Forensics experiment may be described as independently executed. It does not authorize running historical wallet-key generation code. The current safe workflow remains source review plus repository-owned synthetic tests and generic environment diagnostics.

## Security property

An independent attestation must support the bounded claim:

> A specifically identified runner, under a stated trust model, attested that a particular experiment input and command produced a particular result and artifact digest.

It must not be interpreted as proof that the experiment's scientific conclusion is true, that the runner is invulnerable, or that a wallet was compromised.

## Required signed claims

A future provider's signed statement must bind all of the following in one canonical payload:

- schema and attestation-profile version;
- unique run ID and experiment ID;
- immutable source repository and full source revision;
- exact test-vector/fixture identifier and digest;
- exact command/argument vector and command digest;
- harness/script digest and relevant build recipe;
- runner identity, provider identity, and runner image/measurement identity where available;
- start/end time and a fresh nonce or provider-issued run identifier;
- exit status, timeout/resource-limit outcomes, and test outcome;
- result payload digest and each referenced artifact digest;
- explicit statement of whether historical code was executed and whether real key/wallet material was handled;
- attestation issuer key ID and verification chain or configured trust anchor.

The signature must cover the canonical payload, not a subset of fields. Artifact bytes must be independently hashed by the verifier. Any mismatch makes the attestation invalid for qualification.

## Trust and verification requirements

1. Provision trust anchors out-of-band from the receipt/artifact being verified.
2. Verify issuer identity, signature, profile version, and any provider certificate/measurement chain supported by the chosen provider.
3. Compare every attested input to the experiment dossier; do not accept a signed receipt merely because its experiment ID matches.
4. Reject replayed run IDs/nonces when a provider offers replay protection; otherwise record that replay resistance is not established.
5. Enforce a bounded freshness policy and explicit key revocation/rotation behavior.
6. Keep receipt authenticity, artifact integrity, runner isolation, and scientific validity as separate verdicts.
7. Never trust a dossier boolean such as independent_runner_attestation_verified=true as evidence by itself. That field may only be derived from successful verification of an actual attestation envelope against configured trust material.

## Current implementation boundary

The existing Ed25519 lab receipt signs a domain-separated canonical payload containing the envelope schema version, algorithm, key ID, full receipt, receipt digest, and signer public-key fingerprint. Verification uses explicitly configured public keys; changing the key ID is rejected even if an alias maps to the same public key. The verifier also requires the exact schema-1 envelope field set and rejects unsigned extension fields, non-string signatures, and malformed base64 signatures. This prevents callers from attaching extra envelope claims that downstream code might mistakenly treat as authenticated. This authenticates the signer statement and its metadata, but it does **not** establish runner isolation or independence. The current validator intentionally sets independent runner attestation to unavailable/unverified, so signed receipts cannot qualify a historical reproduction. This is fail-closed behavior, not a missing success flag to be manually enabled.

The current LabRunner executes only a fixed, repository-owned synthetic 12-bit toy exercise. Its receipt does not claim an immutable historical source revision, a reproduction command, or a historical reproduction artifact. It must not be repurposed to execute downloaded code or historical key-generation routines.

The repository also contains a generic signed attestor registry used by other proof workflows. That component is not an independent runner provider and must not be treated as one. Its earlier verification path checked a registry signature against the public key embedded in that same registry, which proves self-consistency but not issuer identity. The registry API now requires an out-of-band pinned issuer key for trust decisions and rejects unsigned extension fields, malformed Base64, and timezone-naive validity timestamps. Even with that hardening, its outcome attestation binds only a proof ID and verifier scope; it does not bind the complete experiment dossier required above. It therefore cannot qualify an EVM Key Forensics historical reproduction.

## Acceptance tests required before implementation is enabled

- valid attestation from configured provider and exact matching run inputs qualifies only the matching experiment;
- wrong source revision, fixture digest/ID, command, harness digest, result digest, or artifact digest is rejected;
- unknown issuer, altered signature, malformed payload, unsupported profile, expired/revoked key, and replayed run are rejected where applicable;
- a trusted ordinary lab receipt without an independent attestation remains unqualified;
- an attestation for a different experiment cannot qualify this experiment;
- missing provider/trust configuration yields INCONCLUSIVE, never a permissive fallback;
- test fixtures are synthetic and contain no real private keys, wallet targets, or recoverable wallet material.

## Decision rule

Until a real provider integration and the negative tests above exist, report:

- receipt authenticity: independently evaluated against configured signer keys;
- artifact integrity: evaluated against digests;
- independent runner attestation: **NOT IMPLEMENTED / NOT VERIFIED**;
- historical reproduction qualification: **NOT ESTABLISHED**;
- overall historical claim: **INCONCLUSIVE**.

## Local dossier schema

`shared/experiment_dossier.py` now validates a strict, unsigned experiment dossier. It binds the declared source revision, fixture digest, argument vector and its digest, harness/build-recipe digests, runner labels, execution interval and outcome, result digest, artifact names/digests, and explicit safety scope. Unknown fields are rejected so a caller cannot attach a trust-looking claim that the schema does not authenticate. The argument digest is recomputed from canonical JSON, timestamps must include a timezone, and a full Git object ID is required.

This is a schema and consistency check only. The runner identity fields are claims, not provider authentication. The dossier digest detects changes only when compared with a trusted expected digest; it is not a signature. Artifact digests in the dossier are not proof that the artifact bytes were independently read and hashed. The validator returns `qualification=NOT_ESTABLISHED` even for a structurally valid dossier. No independent runner provider, replay database, or historical reproduction path is enabled by this addition.

The dossier safety vocabulary is intentionally limited to `synthetic_only` and `source_inspection_only`. It rejects contradictory declarations, but a JSON declaration cannot prove that a process behaved as claimed. The actual safe-execution boundary remains enforced by the harness and must be independently assessed.

## Dossier-binding verifier (partial implementation)

`shared/independent_runner_attestation.py` verifies an existing Ed25519 lab receipt with an out-of-band key map, then requires exact equality for the source repository/revision, fixture identity/digest, command and digest, harness/build digests, runner labels/image digest, nonce, safety declarations, execution interval/outcome, result digest, and ordered artifact names/digests. It rejects missing or additional claims in the receipt's input, execution, and artifact objects. This is deliberately stricter than matching only an experiment ID.

A passing result reports `input_binding=MATCHED` and `artifact_binding=MATCHED`, while retaining `runner_independence=NOT_ESTABLISHED`, `replay_protection=NOT_ESTABLISHED`, and `qualification=NOT_ESTABLISHED`. This is a verifier for signed claims, not a runner service or hardware-backed attestation provider. The caller still needs to hash the actual artifact bytes with `verify_experiment_dossier_artifacts`; this receipt-binding function does not read files. The current implementation has no durable replay/nonce database, provider measurement validation, revocation feed, or freshness policy. Do not enable qualification until those gaps and the provider trust model are addressed.
