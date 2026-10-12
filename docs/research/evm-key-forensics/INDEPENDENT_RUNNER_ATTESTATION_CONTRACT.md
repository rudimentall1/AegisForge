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
