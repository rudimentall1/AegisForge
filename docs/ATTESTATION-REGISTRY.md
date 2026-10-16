# Public AegisForge attestation registry

The registry is a portable JSON Merkle snapshot, not a hosted service. It records
only the attestation ID, full signed-attestation digest, case digest, verdict,
issuance time, and signer key ID. It deliberately does not publish finding claims,
source locations, reproduction commands, or raw evidence artifacts.

## Add a trusted attestation

The attestation must first pass Ed25519 verification against an explicitly trusted
public key. Create the first snapshot:

```bash
python aegisforge.py registry add \\
  --attestation ./attestation.json \\
  --trusted-keys ./trusted-attestation-keys.json \\
  --output ./registry-000001.json
```

Append a later entry without overwriting the previous snapshot:

```bash
python aegisforge.py registry add \\
  --attestation ./next-attestation.json \\
  --trusted-keys ./trusted-attestation-keys.json \\
  --previous-registry ./registry-000001.json \\
  --output ./registry-000002.json
```

The new snapshot preserves the old entries and includes a previous-checkpoint
reference. Verify both the current snapshot and the append-only relationship:

```bash
python aegisforge.py registry verify \\
  --registry ./registry-000002.json \\
  --previous-registry ./registry-000001.json
```

## Inclusion proofs

Create a proof for a specific attestation ID:

```bash
python aegisforge.py registry proof \\
  --registry ./registry-000002.json \\
  --attestation-id <attestation-id> \\
  --output ./inclusion-proof.json
```

Verify the proof against an independently pinned root and the original signed
attestation:

```bash
python aegisforge.py registry verify-proof \\
  --proof ./inclusion-proof.json \\
  --attestation ./attestation.json \\
  --trusted-keys ./trusted-attestation-keys.json \\
  --expected-root <externally-pinned-merkle-root> \\
  --expected-size 2
```

The proof check verifies both the attestation signature and that the exact
canonical attestation digest is included in the expected Merkle tree.

## Trust boundary

The registry's Merkle root is **UNANCHORED** until a verifier obtains it through
an independent trusted channel, such as a signed release, trusted Git commit,
or separate transparency service. An attacker who can replace the entire
snapshot can recompute a valid root and its proofs. A previous-checkpoint link
proves prefix continuity only when the prior snapshot is already trusted.

The registry is not deployed or published by this code change. It is an offline
builder and verifier for public snapshots. No live network, production database,
private key, or server is touched by the registry commands.
