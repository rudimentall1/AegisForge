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
reference. Verify the current snapshot and append-only relationship:

```bash
python aegisforge.py registry verify \\
  --registry ./registry-000002.json \\
  --previous-registry ./registry-000001.json
```

## Sign the registry root

Ask the loopback-only signer to sign the snapshot size, Merkle root, full snapshot
digest, and previous-checkpoint reference. The CLI validates the returned
checkpoint against the local snapshot before writing it:

```bash
python aegisforge.py registry checkpoint \\
  --registry ./registry-000002.json \\
  --trusted-keys ./trusted-attestation-keys.json \\
  --output ./checkpoint-000002.json
```

The command uses `AEGISFORGE_SIGNER_URL` and `AEGISFORGE_SIGNER_TOKEN`. The token
belongs only in the master process environment, never worker environments.

Verify the snapshot against its signed checkpoint:

```bash
python aegisforge.py registry verify \\
  --registry ./registry-000002.json \\
  --previous-registry ./registry-000001.json \\
  --checkpoint ./checkpoint-000002.json \\
  --trusted-keys ./trusted-attestation-keys.json \\
  --expected-checkpoint-id <pinned-checkpoint-id> \\
  --expected-size 2
```

## Inclusion proofs

Create a proof for a specific attestation ID:

```bash
python aegisforge.py registry proof \\
  --registry ./registry-000002.json \\
  --attestation-id <attestation-id> \\
  --output ./inclusion-proof.json
```

Verify the proof, signed checkpoint, and original attestation:

```bash
python aegisforge.py registry verify-proof \\
  --proof ./inclusion-proof.json \\
  --attestation ./attestation.json \\
  --trusted-keys ./trusted-attestation-keys.json \\
  --checkpoint ./checkpoint-000002.json \\
  --expected-checkpoint-id <pinned-checkpoint-id> \\
  --expected-size 2
```

The proof check verifies the attestation signature and that the exact canonical
attestation digest is included in the Merkle tree described by the trusted signed
checkpoint.

## Trust boundary

A valid signed checkpoint prevents an untrusted party from substituting a new
root without the configured signing key. It does not prove that the checkpoint is
the latest one: consumers should pass `--expected-checkpoint-id` and `--expected-size`, or obtain a
fresh checkpoint through a trusted channel, to resist rollback.

The registry is not deployed or published by this code change. It is an offline
builder and verifier for public snapshots. No live network, production database,
private key, or server is touched by the registry commands.
