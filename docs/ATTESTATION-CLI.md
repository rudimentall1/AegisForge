# AegisForge attestation CLI

The CLI wraps the existing `shared.attestation` Ed25519 core. It is offline and
does not decide whether a vulnerability is real. The allowed verdicts are
`REPRODUCED`, `NOT_REPRODUCED`, `INCONCLUSIVE`, and `OUT_OF_SCOPE`; `CONFIRMED`
is rejected.

## 1. Create a local signing key

```bash
python aegisforge.py attest keygen \\
  --private-key-file ./data/attestation-ed25519.key \\
  --public-key-file ./data/trusted-attestation-keys.json \\
  --key-id owner-local-v1
```

The private key is a raw 32-byte Ed25519 seed written with owner-only permissions
on POSIX. Existing files are never overwritten. The private key is never printed.
Keep it out of source control and do not provision it to research workers.

## 2. Create an attestation

Prepare an input JSON object containing `case_ref`, `finding_ref`, `reproduction`,
`verdict`, and `verdict_rationale`. The reproduction record includes the
reproduction-contract SHA-256, argv arrays, environment metadata, network-access
flag, artifact path/hash/size entries, start/end timestamps, and exit code.

```bash
python aegisforge.py attest create \\
  --input ./attestation-input.json \\
  --private-key-file ./data/attestation-ed25519.key \\
  --key-id owner-local-v1 \\
  --organization "Your research team" \\
  --output ./attestation.json
```

Output files are created exclusively; the command refuses to overwrite an
existing attestation.

## 3. Verify in three tiers

Tier 1 checks the schema, canonical attestation ID, allowed verdict, required
fields, and basic signature envelope. It does not authenticate the signer:

```bash
python aegisforge.py verify ./attestation.json --level 1
```

Tier 2 verifies the Ed25519 signature against an explicitly trusted key:

```bash
python aegisforge.py verify ./attestation.json --level 2 \\
  --trusted-keys ./data/trusted-attestation-keys.json
```

Tier 3 additionally binds the attestation to the expected case digest and checks
every listed artifact's safe path, byte size, and SHA-256 digest:

```bash
python aegisforge.py verify ./attestation.json --level 3 \\
  --trusted-keys ./data/trusted-attestation-keys.json \\
  --expected-case-digest <64-hex-case-digest> \\
  --artifact-root ./evidence
```

The artifact root must contain each artifact at the relative path recorded in
the attestation. Do not point it at a broader directory than necessary.

## Exit codes

- `0`: tier-1 structure is valid, or requested verification returned `VALID`.
- `1`: invalid or tampered attestation, failed case binding, or failed artifact checks.
- `2`: signer key is not trusted / does not match the configured trusted key.
- `3`: CLI input, filesystem, permission, or configuration error.

A valid signature proves that the attestation payload was signed by the matching
private key. It does not prove the research conclusion, validate the signer
organization's identity, or prove deployed-contract behavior. Key provisioning
and the isolated signer service remain separate operational work.
