# Human-gated evidence attestation workflow

`aegisforge attest workflow` connects a supported offline Solidity Round result to an explicit human verdict, signer verification, a local Merkle snapshot, a signed checkpoint, and an inclusion proof.

## Supported inputs and verdicts

The first version accepts only these checked-in offline runner schemas:
- `aegisforge-solidity-round-run-v1`
- `aegisforge-uniswap-v2-factory-round-run-v1`

The evidence must have passed the independent validator, preserve the exact five-stage order, and remain `INCONCLUSIVE`. For these source-only cases the workflow permits `INCONCLUSIVE` or an explicitly selected `OUT_OF_SCOPE` verdict. It refuses `REPRODUCED` and `NOT_REPRODUCED`: the synthetic predicate is not execution of the Solidity contract, so those verdicts would overstate what was demonstrated.

## Example

First produce the local evidence result:

```bash
python -m tools.evm_key_forensics.run_uniswap_v2_factory_round_case --output ./artifacts/uniswap-v2-factory-round.json
```

Provision `trusted-attestation-keys.json` with the signer's public key through an independent trusted channel. The file must map the signer's key ID to its base64-encoded raw Ed25519 public key. Configure `AEGISFORGE_SIGNER_URL` and `AEGISFORGE_SIGNER_TOKEN` only in the master process environment; workers must not receive the token or private-key path.

Create an empty output directory and run the workflow with an explicit human verdict and rationale:

```bash
mkdir -p ./artifacts/uniswap-v2-attestation
python aegisforge.py attest workflow \
  --evidence ./artifacts/uniswap-v2-factory-round.json \
  --verdict INCONCLUSIVE \
  --rationale "Source-only evidence does not establish Solidity runtime behavior." \
  --trusted-keys ./trusted-attestation-keys.json \
  --output-dir ./artifacts/uniswap-v2-attestation
```

The workflow refuses to overwrite any output. It requests the signature from the loopback signer, verifies the attestation against the trusted public key and evidence artifact, builds or appends a local Merkle registry, requests and verifies a signed checkpoint, creates an inclusion proof, and verifies the proof before writing results.

## Outputs

- `attestation.json`: signed source-only observation and the explicit human verdict/rationale.
- `registry.json`: privacy-minimized Merkle snapshot; no raw source or finding detail is published.
- `checkpoint.json`: signer-authenticated registry root/size/digest.
- `inclusion-proof.json`: proof that the attestation is included in the snapshot.
- `workflow-summary.json`: machine-readable result and verification status.

Pass `--previous-registry PATH` to append to an existing snapshot. The previous registry must validate, and the new snapshot must preserve its entries.

## Trust and safety boundaries

- This command does not publish the registry to a hosted service; all output files are local.
- The signer private key never enters the CLI or worker processes.
- A valid signature proves only that the trusted signer signed the payload. It does not prove the source is safe or that a vulnerability exists.
- `INCONCLUSIVE` remains the default interpretation for these source-only acceptance cases. No finding is created and no automatic confirmation occurs.
- The output directory must already exist, must not be a symlink, and must not contain any of the workflow output filenames.
