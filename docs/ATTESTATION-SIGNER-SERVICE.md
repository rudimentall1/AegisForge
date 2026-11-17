# Isolated AegisForge attestation signer

The signer service is a separate process that owns the Ed25519 private key. It
binds only to `127.0.0.1`, requires a bearer token for signing requests, accepts
only the attestation fields, and never accepts a key in an HTTP request. The
master-side client has no private-key loading code. Do not put the signer token
in worker environment files.

## Environment

Create `/etc/aegisforge/signer.env` with owner-only access for root and read
access for the signer service group. Do not commit this file:

```dotenv
AEGISFORGE_SIGNER_HOST=127.0.0.1
AEGISFORGE_SIGNER_PORT=8765
AEGISFORGE_SIGNER_TOKEN=<random-secret-at-least-32-characters>
AEGISFORGE_ATTESTATION_KEY_PATH=/etc/aegisforge/attestation-ed25519.key
AEGISFORGE_ATTESTATION_KEY_ID=owner-local-v1
AEGISFORGE_ATTESTATION_ORGANIZATION=AegisForge
```

The key file must contain exactly 32 raw Ed25519 private-key bytes, be a regular
non-symlink file, and have no group/world permissions on POSIX. Provision it
owned by `aegisforge-signer` with mode `0600`. The signer does not generate,
rotate, export, or print private keys.

## Install

Create the service account and configuration directories using your normal
server change process, then install this unit at
`/etc/systemd/system/aegisforge-signer.service`. Install the Python package and
virtual environment at the path in `ExecStart`, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegisforge-signer.service
sudo systemctl status aegisforge-signer.service
```

This repository change does not install or start the service on any server.

## HTTP contract

- `GET /healthz`: loopback health response; no key material.
- `GET /v1/public-key`: public Ed25519 key metadata.
- `POST /v1/attest`: bearer-authenticated attestation signing request.
- `POST /v1/registry-checkpoint`: signs only a constrained registry size/root/digest checkpoint.
- Body limit: 256 KiB. Duplicate JSON keys and unknown fields are rejected.
- Only verdicts allowed by `shared.attestation` are accepted; `CONFIRMED` is rejected.
- Request bodies, credentials, and attestation payloads are not written to HTTP logs.

Example master-side call:

```python
from shared.attestation_signer_client import request_attestation, request_registry_checkpoint

attestation = request_attestation(attestation_input)
checkpoint = request_registry_checkpoint(registry_snapshot)
```

The master process alone receives `AEGISFORGE_SIGNER_TOKEN`. Worker units must not
receive the token or private-key path. The client refuses non-HTTP loopback URLs;
do not expose this service to a network. If master and signer are moved to separate
hosts, design an authenticated encrypted transport before changing this boundary.

## Verification

The response contains the signed attestation and its ID. Verify it using the
three-tier CLI and an independently provisioned trusted public key. The signer
proves only that the configured key signed the payload; it does not prove the
research conclusion or organizational identity.
