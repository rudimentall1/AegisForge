# Verifying EVM Key Forensics artifact provenance

The Probe workflow now creates a ZIP of the evidence directory and requests a GitHub build-provenance attestation for that exact ZIP.

## Download

Download the artifact named `evm-key-forensics-probe-<run-id>-<attempt>` from the matching [EVM Key Forensics Probe workflow run](https://github.com/rudimentall1/AegisForge/actions/workflows/evm-key-forensics-probe.yml). It contains:

- `evm-key-forensics-evidence.zip`, the file covered by the attestation
- `probe-evidence/`, the unpacked files for inspection

Do not re-create the ZIP before checking the attestation. A newly created ZIP has a different digest.

## Verify the attestation

With a current GitHub CLI that supports artifact attestations, run this from the directory containing the downloaded ZIP:

```sh
gh attestation verify evm-key-forensics-evidence.zip --repo rudimentall1/AegisForge
```

The command must exit successfully and report the expected repository and workflow identity. Inspect the reported source commit and workflow reference. For a pull-request run, the workflow may use GitHub's synthetic merge commit; compare the attestation metadata with `github_sha`, `github_ref`, and `pull_request_head_sha` in `probe-run-metadata.json`.

If verification fails, the attestation is absent, or the repository/workflow/source identity is unexpected, do not treat the ZIP as having verified provenance.

## What this proves, and what it does not

A successful GitHub attestation can bind the ZIP digest to GitHub's recorded workflow provenance. It is stronger than the bundle's self-reported hash manifest, but it does not establish that the workflow logic is correct, that the runner was free of compromise, or that the research conclusions are true.

The offline verifier still reports `UNTRUSTED_UNSIGNED` for the bundle's internal manifest. It checks internal consistency only; it does not verify the separate GitHub attestation. The historical vulnerability conclusion remains `INCONCLUSIVE`, and source-to-binary provenance remains `NOT_ESTABLISHED`.
