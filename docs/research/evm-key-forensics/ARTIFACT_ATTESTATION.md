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

## Verified workflow record

The workflow's own GitHub CLI verification step completed successfully in [run 38367566112](https://github.com/rudimentall1/AegisForge/actions/runs/38367566112).

- PR head commit: `2621e7052aae437bc3640f84142636ec3e400d5c`
- Workflow checkout / attested source commit: `70e510ea82b1ad0fbad08a248e3affcad034e203` (GitHub's synthetic PR merge commit)
- Workflow identity: `rudimentall1/AegisForge/.github/workflows/evm-key-forensics-probe.yml@refs/pull/32/merge`
- Attested subject: `evm-key-forensics-evidence.zip`
- ZIP SHA-256 from verified provenance: `cb9bd4fcc306825648dc6c4d55519552d5f48c9bf55c655ed13e2519b5bd0043`
- Verification result: `GitHub CLI attestation verification: PASS`
- Uploaded evidence artifact: [evm-key-forensics-probe-38367566112-1](https://github.com/rudimentall1/AegisForge/actions/runs/38367566112/artifacts/11797453245)

This is a real verification result emitted by `gh attestation verify` in the workflow, not just a successful attestation-generation step. For local verification, still download the ZIP from the artifact and run the command above against that exact file.

The offline verifier still reports `UNTRUSTED_UNSIGNED` for the bundle's internal manifest. It checks internal consistency only; it does not verify the separate GitHub attestation. The historical vulnerability conclusion remains `INCONCLUSIVE`, and historical Profanity source-to-binary provenance remains `NOT_ESTABLISHED`.
