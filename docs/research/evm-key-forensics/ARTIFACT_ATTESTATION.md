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


## Latest strict-verification run

The stricter identity checks were exercised successfully in [workflow run 38367831398](https://github.com/rudimentall1/AegisForge/actions/runs/38367831398), against PR head `27e8c954c68291e0ec469643165105b90108b4f7`.

- Workflow checkout / attested source SHA: `24e077826caa40961812ebd06bc735f6355424ca`
- Ref: `refs/pull/32/merge`
- Attested subject: `evm-key-forensics-evidence.zip`
- Subject SHA-256: `89c904a57614c8d57dc50b9bbdea9625e70a10aa4cea5162eb5e0448cc23e646`
- Attestations examined: `1`
- Result: `GitHub CLI attestation identity and subject digest: PASS`
- Uploaded evidence artifact: [evm-key-forensics-probe-38367831398-1](https://github.com/rudimentall1/AegisForge/actions/runs/38367831398/artifacts/11796739500)

The verification step now checks the verified certificate's repository, workflow name, workflow SHA and ref; the in-toto statement's workflow path and repository; and the SHA-256 of the actual ZIP against the attested subject digest. The full probe workflow and independent clean-runner rebuild both passed for this run.

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

## Combined evidence package verification

The combined evidence job completed successfully in [workflow run 38368366193](https://github.com/rudimentall1/AegisForge/actions/runs/38368366193), on PR head `23c079c15f62b942d58c2d15605be1abc3de3a31`.

- Combined artifact: [evm-key-forensics-complete-evidence-38368366193-1](https://github.com/rudimentall1/AegisForge/actions/runs/38368366193/artifacts/11797811330)
- Attested archive: `evm-key-forensics-complete-evidence.zip`
- Archive SHA-256: `336ec3adbd2f0317909dc0fafa7d06d08b2e23c78917f7de877abbbd349f3145`
- Probe source SHA-256: `60611d0f287aee085afab07b3bb5f3747fb3c4ef70d5e2f238594885affdfffa`
- Probe and independent rebuild binary SHA-256: `c8abed601e5c34fd2db77b3b02140381114366550a44ee55c687e43bcd43e274`
- Workflow run: `38368366193`, attempt `1`
- Attestation verification: `PASS`; one verified attestation examined
- Probe/rebuild cross-linkage: `PASS`

The verification step checked the attested subject digest against the actual archive, the GitHub certificate identity and workflow metadata, and consistency between the probe metadata, independent rebuild report, and combined index. The archive explicitly records that historical Profanity was not executed and its vulnerability was not reproduced.

This establishes GitHub-attested provenance and internal consistency for this synthetic diagnostic package. It does not authenticate historical Profanity runtime behavior, establish the historical binary's source provenance, or prove a wallet was exposed.

## Immutable action references and repeat verification

After the combined-package gate passed, the forensic workflow's third-party actions were pinned to the exact commit SHAs observed in the successful GitHub job logs. The workflow no longer uses floating major-version tags for checkout, artifact download/upload, or provenance attestation.

The pinned workflow completed successfully in [run 38368603773](https://github.com/rudimentall1/AegisForge/actions/runs/38368603773), using PR head `cde0549ada415430503c5331b5d26b3d9cf6c8bc`.

- Attested archive SHA-256: `5eeff9610f588edab529d47945ba47109706f2b375c9e2a9a43775b3820758f3`
- Workflow source SHA in the provenance statement: `5ee1a01a3b5ddb95fb4838b936737e2747463d1e`
- Attestation identity, archive digest and probe/rebuild cross-linkage: `PASS`
- Uploaded combined artifact: [evm-key-forensics-complete-evidence-38368603773-1](https://github.com/rudimentall1/AegisForge/actions/runs/38368603773/artifacts/11798690374)

Pinning makes the action code reference immutable for this workflow revision. It does not eliminate risk in the runner image, toolchain downloads, or the actions' own dependencies; those remain separate supply-chain controls.

## Offline combined-archive verifier

The combined ZIP now passes a separate offline validation step inside the publication job. The validator checks the ZIP member allowlist, rejects duplicate entries and unsafe paths, bounds archive and member sizes, streams members into a temporary directory without `extractall()`, invokes the probe artifact verifier, and checks run identity plus source/binary hashes across the probe metadata, independent rebuild report, and combined index.

Verified in [workflow run 38369462635](https://github.com/rudimentall1/AegisForge/actions/runs/38369462635), PR head `af4f566d5ce6f6420cfdc10bce494b2688ea2fcb`:

- Main CI: `823 passed, 1 warning` in [run 38369463019](https://github.com/rudimentall1/AegisForge/actions/runs/38369463019)
- Probe compile, smoke test, and first provenance verification: `PASS`
- Independent clean-runner rebuild: `PASS`
- Offline complete-archive integrity and cross-link validation: `PASS`
- GitHub attestation identity and exact ZIP digest verification: `PASS`
- Attested archive SHA-256: `bdeb7821426703446ca0087ed2143654abb1e07cb674a2c1b8e63a5b06a3f751`
- Combined artifact: [evm-key-forensics-complete-evidence-38369462635-1](https://github.com/rudimentall1/AegisForge/actions/runs/38369462635/artifacts/11798177321)

The offline validator deliberately returns `UNTRUSTED_UNSIGNED` and `NOT_CHECKED_OFFLINE`: archive integrity is not a substitute for independently verifying GitHub's attestation. The workflow performs that separate verification before publishing. The historical Profanity conclusion remains `INCONCLUSIVE`; historical source-to-binary provenance remains `NOT_ESTABLISHED`.

## Archive-abuse regression gate

Added explicit regression cases for ZIP symlink entries, extreme compression ratios, and failure propagation from the underlying probe verifier. The new tests passed in the full suite and the workflow passed against a newly generated, attested combined archive.

Verified in [workflow run 38369700157](https://github.com/rudimentall1/AegisForge/actions/runs/38369700157), PR head `210c63cfac238f79686bd1655b9677e27a710f2f`:

- Main CI: `826 passed, 1 warning` in [run 38369700113](https://github.com/rudimentall1/AegisForge/actions/runs/38369700113)
- Independent clean-runner rebuild: `PASS`
- Offline combined-archive validator: `PASS`, no failed checks
- GitHub provenance attestation and cross-run linkage: `PASS`
- Exact attested ZIP SHA-256: `edb3570ff2d5afeb56d5ae53880e9efc6a398dcfef5b9432405d5c612651b69b`
- Combined artifact: [evm-key-forensics-complete-evidence-38369700157-1](https://github.com/rudimentall1/AegisForge/actions/runs/38369700157/artifacts/11797908886)

The archive is still a synthetic diagnostic evidence package. This gate does not change the historical research conclusion: `INCONCLUSIVE`, with historical source-to-binary provenance `NOT_ESTABLISHED`.

## ZIP special-file rejection regression

The complete-evidence archive verifier now rejects ZIP members whose Unix mode identifies a special filesystem type, including FIFO entries, as well as symlinks. A dedicated FIFO regression test verifies rejection occurs before the inner probe verifier is called.

Verified in [EVM Key Forensics Probe run 38370065463](https://github.com/rudimentall1/AegisForge/actions/runs/38370065463) and [main CI run 38370065438](https://github.com/rudimentall1/AegisForge/actions/runs/38370065438), PR head `eb7f1959077c9d77e0ca1c9d7f1991b8885f5f06`:

- Archive abuse regression tests: passed
- Probe and source checks: PASS
- Independent clean-runner rebuild: PASS
- Complete-evidence attestation verification and publication: PASS
- Main CI: PASS
- Complete artifact: [evm-key-forensics-complete-evidence-38370065463-1](https://github.com/rudimentall1/AegisForge/actions/runs/38370065463/artifacts/11798483680)

This remains an archive-safety improvement. It does not change the historical Profanity conclusion, which remains `INCONCLUSIVE`, or source-to-binary provenance, which remains `NOT_ESTABLISHED`.
