# Firecracker v1.18.0 artifact provenance record

**Assessment date:** 2026-11-22  
**Repository:** https://github.com/firecracker-microvm/firecracker  
**Release:** `v1.18.0`  
**Purpose:** record what can and cannot currently be established before any Firecracker/Jailer binary is installed on an AegisForge execution host.

## Official release metadata observed

The release was retrieved from the official GitHub API endpoint:

`GET https://api.github.com/repos/firecracker-microvm/firecracker/releases/tags/v1.18.0`

The API reported these release assets and GitHub-computed SHA-256 digests:

| Asset | Size (bytes) | GitHub asset digest |
|---|---:|---|
| `firecracker-v1.18.0-x86_64.tgz` | 7,606,252 | `1ac8eec866dd5eea14efecf6323e22b23eea24054545338a5b34bc5bca6623cd` |
| `firecracker-v1.18.0-x86_64.tgz.sha256.txt` | 97 | `742bd137d135e55498fb11b21d0b3cf625c5e9e6cb3a4f86f7a3bba5df6e6758` |
| `firecracker-v1.18.0-aarch64.tgz` | 7,438,783 | `2a6130ff0338901ff9d7fbd73ce046c6b1c6123889dc84a34d678aa53bd0c0c2` |
| `firecracker-v1.18.0-aarch64.tgz.sha256.txt` | 98 | `d11abbccd7d4cb848c6520aa540c77b02558acac6c6fe52728bbd326f65a0e4b` |

These digests are GitHub's release-asset digests exposed by the Releases API. They are useful for detecting corruption or a changed asset relative to the GitHub release record. They are **not a publisher signature** and do not independently prove that the uploaded binary was built or authorized by Firecracker maintainers.

Release API: https://api.github.com/repos/firecracker-microvm/firecracker/releases/tags/v1.18.0

## Tag authenticity check

The official Git reference for `refs/tags/v1.18.0` resolves to annotated tag object:

- Tag object: `07a7c2e20a8f4f661702551d02fc3eca679842a5`
- Target commit: `eaf83bb718a559d324613d566eaf776b31a62340`

GitHub's tag-object verification response reports:

- `verified: false`
- `reason: unsigned`

Therefore this tag cannot currently be treated as a cryptographically verified signed tag through GitHub's signature-verification API.

Tag object API: https://api.github.com/repos/firecracker-microvm/firecracker/git/tags/07a7c2e20a8f4f661702551d02fc3eca679842a5

## Publisher-signature limitation

Firecracker maintainers explain in upstream issue [#6117](https://github.com/firecracker-microvm/firecracker/issues/6117) that their internal per-architecture `SHA256SUMS` file is signed, but `SHA256SUMS.sig` is excluded from public GitHub release assets because the signing keys are not public. The internal signature is therefore not available as a public verification mechanism for this deployment.

The public per-asset `.sha256.txt` files and GitHub asset digests provide integrity checks, not independent publisher authentication. Do not describe them as signed provenance.

## Deployment decision

1. The values above are a **discovery record**, not yet an approved host profile and not proof of binary authenticity.
2. Do not silently promote a GitHub asset digest into a publisher-trust assertion.
3. Before production execution, choose and document an explicit trust path:
   - independently build the exact tagged source in a controlled, reproducible build pipeline and compare the resulting binaries; or
   - obtain an independently authenticated artifact/provenance statement from the maintainers or another approved trust authority.
4. Record the exact architecture, release asset URL, asset digest, source commit, build recipe/toolchain digests, and independent verification evidence in the operator-controlled artifact manifest.
5. Keep Firecracker, matching Jailer, guest kernel, and guest rootfs separately pinned. The guest kernel/rootfs are not authenticated by the Firecracker release asset digest.
6. Until the trust path and the actual dedicated KVM host are verified, the host preflight remains non-executing and the on-chain execution round remains `NOT_RUN`.

## Security boundary

A SHA-256 match against an operator-supplied profile proves only that a local file matches that profile's digest. It does not establish publisher identity, source-to-binary correspondence, secure Jailer configuration, guest isolation, network absence, cleanup, or hostile-code containment. The existing `check_firecracker_host.py` must continue to report only host prerequisites; it must not report execution readiness.
