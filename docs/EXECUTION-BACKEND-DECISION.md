# Execution backend decision — hostile target-code boundary

**Status:** architecture decision for the next implementation phase  
**Date:** 2026-11-15  
**Scope:** AegisForge PR #196 / release gate #158

## Decision

Do not promote the existing Docker reproduction prototype to the production hostile-code boundary.

The production target remains a disposable VM/microVM with no host credentials, no shared writable host mounts, and an independently verified network-denied configuration. The first candidate to evaluate is **Firecracker on a dedicated Linux KVM host**. It is not approved until the actual host passes capability and isolation acceptance tests.

**gVisor with the systrap platform** is the practical fallback for a lower-assurance development or internal tier where KVM is unavailable. It is a meaningful syscall-interception boundary, but it is not a VM/microVM and must not be represented as satisfying the hostile-public-repository release requirement.

Do not select Kata Containers for the first single-host MVP. It also requires hardware virtualization or nested virtualization and KVM (or a specifically supported alternative), and introduces a containerd/CRI-oriented operational stack that is unnecessary for the current single-runner architecture.

## Evidence and constraints

### Firecracker

- Firecracker requires Linux KVM and read/write access to `/dev/kvm`; CPU virtualization extensions must be exposed to the host.
- Production guidance requires more than launching the VMM: jailer, seccomp, resource limits, and host/guest kernel and microcode patching remain part of the security posture.
- Therefore a generic VPS or GitHub Actions VM cannot be assumed suitable. The exact deployment host must prove `/dev/kvm`, device permissions, CPU virtualization, and successful unprivileged/jailer startup before implementation is selected.

### Kata Containers

- Kata requires bare metal or a VM with nested virtualization enabled, with KVM available on each host for the standard Linux hypervisors.
- It is designed around a containerd/CRI integration and launches a lightweight VM for the workload.
- This is viable infrastructure, but disproportionate for the first AegisForge execution service unless the product later needs Kubernetes/CRI orchestration.

### gVisor

- The default `systrap` platform intercepts syscalls through seccomp and does not require hardware virtualization, making it more deployable inside an ordinary VM.
- The KVM platform requires virtualization support. The older ptrace platform is not the preferred path.
- gVisor still uses the host kernel and is not equivalent to a dedicated microVM boundary. Use only as an explicitly labelled lower-assurance tier, not as a silent substitute for Firecracker.

### GitHub Actions

- Standard `ubuntu-latest` runners are documented as fresh VMs, but the runner specification does not guarantee that nested virtualization or `/dev/kvm` is exposed to jobs.
- Do not infer KVM availability from the fact that the runner itself is a VM. A runner capability probe must establish it.
- The current CI workflow is protected by the release-gate scope discipline. Do not modify reserved workflows merely to experiment with virtualization.

## Candidate matrix

| Backend | Host requirement | Isolation boundary | Operational cost | Decision |
|---|---|---|---|---|
| Firecracker | Linux + KVM + `/dev/kvm`, CPU virtualization | Dedicated microVM | Medium/high | First production candidate; host proof required |
| Kata Containers | Bare metal or nested virtualization; usually KVM | VM per pod/container | High for current single-host MVP | Defer |
| gVisor systrap | Linux + compatible seccomp; no KVM required | Userspace kernel/syscall interception on shared host kernel | Medium | Lower-assurance fallback only |
| Docker hardening | Docker daemon and kernel | Namespaces/cgroups/seccomp on shared host kernel | Low | Prototype/dev only; not release boundary |
| Bubblewrap | Linux namespaces, user namespace policy | Same-kernel sandbox | Low | Fixed repository-owned fixture only |

## Mandatory host capability probe

Before choosing or installing a backend, run this read-only inventory on the actual intended execution host:

```bash
set -eu
printf '%s\\n' '== OS / kernel =='
uname -a
cat /etc/os-release
printf '%s\\n' '== CPU virtualization flags =='
grep -Eo '(vmx|svm)' /proc/cpuinfo | sort -u || true
printf '%s\\n' '== KVM device =='
if [ -e /dev/kvm ]; then
  ls -l /dev/kvm
  test -r /dev/kvm && echo readable || echo not-readable
  test -w /dev/kvm && echo writable || echo not-writable
else
  echo '/dev/kvm absent'
fi
printf '%s\\n' '== KVM modules =='
lsmod 2>/dev/null | grep -E '^(kvm|kvm_intel|kvm_amd) ' || true
printf '%s\\n' '== Container runtime =='
command -v docker || true
docker info --format '{{json .SecurityOptions}}' 2>/dev/null || true
printf '%s\\n' '== cgroup mode =='
stat -fc %T /sys/fs/cgroup 2>/dev/null || true
printf '%s\\n' '== User identity =='
id
```

This probe is inventory only. Do not load kernel modules, change permissions, install runtimes, or start a guest as part of discovery.

## Firecracker acceptance before any target execution

A backend is not accepted merely because the binary starts. The isolated runner must demonstrate, on the intended deployment host:

1. A disposable guest boots from pinned kernel/rootfs artifacts whose digests are recorded.
2. The guest receives only a read-only pinned source image and a separate bounded output channel.
3. No host credentials, Docker socket, SSH agent, cloud metadata route, wallet material, or host writable directory is visible.
4. Guest network is absent at the VMM/device and host-network layers; tests attempt DNS, loopback, RFC1918, link-local metadata, and public egress.
5. Resource caps cover vCPU, memory, disk, process count, wall time, and output bytes; timeout kills the VM and all associated processes.
6. Hostile guest tests cannot read a planted host canary or modify a planted host file.
7. Guest teardown removes scratch disks, tap devices, namespaces, and processes; failed cleanup is an INCOMPLETE result and blocks reuse.
8. A clean-runner adversarial acceptance report is exported and independently verified.
9. The runner API accepts only persisted task identity plus fixed adapter/profile enums. It never accepts caller-provided argv, executable path, env, mounts, or network policy.
10. Execution is bound to persisted Research Case, task, runtime round, and planned RoundSpec before provisioning.

Until every condition passes, the supported product execution path remains the repository-owned synthetic fixture. Docker reproduction remains an isolated, opt-in prototype. No arbitrary public repository code may execute.

## Implementation sequence

1. Inventory the actual intended host with the read-only probe above. Record the output as deployment evidence; do not guess from VPS marketing labels.
2. If KVM is present and usable, build a disposable Firecracker proof-of-isolation outside the main worker/API path. Pin VMM, kernel, rootfs, and jailer artifacts.
3. If KVM is unavailable, evaluate gVisor systrap only as a lower-assurance internal tier; do not lower the release gate.
4. Define a server-owned fixed-profile adapter contract and bind it to `admit_target_execution()` before any runner integration.
5. Add host-canary, network-denial, cleanup, timeout, and resource-exhaustion adversarial acceptance.
6. Only after acceptance, wire the runner into evidence persistence. Until then, no production entrypoint changes.

## Sources

- Firecracker production host setup: https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md
- Firecracker getting started / KVM prerequisites: https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md
- Kata installation hardware prerequisites: https://github.com/kata-containers/kata-containers/blob/main/docs/installation.md
- Kata virtualization architecture: https://kata-containers.github.io/kata-containers/design/virtualization/
- gVisor platform selection and systrap behavior: https://github.com/google/gvisor/blob/master/g3doc/architecture_guide/platforms.md
- GitHub-hosted runner specifications: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
