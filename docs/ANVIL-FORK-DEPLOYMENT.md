# Anvil fork deployment topology

This is a controlled deployment scaffold for the authenticated RPC path:

`Anvil -> Anvil RPC Adapter -> RPC Gateway -> approved RPC provider`

It is not a production-ready security boundary until the host egress firewall described below is installed, verified, and kept in sync with the provider's published IP ranges.

## Network boundaries

The Compose file uses the `gw_priority` network attribute to make `rpc-egress` the Gateway default route. Use Docker Compose v2.33.1 or newer; older Compose releases may ignore this routing selection and must not be used for this topology.

- Both Docker networks explicitly disable IPv6; the firewall installer intentionally manages IPv4 provider CIDRs only. `fork-internal` is a Docker internal network. Anvil and the Adapter are attached only to this network.
- The Gateway is attached to `fork-internal` and the separate `rpc-egress` bridge.
- No service publishes a host port. Do not add `ports:` to this Compose file.
- Anvil talks only to `http://anvil-rpc-adapter:8546`.
- The Adapter talks only to `http://rpc-gateway:8545/rpc` and injects the bearer token from its process environment.
- The Gateway is the only service with a Docker network attachment that can route externally.
- The fork block number is mandatory. Do not substitute `latest` or a moving block tag.
- The local Anvil fork chain ID is also explicit and mandatory. The validated execution plan supplies `AEGISFORGE_ANVIL_CHAIN_ID` and `AEGISFORGE_ANVIL_FORK_BLOCK_NUMBER`; keep provider URL and Gateway credentials in the separate deployment secret/configuration channel. Local fork transactions are simulation-only and do not authorize transactions to the upstream network.

## Critical egress limitation

Docker Compose does not enforce an approved-provider IP allowlist. In this scaffold, the Gateway's application layer validates an exact HTTPS hostname allowlist, resolves and pins public DNS answers, and verifies TLS hostnames. However, the `rpc-egress` bridge itself can route to arbitrary destinations unless the Docker host enforces an outbound firewall policy.

The egress bridge has inter-container communication disabled and a stable bridge name (`br-aegisforge`). Keep this network dedicated to the Gateway; do not attach diagnostic or utility containers to it. The firewall rules are scoped to packets entering or leaving this exact bridge: this is essential because the Gateway must still communicate with the Adapter over `fork-internal`. The rules match the Gateway private address and should be reviewed if either the bridge name or network topology changes.

Before running this topology with a real provider:

1. Configure the host firewall to permit Gateway-originated packets entering the host through `br-aegisforge` from `172.31.240.2` only to the provider's current, independently verified IPv4 CIDR ranges (the installer rejects prefixes broader than /16) on TCP/443.
2. Permit established provider replies leaving the host through `br-aegisforge` toward `172.31.240.2` only when their source is in the approved provider CIDRs. Drop other Gateway-originated or Gateway-destined forwarded traffic on that bridge. Traffic on `fork-internal` is intentionally outside these egress rules so Adapter-to-Gateway RPC remains functional.
3. Preserve DNS resolution only through the Docker embedded resolver / host resolver path required by the deployment. Do not give the Gateway unrestricted direct DNS egress.
4. Verify the effective rules against the actual Docker firewall backend (iptables-nft or native nftables), including Docker chain ordering and IPv6 behavior.
5. From each container, prove that Anvil and Adapter cannot reach an external test endpoint, that Gateway can reach the approved provider, and that Gateway cannot reach an unapproved public IP or port.
6. Re-run those checks after Docker, firewall, provider IP-range, or host-network changes.

Do not assume that a host firewall rule is active merely because a configuration file exists. The firewall must be loaded and its effective rules inspected. This repository scaffold intentionally does not install or mutate host firewall rules automatically.

## Isolated firewall packet-path regression test

Run the namespace-level packet-path test on a disposable Linux CI runner:

```sh
sudo apt-get install -y nftables iproute2
sudo python -m pytest -q tests/test_anvil_fork_egress_runtime.py
```

The test creates temporary network namespaces, installs the generated nftables table only inside its disposable router namespace, and checks approved HTTPS, denied destination IPs, denied non-HTTPS ports, Adapter-to-Gateway RPC, and Anvil-to-Adapter RPC. Adapter and Anvil receive default routes through the Gateway; their external connection attempts traverse the Gateway and are rejected by the router policy because their source addresses are not the approved Gateway address. It never applies rules to the host firewall.

This is a Linux forwarding-policy test using an interface named `br-aegisforge`; it is not yet a Docker Compose bridge runtime test. Docker bridge behavior, Docker firewall-chain ordering, DNS forwarding, and container-level Anvil/Adapter egress still require a separate disposable Docker integration run.

## Images and secrets

Copy `.env.example` to `.env`, replace every placeholder, and keep `.env` out of version control. Both image references must be immutable `@sha256:` digests. The Python sidecar image is built from the supplied Python digest; Foundry is pulled from its supplied digest.

The same high-entropy Gateway token is supplied to the Gateway and Adapter. It is never passed to Anvil arguments or fork headers. Rotate it when the deployment is rebuilt or access is suspected to have leaked.

## Start and inspect

From the repository root, first create the containers and networks without starting any service. Obtain provider IPv4 CIDRs from the provider documentation or support channel; do not guess or use broad internet ranges. Validate the firewall rules, apply them, and only then start the stack:

```sh
cp deploy/anvil-fork/.env.example deploy/anvil-fork/.env
# Edit deploy/anvil-fork/.env and replace every placeholder.
docker compose --env-file deploy/anvil-fork/.env -f deploy/anvil-fork/compose.yaml config
set -a
. deploy/anvil-fork/.env
set +a
docker build --build-arg PYTHON_IMAGE="$AEGISFORGE_PYTHON_IMAGE" -f deploy/anvil-fork/Dockerfile.rpc-sidecar -t aegisforge-rpc-sidecar:local .
docker compose --env-file deploy/anvil-fork/.env -f deploy/anvil-fork/compose.yaml create
sudo python3 deploy/anvil-fork/install_egress_firewall.py --provider-cidr <PROVIDER_IPV4_CIDR>
sudo python3 deploy/anvil-fork/install_egress_firewall.py --provider-cidr <PROVIDER_IPV4_CIDR> --apply
docker compose --env-file deploy/anvil-fork/.env -f deploy/anvil-fork/compose.yaml start
docker compose --env-file deploy/anvil-fork/.env -f deploy/anvil-fork/compose.yaml ps
```

This guide does not authorize running the stack on a production server. Validate it in a disposable test host first. Do not expose Anvil or Adapter ports to the host or internet. Repeat `--provider-cidr` for every current provider IPv4 range. The installer validates syntax by default and changes no firewall state without `--apply`. The ruleset is not persistent across reboot; configure and test host-native persistence before production. To remove only this dedicated table, run `sudo python3 deploy/anvil-fork/install_egress_firewall.py --remove`.

## Evidence status

A running container is not proof of a safe egress boundary or a verified vulnerability. This topology does not by itself connect the synthetic Anvil runner to SecurityChecker findings. Keep `dynamic_verified=false` and `confirmed=false` until a finding-specific, hash-pinned fork execution produces validated evidence through the SecurityChecker pipeline.


## Preparation-only runtime orchestration

`agents.security_checker.fork_runtime_orchestrator.prepare_fork_runtime()` validates the snapshot-bound execution plan, exact HTTPS provider-host allowlist, Gateway bearer-token shape, and immutable Foundry image reference. It returns a frozen `PREPARED` description and a minimal Compose environment containing only the fork chain ID, pinned block number, and Foundry image digest.

The preparation result deliberately does not retain the provider URL or bearer token. It names the three secret inputs that a future runtime launcher must supply through a separate secret channel. Do not serialize secret values into the execution plan, preparation result, logs, or Anvil command line.

This orchestrator is preparation-only: it does not invoke Docker or Compose, create files, start containers, execute transactions, or validate the effective host firewall. A `PREPARED` result is not execution evidence. Keep `runtime_started=false`, `dynamic_verified=false`, and `confirmed=false`; do not promote a finding based on preparation or synthetic test fixtures.
