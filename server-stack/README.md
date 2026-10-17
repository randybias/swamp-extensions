# @randybias/server-stack

[Swamp](https://github.com/swamp-club/swamp) workflows that build and tear down
a hardened single-node k0s host on a WireGuard mesh, running NATS, with its A
record published in Cloudflare DNS. The package ships **no models of its own**:
it composes the server, SSH, mesh, hardening, cluster and secret model types,
and every instance value arrives as a workflow input.

## Workflows

### `server-stack-provision-host`

Build a hardened k0s host running NATS on the mesh, then publish its DNS.

| Job       | Steps                                                                                                                          |
| --------- | ------------------------------------------------------------------------------------------------------------------------------ |
| preflight | check-inputs, probe-server, check-cloudflare-token, probe-record, refuse-existing                                              |
| host      | create, wait-ready, apply-base, join-mesh, verify-mesh, check-mesh                                                             |
| harden    | apply-firewall, verify-firewall, commit-firewall, lockdown, verify-lockdown, inspect-lockdown, check-lockdown, commit-lockdown |
| cluster   | install-k0s, wait-k0s, check-k0s, kubeconfig, check-kubeconfig, apply-namespaces, apply-secrets, apply-nats                    |
| verify    | probe-nats, check-nats                                                                                                         |
| publish   | create-record, check-record                                                                                                    |

### `server-stack-teardown-host`

Remove a provisioned host's DNS record, k0s cluster and server.

| Job      | Steps                                                                                                                                                              |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| teardown | check-inputs, sync-server, check-ownership, find-record, check-record, delete-record, reset-k0s, delete-server, verify-cherry, check-cherry, verify-dns, check-dns |

## Dependencies

The models the workflows call, installed alongside this package:
`@randybias/cherry-servers`, `@randybias/ssh-host`, `@randybias/wireguard-mesh`,
`@randybias/server-host`, `@randybias/k0s-cluster`, `@randybias/k8s-secret`,
`@swamp/cloudflare/dns` and `@webframp/cloudflare`. The control host that runs
the workflow must already be a mesh peer (or inside `management_cidrs`), and the
other mesh peers must already list the new node's public key.

## Install

```bash
swamp extension pull @randybias/server-stack
```

## Example

Secrets live only in the fixed vault `server-stack`; the inputs name vault keys,
never values. The example uses documentation addresses and `example.com`.

```yaml
# provision-host.yaml
hostname: host-1
ownership_tag: swamp-e2e=sp-20261017
server_model: cherry-server
project_id: 1001
plan: example-plan
region: example-region
image: example-image
cycle: hourly
tags: { swamp-e2e: sp-20261017 }
ssh_private_key_key: host-1-ssh-key
user_data_key: host-1-user-data
cloudflare_token_key: dns-edit-token
wg_private_key_key: host-1-wg-key
kubeconfig_key: host-1-kubeconfig
ssh_user: root
host_key_policy: strict
known_hosts: ["192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE"]
admin_user: ops
management_cidrs: ["192.0.2.0/24"]
allow_udp: [51820]
trusted_interfaces: [kube-bridge]
verify_timeout_s: 120
mesh_node: { name: host-1, address: 192.0.2.10/32, listen_port: 51820 }
mesh_peers: []
mesh_peers_allowlist: []
k0s_version: v1.31.2+k0s.0
k0s_binary_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
k0s_api_sans: ["192.0.2.10"]
k0s_pod_cidr: 198.51.100.0/24
k0s_service_cidr: 203.0.113.0/24
nats_chart: {
  chart: nats,
  repo: "https://example.com/charts",
  version: 1.0.0,
  namespace: nats,
}
cloudflare_zone_id: "00000000000000000000000000000000"
dns_record_name: host-1.example.com
dns_record_target: public
```

```bash
swamp workflow run @randybias/server-stack-provision-host --input-file provision-host.yaml
swamp workflow run @randybias/server-stack-teardown-host \
  --input hostname=host-1 --input confirm_hostname=host-1 \
  --input server_model=cherry-server --input project_id=1001 \
  --input ownership_tag=swamp-e2e=sp-20261017 \
  --input ssh_private_key_key=host-1-ssh-key --input ssh_user=root \
  --input host_key_policy=strict --input mesh_address=192.0.2.10/32 \
  --input cloudflare_zone_id=00000000000000000000000000000000 \
  --input dns_record_name=host-1.example.com \
  --input cloudflare_token_key=dns-edit-token
```

## NATS authentication (optional)

Set `nats_auth_token_key` to a key in the `server-stack` vault that holds the
token. The workflow writes it to Secret `nats-auth` (key `token`, override with
`nats_auth_secret`) in the chart namespace before installing the chart. The
chart values must read it from there; they hold a reference, never the token:

```yaml
nats_chart:
  values:
    container:
      env:
        NATS_TOKEN:
          valueFrom:
            secretKeyRef: { name: nats-auth, key: token }
    config:
      merge:
        authorization:
          token: << $NATS_TOKEN >>
```

Write the reference as `<< $NATS_TOKEN >>`: the chart renders it unquoted, which
NATS expands from the environment. A quoted `"$NATS_TOKEN"` is taken literally,
so the literal string would become the password. The token must be printable
ASCII.

The probe presents the token and then checks that an anonymous connection is
refused; the run fails if NATS does not enforce authentication. With the key
unset nothing changes: NATS stays unauthenticated and the original probe runs.

`mesh_handshake_wait_s` (default 60) bounds the wait for the first WireGuard
handshake after the node joins the mesh; `0` skips the wait.

## How it works

- `known_hosts` lines may be `<type> <key>` or `<host> <type> <key>`. A line
  without a host field is pinned for every address, so `host_key_policy: strict`
  works for a fresh host whose public address is unknown before it is ordered.
- With `publish_dns: false` the Cloudflare inputs (`cloudflare_zone_id`,
  `dns_record_name`, `cloudflare_token_key`) may be left out; with `true` all
  three are required.
- Every secret is resolved inside a step with
  `vault.get("server-stack", inputs.<key>)`. Workflow inputs are recorded, so a
  value never passes through one. Do not capture `--json` of a run that resolves
  the SSH key, WireGuard key or kubeconfig
  ([swamp lab 3555](https://swamp-club.com/lab/3555)).
- `apply_firewall` and `lockdown` arm a host-side revert before they change
  anything. The workflow commits each only after a fresh SSH connection over the
  mesh proves the host is still reachable; if it is not, the revert fires and
  the run fails.
- The admin kubeconfig is written straight to the vault key `kubeconfig_key`; it
  never passes through step outputs, logs or `--json`. Teardown leaves that
  vault key in place, a documented residual.
- DNS is created only after NATS answers over the mesh, and teardown removes DNS
  first so the name never points at a released address. Set `publish_dns: false`
  to skip every Cloudflare DNS step in both workflows, for example to prove NATS
  answers before a zone is chosen; the server teardown still proceeds because a
  step succeeds when DNS is disabled.
- The firewall owns its own nftables table and never flushes the whole ruleset,
  so a later re-apply does not wipe the cluster's CNI and kube-proxy rules. Its
  input and forward policies drop, so the CNI interface must be trusted:
  `trusted_interfaces` (default `[kube-bridge]`, k0s's kube-router bridge; use
  `cali*` and the like for another CNI) is passed to both firewall steps. This
  needs `@randybias/server-host` 2026.10.17.3 or later.
- A re-run never reopens public SSH: `apply-firewall` asks for SSH from anywhere
  only on a host that is not already locked down (the recorded exposure is read
  when `adopt` is set), and server-host itself refuses to replace a live
  management-only SSH rule with an open one.
- Every server-host step passes the provider server id as the record `identity`,
  and teardown runs `forget` for the host's public and mesh addresses once the
  server is gone. A rebuilt host that receives a deleted host's address
  therefore starts clean instead of inheriting its records. Records of the other
  models (`wireguard-mesh`, `k0s-cluster`) are keyed by node or by user and
  address and are overwritten by the next run.
- The API server binds the mesh address (`api_address`), and the kubeconfig the
  workflow stores points at it; the step's log line shows it.

## License

Apache-2.0.
