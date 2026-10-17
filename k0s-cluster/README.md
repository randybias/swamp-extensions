# @randybias/k0s-cluster

[Swamp](https://github.com/swamp-club/swamp) extension for installing and
operating a [k0s](https://docs.k0sproject.io) Kubernetes cluster on a Linux host
over SSH. It installs a SHA-256-pinned k0s binary, renders a deterministic
`k0s.yaml`, waits for the node and system pods to become ready, stores the admin
kubeconfig as a vault secret, and reconciles manifest stacks and Helm charts.

## Models

### `@randybias/k0s-cluster`

One definition serves any host. Every method takes the SSH target and the
cluster inputs as arguments, and state is keyed by user, host and port, so a
single definition can drive a fleet and `host:22` never shares a record with
`host:2222`. With `insecure_tofu` the host keys are read once, recorded, and
every later connection is pinned to them; if a host is rebuilt, supply
`host_keys` or delete the recorded keys.

| Method            | Description                                                                       |
| ----------------- | --------------------------------------------------------------------------------- |
| `render_config`   | Render the deterministic `k0s.yaml` for the given inputs (read-only)              |
| `install`         | Verify, upload and install the pinned binary and role, then start the service     |
| `wait_ready`      | Poll until a node is Ready and kube-system pods are running                       |
| `kubeconfig`      | Fetch the admin kubeconfig into a sensitive value or a vault key you name         |
| `apply_manifests` | Place a named manifest stack under the k0s manifest directory; remove stale files |
| `apply_helm`      | Reconcile the declared Helm extensions in `k0s.yaml`                              |
| `get`             | Read the k0s version, node status, stacks and Helm releases (read-only)           |
| `sync`            | Compare the recorded install with the host and report drift (read-only)           |
| `reset`           | DESTRUCTIVE: stop and uninstall k0s and remove its configuration                  |

## Dependencies

- A Linux host reachable over SSH by a user that can install systemd services
  (typically `root`), with `base64`, `find`, `mktemp`, `sha256sum` and
  `systemctl`.
- An SSH private key. It is delivered to a short-lived `ssh-agent` over stdin
  and never appears on a command line.
- A pinned k0s version and the SHA-256 of its release binary. `install` refuses
  to install a binary whose digest does not match, and re-verifies the installed
  binary and version before adopting a running service.
- `pod_cidr` and `service_cidr` are required; there are no baked-in defaults.

## Install

```bash
swamp extension pull @randybias/k0s-cluster
```

## Example

Put the inputs in a file so the private key never reaches the command line. The
key stays a vault reference; swamp resolves it at run time and never prints it.

```yaml
# args.yaml — keep this file out of version control
ssh:
  host: 192.0.2.10
  user: root
  port: 22
  host_key_policy: insecure_tofu
  connect_timeout_s: 15
  private_key: ${{ vault.get("default", "K0S_SSH_KEY") }}
k0s_version: "v1.31.2+k0s.0"
k0s_binary_sha256: "<64 hexadecimal characters>"
role: single
cluster_name: k0s-lab
api_sans: ["192.0.2.10", "k8s.example.com"]
pod_cidr: 192.0.2.0/24
service_cidr: 198.51.100.0/24
```

The pod and service CIDRs above are documentation placeholders; replace them
with the cluster's network plan.

```bash
# One definition, two hosts: run the same method with each host's inputs.
for host in 192.0.2.10 198.51.100.20; do
  swamp behavior run @randybias/k0s-cluster install k0s-host \
    --input-file "args-${host}.yaml"
done

swamp behavior run @randybias/k0s-cluster wait_ready k0s-host \
  --input-file args-192.0.2.10.yaml
swamp behavior run @randybias/k0s-cluster kubeconfig k0s-host \
  --input-file args-192.0.2.10.yaml
```

Do not add `--json` to a run that carries the SSH key or the kubeconfig: the CLI
echoes method arguments, including sensitive ones, in that output
([swamp-club lab 3555](https://swamp-club.com/lab/3555)). The kubeconfig is
written to the configured vault, not to stdout; read it from the vault, and
never from a captured `--json`. To choose the vault and key yourself, pass
`store_in_vault` (`vault` and `key`); the kubeconfig is then written only there,
and a later step reads it with a `vault.get(...)` reference.

Set `api_address` to the private or mesh address to keep the API off the public
one: it is written to `spec.api.address`, always added to the certificate SANs,
and passing the same `api_address` (and `api_port`) to `kubeconfig` builds the
returned and stored kubeconfig's server URL from it.

A strict host-key policy pins the expected keys and requires them:

```yaml
ssh:
  host: 192.0.2.10
  user: root
  host_key_policy: strict
  host_keys:
    - "192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
  private_key: ${{ vault.get("default", "K0S_SSH_KEY") }}
```

A manifest stack is a set of files k0s applies from its manifest directory.
`apply_manifests` is idempotent: unchanged files are not uploaded, and files no
longer declared are removed.

```yaml
ssh:
  host: 192.0.2.10
  user: root
  host_key_policy: insecure_tofu
  private_key: ${{ vault.get("default", "K0S_SSH_KEY") }}
stack:
  name: example
  files:
    - path: namespace.yaml
      content: |
        apiVersion: v1
        kind: Namespace
        metadata:
          name: example
```

Manifest content may carry Kubernetes Secret data, so it is treated as sensitive
and never logged; use a vault-backed Secret rather than a literal in the
manifest where possible.

## How it works

- `render_config` writes `k0s.yaml` with the API port and SANs, the pod and
  service CIDRs, the datastore type, telemetry, and any Helm repositories and
  charts. OpenAPI version `k0s.k0sproject.io/v1beta1`. Helm values often carry
  passwords, so a render that includes them is neither stored nor returned:
  callers get a redacted copy and `values_redacted: true`.
- `install` downloads the release artifact for `k0s_version` and the host's
  architecture (`uname -m`), verifies `k0s_binary_sha256` **before** anything is
  executed, uploads the binary and `k0s.yaml`, runs `k0s install` and starts the
  systemd unit. A release or chart URL may not carry user info, a query or a
  fragment; a private mirror's token comes from `k0s_download_token` (a vault
  reference) or `K0S_DOWNLOAD_TOKEN` and is sent as an `Authorization` header. A
  re-run re-verifies the installed binary digest and version, then adopts the
  active service and never installs a second node. Role `worker` requires a
  `join_token`, written to a root-only token file. An installed role is never
  replaced by another (`single` and `controller` count as different roles even
  though they share one unit): set `confirm_role_change` to the host name to
  stop and reset the old role, which is irreversible and happens only after the
  replacement binary has been downloaded and verified. Config, token and
  manifest uploads are mode 0600.
- `wait_ready` returns `ready: false` after `ready_timeout_s`; a connection,
  authentication or host-key failure is raised instead, because it is not the
  same as a cluster that has not finished starting. `get` and `sync` reflect
  real cluster state and write nothing when the host cannot be reached.
- `reset` is declared an action, not a model `delete`, because one definition
  holds many hosts; it verifies that `k0s stop`, `k0s reset` and the config
  removal all succeed before recording the host as reset, and is a clean no-op
  on a host with no k0s unit.
- Every caller-supplied value that reaches the remote shell is validated against
  an allowlist grammar and quoted as a single argv element; remote exit codes
  are returned as data, except a local `ssh` failure (exit 255), which is raised
  as an error. Remote error text is never reflected into messages.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
