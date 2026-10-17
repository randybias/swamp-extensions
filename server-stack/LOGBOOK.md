# Maintainer logbook

Not packaged. Notes for whoever maintains this package.

## Shape

`@randybias/server-stack` is workflows-only. It declares no models; each step
references another extension's model type: `@randybias/cherry-servers/servers`
(by the `server_model` definition name), `@randybias/ssh-host`,
`@randybias/wireguard-mesh`, `@randybias/server-host`, `@randybias/k0s-cluster`,
`@randybias/k8s-secret`, `@swamp/cloudflare/dns/dns-records` and
`@webframp/cloudflare/zone`.

## Decisions

- Vault is the fixed generic name `server-stack`; every secret is read with
  `vault.get("server-stack", inputs.<key>)`. Keys are per instance, for example
  `<hostname>-kubeconfig`. Teardown leaves the kubeconfig key behind: there is
  no workflow step that deletes a vault key. Documented residual.
- Host-key bootstrap uses the recorded readiness keys from `cherry-servers`
  `wait_ready` as strict pins for every later SSH step. `insecure_tofu` is never
  used.
- Lockdown order is
  `apply_base -> apply_firewall -> wireguard-mesh apply ->
  lockdown -> fresh-connection verify -> commit`.
  A commit is never reached before the fresh reachability check; a failure lets
  the armed revert fire.
- DNS: `@webframp/cloudflare/zone` `get` proves the token, then
  `@webframp/cloudflare/dns` `list` returns the matching records (empty means
  absent, never an error). The first-party dns-records `lookup` throws
  identically on absence and on errors, so it is not used. DNS is created only
  after the host passes its verify steps, and only when the list was empty.
- Teardown lists the project (no allowFailure: an auth or network error fails
  closed), removes DNS first, resets k0s, deletes the server, then proves via
  the Cherry and Cloudflare APIs that nothing remains. It does not edit peer
  entries on other mesh members; pre-registering the node's public key is a
  precondition outside this workflow.

## Open items for the live e2e

- `@webframp/cloudflare/zone` stands in for the token check because no
  first-party `@swamp/cloudflare` zone model exists.
- `cluster_secrets` maps each `data` key to a vault key; resolving an input map
  of vault keys into a map of values inside one expression is the fragile part
  and must be proven live.
- The step-output contract (`steps["<step>"].outputs.*`) and the stored resource
  names used by the asserts need confirmation against the merged extensions.
- `@randybias/wireguard-mesh` must accept `ssh.host_keys` in the same
  ssh-keyscan string form as the other models once the canonical transport is
  vendored.

## Reviews

- Round 1 (f-server-stack-auto): fixed. Steps run in parallel inside a job, so
  every ordering is now an explicit `dependsOn`; guards are wrapped and their
  polarity corrected; DNS absence uses `@webframp/cloudflare/dns` `list` (empty
  records), never an error; teardown is re-runnable; args and outputs aligned to
  the current heads (wireguard `host_keys` objects, server-host revert `token`
  resource, cherry `deleted`/`not_found` and map tags).
- Scratch runs (fake inputs, real models), receipts:
  - provision with a failing `check-inputs` and then a failing `probe-server`:
    both times every downstream step was `skipped`; no sibling ran in parallel.
  - teardown in a fresh repo: `check-inputs` passed, `sync-server` failed
    (allowed), `check-ownership` passed on the missing server, `find-record`
    failed at the missing vault, and every delete/reset step skipped. The safety
    gate held and the run was re-runnable.
  - a control workflow: a truthy guard skips, a falsy guard runs, and
    `or [succeeded, skipped]` runs after a guard-skip but not after a failure.
- Both workflows pass `swamp workflow validate` with the real model types.

## Known limitations for the live run

- `check-mesh` asserts a handshake exists; `mesh_handshake_max_age_s` cannot be
  evaluated because swamp CEL has no clock function (`now()` is unsupported).
- `check-kubeconfig` only asserts the server URL is present: the k0s model sets
  no `api.address`, so k0s advertises the default-route address, not the mesh.
- `cluster_secrets` data values are vault keys; resolving a dynamic key map in
  CEL is not supported, so this needs a model-side vault-key map or a per-key
  shape confirmed with the k8s-secret lane.
- `@webframp/cloudflare` stands in for the first-party dns-records model because
  its `lookup` throws identically on absence and on errors; `list` returns
  empty.

## 2026.10.17.2 (first live run, fixes)

Found by the first end-to-end run on a throwaway host (the receipts are in the
maintainer's e2e repo):

- The firewall's drop policies cut off a k0s node's pods; both firewall steps
  now pass `trusted_interfaces` (server-host 2026.10.17.2).
- `probe-nats` passed `NATS_PORT` as a number (the command model wants a string)
  and its timeout in seconds (the model takes milliseconds); both fixed.
- The stored kubeconfig pointed at the node's public address. `api_address` is
  now the mesh address for `install`, `apply_helm` and `kubeconfig`, and
  `check-kubeconfig` asserts the URL is `https://<mesh>:6443`.
- `apply-nats` was skipped in every run: a step that depends on a `forEach` step
  with nothing to iterate gets no state from it, so even
  `or[succeeded, skipped]` never matched. `apply-nats` now has no dependency on
  `apply-secrets` and runs when there are no secrets; `apply-nats-after-secrets`
  waits for `apply-secrets` to have succeeded and runs when there are. No safety
  gate uses `skipped`.
- A fresh host cannot use `host_key_policy: strict` for the Cherry readiness
  wait: `wait_ready` matches the known_hosts host field against the public IP,
  which is unknown before the order. Use `accept-new` for that step only; every
  later step is strict against host keys pre-generated into the cloud-init user
  data.

### Known issue: a wedged NATS Helm release

If the chart's first install never becomes Ready (here: NATS bound only to the
mesh address while the kubelet probed the node address) and its values are then
changed, the k0s Helm controller stays at
`can't install loadedChart nats: cannot re-use a name that is still in use`, and
`apply_helm` times out with the release `uninstalling`. Changing the values
again does not help. Recovery on the node, as root, using only what the chart
created:

```
k0s kubectl -n nats delete statefulset/nats --wait=false
k0s kubectl -n nats delete secret/sh.helm.release.v1.nats.v1
k0s kubectl -n kube-system patch chart.helm.k0sproject.io k0s-addon-chart-nats \
  --type=merge -p '{"metadata":{"finalizers":null}}'
systemctl restart k0scontroller
```

The Chart object is recreated from `k0s.yaml` within a minute and installs with
the current values. Avoid it by getting the values right before the first
install: `config.merge: {host: <mesh address>, http: "0.0.0.0:8222"}` with
`hostNetwork`, because the firewall still blocks 8222 from outside.
