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
  `check-kubeconfig` asserts a `:6443` URL exists (the stored record masks the
  host, so the log line `server https://<mesh>:6443` is the evidence of the
  address).
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

## 2026.10.17.3 (adopt re-run)

- The first adopt re-run re-applied `allow_ssh_from_anywhere: true` before
  lockdown closed it again, re-exposing public SSH for about 20 seconds on a
  locked-down host. `apply-firewall` now passes `allow_ssh_from_anywhere` from
  the recorded exposure when adopting (a locked-down host gets the management
  ruleset, which server-host finds already live), and server-host 2026.10.17.3
  refuses to widen on its own regardless of the workflow.
- A rebuilt server that received a deleted server's address inherited its
  server-host records, so `apply_base` did nothing. Every server-host step now
  passes the Cherry server id as `identity`, and teardown calls `forget` for the
  public and mesh addresses after the server is verified gone.
- Adopting still re-runs `apply-base` through the mesh address under a separate
  record from the public address used on the first run; its steps are
  idempotent.

## Preparing the first long-lived host

- `publish_dns: false` could not be used with the Cloudflare inputs left out:
  `cloudflare_token_key`, `cloudflare_zone_id` and `dns_record_name` were
  required. They are optional now (default empty) and `check-inputs` requires
  all three when `publish_dns` is true; teardown has the same rule.
- A `known_hosts` line without a host field worked for the Cherry readiness wait
  but broke `join-mesh` and `verify-mesh`, which read fixed positions. They now
  read the last two fields, so `<type> <key>` pins every address and `strict`
  works for a host whose public address is unknown before it is ordered. Checked
  by evaluating the expression in a workflow assert for both shapes.

## Live e2e 2026-10-17 (run sp-20261017)

Folded from the maintainer's acceptance receipts. Real addresses, hostnames, DNS
names and provider ids are redacted: `<stack1>` and `<stack2>` are throwaway
Cherry VPS hosts (Ubuntu 24.04, hourly), `<mesh-hub>` the WireGuard hub,
`<control>` the control host (joined through a temporary interface, removed
afterwards), `<outside>` the outside probe source, `<zone>` the test DNS zone.
Every model was installed from local sources, never the registry. Provider
snapshots before and after each teardown were identical (Cherry project servers,
`<zone>` records: ids, names, types, contents).

| Part | Heads                                     | Cells               | Result                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---- | ----------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | server-stack 2b09a5b, server-host 0cfe601 | 13 pass, 2 fail, 15 | bad Cloudflare token stops in preflight; steps 1-16 pass; wait-k0s failed (server-host drop policies cut off the pods) and passed only with a manual firewall workaround; NATS over the mesh, not on the public address; refuse without adopt; adopt no-dup; wrong k0s sha256 refused with nothing changed; teardown twice. FAIL: apply-nats always skipped                                                              |
| 3    | 8d77d02 then a988fa5, server-host cec6bfd | 14 pass, 3 fail, 17 | no manual rule: k0s Ready in 1m22s, kubeconfig on the mesh address, apply-nats runs, NATS INFO + PING over the mesh, public 22/4222/6443/8222/10250 closed from `<outside>`, DNS create/verify, teardown twice. FAIL: a stale record for a reused address (apply-base 0 steps); a too-strict harness assertion on the kubeconfig URL (the record masks the host; relaxed in a988fa5); adopt re-opened SSH for about 20 s |
| 4    | e8aad54, server-host fd3716d              | 8 pass, 0 fail, 8   | below                                                                                                                                                                                                                                                                                                                                                                                                                    |

Part 4 on `<stack2>` (fresh):

| Cell                                                  | Result | Detail                                                                                                                                                                                                |
| ----------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| fresh provision, one uninterrupted run, no workaround | PASS   | 8m55s: order, wait-ready, apply-base, mesh handshake, firewall + lockdown committed, k0s Ready in 1m20s, kubeconfig on the mesh, apply-nats, NATS INFO + PING over the mesh, DNS created and verified |
| adopt: no second server, no second record             | PASS   | `Ensuring server`, no order; `skipped create-record`; one record found                                                                                                                                |
| adopt: firewall and lockdown are no-ops               | PASS   | `ruleset already live, no-op` for both; commit-firewall and commit-lockdown skipped                                                                                                                   |
| adopt never reopens public SSH                        | PASS   | `<outside>` probed public :22 once a second for the whole run: 57 probes, 0 open                                                                                                                      |
| adopt: NATS still answers, k0s still Ready            | PASS   | probe-nats, check-nats, wait-k0s                                                                                                                                                                      |
| teardown forgets the server-host records              | PASS   | forget-public-record and forget-mesh-record run after check-cherry; both records hold only `host, forgotten_at, observed_at`                                                                          |
| teardown proof against the providers                  | PASS   | DNS record deleted, k0s reset, server deleted; Cherry and `<zone>` counts equal the before snapshots                                                                                                  |
| teardown again                                        | PASS   | delete-record, reset-k0s, delete-server skipped; verify steps pass                                                                                                                                    |

bbfb279 (optional DNS inputs with `publish_dns: false`, host-agnostic
known_hosts lines) was reviewed clean and checked by workflow asserts; it was
not run live.

Residuals on 2026.10.17.3 (beta):

- MEDIUM: the mesh steps accept a bare `<type> <key>` known_hosts line with no
  host field, which pins that key for every address.
- The known_hosts input description still describes the host-field form.
- DNS checks read only `records[0]`; with two A records for the name the second
  is not checked.
- A wedged NATS Helm release needs the manual recovery above.
