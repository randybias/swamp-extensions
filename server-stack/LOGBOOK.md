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

## 2026.10.17.4 (handshake wait, optional NATS auth)

- `check-mesh` ran 2 s after the join, before the first WireGuard handshake
  (found on the ops1 run). A new `wait-mesh` step first tries a TCP connection
  to the mesh address every 2 s for up to `mesh_handshake_wait_s` (default 60, 0
  skips the step). Traffic makes WireGuard handshake at once; a control host
  that is not a peer just waits out the bound for the peer's keepalive. The step
  never fails: `check-mesh` stays the gate. `verify-mesh` names `join-mesh` as
  well, so a skipped wait cannot stand in for a failed join.
- Optional NATS auth: `nats_auth_token_key` (a key in the `server-stack` vault)
  writes Secret `nats_auth_secret` (default `nats-auth`, key `token`) into the
  chart namespace, through `k0s-cluster` `apply_manifests` on the host (the live
  run found that the first version, `k8s-secret` from the control host, hangs:
  the firewall opens no 6443 to it; the dormant `cluster_secrets` path has the
  same flaw), before the chart is installed. `check-nats-token` first checks the
  token shape in a shell (asserts cannot read the vault), because the token is
  placed in a double-quoted YAML scalar and CEL has no escaping function, and
  `probe-nats-auth` presents the token (env only, never argv) and then proves an
  anonymous connection is refused; `check-nats` requires `auth_required`, a
  `+OK` and the refusal. Unset, the four new auth steps are guarded off and the
  original `probe-nats` runs unchanged.
- Why the chart values are not generated: swamp CEL has no map merge and
  `string(map)` fails, so the workflow cannot add the token reference to the
  operator's `nats_chart.values`. The operator adds a reference (not the secret)
  as in the README; a missing reference is caught because the probe then sees no
  `auth_required`. The reference must be the chart's unquoted
  `<< $NATS_TOKEN >>`: a quoted `"$NATS_TOKEN"` is a literal password to NATS
  (review finding). The README values are rendered with `helm template` and run
  through nats in `probes_test.ts`.
- `vault.get(...)` is resolved before a ternary picks a branch, so an optional
  secret needs a guarded step (as here), never `cond ? "" : vault.get(...)`.
- The probe script's replies end in `\r`: assert on `"\n+OK"`, not `"\n+OK\n"`
  (found by running the script against a real NATS server in the test).
- Live (throwaway host, auth on, README values): `check-mesh` passed on the
  first run; the token never appeared in 700k local and 60k remote argv samples,
  run logs or any file of the repo; adopt re-run was a no-op (manifests and Helm
  `changed false`, firewall and lockdown already live).
- The probe test's flake was real, not a test race: `<< $NATS_TOKEN >>` makes
  NATS parse the env value as a config value, so a random token that looks like
  a number, an exponent or a date (a UUID or hex string starting with digits)
  fails the server start
  (`variable reference for 'NATS_TOKEN' ... could not be parsed`).
  `check-nats-token` now requires a leading letter (all such letter-first shapes
  were verified to start). Also fixed in the tests: docker-assigned ports,
  polling for the port mapping and the INFO line instead of a fixed sleep.
- Not done: TLS (server cert handling needs its own design), token rotation
  (re-running with a new vault value rewrites the Secret; the pods need a roll).

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
- Review residuals (filed High on e8aad54, downgraded at triage): teardown's
  `project_id` input is declared but unused (the server definition carries its
  own project and the ownership tag is checked before delete); `mesh_address`
  for the k0s reset is operator input not bound to the owned server (strict pins
  and `confirm_host` still apply); `cluster_secrets` must be empty, so its
  forwarding branch is dormant; `nats_chart.values` is unconstrained.

## Live e2e 2026-10-17, 2026.10.17.4 (run sp-20261017)

A fresh throwaway Cherry VPS (`<stack3>`), end to end with NATS auth on and the
README chart values: 13 of 15 cells passed. Addresses, hostnames, DNS names and
provider ids are redacted. The two failures:

| Cell                     | Result | Disposition                                                                                                                                                              |
| ------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| NATS auth Secret written | FAIL   | written with `k8s-secret` from the control host, which cannot reach 6443. Fixed in c7a115e: the Secret is written on the host through `k0s-cluster` `apply_manifests`    |
| teardown `reset-k0s`     | FAIL   | not server-stack's: the published `k0s-cluster` 2026.10.17.2 reset rebuilds the vault key from the masked host in its stored record. Fixed in `k0s-cluster` 2026.10.17.3 |

Merge prep (quality pass a493a21): `nats_chart.namespace` takes the DNS-1123
pattern of `cluster_namespaces`, and `check-inputs` requires it to be listed
there when NATS auth is on (a test evaluates the real expression with cel-js);
the README says `cluster_secrets` is disabled because the control host cannot
reach 6443.

Residuals on 2026.10.17.4 (beta):

- **Teardown needs `k0s-cluster` 2026.10.17.3.** `reset-k0s` depends on its
  reset fix; until 2026.10.17.3 is published, teardown fails at `reset-k0s` on
  the published 2026.10.17.2 and the server is not deleted. The README says so
  under the teardown workflow.
- TLS and token rotation are not done (a new vault value rewrites the Secret,
  but the NATS pods need a roll).
- `wait-mesh`'s give-up path (no handshake within `mesh_handshake_wait_s`) was
  tested offline only, against closed and black-holed ports.
- The NATS token must be 16-256 printable characters from `[A-Za-z0-9._~+=-]`;
  `check-nats-token` refuses anything else before it reaches a manifest.
