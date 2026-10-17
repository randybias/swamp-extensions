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
