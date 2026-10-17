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
- DNS: a cheap authenticated Cloudflare read (`@webframp/cloudflare/zone` `get`)
  runs before the record lookup, so a token failure is distinguishable from an
  absent record. `lookup` first; an existing record with the same content is
  adopted, different content is refused unless `adopt_dns` is true; DNS is never
  created before the host passes its verify steps.
- Teardown removes DNS first, resets k0s, deletes the server, then proves via
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

- Offline: both workflows pass `swamp workflow validate` with the model types
  installed (`@randybias/server-host`, `wireguard-mesh`, `ssh-host`,
  `k0s-cluster`, `k8s-secret`, `cherry-servers`, `@swamp/cloudflare/dns`,
  `@webframp/cloudflare`); step inputs were checked against the real schemas.
- None recorded yet from a code review panel.
