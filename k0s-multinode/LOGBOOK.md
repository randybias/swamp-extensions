# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

## Scope

Cluster-scope work for a multi-node k0s cluster, orchestrated over SSH through a
controller; per-node work is `@randybias/k0s-cluster`. Token values live only in
memory and a caller-named vault key; state and output carry token IDs and expiry
only.

## Decisions for Randy review

- **`k0s-cluster` gaps.** `k0s-cluster` 2026.10.17.2 shipped `join_token` and
  `api_address`, but not the other changes this spec's §2 requires: an `upgrade`
  action, a `controller_worker` role with `no_taints`, `api.externalAddress`,
  `network.nodeLocalLoadBalancing` and `network.controlPlaneLoadBalancing`. The
  join/drain/detach/upgrade methods and workflows here cannot be wired until
  those land. This first commit ships the pure planner and the state it writes;
  the action methods follow the `k0s-cluster` MICRO bump.
- **HA endpoint on VPS.** The spec's open question: default `node_local_lb` plus
  an admin kubeconfig pointed at one controller or a DNS name over all three,
  versus requiring an external TCP load balancer. `plan` currently only requires
  _some_ endpoint (`ha_mode` or `external_address`) when there is more than one
  controller, and does not pick one.
- **`cplb_vip`.** Kept reachable in the grammar but expected `blocked` on most
  VPS providers (VRRP needs L2 adjacency); no code assumes it works.
- **k0sctl wrapper.** Followed the spec: not wrapped; a documented fallback
  only.

## Plan operation inference

`plan` infers the operation: a `target_version` means upgrade, a non-empty
`observed` means add, otherwise create. `plan_remove` is separate because it
names the node to remove. If this proves surprising, make the operation an
explicit input.

## Tests

- `_lib/plan_test.ts` covers create (1+2), HA (3 controllers), even-count
  rejection, duplicate names/addresses, upgrade ordering and the downgrade/skip
  refusals, the quorum refusal on a controller detach, and the last-controller
  refusal.

## Cluster-scope methods (17.3 dependency landed)

`@randybias/k0s-cluster` 2026.10.17.3 (head a101b99) supplies every per-node
feature §2 required, so the action and read methods are now wired. The shared
`_lib` (`grammar.ts`, `k0s.ts`, `transport.ts`, `ssh.ts`) is vendored from that
head byte-identically; `_lib/cluster.ts` adds only cluster-scope argv builders
and output parsers.

- `mint_join_token` refuses before any remote call when no vault service is
  exposed, writes the token to the caller-named key and stores only the ID, role
  and expiry. The ID is the diff of `k0s token list`, falling back to the
  token's own `<id>.<secret>` prefix.
- `invalidate_join_token` overwrites the key with a fixed tombstone and is a
  no-op for an unknown or expired ID.
- `detach_node` runs `k0s etcd leave --peer-address` (derived from
  `etcd member-list` when not passed) plus a ControlNode delete for a
  controller, a Node delete for a worker, and refuses an undrained node or a
  3->2 / 2->1 controller removal without `confirm`.
- `get`/`sync` write `status`, keyed `<cluster>-status`; `sync` compares the
  `plan` record against the live nodes and etcd members. Resource instances are
  named `<cluster>` (plan), `<cluster>-status`, `<cluster>-tokens` because
  `readResource` keys on the instance name, not the spec name.

Tests (`cluster_test.ts`, `k0s_multinode_test.ts`) cover the parsers, the argv
builders, the vault refusals, the drain PDB block, the detach refusals and the
`sync` drift. 26 pass offline. Workflows and their `swamp workflow validate`
runs are the next slice.

## Review round 1 (HEAD 8f531eb) — fixed

Checked against the real k0s v1.36.4 binary in a container.

- `k0s token create` prints a base64 gzipped kubeconfig, not `id.secret`.
  `joinTokenIdFromCreate()` now base64-decodes, gunzips and reads
  `users[].user.token`, returning the id only if it matches `^[a-z0-9]{6}$`;
  mint corroborates it against the token-list diff and invalidates the token on
  any doubt or on a later failure, so a secret can never be mistaken for an id.
- `k0s token list` refuses a role-less call, so listing is now per role and the
  two lists are merged. The JSON branch of the parser is dropped (table only).
- `k0s etcd member-list` maps each name to its peer-URL string; the parser now
  reads that shape.
- Node names in wait/drain/uncordon/detach/plan_remove use the DNS-1123
  subdomain grammar (exported once from plan.ts), closing the argv-injection
  path where `-lkubernetes.io/os=linux` cordoned every node.
- Controller-ness is taken from the etcd member list and the ControlNode, not
  the Node label: a dedicated controller (no Node) is waited for and detached
  correctly, and a worker that is an etcd member is refused.
- `insecure_tofu` is dropped (strict only, `host_keys` required); no first-seen
  key was ever learned or persisted.
- `kind: "action"` is set on mint/invalidate/drain/uncordon/detach.
- `plan_remove` parses its extended schema (was failing "Unrecognized key").
- The last-controller refusal counts controllers, so 1 controller + workers
  cannot remove the only controller even with confirm.
- external_lb/cplb_vip now require external_address.
- detach is retry-safe (absent member is already left), refuses a peer_address
  that is not the named member's, refuses to run through the leaving node's own
  host, and requires no non-DaemonSet pods unless confirm.
- invalidate uses run() and marks invalidated_at only on success.
- ClusterCommandError reports stderr only, never stdout (token commands).
- The unused vendored grammar.ts and k0s.ts are removed; `ok` is local.
- create-cluster workflow added (per-node mint -> install -> wait -> invalidate
  with `dependsOn completed`), plus a structural test.

## Review round 1 — deferred (recorded)

- `render_config` (spec §4) is not implemented; the vendored renderer was
  removed with k0s.ts. It returns when sync's config-sha drift check is added.
- The other four workflows (add-node, remove-node, upgrade-cluster,
  reset-cluster) are the next slice.
- `sync` has no config-sha drift check and `get` has no etcd health.
- No dedicated §7.4 regression test greps state, logs and results for token- or
  kubeconfig-shaped text; the mint test covers the mint path only.
- `swamp workflow validate` could not run locally: the CLI only loads
  extension-shipped workflows once the extension is installed, and it is
  unpublished (release.yaml `ci: false`). It runs before the first live cell.

## Prior art

No prior k0s/k0sctl/etcd/multinode swamp extension found on stable or beta; the
only near neighbour is `@dataverket/talosctl`, which targets Talos, a different
distribution.
