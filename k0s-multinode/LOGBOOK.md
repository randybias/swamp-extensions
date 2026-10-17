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
  and expiry. The ID is the diff of `k0s token list`, falling back to the token's
  own `<id>.<secret>` prefix.
- `invalidate_join_token` overwrites the key with a fixed tombstone and is a
  no-op for an unknown or expired ID.
- `detach_node` runs `k0s etcd leave --peer-address` (derived from
  `etcd member-list` when not passed) plus a ControlNode delete for a controller,
  a Node delete for a worker, and refuses an undrained node or a 3->2 / 2->1
  controller removal without `confirm`.
- `get`/`sync` write `status`, keyed `<cluster>-status`; `sync` compares the
  `plan` record against the live nodes and etcd members. Resource instances are
  named `<cluster>` (plan), `<cluster>-status`, `<cluster>-tokens` because
  `readResource` keys on the instance name, not the spec name.

Tests (`cluster_test.ts`, `k0s_multinode_test.ts`) cover the parsers, the argv
builders, the vault refusals, the drain PDB block, the detach refusals and the
`sync` drift. 26 pass offline. Workflows and their `swamp workflow validate`
runs are the next slice.
