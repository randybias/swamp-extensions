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
