# Maintainer logbook

visibility: public

audience: general

Not packaged. Notes for whoever maintains this extension.

## Naming rubric (shared-docs 2026-10-17, section 3)

1. **Public or private:** public.
2. **Individual or general:** general.
3. **Public and general — does the name describe and disambiguate while staying
   short:** `k0s-multinode` names the system (`k0s`) and the kind (`multinode`),
   disambiguating the multi-node orchestrator from the single-node `k0s-cluster`
   in two segments.
4. **Private and specific:** not applicable (this is public and general).
5. **Would a stranger guess roughly right, and wrong about nothing:** yes — it
   drives multi-node k0s clusters and is not a node-level installer
   (`k0s-cluster`), a CLI tool or a provider service.

Workflows follow `<ext>-<verb>-<object>` with a verb from the convention list:
`k0s-multinode-create-cluster` (create) and `k0s-multinode-join-node` (join).

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
  the action methods follow the `k0s-cluster` MICRO bump. **Update (merge
  2026.10.17.1):** resolved. `k0s-cluster` 2026.10.17.3 supplied every per-node
  feature, and the token, wait, drain, uncordon, detach, get and sync methods
  plus the create-cluster and join-node workflows are wired. The `upgrade`
  method/workflow is still deferred (see "Untested and residuals").
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

Re-checked at merge (2026-10-17, `swamp extension search` on stable and beta for
k0s, multinode, k3s, talos, etcd, kubeadm, rke2):

- k0s: only our own `@randybias/k0s-cluster` (per-node, which this extension
  drives) and `@randybias/server-stack` (beta).
- Talos: `@dataverket/talosctl`, `@dataverket/omni`, `@dataverket/omnictl`,
  `@magistr/talm-cluster`, `@magistr/talos-node`, `@mccormick/omni` (stable).
  Talos has its own machine API and bootstrap; none of them drives k0s.
- k3s: `@shelson/k3s`, `@rjeschmi/vm` (stable), single-distribution k3s
  installers with no k0s join-token or etcd-leave handling.
- multinode, kubeadm, rke2: no hits on either channel; etcd: only
  `@dataverket/talosctl`.

Verdict: NONE. No package covers multi-node k0s, so there is nothing to file
upstream.

## Review round 2 (HEAD 4982ce9) — fixed

- `plan_remove` now destructures `node` before `PlanInputSchema.parse` (it was
  throwing "Unrecognized key: node"); a model-level test is still to add.
- `TOKEN_ID` is `^[a-z0-9]{6}$`, so a leading-dash id (`-h`, which prints help
  and exits 0) is refused.
- `invalidate_join_token` invalidates every live record for the key (not the
  oldest) and marks each.
- `hasNonDaemonSetPods` throws on a non-List, and detach turns that into a
  refusal (fails closed).
- `sync` checks controllers by etcd membership, not Node presence, so a
  dedicated controller is no longer "missing".
- The etcd fixtures use the real `{"members":{"<name>":"https://ip:2380"}}`
  shape; the invented object/array branches are gone.
- `durationMinutes` and `LABEL_RE`/`IP_RE` are exported from plan.ts (one
  duration helper; the model's `expiresAt` uses it).
- create-cluster workflow: UUID id; single input types with `has()`/empty-string
  handling for absence; `+` instead of `.concat()`; the vault key is a plain
  per-node `token_key` field (no concatenation in `vault.get`); the verify
  assert checks each desired name (workers Ready, controllers ssh members).

## Review round 2 — deferred (recorded, HIGH)

- **The create workflow's forEach grouping is not safe.** A mock run proved
  `dependsOn` between forEach steps is a group barrier (all mints, then all
  installs, then all waits) and that `completed` excludes `skipped`, so a failed
  install leaves live tokens. The fix is a per-node child workflow: mint ->
  install -> wait -> invalidate called with forEach concurrency 1 (controllers
  first), with an invalidate for `wait completed` and one for `install failed`.
  This must land before the workflow is used; the extension is unpublished
  (`release.yaml ci: false`), so nothing live is affected.
- Nested input defaults are not applied by swamp; several `cluster` fields are
  optional and rely on `has()`/empty handling. A per-node `token_key_prefix`
  input is now unused.
- `peer_address` has no IP grammar yet and self-host refusal compares only the
  ssh.host string (hostname-vs-IP bypass); resolving the node's InternalIP is
  still to add.
- `swamp workflow validate` `workflow not found` was the broken-workflow load
  error; it can be run in a scratch repo with
  `swamp extension source add <ext dir>` (the LOGBOOK's earlier claim that it
  cannot run locally was wrong).
- The model export is still `createModel()` (not a plain literal), so swamp's
  static type read may warn (gate 7); transport.ts keeps unused upload/learn
  adapters; `fakeJoinToken` is duplicated in two test files.

## Review round 2 follow-up: per-node child workflow, validated live

- **Per-node child workflow** `@randybias/k0s-multinode-join-node`: mint ->
  install (dependsOn mint succeeded) -> wait (dependsOn install succeeded) ->
  invalidate (dependsOn wait completed) + invalidate-failed (dependsOn install
  failed). The create workflow's join job calls it once per node with forEach
  concurrency 1, controllers before workers. This removes the forEach
  group-barrier bug: each node's mint/install/wait/invalidate is a real per-step
  DAG inside the child.
- **Scratch validation** (correction: `swamp workflow validate` CAN run
  locally): in a scratch repo, `swamp extension source add <ext dir>` then
  `swamp workflow validate` — both workflows load and every validation passes (0
  failures). The earlier load error ("Workflow not found") was the broken
  workflow, now fixed.
- **Mock run** with two local mock model sources named
  `@randybias/k0s-multinode` and `@randybias/k0s-cluster` (models only, log
  every call), vault `k0s-multinode` created:
  - install fails (`mock install failed`): calls are `mint:tok-w1`,
    `install:...`, `invalidate:tok-w1`; `wait` and `invalidate` skipped,
    `invalidate-failed` succeeded. Every minted token is invalidated.
  - install succeeds: calls are `mint:tok-w1`, `install:...`,
    `invalidate:tok-w1`; `invalidate-failed` skipped. So a failed install leaves
    no live token.
- Live evidence from the mock run also confirmed the nested-default gap: swamp
  does not apply the child's nested `ssh_port`/`api_address` defaults, so the
  caller must supply them (or the fields must be made required). Still to fix.

## Failed-node gating and open residuals

- The create workflow now splits `join-controllers` and `join-workers`; the
  workers job depends on the controllers job **succeeded**, so after a
  controller failure no further controller or worker join. Mock run (c1
  controller fails): calls are the bootstrap install, `mint:tok-c1`,
  `install:<c1>`, `invalidate:tok-c1`; no worker call. **swamp forEach has no
  early stop**, so a later node in the _same_ job still runs after one fails;
  the split only gates one job on the whole previous job. This is the strongest
  gating the engine offers without a child workflow per node category.

### Open residuals (from review round 2, still to fix)

- `peer_address` self-host refusal compares only the ssh.host string
  (hostname-vs-IP bypass); resolve the leaving node's InternalIP.
- swamp does not apply nested input defaults (`ssh_port`, `api_address`, ...);
  either make them required or guard with `has()` at each use site.
- The model export is still `createModel()` (not a plain literal), so swamp's
  static type read warns (gate 7 risk).
- `transport.ts` keeps unused upload/learn-key adapters; `fakeJoinToken` is
  duplicated in two test files; the workflow test asserts expression text rather
  than behaviour.
- `render_config`, the add/remove/upgrade/reset workflows, `sync` config-sha
  drift and `get` etcd health are still to add.

## Live fixes (f94659f)

- `sync` now persists its drift: the `status` resource gains `in_sync` and
  `diffs` (`get` writes `in_sync: null`, since it does not judge drift). swamp
  never shows or stores a method result, so before this the drift was invisible
  (live cell 3b).
- A Node's role comes from the cluster, not the Node label: a member of etcd or
  a ControlNode is a controller, anything else is a worker. k0s 1.36.4 puts no
  `node.k0sproject.io/role` or `node.k0sproject.io/version` label on worker
  Nodes, so workers had shown role `unknown` (live cell 3a). `k0s_version` falls
  back to the Node's kubelet version.

## 2026-10-17 live e2e (2026.10.17.1): 11 of 12 on 3c8afc1, then 5 of 5 on f94659f

Run sp-20261017, from a scratch repo with `swamp extension source add`. Three
throwaway Ubuntu VPS: `<vps7>` (2 GB) a dedicated controller, `<vps5>` and
`<vps6>` (1 GB) workers. Cluster `e2emn`, etcd, k0s v1.36.4+k0s.1 (amd64 binary
pinned by its official sha256). Per-node model: the PUBLISHED
`@randybias/k0s-cluster` 2026.10.17.3. Strict host-key pins only; the SSH key is
a vault reference (compared by sha256 only). The nested `cluster`/`controller`
fields were passed explicitly (nested-default residual).

On 3c8afc1 (the controllers/workers job split; same model code as the reviewed
6b8a0c0):

| Cell                               | Result | Detail                                                                                                                                                                                                                                    |
| ---------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 plan, 1 controller + 2 workers   | PASS   | operation create; install and wait the first controller, then per worker mint -> install -> wait -> invalidate; every mint paired with an invalidate                                                                                      |
| 2 create-cluster workflow          | PASS   | bootstrapped from nothing in 3m7s; workers joined one at a time; afterwards no join tokens for either role, 0 bootstrap-token secrets, both workers Ready, etcd = `<vps7>`; both token records invalidated, vault keys hold the tombstone |
| 3a get                             | PASS   | membership correct; residual: workers showed role `unknown` and no version (fixed in f94659f)                                                                                                                                             |
| 3b sync                            | FAIL   | sync's `{in_sync, diffs}` was visible nowhere (not console, `--json`, outputs or data); fixed in f94659f                                                                                                                                  |
| 4 mint, then invalidate by key     | PASS   | token listed after mint (value not printed); invalidate emptied both role lists, tombstoned the key, set `invalidated_at`; a re-run is a no-op with no remote call                                                                        |
| 5 drain under a PDB, then uncordon | PASS   | PDB minAvailable 2: typed "blocked by a PodDisruptionBudget" error, node stays cordoned, nothing evicted; at minAvailable 1 the drain succeeded; uncordon restored scheduling                                                             |
| 6 detach a worker, then reset      | PASS   | detach before drain refused "not drained"; after drain, detach removed the Node, etcd unchanged; k0s-cluster reset left no k0s units, binary or state, and the node did not re-register                                                   |
| 7a detach the only controller      | PASS   | with confirm: "cannot remove the last controller; use reset-cluster"; etcd member and ControlNode kept                                                                                                                                    |
| 7b node-name injection `-l x=y`    | PASS   | wait_joined, uncordon_node, detach_node, drain_node all refused "not a DNS-1123 subdomain"; 0 remote calls (sshd accept count)                                                                                                            |
| 8 join with a bad binary pin       | PASS   | the join-node workflow minted, the install refused the sha256 mismatch, wait skipped, invalidate-failed ran; no tokens left, key tombstoned, nothing installed                                                                            |
| 9 ps/argv scan during joins        | PASS   | `ps -eww` every 0.2 s on all three nodes and locally across cells 2 to 8; needles per token (raw value, bearer, secret half, their sha256): 0 hits anywhere, 0 `H4sI` strings                                                             |
| 10 teardown                        | PASS   | k0s-cluster reset on all three: no k0s units, binaries, state dirs, processes or kube/cni/vxlan interfaces                                                                                                                                |

On f94659f (the live fixes; the published code is this plus the gate-7 export
commit):

| Cell               | Result | Detail                                                                                                                                                                                                    |
| ------------------ | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1 create-cluster  | PASS   | from three clean hosts in 3m7s; afterwards no join tokens for either role, both workers Ready, vault keys tombstoned                                                                                      |
| R2 get             | PASS   | `swamp data get`: both workers role `worker`, `k0s_version` `v1.36.4+k0s` (the kubelet string); etcd = `<vps7>`; tokens []; `in_sync` null                                                                |
| R3 sync, no change | PASS   | persisted `in_sync` true, `diffs` []                                                                                                                                                                      |
| R4 drift           | PASS   | a hand cordon is not drift (`in_sync` true, the record shows cordoned); stopping the worker and deleting its Node outside the model gave `in_sync` false, `diffs` ["recorded worker `<vps6>` is missing"] |
| R5 teardown        | PASS   | k0s-cluster reset on all three, every node clean                                                                                                                                                          |

## Untested and residuals (not failures, do not block beta)

- **HA with 3 controllers is NOT live-tested.** Every live cell used one
  controller; quorum refusals (3->2, 2->1) are unit-tested only, and so is the
  `ha_mode`/`external_address` endpoint choice.
- The add-node, remove-node, upgrade-cluster and reset-cluster workflows, the
  `upgrade` method and `render_config` are deferred (review round 1). `sync` has
  no config-sha drift check and `get` has no etcd health.
- `sync` compares membership only: a cordoned or NotReady node is not drift
  (live R4a).
- A worker's `k0s_version` is the kubelet string (`v1.36.4+k0s`), not the full
  k0s build (`v1.36.4+k0s.1`), because k0s labels no version on worker Nodes.
- swamp does not apply nested input defaults, so the workflow callers must pass
  the nested `cluster`/`controller` fields (`ssh_port`, `api_address`,
  `api_port`, `external_address`, `etcd_peer_address`, `api_sans`,
  `node_local_load_balancing`) explicitly.
- swamp forEach has no early stop: after one controller join fails, the later
  controllers in the same job still run; only the workers job is gated on the
  whole controllers job.
- `k0s reset` (through k0s-cluster) leaves the `/opt/cni/bin` plugins, an empty
  `/etc/cni/net.d` and a stale `/var/lib/kubelet/device-plugins/kubelet.sock` on
  workers.
- The detach self-host refusal compares the etcd peer with the `ssh.host` string
  only, so a hostname or another interface of the leaving controller is not
  caught (the quorum and last-controller refusals still apply).
- `mint_join_token` invalidates the minted token on every failure after the
  list/vault steps, but not when the create output cannot be parsed into an ID
  or when the final `tokens` record write fails: that token stays live on the
  controller until it expires (`token_expiry`, default 1h), held nowhere else.
- An explicit `invalidate_join_token` with an already-invalidated `token_id`
  re-runs `k0s token invalidate` and fails if k0s reports it unknown; the by-key
  path (used by the workflows) is a no-op.
- `transport.ts` keeps the vendored upload/learn-key adapters unused;
  `fakeJoinToken` is duplicated in two test files (tightness: COULD-BE-TIGHTER).

## Merge prep (2026-10-17, main)

- Reviews: round 1 (8f531eb, 9 High) and round 2 (4982ce9, 6 High) fixed in the
  lane; round 3 (6b8a0c0) CLEAN after triage, with 13 mock workflow cases in
  which every minted token was invalidated. The branch was rebased; the reviewed
  commits map tree-for-tree onto bee9b18, 2c17c45, 1326a2f and f97f0b7 (=
  3c8afc1).
- Self-review of 6b8a0c0..f94659f: the controllers/workers job split (the verify
  job is a read and runs after either), metadata, and the two live fixes above
  with tests that drive the real worker Node shape and assert the persisted
  status.
- Gate 7 mechanics only, no behaviour change: the plain `export const model`
  literal and `swamp-quality-ignore` comments on `token_expiry`, `TOKEN_EXPIRY`
  and `TokensStateSchema` (a lifetime and token IDs, not secrets).
- `_lib/ssh.ts` (blob `fe0139f0`) and `_lib/transport.ts` are byte-identical to
  `k0s-cluster`'s. Branch history carries only RFC 5737 addresses and lockfile
  integrity hashes.
