# Spec: P2 — `@randybias/k0s-multinode`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone running a multi-node k0s cluster with an HA control plane.

Q3: Yes. `k0s-multinode` names the system (k0s) and the kind (multi-node); the workflows `k0s-multinode-create-cluster` and `k0s-multinode-join-node` use listed verbs at four segments; short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `k0s-multinode` as a multi-node k0s cluster manager, which is what it does, and guesses wrong about nothing.

Status: approved (see `docs/CLEANROOM.md`); written from public docs only, no prior implementation consulted. The next-version scope is at the end.
RFC 2119 keywords.
Sources: docs.k0sproject.io (multi-node, HA control plane, control plane load
balancing, node-local load balancing, join tokens, upgrade, remove controller,
etcd), the public k0sctl README/docs, kubernetes.io (drain, version skew). This
repo: CONVENTIONS.md, `k0s-cluster`, `server-host`, `wireguard-mesh`.

## 1. Purpose

Build and operate a **multi-node** k0s cluster in the k0sctl style: a set of
controllers (1 or an odd HA count) plus workers, joined with **short-lived join
tokens**; add and remove nodes (drain first); and upgrade in the safe order
(controllers one at a time, then workers). Single-node remains `k0s-cluster`'s job.

## 2. Build decision: orchestrate `k0s-cluster` per node (do not wrap k0sctl)

**Decision:** per-node work (binary verify, install, reset, wait) is done by the
existing `@randybias/k0s-cluster`; this extension adds a thin cluster-scope model
for what no single node owns (tokens, membership, drain, detach, ordering) and
workflows that compose the two. k0sctl was considered and rejected for v1:

| Concern | k0sctl (wrapped) | Orchestrate `k0s-cluster` |
|---|---|---|
| Binary trust | k0sctl downloads k0s itself; we would pin + SHA a *second* binary (k0sctl) and still pre-stage k0s to keep SHA verification | SHA-256-verified k0s already implemented and reviewed |
| SSH host keys | Its own SSH stack; strict pinning behaviour must be proven, not assumed | Vendored, reviewed `_lib/ssh.ts`, strict policy required |
| SSH key delivery | Key file path or ssh-agent | Key over stdin to a short-lived agent (existing) |
| Tokens | Handled internally (good), but invisible to swamp state/receipts | Explicit, vaulted, invalidated, auditable |
| Partial failure | One opaque `apply`; resume = re-run whole plan | Each step is a swamp step with its own state and receipt |
| Ordering logic | Upstream-maintained (its main advantage) | We own it — mitigated by a pure, golden-tested `plan` |

Wrapping k0sctl stays a documented fallback if the per-node path proves too
costly; it would be a separate type, never a hidden dependency.

### Required `k0s-cluster` changes (separate MICRO bump + review, lands first)

1. `join_token` accepted for role `controller` and a new role
   `controller_worker` (`k0s install controller --enable-worker`, optional
   `no_taints`). Token still goes to a root-only token file over stdin.
2. `upgrade` action: verify the new pinned binary, stop, swap, start, verify
   version; **never reset**, data preserved. Refuses downgrade.
3. HA config inputs: `api.externalAddress`, `network.nodeLocalLoadBalancing`,
   `network.controlPlaneLoadBalancing` (VIP), `storage.type: etcd`,
   `api.address`/`etcd.peerAddress` (private/mesh address).

## 3. Transport

Vendor `_lib/ssh.ts` from `ssh-host` byte-identical (same as `k0s-cluster`).
Cluster-scope commands run **on a controller over SSH** using `k0s kubectl`
and `k0s etcd`, so this model needs **no kubeconfig at all**.

## 4. Model contract

- **Type** `@randybias/k0s-multinode`. CalVer == manifest version.
- **`globalArguments` empty.** Each method takes `cluster_name` (DNS-1123
  label), an `ssh` target for the controller it acts through, and operands.
- **State keys**: cluster `{cluster_name}`; per node
  `{cluster_name}/{user}@{host}:{port}` (canonical, lowercased host). Never the
  definition name; never a token.
- **Factory with injectable deps**: SSH spawner, vault service, clock, sleep.
  Unit tests assemble argv and parse sanitized command output only.

### Methods

| Method | Kind | Description |
|---|---|---|
| `plan` | — | READ-ONLY. Given desired topology, target version and (optional) observed membership, return the ordered step list for create / add / remove / upgrade. Pure and deterministic; enforces every ordering rule in §5. |
| `render_config` | — | READ-ONLY. The shared controller `k0s.yaml` (delegates to `k0s-cluster` rendering + HA inputs). Returns text and sha256; every controller MUST get the same sha. |
| `mint_join_token` | action | On a controller: `k0s token create --role <worker\|controller> --expiry <d>`. Token captured in memory, written to the caller-named vault key, never returned. Token ID found by diffing `k0s token list` before/after. Returns `{token_id, role, expires_at, vault:{vault,key}}`. |
| `invalidate_join_token` | action | `k0s token invalidate <id>`, then overwrite the vault key with a fixed non-secret tombstone. Idempotent: unknown/expired id → no-op. |
| `wait_joined` | action | READ-ONLY semantics. Poll from a controller until the named node is `Ready` (worker) or is an etcd member and its `ControlNode` is present (controller). Returns `{joined, ready, roles, kubelet_version}`. |
| `drain_node` | action | `k0s kubectl cordon` + `drain --ignore-daemonsets --delete-emptydir-data --timeout`. Idempotent. A PodDisruptionBudget block is a typed error, never `--disable-eviction`. Returns `{node, evicted, remaining_pods}`. |
| `uncordon_node` | action | Uncordon. Idempotent. |
| `detach_node` | action | DESTRUCTIVE. Remove a **drained** node from the cluster: controller → quorum check, then etcd leave (via `k0s etcd leave` or the `EtcdMember` resource, per pinned version docs) and delete its `ControlNode`; worker → delete the `Node`. Refuses an undrained node unless `confirm` = node name. Does not touch the host (the workflow then runs `k0s-cluster reset` there). Absent → no-op. |
| `get` | — | READ-ONLY. Nodes (role, Ready, cordoned, kubelet and k0s version), etcd member list and health, outstanding token IDs + expiry. |
| `sync` | — | READ-ONLY. Reconcile recorded membership with the cluster; flag drift (unknown nodes, lost members). |

### Workflows (compose this model + `k0s-cluster`)

- `k0s-multinode-create-cluster` — install controller 1 → wait → for each extra
  controller: mint (controller) → install with token → wait_joined → invalidate
  (`dependsOn … completed`, so it runs even on failure) → workers likewise.
- `k0s-multinode-add-node` / `k0s-multinode-remove-node` (drain → detach →
  `k0s-cluster reset` on the node → get).
- `k0s-multinode-upgrade-cluster` — §5 order; per worker: drain → upgrade →
  wait_joined → uncordon.
- `k0s-multinode-reset-cluster` — DESTRUCTIVE: workers first, controllers last.

### Inputs and grammars

- `cluster_name` — DNS-1123 label. `ssh` — `k0s-cluster`'s transport block
  (host, user, port, required `host_key_policy` + pinned `host_keys`, key over
  stdin, sensitive).
- `nodes[]` (plan) — `{name (DNS-1123 subdomain), ssh_host, role:
  controller|controller_worker|worker, private_address (IPv4/IPv6)}`, max 50,
  unique names/addresses. Controller count MUST be odd (1, 3, 5) unless
  `allow_even_controllers`.
- `k0s_version` + `k0s_binary_sha256` — as `k0s-cluster` (pinned, required).
- `token_expiry` — Go duration `^\d{1,3}(m|h)$`, bounded 5m–24h, default `1h`.
- `token_vault` — `{vault, key}`, both `^[A-Za-z0-9._-]{1,128}$`.
- `ha_mode` — `none | external_lb | cplb_vip | node_local_lb`; `external_address`
  (IP or DNS name) required for `external_lb`/`cplb_vip`; `vip` CIDR-validated.
- `drain_timeout_s` 30–3600; `confirm` exact-match string.
- Strict `z.object`, no `.passthrough()`. Token values exist only in memory and
  in vault.

### Outputs

Typed objects above. **No join token, kubeconfig, or SSH key in any output,
state, log, or receipt** — token IDs and expiry only (the ID is the public half
of a bootstrap token).

## 5. Ordering invariants (pure; each a `plan` golden test)

1. First controller up and Ready before any token is minted.
2. HA endpoint (`externalAddress`/VIP) configured **before** minting tokens —
   tokens embed the API address, so a token minted earlier pins nodes to one
   controller.
3. Controllers join one at a time; each is an etcd member before the next.
4. Upgrade: controllers one at a time (wait healthy between), then workers
   (drain → upgrade → Ready → uncordon), never a worker before all controllers.
   One Kubernetes minor per upgrade; refuse skips and downgrades.
5. Remove: drain → detach → reset. Never detach a controller if the remaining
   members would lose etcd quorum (refuse 2→1 and 3→2 unless `confirm`);
   never remove the last controller (use reset-cluster).
6. Reset-cluster: all workers, then controllers.
7. Every mint is paired with an invalidate step that runs on success or failure.

## 6. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| Token expired before use | Join fails typed; `get` shows no new node; re-mint works. |
| Invalidated token reused | Join refused by k0s; typed error. |
| Mint on a non-controller | Typed error. |
| Vault service unavailable | Refuse to mint (never fall back to returning the token). |
| Even controller count | Rejected by `plan` without `allow_even_controllers`. |
| Detach undrained / quorum loss | Refused without `confirm`. |
| Drain blocked by PDB / timeout | Typed error, node stays cordoned, nothing evicted forcibly. |
| Upgrade skip / downgrade | Refused by `plan` and by `k0s-cluster upgrade`. |
| Controller config sha differs | `sync` flags drift; `plan` refuses to add a mismatched controller. |
| Node unreachable mid-workflow | Step fails; invalidate still runs; state shows partial membership. |
| Re-run create on a built cluster | Adopts; no second install, no extra token. |
| Injection in names/addresses/durations | Rejected by grammar; argv-quoted. |

## 7. Tests (offline, increasing risk)

1. Schema/secret/license: token never in any output schema; ssh key sensitive.
2. Pure mapping: `plan` goldens for create (1+2, 3 HA), add, remove, upgrade;
   §5 invariants as table tests; token-ID diff parser on sanitized `token list`
   output; argv contains no token (token only on stdin to vault/token file).
3. Failure + adversarial: §6 rows; injection on every remote-bound input.
4. A regression test greps outputs/fixtures/state for token- or
   kubeconfig-shaped text.
5. Packaging; vendored `_lib` byte-identity.

## 8. Live e2e matrix (3 throwaway VPS)

Targets: three hourly VPS (≥2 GB) tagged `swamp-e2e=<run-id>`, same region,
private network or `wireguard-mesh` between them; node ports (6443, 8132, 9443,
2380, 10250, CNI) allowed between nodes only (`server-host` firewall).

| Cell | Expected |
|---|---|
| plan / render_config | match goldens for the live topology |
| **Topology A: 1 controller + 2 workers** | |
| create-cluster workflow | 3 nodes, 2 workers Ready |
| tokens after create | all minted IDs invalidated; vault keys tombstoned |
| expired-token join (negative) | `token_expiry=5m`, wait, join refused |
| reused-token join (negative) | refused |
| create re-run | adopts, no change |
| drain + detach + reset a worker | node gone, workloads rescheduled |
| add worker back | Ready |
| upgrade n→n+1 minor | controller then workers in order, all at target |
| get / sync | reflect real membership |
| reset-cluster / again | all hosts clean; then no-op |
| **Topology B: 3 controller_worker, HA** (`node_local_lb` default) | |
| create-cluster | 3 etcd members healthy, 3 nodes Ready |
| controller failure | stop one controller: API still served, workloads run |
| remove controller (3→2, confirm) | etcd leave, ControlNode gone, 2 healthy members |
| quorum refusal | 2→1 without confirm refused |
| re-add controller | 3 members again |
| upgrade (rolling) | controllers one at a time, API available throughout |
| `cplb_vip` | `blocked` unless the provider allows VRRP/L2 between VPS |
| reset-cluster | all clean |

Afterwards confirm on each host that no k0s unit, data dir or token file remains.
Receipts into `k0s-multinode/LOGBOOK.md`. No `stable` while any cell is
`untested`/`skip`.

## 9. Credential policy

Per RULINGS ¶3: credentials are vault references only. Join tokens are minted
into a caller-named vault key and read by `k0s-cluster install` as a
`vault.get(...)` input, written to a root-only token file **over stdin**, never
argv, never state, never step output; invalidated and tombstoned after join.
Token expiry (k0s-side) is the backstop if invalidation never runs. SSH keys and
any admin kubeconfig follow `k0s-cluster`'s existing rules.

## 10. Known traps (public docs; verify at the pinned version)

- Controllers do not run workloads by default; `controller_worker` is opt-in and
  tainted unless `no_taints`.
- Single-node (`--single`) uses kine and cannot be grown into HA; HA needs etcd
  and an odd controller count.
- All controllers must share the same `k0s.yaml`; drift is silent until failure.
- `cplb_vip` (keepalived VRRP) needs L2 adjacency, which most VPS providers do
  not offer; `node_local_lb` covers worker→API traffic but an admin kubeconfig
  still targets one address.
- Join tokens embed the API address at mint time (invariant 2).
- Worker token files can be removed after join; the token file must never be
  world-readable.
- Removing a controller without etcd leave leaves a dead member that can cost
  quorum later.
- Kubernetes skew policy: kubelet never newer than the API server — hence
  controllers first. k0s Autopilot is an alternative upgrade path; out of scope v1.
- Node ports must be open between nodes and closed publicly — coordinate with
  `server-host` lockdown (armed revert) before joining.

## 11. Open questions for Randy

1. **HA endpoint on VPS.** Default `node_local_lb` + admin kubeconfig to one
   controller (or a DNS name over all three), or require an external TCP load
   balancer? Drives `externalAddress`, tokens, and the Topology B cells.
2. Approve the three `k0s-cluster` changes in §2 landing first as a MICRO bump.
3. Keep the k0sctl wrapper as a documented fallback only (as drafted), or drop it.

## Next version scope: next

Next `k0s-multinode` version (public, beta).

- Re-vendor the canonical transport (`8f132c4329c9e64bed686731cd5a0e02980194ea`).
- Build the deferred pieces of this spec: the add-node, remove-node,
  upgrade-cluster and reset-cluster workflows (per-item child workflows,
  succeeded-only gate edges, re-gate after approval), the `upgrade` method,
  `render_config`, `sync` drift beyond membership (config sha per node, cordoned
  and NotReady as drift), and etcd health in `get`.
- Medium: the detach self-host refusal compares only the SSH host string, and
  `peer_address` has no address grammar.
- Tests: a regression test that greps state, logs and results for token- or
  kubeconfig-shaped text; a model-level `plan_remove` test.
- Live: HA with three controllers on 2 GB nodes, including controller loss and
  etcd member removal. The VRRP VIP cell stays untested on VPS, with the reason.
