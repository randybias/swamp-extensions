# @randybias/k0s-multinode

[Swamp](https://github.com/swamp-club/swamp) extension for planning a multi-node
k0s cluster in the [k0sctl](https://github.com/k0sproject/k0sctl) style. The
cluster-scope work that no single node owns — topology, join tokens, membership,
drain/detach and upgrade ordering — runs on a controller over SSH, so this model
needs no kubeconfig. Per-node binary verification, install, upgrade and reset
belong to
[`@randybias/k0s-cluster`](https://github.com/randybias/swamp-extensions).

## Models

### `@randybias/k0s-multinode`

One cluster, described by a name, a desired topology and a pinned k0s version.

| Method                  | Description                                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------------------------- |
| `plan`                  | Return the ordered step list for creating, adding to, or upgrading a cluster, without touching anything |
| `plan_remove`           | Return the drain -> detach -> reset step list for one node                                              |
| `mint_join_token`       | Mint a short-lived join token into a caller-named vault key; return only its ID, role and expiry        |
| `invalidate_join_token` | Invalidate a token by ID and tombstone its vault key; idempotent                                        |
| `wait_joined`           | Poll until a node is Ready (worker) or an etcd member with a ControlNode (controller)                   |
| `drain_node`            | Cordon and drain, honoring PodDisruptionBudgets; a PDB block is a typed error                           |
| `uncordon_node`         | Return a node to service                                                                                |
| `detach_node`           | Remove a drained node (etcd leave + ControlNode delete for a controller); refuses quorum loss           |
| `get`                   | Report nodes, etcd members and outstanding token IDs                                                    |
| `sync`                  | Reconcile recorded membership with the cluster and flag drift                                           |

`plan` is pure and deterministic and enforces the ordering rules: the first
controller is Ready before any token is minted, an HA endpoint is chosen before
tokens are minted (a join token embeds the API address), controllers join one at
a time, upgrades go controller by controller and then worker by worker (drain ->
upgrade -> Ready -> uncordon) one Kubernetes minor at a time, and every minted
token is paired with an invalidate step. It refuses an even controller count
unless `allow_even_controllers` is set, a detach that would lose etcd quorum
without `confirm`, and any downgrade or skipped minor.

Join tokens are minted into a caller-named vault key and read by
`k0s-cluster install`; the token value never appears in this model's state or
output.

## Install

```bash
swamp extension pull @randybias/k0s-multinode
```

## Example

```bash
swamp model create @randybias/k0s-multinode k0s-lab --json
swamp model method run k0s-lab plan --input-file plan.yaml
```

```yaml
# plan.yaml
cluster_name: k0s-lab
k0s_version: v1.31.2+k0s.0
ha_mode: node_local_lb
external_address: 192.0.2.10
nodes:
  - {
      name: ctrl-1,
      ssh_host: 192.0.2.10,
      role: controller_worker,
      private_address: 192.0.2.10,
    }
  - {
      name: ctrl-2,
      ssh_host: 192.0.2.11,
      role: controller_worker,
      private_address: 192.0.2.11,
    }
  - {
      name: ctrl-3,
      ssh_host: 192.0.2.12,
      role: controller_worker,
      private_address: 192.0.2.12,
    }
  - {
      name: wrk-1,
      ssh_host: 192.0.2.13,
      role: worker,
      private_address: 192.0.2.13,
    }
```

## How it works

- The plan is a pure function of the desired topology and the observed
  membership; the same inputs always give the same steps, and each ordering rule
  has a unit test.
- `plan` never mints anything. Minting, draining, detaching and upgrading run
  through a controller over SSH with the reviewed SSH transport, and are added
  in the workflows that compose this model with `@randybias/k0s-cluster`.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
