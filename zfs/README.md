# @randybias/zfs

[Swamp](https://github.com/swamp-club/swamp) extension for managing
[OpenZFS](https://openzfs.org) on a Linux host over SSH: a pool, datasets,
sparse zvols, snapshots, clones and rollback. It is the storage layer for a
golden-image workflow, where a base zvol is cloned once per node.

## Models

### `@randybias/zfs`

One definition serves any host. Every method takes the SSH target and the ZFS
operands as arguments, and state is keyed by the target's `{host, port, user}`
plus the pool or dataset name.

| Method           | Description                                                                        |
| ---------------- | ---------------------------------------------------------------------------------- |
| `create_pool`    | DESTRUCTIVE. Create a pool from named vdevs, refusing any boot/root device         |
| `create_dataset` | Create a dataset, or set only the properties that differ                           |
| `create_zvol`    | Create a sparse zvol of a given size                                               |
| `snapshot`       | Create a `dataset@tag` snapshot                                                    |
| `clone`          | Clone a snapshot to a new dataset or zvol                                          |
| `rollback`       | DESTRUCTIVE. Roll a dataset back to a snapshot                                     |
| `get`            | READ-ONLY. Report pool, dataset and snapshot state                                 |
| `sync`           | READ-ONLY. Compare recorded state with the host and report drift                   |
| `destroy`        | DESTRUCTIVE. Destroy a dataset, zvol or snapshot                                   |
| `destroy_pool`   | DESTRUCTIVE. Destroy a pool; refuses a system pool and children unless `recursive` |
| `export_pool`    | Export a pool; absent is a no-op                                                   |

## System pools

`destroy_pool` and `export_pool` refuse a pool that carries the running system:
`bootfs` set, a system mount (`/`, `/boot`, `/boot/efi`, `/usr`, `/var`,
`/var/lib`, `/var/log`) sourced from a dataset or zvol of the pool, or a zvol of
the pool active as swap. Zvol-backed mounts are matched by their canonical
`/dev/zdN` (or `/dev/zdNpM`) device, because `mount(8)` reports that, not the
`/dev/zvol/...` link. Every probe must succeed; an unreadable host refuses. A
system mount under a _different_ `/var/*` path (for example `/var/lib/docker`)
is a known limit — a pool dedicated to it is a legitimate target.

## Dependencies

- A Linux host with OpenZFS (`zpool`, `zfs`) and `lsblk`, reachable over SSH by
  a user that can run those tools (typically `root`).
- The local host needs the OpenSSH client tools: `ssh`, `ssh-agent` and
  `ssh-add`.
- An SSH private key. It is loaded into a short-lived `ssh-agent` over stdin and
  never appears on a command line.

## Install

```bash
swamp extension pull @randybias/zfs
```

## Example

Put the inputs in a file so the private key never reaches the command line. The
key stays a vault reference; swamp resolves it at run time and never prints it.

```yaml
# args.yaml — keep this file out of version control
ssh:
  host: 192.0.2.10
  port: 22
  user: root
  host_key_policy: strict
  host_keys:
    - "192.0.2.10 ssh-ed25519 AAAA..."
  connect_timeout_s: 15
  private_key: ${{ vault.get("default", "ZFS_SSH_KEY") }}
pool: tank
```

```bash
# One definition, two hosts: each call carries the target and its inputs.
for host in 192.0.2.10 198.51.100.20; do
  swamp behavior run @randybias/zfs create_pool zfs-host \
    --input-file "args-${host}.yaml" \
    --input 'vdevs:json=["/dev/disk/by-id/ata-SPARE-DISK"]'
done

swamp behavior run @randybias/zfs create_dataset zfs-host \
  --input-file args-192.0.2.10.yaml \
  --input name=tank/data --input 'properties:json={"compression":"zstd"}'

swamp behavior run @randybias/zfs create_zvol zfs-host \
  --input-file args-192.0.2.10.yaml \
  --input name=tank/golden --input volsize=10G

swamp behavior run @randybias/zfs snapshot zfs-host \
  --input-file args-192.0.2.10.yaml \
  --input name=tank/golden --input tag=base

swamp behavior run @randybias/zfs clone zfs-host \
  --input-file args-192.0.2.10.yaml \
  --input name=tank/golden --input tag=base --input target=tank/node-1
```

A strict host-key policy pins the expected keys; `insecure_tofu` trusts the
host's keys for one call only, so supply `host_keys` to pin.

Do not add `--json` to a run whose inputs carry a literal secret. A vault
reference is resolved at run time and never printed, but the CLI echoes literal
sensitive arguments in that output.

```yaml
ssh:
  host: 192.0.2.10
  user: root
  host_key_policy: strict
  host_keys:
    - "192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
  private_key: ${{ vault.get("default", "ZFS_SSH_KEY") }}
```

## How it works

- **Boot-disk safety.** Before `create_pool`, the model reads the host's
  block-device tree (`lsblk -J`), `/proc/mounts`, `/proc/swaps`, `/etc/fstab`,
  `/proc/mdstat` and `zpool status -P`, and builds an explicit protected-device
  set: every mounted device, every device named in `fstab` (including a
  `/dev/disk/by-id` reference, resolved on the host), every member of an md
  array (active or degraded), any device carrying `linux_raid_member` or
  `zfs_member`, every member of an existing ZFS pool, and every whole disk and
  partition in those devices' families. A candidate vdev that shares a family
  with any protected device is refused before `zpool` runs. The method refuses
  rather than guesses when the block-device tree or a protected reference cannot
  be read, so a boot disk can never be taken.
- `create_pool` is idempotent: an existing pool with the same resolved vdev set
  is a no-op, and a different set is refused.
- `create_dataset` sets only the properties that differ; `create_zvol` is sparse
  by default and refuses a different existing size; `snapshot` and `clone` are
  no-ops when the target already exists with the same origin.
- `rollback` refuses when snapshots newer than the target exist unless
  `destroy_later_snapshots` is set.
- Every caller-supplied value is validated against an allowlist grammar and
  passed as an argument vector, never a shell string. Device paths are
  `/dev/...` with no metacharacters; names follow the ZFS grammar; property
  names and values are allowlisted.
- All remote work goes through the vendored `_lib/ssh.ts` transport, which
  requires an explicit host-key policy and raises a typed error on a local SSH
  failure (exit 255) rather than mistaking it for remote output.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
