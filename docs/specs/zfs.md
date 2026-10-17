# Spec: `@randybias/zfs`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone managing ZFS pools, datasets, zvols and snapshots on a Linux host over SSH.

Q3: Yes. `zfs` names the system (ZFS) and nothing else is needed while it is the only ZFS extension (`zfs-pool` if a second one appears); short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `zfs` as a ZFS manager, which is what it does, and guesses wrong about nothing.

Status: implemented and published (beta); the next-version scope is at the end.
Not clean-room (net-new). RFC 2119 keywords.

## 1. Purpose

Manage ZFS on a Linux host over SSH: a pool, datasets, sparse zvols, snapshots,
clones and rollback. This is the twin substrate's storage layer (golden zvol +
`zfs clone` per node). Generic: devices, names and sizes are inputs; no host or
pool name is baked in.

## 2. First task: evaluate, then build

Pull and judge `@josephholsten/zfs` and `@bixu/zfs` before writing code; report
whether either covers pool+dataset+zvol+snapshot+clone+rollback over
SSH with a safe device allowlist and idempotent lifecycle. If one does, adopt
it; otherwise build per below. Escalate the adopt-vs-build call.

## 3. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host`, BYTE
IDENTICAL — do not hand-roll a transport (that is the recurring defect).
All remote exec goes through it (strict host-key policy required; key stdin).

## 4. Model contract

- **Type** `@randybias/zfs`. CalVer == manifest version. `globalArguments` empty;
  every method takes its SSH target + ZFS operands per call. State keyed by a
  canonical `{host,port,user}` + the pool/dataset name — never the definition name.
- **Factory with overridable deps** (transport spawner, clock). Unit tests
  assemble argv and parse `zfs`/`zpool` output only — no host.

### Methods (every mutating one `kind:"action"`)

| Method | Kind | Description |
|---|---|---|
| `create_pool` | action | DESTRUCTIVE. Create a pool from the named vdevs. Idempotent: if the pool exists with the same vdev set, no-op. **Refuses any device that is mounted, holds a partition in `/etc/fstab`, or is a member of the host's boot/root array** (see §6). Returns `{pool, vdevs, guid}`. |
| `create_dataset` | action | Create/update a dataset with properties; idempotent by property diff. Returns `{name, properties_changed}`. |
| `create_zvol` | action | Create a **sparse** zvol of a given size; idempotent. Returns `{name, volsize, sparse:true}`. |
| `snapshot` | action | Create a snapshot `name@tag`; idempotent (existing snapshot = no-op). |
| `clone` | action | Clone `name@tag` to a new dataset/zvol; idempotent. |
| `rollback` | action | DESTRUCTIVE. Roll a dataset back to a snapshot (destroys later snapshots unless guarded). Requires an explicit `destroy_later_snapshots` acknowledgement. |
| `get` / `sync` | — | READ-ONLY. Report pool/dataset/zvol/snapshot state. |
| `destroy` | action | DESTRUCTIVE. Destroy a dataset/zvol/snapshot; `destroy`-again on an absent target is a clean no-op. |

### Inputs (selected)

- `ssh` — transport target block (host, user, port, `host_key_policy` + pinned
  `host_keys`, key over stdin, sensitive).
- `vdevs[]` — device paths, each validated against a strict allowlist grammar
  (`/dev/disk/by-id/...` preferred; reject anything with shell metacharacters).
- names (`pool`, dataset, zvol, snapshot `tag`) — ZFS name grammar only.
- `properties{}` — bounded map of known ZFS properties.
- `volsize`, `sparse` (default true).
- Strict `z.object`, no `.passthrough()`.

### Outputs

Typed state. No secret in any output. Device/pool GUIDs are fine.

## 5. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| vdev is a boot/root/fstab/mounted disk | Refuse before any `zpool` call; typed error naming the disk. |
| create_pool idempotent | Existing pool, same vdevs → no-op. |
| destroy absent | Clean no-op. |
| rollback without ack when later snapshots exist | Refuse. |
| injection in device/name | Rejected by grammar; argv-quoted (exec vector, never a shell string). |
| SSH transport failure | Typed error (from the vendored transport's exit-255 handling); no state written. |
| zpool/zfs non-zero exit | Surfaced as a typed error; no success state written. |

## 6. Safety (mirror the cephadm wipe lesson)

Before `create_pool`, enumerate each candidate vdev's role: reject anything
mounted, listed in `/etc/fstab`, or a member (including inactive/degraded) of the
host's boot/root md or ZFS array. Build an explicit protected-device set and
preserve it across re-reads. A disk-eating primitive must never be able to take
the boot device.

## 7. Live e2e matrix (needs a bare-metal box with ≥2 spare disks)

Live cells are **blocked** until a bare-metal target is provisioned (Cherry, two
disks, `os_partition_size` leaving the second disk unallocated — see cherry
LOGBOOK). Build and offline-gate everything; mark live cells `blocked` (not skip)
and record in LOGBOOK. When a target exists:

| Cell | Expected |
|---|---|
| create_pool / idempotent | pool present once |
| create_dataset + props | dataset with properties |
| create_zvol sparse | sparse zvol, refquota as set |
| snapshot / clone / rollback | lifecycle works; rollback destroys later snaps only with ack |
| boot-disk refusal (negative) | refuses a protected device |
| destroy / destroy-again | gone; second is a clean no-op |
| transport failure | typed error, no state written |

Receipts into `zfs/LOGBOOK.md`.

## Next version scope: next

Next `zfs` version (public, beta).

- Re-vendor the canonical transport (`8f132c4329c9e64bed686731cd5a0e02980194ea`).
- Deferred features from this spec: `import_pool`, and a `mountpoint` property
  on `create_dataset`.
- Guard: protect any pool that backs a mounted path under the system (not only
  the listed paths); keep "cannot decide" as refuse.
- Live on bare metal with an md root: guard refusals, import, mountpoint,
  destroy, export, in one batch so the server is deleted within the hour (same
  batch as `libvirt`).
