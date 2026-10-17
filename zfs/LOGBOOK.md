# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17: initial model (`@randybias/zfs`, 2026.10.17.1). Net new. Layout
  mirrors the other extension: a model entry point plus `_lib/` helpers, a
  sibling `_test.ts` for every `.ts`.

## Evaluation (before building)

Neither candidate covers the required lifecycle, so the lead's call was BUILD.

- `@josephholsten/zfs` 2026.06.11.1 — SSH yes, but the host-key policy is
  `accept-new` only (a `UserKnownHostsFile` path plus
  `StrictHostKeyChecking=accept-new`); there is no strict pinned mode and auth
  relies on the caller's ssh-agent, not a key over stdin. Methods: pool
  status/sync/scrub/trim (no create_pool, no vdev input), dataset
  sync/create/destroy/set (no zvol/volsize/sparse), snapshot
  sync/create/destroy/prune (no clone, no rollback).
- `@bixu/zfs` 2026.04.23.1 — runs `zpool`/`zfs` locally through `Deno.Command`
  (global arguments `zpoolBin`/`zfsBin`), with no SSH at all.
- Neither has a device allowlist, a mounted/`fstab`/boot-array guard, a sparse
  zvol, a clone or a rollback.

## Vendored transport

- `_lib/ssh.ts` and `_lib/ssh_test.ts` are copied byte-identical from lane/d1's
  `ssh-host` extension at HEAD `70b698f` (round 7). The model calls
  `exec(deps, target, argv)` for every remote command; no transport is
  hand-rolled. Blob hash (git hash-object) of the vendored `ssh.ts`:
  `cb61c4adfbedee0a6c9914deae52d3864d5a1afb`.
- The transport requires an explicit host-key policy, loads a key into a
  short-lived ssh-agent over stdin, and raises a typed `SshError` on a local SSH
  failure (exit 255) so a transport failure is never mistaken for remote output.
  It also refuses when supplied host keys apply to no host/port, bounds captured
  output, and refuses symlink/directory upload destinations.

## Design decisions

- **globalArguments empty.** Every method takes the SSH target and operands per
  call, and state is keyed by `{host, port, user}` plus the pool/dataset name,
  so one definition serves a fleet.
- **Boot-disk safety is its own module** (`_lib/safety.ts`). It parses `lsblk`
  JSON, `/proc/mounts`, `/proc/swaps`, `/etc/fstab`, `/proc/mdstat` and
  `zpool status -P`, resolves every protected `/dev/` reference (by-id, by-uuid,
  by-partuuid) to its kernel path, then builds one explicit protected-device set
  and refuses any vdev whose family intersects it. If `lsblk` cannot be read, a
  fact read fails, or a reference cannot be resolved, the method refuses rather
  than guesses. The guard runs before `zpool create` and is skipped only when
  the pool already exists (its own vdevs are protected once it does).
  - The set is rebuilt from live facts on every `create_pool` call rather than
    trusted from a recorded snapshot. The spec's "preserve it across re-reads"
    is met within a call: the set is computed once and every candidate is
    checked against that same set. Rebuilding across calls is at least as
    protective — a device that gained a boot/array role since the last call is
    caught by the fresh read, and a fact that cannot be read refuses.
- **Argument vectors only.** `_lib/zfs.ts` builds `zpool`/`zfs` argv; the
  transport quotes each element, so a device, name or property value can never
  split into a second command. Names follow the ZFS grammar, device paths are
  `/dev/...` with no metacharacters, and property names and values are
  allowlisted.
- **Idempotent lifecycle.** `create_pool` no-ops on the same resolved vdev set
  and refuses a different one; `create_dataset` applies only the property diff;
  `create_zvol` no-ops on the same size and refuses a different one; `snapshot`
  and `clone` no-op when the target exists; `destroy` no-ops on an absent
  target. `rollback` refuses later snapshots without an explicit
  `destroy_later_snapshots`.
- **`destroy` is `kind:"action"`** so it destroys the named target and never
  tombstones the model or its other hosts.

## Fixtures

- All addresses are RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`); names are
  `example.com` or placeholders; the SSH key is a placeholder string, never a
  PEM. The safety fixtures are synthetic `lsblk`/`fstab`/`mdstat` output.

## Live end-to-end status

- Offline gates green. Every live cell is **blocked**: no bare-metal host with
  two spare disks has been provisioned. The spec requires a Cherry bare-metal
  target with `os_partition_size` leaving a second disk unallocated. Blocked,
  not skipped:
  - create_pool / idempotent — blocked
  - create_dataset + properties — blocked
  - create_zvol sparse — blocked
  - snapshot / clone / rollback — blocked
  - boot-disk refusal (negative) — blocked
  - destroy / destroy-again — blocked
  - transport failure — blocked
- Because no cell has passed, this version stays on the `beta` channel. Pin a
  tested OpenZFS version in the README only after a live pass.

## Review findings

Review round 1 (head `1cf833a`). All fixed.

- BLOCKER branch carried k0s-cluster/. Rebuilt `lane/d5` on top of `origin/main`
  with only `zfs/` and the `zfs` release.yaml stanza; the k0s history stays on
  b2's branch.
- CRITICAL `parsePoolVdevs` stopped at the first `errors:`, leaving a second
  pool (e.g. `rpool`) unprotected. It now leaves the config block and continues;
  a two-pool test (`data` then `rpool`) covers it.
- CRITICAL protected `/dev/` references were matched against lsblk paths only,
  so a `/dev/disk/by-id` vdev or fstab entry protected nothing. The model now
  resolves every protected reference with `readlink -f` and refuses when one
  cannot be resolved; `computeProtectedDevices` matches the raw path first, then
  the resolved kernel path. A by-id test covers it.
- HIGH safety fact reads failed open. `/proc/mounts` and `/proc/swaps` now
  require exit 0; `/etc/fstab` and `/proc/mdstat` may be empty only when the
  file is confirmed absent; `zpool status -P` accepts only exit 0 or the
  documented "no pools available"; anything else refuses.
- HIGH `parseMdstatMembers` missed nvme/dm/mmcblk and whole-disk members. It now
  parses each token generically, and any `linux_raid_member`/`zfs_member` device
  is protected by fstype even when its array is not assembled.
- HIGH `create_zvol` compared bytes to `10G`. Both sides are normalized to bytes
  (`volsizeToBytes`), accepting either a byte count or a literal, with a re-run
  test.
- MEDIUM `insecure_tofu` description no longer claims learned keys are pinned;
  README and schema say it trusts for one call and that `host_keys` pins.
- MEDIUM an auto-discovered pool name is validated with `assertPoolName`, and an
  empty selection is refused.
- MEDIUM protected-set rebuild documented (see the safety bullet).
- LOW README example no longer uses `--json`, and warns against it for literal
  secrets.
- LOW removed the unused `DATASET_COMPONENT_RE`.

Review round 2 (head `429276f`). The four boot-disk CRITICALs are routed to a
shared `_lib/protected_devices.ts` (b2) that zfs and cephadm will vendor
byte-identical; `safety.ts`'s decision logic will be replaced by calls into it
and only the probe-running code kept. The guard was NOT rewritten here.

- CRITICAL (deferred to the shared module): fstab tag and md member references
  that match no lsblk row protected nothing (empty udev columns), single-value
  lsblk lookup maps lost a multi-parent holder's other parent, combined mdstat
  flags like `sdc1[2](W)(F)` were dropped, and `readFileFact` read a failed
  `test -e` as absent. The probes now capture `blkid` and per-candidate
  `mdadm --examine` output for the shared module to consume.
- MEDIUM `instanceKey` collided (`tank/a_b` vs `tank_a/b`). `_` is now escaped
  before other separators collapse, and a short hash of the raw tuple is
  appended, so distinct operands cannot overwrite each other's state.
- MEDIUM existence probes and list calls read an operational error as absent or
  empty. `zfsExists` treats only an explicit "does not exist" as absent and
  throws otherwise; `listPools` accepts only exit 0 or "no pools available";
  `readDatasets`/`readSnapshots` throw on any other non-zero exit, so `destroy`
  cannot no-op and `get`/`sync` cannot write empty state on a broken host.
- MEDIUM `create_zvol` passed when the observed size was empty or unparseable.
  It now requires a parsed size equal to the requested size and refuses
  otherwise.
- MEDIUM a by-id pool re-run falsely reported a different vdev set. Both the
  existing `zpool status -P` paths and the requested paths are resolved with
  `readlink -f` before `vdevsMatch`.
- MEDIUM `resolveDevice` passed host-fact paths to `readlink` unchecked. It now
  applies `assertDevicePath` first and fails closed on a grammar mismatch.
