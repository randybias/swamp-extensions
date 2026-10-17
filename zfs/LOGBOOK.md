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

## Shared boot-disk guard (final)

- The four round-2 CRITICALs are fixed by the shared guard, not by local logic.
  `_lib/protected_devices.ts` and `_lib/protected_devices_test.ts` are vendored
  byte-identical from `b2/cephadm` at commit `8798f32` (the final signed-off
  shared module, also vendored by cephadm). `git hash-object` of the module is
  `2a2592a40f3d234977cb520f05f8e8d7fc23b743`; it is not edited here.
- `_lib/safety.ts` now holds only the probe runner. `collectProbes` runs the
  module's fixed probe set over the vendored `_lib/ssh.ts`; `lsblk`, `blkid`,
  `mdadm --examine`, `zpool status -P` and `pvs` run privileged with
  `sudo -n --`, while `findmnt`, the device-link table and the file reads do
  not. A sudo refusal is a typed `boot-unverifiable` error. `assessProtected`
  calls `assess(probeInputs, candidates, previous?)` and maps any refusal to a
  typed `DeviceGuardError` naming the device.
- `create_pool` runs `assessProtected` and then re-runs it immediately before
  `zpool create`, passing the previous set so it can only grow. The model has no
  boot-disk decision logic of its own.
- Model-level `create_pool` tests drive the shared module end to end: boot disk
  by-id, root-on-ZFS by-id (`rpool`), an fstab `UUID=` disk, a multi-parent LV,
  a faulty md member with combined `(W)(F)` flags, and the twin layout (a whole
  disk carrying a root md member partition is refused, while a new free sibling
  partition is allowed both plain and by-id), plus a spare-disk allow. The
  shared module's own vendored test file also runs in the gate.

## Pool lifecycle and review fixes (lane/d4-zfs)

- Re-vendored the shared boot-disk guard `_lib/protected_devices.ts`
  **byte-identical** from lane/b2-cephwipe `8729580` (git hash-object
  `62743884da58660bac32df914fd6577f269280e5`), plus its `boot_fixtures.ts` and
  `protected_devices_test.ts`. `_lib/safety.ts` now collects the guard's new
  `efi`, `efibootmgr` and `mbr` probes and maps the new `boot-partition`
  refusal.
- Added `destroy_pool` (DESTRUCTIVE; refuses while datasets, zvols or snapshots
  exist unless `recursive` is set; destroying an absent pool is a no-op) and
  `export_pool` (idempotent; `-f` to force a busy pool out).
- `zfs`/`zpool` failures now surface a sanitized reason: the last meaningful
  stderr/stdout line, control characters blanked, truncated to 300 characters —
  e.g.
  `zpool create tank failed (exit 1): cannot create 'tank': one or more
  devices is currently unavailable`.
- The vdev grammar accepts `:` so a by-id `md-uuid-<a>:<b>:<c>:<d>` path (the
  form Ubuntu writes in fstab) resolves; it is still passed only as one argv
  word and every other metacharacter is still refused.
- Host keys are strict-only with a required, non-empty `host_keys`; the model
  persists no learned keys, so trust-on-first-use is no longer offered.

## Pool-review round 1 fixes

- **System-pool refusal (HIGH).** `destroy_pool` and `export_pool` share
  `assertNotSystemPool`: before touching a pool they read `zpool get … bootfs`,
  `findmnt -J` and `/proc/swaps` and refuse with a typed `SystemPoolError` if
  `bootfs` is set, a system mount (`/`, `/boot`, `/boot/efi`, `/usr`, `/var`) is
  sourced from a dataset or zvol of the pool, or a zvol of the pool is active
  swap. Both probes must succeed; an unreadable host fails closed, and
  `recursive` never overrides this. So `destroy_pool{bpool, recursive:true}` and
  `export_pool{rpool}` are refused.
- **`export_pool` is not forced by default** (`force` defaults to false) and its
  description leads with `DESTRUCTIVE.`.
- **EFI boot entries (MEDIUM).** `safety.ts` now runs `efibootmgr -v` under
  `sudo -n --`, matching cephadm's caller of the same guard, so an unprivileged
  read cannot silently drop that protection.
- **Synthetic fixtures (MEDIUM).** The by-id test IDs are now obviously
  synthetic (`ata-ExampleDisk_SYNTHETIC0001-part3`,
  `md-uuid-00000000:11111111:22222222:33333333`).

## Pool-review round 2 fixes

- **Zvol-backed system mounts (HIGH).** `assertNotSystemPool` now resolves every
  zvol of the pool to its canonical device up front (`zfs list -t volume` +
  `readlink -f /dev/zvol/<name>`), failing closed on any readlink error or empty
  result. A system mount whose source equals a resolved `/dev/zdN`, or a
  `/dev/zdNpM` partition of one, is refused — as is a swap device equal to
  either. `mount(8)` reports `/dev/zd0`, never `/dev/zvol/<pool>/...`, so the
  old link-only check never matched a real mount. Tests use real shapes
  (`/dev/zd0`, `/dev/zd0p1`, swap `/dev/zd16`, a failing readlink).
- **Bind mounts (MEDIUM).** `mountFromPool` strips the `[...]` suffix findmnt
  appends, so a bind of `tank[/var]` onto `/var` is refused.
- **Strict findmnt parse (MEDIUM).** `parseFindmnt` throws when any node lacks a
  string target or source, or has non-array children, instead of silently
  skipping it — a malformed probe can no longer read as "no system mounts".
- **Wider system-mount set (MEDIUM).** `/var/lib` and `/var/log` are refused
  too; the remaining `/var/*` gap is documented in the README as a known limit.

## Pool-review final polish

- **dm/LVM/dm on a zvol (MEDIUM).** For every system mount source and every swap
  device, `assertNoZvolAncestor` walks `lsblk -s -n -o PATH,TYPE <dev>` and
  refuses when any ancestor is a `/dev/zdN` of the pool (so encrypted swap on a
  zvol is refused). A failed `lsblk` fails closed.
- **Strict readlink (MEDIUM).** A zvol's `readlink -f /dev/zvol/<name>` must be
  exactly `/dev/zd<digits>`; anything else refuses.
- **Nested bind suffix (MEDIUM).** The findmnt `[...]` suffix is stripped from
  the first `[` (dataset names cannot contain one), so `tank[/a[b]]` is refused.

## Live bug: swap check refused every pool on a stock Ubuntu host

`/proc/swaps` was parsed for the device only, and every entry went through
`lsblk -s`. The Ubuntu default swap is a **file** (`/swap.img`); `lsblk` exits
32 ("not a block device") on it, and the fail-closed rule then refused
`destroy_pool` and `export_pool` on every pool.

Fix: `parseSwaps` now returns `{device, type}` and the swap loop branches.

- **`file`**: a swap file is never a zvol, but its filesystem can be backed by
  one. `findmnt -n -o SOURCE -T <file>` resolves the backing source, which is
  then judged like any mount source — a dataset of the pool, a pool zvol, or a
  block device whose `lsblk -s` ancestry includes a `/dev/zdN` of the pool.
- **`partition`**: unchanged `lsblk -s` ancestry path.
- **anything else, or a failed/empty `findmnt`**: refuses.

Tests added: `parseSwaps` on the real `/proc/swaps` shapes (file and partition);
a stock `/swap.img` on `/dev/sda1` does not refuse a pool on another disk; a
swap file on a pool dataset refuses (destroy_pool and export_pool); a swap file
on `/dev/dm-0` stacked on a pool zvol refuses; an unresolvable swap file and an
unknown swap type fail closed. 157 tests.

## 2026-10-17 live e2e

Supersedes "Live end-to-end status" above. Folded from the run receipts
(`sp-20261017`); real addresses, hostnames, disk serials and ids are redacted
(`<bm1>` is the target). Every head was installed from `git archive` (tests
excluded) into a separate repo. Target `<bm1>`: Cherry bare metal, Ubuntu 24.04,
OpenZFS 2.2.2, root on md0 (sda2 + sdb2) with BIOS-boot partitions sda1/sdb1 and
the stock swap file `/swap.img`. Spare space only: a 2 GiB partition 3 at the
unallocated tail of each disk. Key as a vault reference, strict host keys,
`--input-file` only, no `--json` capture. `lsblk` was identical before and after
every run.

### First run on the pre-lifecycle head (superseded)

61 cells, 59 pass, 2 fail. Passing: create_pool re-run no-op (by-id and kernel
names) and differing vdev set refused; create_dataset with properties, re-run
no-op, single property change; create_zvol sparse, re-run no-op, byte-equal
volsize no-op, differing volsize refused; snapshot and re-run; clone, re-run,
missing snapshot and non-clone target refused; rollback latest, refused with
later snapshots, `destroy_later_snapshots`; get and sync (no drift, drift,
refresh); destroy of clone, snapshot, zvol and dataset plus every destroy-again
no-op, and typed refusals for dependents; injection refusals on every
remote-bound input (name, `$(...)`, `..`, property values, destroy target,
snapshot tag, vdev, option injection; `/tmp/e2e-pwn` absent afterwards);
transport refusals (wrong pin, wrong pin on a destructive call, pins for another
host only; no state written). Failed: create_pool on free partitions of an
md-root host (shared guard: `mdadm --examine --` rejected every device) and no
pool destroy/export method. The offline replay also found an unprotected GPT
BIOS-boot partition. All three were fixed: the shared guard (final, vendored)
and the pool lifecycle above; the by-id `:` grammar and stderr-free failure
reasons were fixed in the same round.

### Run on bc7ec1d (superseded)

| Cell                                                          | Result  | Detail                                                                                           |
| ------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------ |
| guard: create_pool `/dev/sda` (kernel name and by-id) refused | PASS    | "the device backs the running or bootable system; no pool created"                               |
| guard: create_pool `/dev/sda1` (BIOS boot) refused            | PASS    | backs the bootable system                                                                        |
| guard: create_pool `/dev/sda2` and `/dev/md0` refused         | PASS    | backs the running system                                                                         |
| guard: create_pool mixed by-id set refused                    | PASS    | a candidate is not in lsblk, safety unknown                                                      |
| guard: create_pool part3 + `/dev/sdb2` (root md member)       | PASS    | refused on sdb2                                                                                  |
| injection: pool name, vdev                                    | PASS    | schema refusal; `/tmp/zpwn` absent                                                               |
| create_pool sda3 + sdb3, then re-run                          | PASS    | pool ONLINE on both by-id part3 paths; re-run no-op                                              |
| create_dataset a, a/b; snapshot a@s1                          | PASS    | present                                                                                          |
| destroy_pool / export_pool on a plain pool, stock swap on     | FAIL    | every call refused: `lsblk -s` on the swap file `/swap.img` exits 32 and the guard fails closed  |
| (swap off) destroy_pool with children, not recursive          | PASS    | refused; pool kept                                                                               |
| (swap off) export_pool; plain `zpool import`; get             | PASS    | pool and datasets reflected                                                                      |
| system pool cells (mount at `/boot/efi`, bootfs) x4           | INVALID | setup error: `create_dataset` takes no mountpoint, so no system mount existed; redone on dfc3124 |
| (swap off) destroy_pool recursive; again                      | PASS    | pool gone; again a clean no-op                                                                   |

17 pass, 1 fail (the swap-file bug, fixed in dfc3124 above), 4 invalid.

### Final matrix on dfc3124 (stock swap file on)

| Cell                                                             | Result | Detail                                                            |
| ---------------------------------------------------------------- | ------ | ----------------------------------------------------------------- |
| create_pool sda3 + sdb3                                          | PASS   | pool ONLINE                                                       |
| destroy_pool with datasets, not recursive                        | PASS   | refused for the children, not for swap                            |
| [earlier fail] export_pool with the swap file on                 | PASS   | pool exported                                                     |
| plain `zpool import`, then get                                   | PASS   | pool and datasets reflected                                       |
| system pool: destroy_pool with a dataset mounted at `/boot/efi`  | PASS   | "/boot/efi is mounted from e2etank/sysefi"                        |
| system pool: export_pool with a dataset mounted at `/boot/efi`   | PASS   | same refusal                                                      |
| system pool: destroy_pool with bootfs set                        | PASS   | "bootfs is e2etank/a; this pool boots the system"                 |
| system pool: export_pool with bootfs set                         | PASS   | same refusal                                                      |
| [earlier fail] destroy_pool recursive on the plain pool, swap on | PASS   | pool gone                                                         |
| destroy_pool again (absent)                                      | PASS   | clean no-op                                                       |
| cleanup                                                          | PASS   | no pools, part3 removed on both disks, swap on, `lsblk` identical |

11 pass, 0 fail.

### Residuals (accepted for beta)

- The extension has no pool import method, and `create_dataset` takes no
  `mountpoint` property; the live run used plain `zpool import` and
  `zfs set mountpoint` / `zpool set bootfs` to set up those cells.
- Only exact system mount paths are protected (`/`, `/boot`, `/boot/efi`,
  `/usr`, `/var`, `/var/lib`, `/var/log`); a pool mounted at any other path,
  such as `/var/lib/docker` or `/home`, is not refused (documented in the
  README).
- A pool zvol with no `/dev/zvol` link (`volmode=none`) makes the system-pool
  guard refuse (fails closed on the readlink).
- The system-pool guard costs one ssh round trip per zvol (`readlink -f`).

## Prior art

Registry search on stable and beta (`swamp extension search`, whole-word matches
in the package name or description) for `zfs`. This extends the "Evaluation
(before building)" section above with the full hit list.

- `@josephholsten/zfs` (stable): pool sync, scrub and trim; dataset create,
  destroy and set; snapshot create, destroy and prune, over SSH with an optional
  known_hosts. No pool creation, no zvols, clones or rollback, and no
  device-refusal guard. OVERLAP, justified: the pool lifecycle, zvols and the
  boot-disk guard are the reason this extension exists.
- `@bixu/zfs` (stable): local only (no SSH); import and export, health sync,
  snapshot, prune, scrub and trim. OVERLAP, justified: no remote host and no
  pool or dataset creation.
- `@mccormick/helios` (stable): manages an illumos/Helios host, including its
  ZFS, over SSH; illumos only. NONE (adjacent).
- `@magistr/cozystack-linstor` (stable): creates ZFS-backed Linstor storage
  pools inside Cozystack through its own API; not a host-level ZFS manager. NONE
  (adjacent).
- `@mccormick/truenas` (stable): read-only VM inventory on TrueNAS SCALE through
  its JSON-RPC API; ZFS appears in the description only. NONE.

Verdict: OVERLAP, justified. Worth filing upstream (low priority): zvols,
clones, rollback and a device guard on pool creation for `@josephholsten/zfs`.
