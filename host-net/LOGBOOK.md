# LOGBOOK — @randybias/host-net

Item 11 (P1b) of run sp-20261017. Lane d4, branch `lane/d4-hostnet`, based on
`origin/main` (2136d7f).

## Sources

- Spec: `~/code/swamp/docs/specs/host-net.md`, plus the lead's rulings that
  override it:
  1. the revert removes only the objects this change created/owns (no whole-OVS
     or whole-network restore);
  2. `bridge_type` is required with no default (`linux` or `ovs`);
  3. a failed restore is recorded and reported, never an automatic reboot;
  4. a seventh method `revert_now` fires the armed revert immediately;
  5. no storage-VLAN peer exists, so the jumbo-ping live cells are `blocked` and
     host-net ships at `beta`.
- Registry evaluation (before building): no published extension covers bridge +
  VLAN + jumbo MTU + armed revert. `@webframp/system` is local diagnostics,
  `@shrug/vyos` configures a VyOS router (not Linux/OVS, no armed revert),
  `@mccormick/migrate` rewrites a _guest_ netplan as a migration fallback, and
  `@svendowideit/host-facts` is read-only facts. Net-new build confirmed.
- Transport: `extensions/models/_lib/ssh.ts` vendored **byte-identical** from
  `@randybias/ssh-host` (version 2026.10.17.2, lane/d1-ssh2 e3c0057), git blob
  `fe0139f08c42e3fdae0061b9688fb5c534174957`; its upload no longer puts the
  content digest on argv. Not edited; all remote exec and upload go through it.

## Layout

- `extensions/models/host_net.ts` — factory, schemas, the seven methods.
- `_lib/validate.ts` — name/MAC/VLAN/MTU/CIDR grammars, the MTU chain and the
  storage-vs-management overlap check; `deviceGraph`.
- `_lib/render.ts` — deterministic netplan YAML and networkd
  `.netdev`/`.network` renderers, the created/managed device sets and the config
  sha256.
- `_lib/plan.ts` — the ordered step stream, MTU raise/lower order and
  `assertArmBeforeApply`.
- `_lib/probe.ts` — the probe argv vectors and the `ip -j` parsers.
- `_lib/revert.ts` — the marker JSON, the restore script and the arm/disarm
  argv. The restore is token-guarded under `flock`, deletes only the created
  devices, restores the managed files from the snapshot and records `fired_at`.
- A sibling `_test.ts` for every file.

## Decisions

- arm-before-apply is enforced structurally: the `arm` step is the `systemd-run`
  activation and `assertArmBeforeApply` fails if any `mtu`/`write`/`apply`/
  `delete` step precedes it, or if the `stage` step is passed off as the arm.
- `apply` arms (uploads the restore script and marker, runs the arm script under
  `flock`, persists the `revert` record) **before** uploading any config file,
  running any `mtu` step or `netplan apply`. `remove` follows the same protocol.
- The config sha256 is over `path\0mode\0content` for every rendered file, so an
  identical config is a stable identity.
- The restore script never restores the whole OVS database and never runs
  `ovsdb-client`; it deletes only netplan-owned OVS bridges in the created set.
- `ssh_key_ref` is sensitive and resolved through the injected `resolveSecret`
  or `context.vaultService`; the key reaches the transport over stdin, never
  argv. Host scripts interpolate only grammar-validated names.

## Gates

`scripts/gates.sh --offline host-net` gates 0-6 pass; 74 unit tests. Gates 7-8
are skipped offline. The live e2e matrix is the lead's slot: the peer-dependent
jumbo cells are `blocked` (no storage-VLAN peer), so host-net stays at `beta`.

## Round-1 review (armed-revert lifecycle)

Adapted the server-host hardened pattern (lane/b3 `bc9992d`) rather than
rediscovering it:

- **CRITICAL** — `run()` now throws on any non-zero exit. The arm script's
  refusal codes (75/76) abort before any mutation; a failed mtu/write/apply/
  delete throws and leaves the revert armed. A test makes the arm answer 76 and
  asserts no later command is sent and no record is written.
- **HIGH** — the arm is one self-contained host script: it `mkdir`s the state
  dir, takes the `flock`, refuses while an earlier timer or service is active
  (or within the 120 s firing grace), snapshots only the owned files, writes the
  per-token restore script and the current marker, then starts the timer. The
  fixed-path upload-before-mkdir and restore-script-overwrite bugs are gone.
- **HIGH** — one field spelling: `committedAt`/`firedAt`; stacking refuses only
  a pending, unexpired record.
- **HIGH** — `commit` refuses after expiry, after the revert fired, when the
  host marker is no longer this token, or when the live managed-file content
  digest differs from the armed digest; it then runs the require-active disarm
  and checks its exit before recording `committedAt`.
- **HIGH** — the management interface may not be a bridge member or have its MTU
  changed unless `mode: takeover` and `management_change_ack: true`.
- **HIGH** — the restore restores only the owned files, runs under a trap that
  records `result=fail`, requires a non-empty default route, deletes created
  devices bridge-first and restores the pre-change parent MTUs.
- **HIGH** — `created` is declared minus pre-existing live devices; a declared
  name that exists but is unowned is refused; only that set is deleted.
- **HIGH** — the restore and `revert_now` are token-checked (`TOKEN_RE`, and the
  script exits non-zero unless `$1` equals its embedded token); `revert_now`
  requires a pending record with that token.
- **MEDIUM** — MTU raise steps are existing parents only (created devices get
  their MTU from the renderer); disarm uses `flock` and stops the timer and
  service; `remove` checks stacking, no-ops when nothing managed is live,
  deletes the bridge before its ports and says `commit_required`; YAML scalars
  are quoted; the plan's precheck is a staged `netplan generate` before arming;
  the verify compares the live `ip -j` read-back to the pre-apply probe, never
  the rendered text.
- **LOW** — `netplan try` is not used: it is foreground/session-bound and its
  docs list virtual devices it cannot revert; the model uses `netplan generate`
  as the pre-check and `netplan apply` under its own timer. In `additive` mode
  cloud-init is left alone (only the `90-` file overrides MTU); `takeover` mode
  writes and snapshots the network-disable drop-in.

The `context.vaultService` path is now driven as a plain `{get(vault,key)}`
object in a test, with `resolveSecret` left undefined.

80 unit tests; gates 0-6 pass offline. Live jumbo cells remain `blocked`.

## Round-2 review

- **HIGH** — the arm script wrapped `shellQuote(restorePath)` in double quotes,
  so every live arm would `cat` a path with literal apostrophes and abort under
  `set -e`. The quoted paths are now bare at `cat`, `chmod`, `systemd-run` and
  the rollback `rm`; a regression test asserts no double-wrapped restore path.
- **HIGH** — ownership is persisted: the revert record stores `created`, the
  config record stores the owned `devices`, and `apply`/`remove` read ownership
  only from the config record. An identical live config (recorded content sha
  matches and every owned device is present) arms nothing; a declared name that
  exists but is unowned is refused. Tests cover apply-after-commit and
  remove-of-unowned.
- **HIGH** — the revert record stores the `operation`; commit of a `remove`
  verifies the owned files are absent and the recorded devices are gone, then
  clears the config record, instead of trying to `cat` deleted files.
- **HIGH** — the snapshot records exactly `ctx.ownedFiles` with a present/absent
  manifest and the restore replays only those, so a takeover drop-in is
  snapshotted and networkd no longer copies netplan YAML.
- **MEDIUM** — the restore treats `[]` as no default route and keeps the marker
  on failure; the arm refuses (76) while an old marker says `fail`; config files
  are uploaded to the revert dir and moved into place inside the guarded apply
  (removed on a guard refusal); `revert_now` requires a pending unfired record
  and reads the host marker result; the management guard resolves `match_mac`
  against the live probe; every interpolated YAML scalar is quoted; networkd
  `MTUBytes` moved to `[Link]`; commit reports `jumbo: not-verified` when a peer
  is configured.
- **LOW** — `flock -w 30` everywhere so a held lock exits non-zero instead of
  blocking; the dead `armArgv`/`revertNowArgv`/`disarmArgv` builders are gone.
- 83 unit tests; gates 0-6 pass offline. Live jumbo cells remain `blocked`.

## Round-3 review (ownership and desired state, single-sourced)

Design invariants (also a comment block in `host_net.ts`):

- The `config` record holds the FULL owned set (`devices`, `ownedFiles` with a
  `preExisted` flag, `parentMtus`) and is written **only at commit**, never by
  one apply's delta.
- An apply computes `owned = (previous owned ∩ declared) ∪ created` and parks it
  in the pending `revert` record; a reverted apply leaves committed ownership
  untouched.
- The identical-config no-op compares the **live read-back against the NEW
  desired render**, and only when that render is the committed one — so an edit
  (netplan MTU change, networkd add-unit) is never silently ignored.
- `remove` derives every device, file and MTU from the `config` record alone,
  proceeds when only files/MTUs are owned (an MTU-only apply), and never removes
  a file recorded as pre-existing.

Other fixes: config files stage as `<path>.host-net-new` in the target dir; MTU
commands run inside the guarded apply/remove; remove-commit prints
present/absent via `run()` (an ssh 255 is not absence); the match_mac guard also
refuses enslaving the management NIC into a bridge; the restore restores files
before MTUs and aborts on a `cp` failure; `revert_now` records a failed restore
before throwing. Tests cover apply A, A+B, B-only, MTU-only apply→remove, and a
match_mac bridge member. 88 unit tests; gates 0-6 pass offline.

## Round-4 review (escalated to a second author)

Proven first in a fake-host simulation (a real `sh` with stub `ip`, `netplan`,
`networkctl`, `systemctl`, `systemd-run`), now permanent in
`host_net_sim_test.ts` (needs `sh` and `python3`; it skips itself without them).
Every one of those tests fails on the previous round's code.

- **HIGH file provenance flipped.** Each commit took `preExisted` from that
  apply's own snapshot, so files host-net wrote in apply A looked pre-existing
  by A+B and `remove` left them behind (netplan re-created the devices).
  Provenance is now FIRST-SEEN: a path already in the committed record keeps its
  flag.
- **HIGH parent MTU baseline lost.** A second commit saw the NIC already raised
  and recorded 9000 as the baseline, so `remove` left it at 9000. The baseline
  is now the ORIGINAL pre-change value; a parent stays recorded while it is
  managed.
- **HIGH dropped VLAN left unowned.** Dropping a declared device relinquished
  ownership without deleting it, so re-adding it was refused as foreign. A
  device that was owned and is no longer declared is now deleted at apply, under
  the armed revert and the apply guard, and the files host-net created for it
  are removed; both are in the arm snapshot so a fired revert restores them, and
  `commit` refuses unless they are really gone.
- **MEDIUM takeover precheck.** The staged root now has `etc/cloud/cloud.cfg.d`,
  so the cloud-init drop-in uploads (it failed safe).
- `ssh.ts` resynced; the unit-test fake answers the upload helper's
  hash-and-mode read-back like a host that stored the bytes.

## Round-5 (two live bugs on a real host; strict-only host keys)

- **Keyless ethernet rendered as a null mapping.** `"enp7s0":` with no settings
  is a null, which netplan 1.1 rejects ("expected mapping"). It now renders as
  `"enp7s0": {}`, which netplan accepts and merges with the same NIC defined in
  another file. Omitting the NIC was not an option: a VLAN's `link` must be
  defined in the merged config. The management NIC may still be a VLAN link
  without being declared.
- **The pre-check staged only our file.** A VLAN on a NIC that cloud-init's file
  defines failed `netplan generate` ("interface enp7s0 is not defined"). The
  staged root is now a copy of the whole live `/etc/netplan` (names, order and
  modes kept) with the rendered file on top, so the parser sees the merge the
  apply will.
- **Real-parser tests.** `_lib/netplan_real_test.ts` runs every netplan render
  (keyless NIC, MTU-only/takeover, no-carrier NICs, MAC match, Linux bridges,
  two VLANs) and a two-file case (cloud-init's file defining the NIC and the
  provider VLAN, ours with only the VLAN) through `netplan generate --root-dir`.
  Without netplan they are reported as ignored, not passed. A guard test checks
  that the parser still rejects the old output.
- **Host keys are strict-only.** The model does not persist a first-seen key, so
  `insecure_tofu` is gone and `host_keys` is required (at least one) on every
  method.

## Round 6 (live finding)

- The restore's `netplan apply` exit status is advisory (logged); pass or fail
  rests on the post-restore checks (default route and a global address on its
  interface). Found live: a cloud-init netplan matching a renamed NIC by MAC
  made `apply` exit 1 on a host that was restored, so the EXIT trap wrote `fail`
  and fail-closed every later apply.
- New `clear_failed_revert` action (refuses unless the marker is `fail` and the
  checks pass now); recovery documented in the README.
- Sim tests: apply exits 1 with passing checks gives `pass` and clears the
  marker; failing checks give `fail`, block until cleared, and the clear refuses
  until the checks pass.
- Round 6 review fixes: the post-restore checks now require a default route
  through the management interface and every pre-change management address on it
  (recorded at arm time in `checks.sh`, also used by `clear_failed_revert`); the
  restore installs its EXIT trap only after the token, lock and superseded
  checks, so a refused call never writes the marker; `clear_failed_revert`
  updates only the record whose token it cleared and converges on a retry;
  README gives the by-hand clear without a blanket `rm -rf`.
- Round 6 review 2: the post-restore checks follow the path actually used (peer
  address, device, gateway, source, prefix length; both families) instead of an
  IPv4 default route, so a management NIC off the default route and IPv6-only
  management restore as `pass`, while a lost IPv6 path under working IPv4 is
  `fail`. The arm records and self-tests the path before changing anything. The
  clear's "no marker" is exit 10 (a broken checks.sh is exit 5), and a repeated
  clear is a no-op.
