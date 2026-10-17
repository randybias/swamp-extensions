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
  `@randybias/ssh-host` on `origin/main`, git blob
  `cb61c4adfbedee0a6c9914deae52d3864d5a1afb` (ssh-host version 2026.10.17.1).
  Not edited; all remote exec and upload go through it.

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
