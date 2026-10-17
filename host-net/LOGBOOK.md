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
