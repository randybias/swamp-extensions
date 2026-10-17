# Spec: `@randybias/host-net`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone configuring a bridge, VLAN plane or MTU on a bare-metal Linux host.

Q3: No. "host" is a banned noun, "net" an abbreviation, and no system is named; it writes Netplan configuration for a Linux or OVS bridge, a VLAN plane and MTU under an armed revert. Naming audit verdict: rename to `netplan-bridge`, pending Randy's confirmation; until confirmed the published name stays `host-net`.

Q4: Not applicable (public and general).

Q5: No. A stranger cannot tell from `host-net` what system is driven or what resource is managed (alternative if non-Netplan backends are planned: `linux-host-network`). The proposed name fixes that.

Status: implemented and published (beta); the next-version scope is at the end.
Not clean-room (net-new). RFC 2119 keywords.

## 1. Purpose

Configure Linux host networking on a bare-metal host over SSH: a **bridge**
(Linux bridge by default, Open vSwitch optionally), a **storage plane** on a
VLAN-tagged subinterface, and **jumbo MTU** (typically 9000) on the physical
NIC / VLAN / bridge chain. Every change is applied under an **automatic revert
armed before anything is changed**: a host-side dead-man's switch that puts the
previous network configuration back if the operator does not confirm, over a
fresh connection, that the management path still works.

On bare metal a bad network change is the most expensive mistake there is: the
only recovery is an out-of-band console. The revert protocol from
`@randybias/server-host` (its spec, and the lessons in its LOGBOOK) is reused
and specialised here; where this spec is silent, server-host's behaviour holds.

Generic: interface names, MACs, VLAN ids, MTUs and addresses are inputs. No
host, NIC, VLAN or subnet is baked in.

## 2. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host` **byte-identical**
to the reviewed copy (record its source commit and sha256 in the LOGBOOK, as
server-host does). Do not hand-roll a transport. All remote exec and upload go
through it: `host_key_policy` required (`strict` with pinned `host_keys`, or
explicit `insecure_tofu`, which pins once per method and runs every step
strictly against that pin); the key arrives as `ssh_key_ref` (vault name + key)
resolved through `context.vaultService` (a `{get, put}` object, not a factory)
or the injected `resolveSecret` seam, and is delivered over stdin, never argv.

Each transport call is a new `ssh` process with the operator's ssh config
disabled (as the helper does). The model MUST NOT add `ControlMaster`/
`ControlPersist`: the commit verify (§5.4) depends on a genuinely new TCP
connection.

## 3. Model contract

- **Type** `@randybias/host-net`. CalVer == manifest version.
- **`globalArguments` empty.** Every method takes its SSH target and network
  inputs per call; one definition serves any host.
- **State keyed by the canonical target** `{host, port, user}` (host lowercased,
  port numeric) — never the definition name. One managed network config per
  host:port; the user is part of the evidence key only.
- **Factory with overridable deps** (transport runner, clock, sleep,
  `resolveSecret`, token generator). Unit tests render configs and assemble the
  step stream only — no host, no socket. Production export = factory with no
  overrides, as a plain `export const model = {...}`.
- Resources: `config` (backend, bridge type, rendered sha256, managed device
  set, committed_at), `revert` (token, armed_at, expires_at, armed sha256,
  committed_at | cancelled_at | fired_at), `probe` (last live link/addr/route
  digest). Declare lifetime and GC for each.

### Methods (every mutating one `kind:"action"`; none is named `delete`)

| Method | Kind | Description |
|---|---|---|
| `render` | — | READ-ONLY. Return the files the backend would write (netplan YAML, or networkd `.netdev`/`.network`) plus the ordered step plan and its sha256. Deterministic: stable key and device order. Touches no host. |
| `apply` | action | DESTRUCTIVE. Validate, pre-check, snapshot, **arm the revert**, then apply the rendered config with MTU ordering (§6) and run the verify (§7). Idempotent: identical live config = no-op that arms nothing. Returns `{host, revert_token, expires_at, config_sha256, verify}`; the change is not permanent until `commit`. |
| `commit` | action | DESTRUCTIVE. Verify over a fresh connection that the management path and (if a peer is given) jumbo path work, then cancel the armed revert. Refuses after expiry, after the revert fired, or when the live config no longer matches the armed sha. Returns `{host, committed:true, verify}`. |
| `get` | — | READ-ONLY. Return the recorded config and any revert plus a live probe: links, MTUs, VLANs, bridges (and OVS bridges), addresses, default route, revert timer state. |
| `sync` | — | READ-ONLY with respect to the host. Re-probe and reconcile recorded state with the host (adopt a fired revert, detect drift by managed-config hash); persists only after every probe succeeds. |
| `remove` | action | DESTRUCTIVE. Remove the managed devices and config files, restoring MTUs in reverse order. Same armed-revert protocol as `apply`; needs `commit`. A second `remove` with nothing managed is a clean no-op. |

Six methods. An explicit early `revert_now` is not in scope (open question 4).

## 4. Inputs (selected)

- `ssh` target block: `host`, `port` (default 22), `user`, `host_key_policy`,
  `host_keys[]`, `ssh_key_ref` (sensitive), `connect_timeout_s`.
- `backend` — `netplan` (**default**) or `networkd`.
- `bridge_type` — `linux` (**default**) or `ovs`.
- `management_interface` — name of the interface carrying the SSH session and
  the default route. REQUIRED. The model also discovers it host-side (the route
  to the SSH client from `SSH_CONNECTION` via `ip -j route get`) and refuses on
  mismatch.
- `mode` — `additive` (**default**) or `takeover` (see §8 and traps).
  `takeover` requires `management_change_ack: true`.
- `ethernets[]` — `{name | match_mac, mtu?}`. Physical NICs the config touches.
- `vlans[]` — `{id, link, name?, mtu?, addresses[], optional}`.
- `bridge` — `{name, interfaces[], mtu?, addresses[], stp?}` (optional; zero or
  one bridge per call).
- `mtu_peer` — `{address, interface}`: a peer on the storage plane used by the
  jumbo verify. Optional; without it the jumbo verify is `skipped`, not passed.
- `revert_after_s` — default 300, bounded 120–1800 (a network apply plus a
  fresh-connection verify needs more headroom than a firewall reload).
- `require_mtu_verify` — default `true`: `commit` refuses unless the jumbo
  verify passed, whenever any MTU above 1500 is configured and a peer is given.

Validation (schema, before any remote call; grammar re-enforced in every host
script the value reaches):

- **Interface / bridge names:** `^[A-Za-z][A-Za-z0-9_.-]{0,14}$` (kernel
  `IFNAMSIZ` is 16 including the NUL); not `.`/`..`; no `/`, `:`, whitespace.
  The default VLAN name is `<link>.<id>`; if that exceeds 15 characters, `name`
  is REQUIRED. Names are unique across ethernets, VLANs and the bridge.
- **MAC:** `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, lowercased; not multicast.
- **VLAN id:** integer 1–4094 (0 and 4095 are reserved). `(link, id)` unique.
  `link` MUST name a declared ethernet or an existing physical interface; it
  MAY be the management interface (single NIC + VLAN case).
- **MTU:** integer 1280–9216. A VLAN's MTU MUST be ≤ its link's MTU; a bridge's
  MTU MUST be ≤ the smallest MTU of its ports. Rendered explicitly on every
  device in the chain so no kernel default is relied on.
- **Addresses:** CIDR in host form (`198.51.100.10/24`, `2001:db8:10::10/64`),
  parsed by the strict IPv4/IPv6 parser shared with server-host (`]`, `/`, `#`,
  `@`, `%`, whitespace refused). Prefix `/0` refused. A storage-plane address
  MUST NOT overlap any address or route on the management interface.
- **No routing on the storage plane:** no `gateway4`/`gateway6`, no
  `routes: to: default`, DHCP off, IPv6 RA off (`accept-ra: false`). Routes
  other than on-link subnets are out of scope.
- **`mtu_peer.address`:** a bare IP inside one of `interface`'s subnets.
- Strict `z.object`, no `.passthrough()`. Bounded arrays (≤ 16 ethernets, ≤ 64
  VLANs, ≤ 32 bridge ports, ≤ 16 addresses per device).

### Backend choice

**Default `netplan` (networkd renderer)** for Ubuntu 24.04. Justification:
netplan is the configuration layer Ubuntu Server, its cloud images and
cloud-init all write; a host configured behind netplan's back with raw networkd
files is overridden or contradicted on the next `netplan apply` or cloud-init
render. netplan expresses all three features (bridges, VLANs, MTU) and is the
supported path to OVS on Ubuntu (its `openvswitch` support drives `ovs-vsctl`
itself), so one backend covers both bridge types. `netplan generate` gives a
syntax pre-check (the analogue of server-host's `nft -c`) and `netplan get`
shows the merged result of all files.

**Optional `networkd`** writes `.netdev`/`.network` files under
`/etc/systemd/network/` with a `90-host-net-` prefix, for hosts without netplan
(e.g. Debian). It supports `bridge_type: linux` only; `ovs` with `networkd` is
refused by schema. **Direct `ovs-vsctl` is not a backend**: OVS objects created
outside netplan would not survive a `netplan apply` reconciliation and would
need their own persistence. The model installs no packages: `bridge_type: ovs`
refuses unless `ovs-vsctl` and `openvswitch-switch` are present.

### Outputs

Typed objects as in the methods table. `verify` is
`{management: pass|fail, fresh_connection: pass|fail, default_route: pass|fail,
links: pass|fail, jumbo: pass|fail|skipped}`. No secret in any output, rendered
file or host-side script.

## 5. The armed-revert protocol, specialised to networking

The core safety property: **the management path survives, or the host restores
the previous configuration by itself.** `apply` and `remove` build one ordered
step stream; each step has a kind (`probe`, `precheck`, `snapshot`, `stage`,
`arm`, `mtu`, `write`, `apply`, `verify`).

### 5.1 Before arming

1. **Probe** live state: `ip -d -j link`, `ip -j addr`, `ip -j route`,
   management interface discovery, backend presence, OVS presence when needed.
   A failed or truncated probe throws and is never persisted.
2. **Refuse stacking:** read the recorded uncommitted revert and the host-side
   marker; if a revert timer or its service is active, or its files are within
   120 s of expiry, refuse with a clear message. An identical config that is
   live is a true no-op returning the existing token.
3. **Management guard:** classify the change against the management interface:
   none; MTU-only or adding a VLAN child (allowed); anything that moves its
   addresses into a bridge, changes its addresses or touches its routes
   (requires `mode: takeover` + `management_change_ack: true`). In every mode,
   the rendered merged config (`netplan get` on a staged copy) MUST carry the
   same default route(s) — gateway, device after enslavement, metric — as the
   live host, or the apply refuses.
4. **Pre-check:** stage the rendered files in a temp directory and run
   `netplan generate --root-dir <staged>` (networkd: `systemd-analyze verify`
   on the units is insufficient; parse and validate in the model, then check
   `networkctl` accepts them after write). A pre-check failure stops before
   anything is armed.

### 5.2 Arm (one host script, under `flock` on `/run/host-net.lock`)

5. **Snapshot**, under the lock, into `/var/lib/host-net/revert/<token>/`:
   - netplan: the whole `/etc/netplan/` directory (netplan merges every file, so
     a partial snapshot cannot be restored correctly), with modes;
   - networkd: every `90-host-net-*` file and the list of files present;
   - cloud-init: presence and bytes of the network-disable drop-in;
   - OVS: `ovsdb-client backup` of the database (evidence and manual recovery
     only) and the list of bridges/ports carrying netplan's ownership marker;
   - the live `ip -d -j link` / `addr` / `route` JSON and the default route, for
     the post-restore check.
   Every read runs on its own under `set -e`, so a failing command aborts the
   arm before the marker or timer exist (server-host round 7).
6. **Write the marker** (token, expires_at, armed config sha256, the set of
   devices this change will create, snapshot digest) and the restore script.
   These are `stage` steps.
7. **Activate the timer** — the only step of kind `arm`:
   `systemd-run --unit=host-net-revert-<token> --on-active=<revert_after_s>
   --timer-property=AccuracySec=1s /var/lib/host-net/restore.sh <token>`.
   It runs host-side and fires regardless of the SSH session.
8. **Persist the `revert` record in the model the moment the arm step
   succeeds, before any apply step.** A lost connection after this point leaves
   the timer armed and the record open; `commit`/`sync` also discover an
   unrecorded revert from the host marker.

### 5.3 Apply

9. A single host script takes the lock and proceeds only while its token is the
   current revert, the snapshot exists, the deadline has not passed and the
   timer is active (distinct exit codes otherwise). It runs the MTU raise steps
   (§6), writes the config files atomically (temp file in the destination
   directory, mode `0600` for netplan, then `mv`), then runs `netplan apply`
   (networkd: `networkctl reload` then `networkctl reconfigure <devices>`), then
   the MTU lower steps if any. The apply step has a bounded transport timeout
   (60 s): a drop mid-apply is expected to be survivable, not an error to retry.
10. A definitely rejected apply (non-zero exit before any file was replaced)
    disarms its own timer and marks the record `cancelled_at`. Any other failure
    leaves the revert armed.
11. **Verify** (§7) over a new connection; the result is returned, not
    enforced, by `apply`.

### 5.4 Commit

`commit` opens a **fresh** SSH connection to the management address with the
pinned host keys, re-runs §7, and refuses unless management, default route and
links pass (and jumbo, under `require_mtu_verify`). Then, under the host lock:
the timer is active, the live managed-config hash equals the armed sha; stop the
timer and any started service; re-probe that both are gone; only then record
`committed_at`. A fired or expiring revert can never be recorded as committed.

### 5.5 Revert fires

The restore script takes the lock for its whole run and is a no-op unless its
token is still current. It restores in **one transaction** from the operator's
point of view:

1. lower MTUs on created VLANs/bridges before their parents (§6 reverse order);
2. delete every device in the marker's created set that is absent from the
   snapshot (`ip link delete`; OVS: `ovs-vsctl --if-exists del-br` for
   netplan-owned bridges only) — `netplan apply` is not relied on to remove
   stale virtual devices;
3. swap the snapshot back into `/etc/netplan/` (stage beside it, then rename)
   and restore the cloud-init drop-in to its snapshot state;
4. one `netplan apply` (networkd: reload + reconfigure);
5. compare live default route and management addresses against the snapshot
   and write `fired_at` plus a pass/fail result into the marker for `get`/`sync`.

The restore MUST NOT restore the whole OVS database or flush interfaces it did
not create: other software (libvirt, a CNI, OVN) owns state there, the same
lesson as server-host round 6. Failure is fail-closed: the timer and files stay
for inspection, the result is recorded as `fail`, and nothing further is armed
until an operator clears it (open question 3).

**Invariant tested offline:** the `arm` step (timer activation — not the
`stage` of the script) precedes every `mtu`, `write` and `apply` step, and the
`revert` record write precedes the first apply step, in both the step list and
the emitted command strings (`systemd-run` before `ip link set ... mtu`,
`netplan apply`). A reordering is a test failure.

## 6. MTU change ordering

A VLAN or bridge cannot carry an MTU larger than its lower device, and the
backend applies devices in no guaranteed order. So the apply script sets MTUs
explicitly, in order, with `ip link set dev <dev> mtu <n>`, and persists the
same values in the config:

- **Raising:** physical NIC → bond (if present) → VLAN subinterface → bridge.
  Raised before `netplan apply`, so the backend finds parents ready.
- **Lowering:** bridge → VLAN → bond → physical NIC, after `netplan apply`
  (the restore and `remove` use this order).
- A no-change device emits no MTU step. The management interface's MTU may be
  raised only in its own step, so its brief renegotiation is isolated and
  covered by the armed revert.

The planner derives the order from the device graph, not from input order;
both directions have golden ordering tests.

## 7. Verify

Run after `apply` and again by `commit`, each over a new SSH process:

- `fresh_connection` / `management`: the new connection succeeds with the
  pinned host keys, and the management interface still holds its addresses.
- `default_route`: `ip -j route show default` equals the snapshot's.
- `links`: every managed device exists, is up (or `optional` and down without
  carrier, reported), has the rendered MTU, VLAN id and bridge membership
  (`ip -d -j link`; OVS: `ovs-vsctl list-ports`).
- `jumbo`: `ping -M do -c 3 -W 2 -I <interface> -s <mtu−28> <peer>` for IPv4
  (`8972` at MTU 9000); `ping -6 -M do -s <mtu−48>` for IPv6 (`8952`). Run a
  1500-sized ping first, so the result distinguishes "peer unreachable" from
  "path does not pass jumbo frames" (a switch at 1500 that silently drops).

## 8. Idempotency

- `render` is byte-stable for the same inputs; its sha256 is the config
  identity. `apply` with a recorded committed sha that also matches the live
  managed-config hash (canonical: comments stripped, keys sorted) emits no
  steps and arms nothing.
- `additive` mode owns exactly one file (`/etc/netplan/90-host-net.yaml` or the
  `90-host-net-*` networkd files) and the devices it created; it never rewrites
  other files. `takeover` mode additionally moves other netplan files into the
  snapshot and writes the cloud-init network-disable drop-in.
- `remove` twice: the second is a clean no-op. `sync` adopts out-of-band drift
  as drift (reported), never silently rewrites.

## 9. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| Bad name / VLAN id / MTU / CIDR / MAC | Rejected by schema before any remote call. |
| VLAN MTU > link MTU; bridge MTU > port MTU | Rejected by schema. |
| Storage plane carries a gateway, default route, DHCP or RA | Rejected. |
| Change touches management addressing without `takeover` + ack | Refused before arming. |
| Rendered default route differs from live | Refused before arming. |
| `netplan generate` fails | Stops before arming; nothing written. |
| Snapshot read fails | Arm aborts; no marker, no timer. |
| Revert already armed (stacking) | Refused with the active token and expiry. |
| SSH drops mid-apply / management path lost | Timer fires host-side; previous config restored; `sync` records `fired_at`. |
| Not committed | Host reverts at `expires_at`; `get` shows original links and MTUs. |
| `commit` after expiry or after the revert fired | Clean error; nothing recorded as committed. |
| Jumbo verify fails (path at 1500) | `apply` returns `jumbo: fail`; `commit` refuses under `require_mtu_verify`. |
| `bridge_type: ovs` without OVS installed, or with `networkd` | Refused. |
| Restore itself fails | Marker records `fail`; further applies refused until cleared. |
| Host unreachable before arm | Transport error; nothing changed. |
| Injection in any name, MAC, address, peer or token | Rejected by grammar; argv-quoted; literal in scripts. |

## 10. Tests (offline, increasing risk)

1. Schema/secret/license: sensitive `ssh_key_ref`, strict objects, bounds, the
   grammars above.
2. Pure mapping:
   - **golden renders**: VLAN-only additive on the management NIC; Linux bridge
     on a second NIC with a VLAN and MTU 9000; OVS bridge via netplan; the
     `networkd` backend's `.netdev`/`.network` set; `takeover` with the
     cloud-init drop-in; `remove`;
   - **arm-before-apply ordering**: assert the timer-activation step (kind
     `arm`, the `systemd-run` command) precedes every `mtu`/`write`/`apply`
     step, and the model's `revert` record write precedes the first apply step
     (injected runner records call order); a test that moves the arm after the
     apply or treats the `stage` step as the arm MUST fail;
   - MTU raise and lower order from the device graph, both directions;
   - verify ping sizes from MTU (IPv4 −28, IPv6 −48).
3. Failure + adversarial: every §9 row; injection (`; rm -rf /`, `$(...)`,
   backticks, newline, quote) on every remote-bound input; host scripts run
   under a real `sh` with stub `ip`, `netplan`, `networkctl`, `systemd-run`,
   `systemctl`, `ovs-vsctl`, `ovsdb-client`, `flock`, proving: lock-busy refusal,
   superseded restore is a no-op, restore deletes only created devices and
   leaves a foreign OVS bridge and a foreign VLAN intact, a failing probe aborts
   the arm.
4. Packaging.

Fixtures synthetic: RFC 5737 addresses (`198.51.100.0/24` storage,
`192.0.2.0/24` management), `2001:db8::/32`, placeholder MACs, `example.com`.

## 11. Live e2e matrix

Target: a throwaway bare-metal host, Ubuntu
24.04, **with working out-of-band console confirmed before any destructive
cell** (the revert is the plan; the console is the backstop). Single NIC +
tagged VLAN is the minimum; the switch port MUST trunk the storage VLAN. Cells
marked **peer** need a second host (or a peer address) on the storage VLAN with
MTU 9000; cells marked **2nd NIC** need a second physical NIC. If only one host
exists, **peer** cells are `blocked`, never `skip`-as-pass.

| Cell | Needs | Expected |
|---|---|---|
| render | — | matches golden for the live inputs |
| apply VLAN + MTU 9000 (single NIC), commit | — | VLAN up, MTUs set, default route unchanged, revert cancelled |
| apply idempotent | — | no steps, no timer |
| **revert fires** | — | apply, do not commit → after `revert_after_s` the original links/MTUs are back; `sync` shows `fired_at` |
| SSH drop mid-apply | — | kill the session after arm → host restores; reconnect succeeds |
| management lockout (takeover, deliberately wrong address) | console | path lost → revert restores reachability without console |
| stacking refused | — | second apply while armed is refused |
| commit after expiry | — | clean error |
| Linux bridge on VLAN, single NIC | — | bridge carries the VLAN, MTU 9000 |
| Linux bridge on second NIC | 2nd NIC | bridge up with port at 9000 |
| OVS bridge (netplan) + commit + revert-fires | 2nd NIC or VLAN port | OVS bridge present, then removed by revert; foreign OVS bridge untouched |
| `networkd` backend apply/commit | — (or a non-netplan host) | files rendered, devices up |
| jumbo verify pass | **peer** | `ping -M do -s 8972` succeeds |
| jumbo black-hole detected | **peer** + switch port at 1500 | `jumbo: fail`, commit refuses |
| reboot after commit | — | config persists; boot not delayed by wait-online |
| cloud-init re-render on reboot | — | additive file still effective; takeover drop-in holds |
| get / sync | — | reflect live state, including drift |
| remove, remove again | — | devices gone, MTUs lowered in order; second is a no-op |
| injection literal | — | metacharacters land as literal argv |

Receipts (content hash, cell, result, timestamp) into `host-net/LOGBOOK.md`. No
`stable` while any cell is `untested`, `skip` or `blocked`.

## 12. Known traps

- **`netplan apply` vs `netplan try`.** `try` has its own rollback, but it is a
  foreground interactive process tied to the session, and its documentation
  lists changes it cannot revert (virtual devices such as bridges and bonds).
  The model never uses `try`; it uses `netplan generate` as the pre-check and
  `netplan apply` under its own host-side timer. `netplan apply` may bounce
  links (including the management NIC) — expected, covered by the revert.
- **netplan merges every file in `/etc/netplan/`** in lexical order; a later
  file overrides keys of an earlier one. Hence a whole-directory snapshot, a
  single owned `90-` file in additive mode, and `netplan get` on the staged
  merged result before arming. netplan warns on world-readable files: write
  `0600`.
- **`netplan apply` does not reliably delete virtual devices** removed from
  config; the restore and `remove` delete created devices explicitly.
- **cloud-init re-renders network config.** On cloud-style images cloud-init
  writes `50-cloud-init.yaml` and can rewrite it on boot or instance change. In
  additive mode leave it alone and override only MTU on shared NICs from the
  later file; in takeover mode write
  `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg`
  (`network: {config: disabled}`) and snapshot/restore it with the rest.
- **`systemd-networkd-wait-online`.** A storage VLAN without carrier or a peer
  makes boot wait (default timeout two minutes) for a device that will not come
  up. Storage-plane devices are rendered `optional: true` (networkd:
  `RequiredForOnline=no`).
- **Never touch the management interface's default route.** No gateway, DHCP
  route or IPv6 RA on the storage plane; the rendered default route must equal
  the live one; enslaving the management NIC into a bridge moves its addresses
  and route with it and requires `takeover` + ack.
- **networkd will not change a netdev's kind or VLAN id in place**; such a
  change requires deleting the device first (planned as delete + create under
  the same armed revert).
- **Jumbo frames need the whole path.** A host at 9000 behind a switch at 1500
  passes small pings and silently drops large ones; only the `-M do` sized ping
  catches it.
- Ubuntu 24.04 socket-activates sshd; nothing here changes the SSH port, but a
  link bounce resets the session — expected under the armed revert.

## 13. Carry-overs

- Mutating verbs are `kind:"action"`; no method is named `delete` (model
  `delete` tombstones all).
- Never capture `--json` of a run carrying the SSH key (lab 3555).
- `context.vaultService` is an object with `get`/`put`; test without the
  injected resolver too (server-host round 8).

## 14. Open questions

1. OVS revert scope: the spec restores netplan files and deletes only
   netplan-owned OVS objects this change created, never the whole ovsdb. Confirm
   that, or require a full `ovsdb-client restore` option.
2. Default `bridge_type: linux` with `ovs` optional — or should OVS be the
   default for the intended consumers?
3. A failed restore: record and stop (spec), or offer an opt-in
   `reboot_on_failed_revert` (the snapshot files are on disk, so a reboot comes
   up on the old config)?
4. Add a seventh method `revert_now` (fire the armed revert early), or leave
   that to timer expiry?
5. Live: is a second host or peer on the storage VLAN available? If not, the
   two **peer** cells stay `blocked` and the extension cannot reach `stable`.

## Next version scope: next

Next `host-net` version (public, beta).

- Re-vendor the canonical transport (`8f132c4329c9e64bed686731cd5a0e02980194ea`): stdin
  delivery, remote deadlines.
- Residual Mediums: a failed SSH connect inside `revert_now` surfaces as the
  120 s timeout instead of the connection error; the restore removes its marker
  before writing its result, so a crash in between leaves neither (write the
  result first, remove the marker last); the 120 s bound is checked only between
  SSH calls, so a hung call overruns it (remote deadline); `arm` refuses a source
  address on `lo`, on another NIC or link-local, which excludes real hosts
  (document or support); `apply` and `remove` run the forward `netplan apply`
  in-session, relying on the armed revert.
- Live on bare metal: `revert_now`, apply and commit, revert by expiry, jumbo MTU
  with a peer if the lab allows, else untested with the reason.
- If the rename is confirmed, this head becomes the `netplan-bridge` base.

## Next version scope: netplan-bridge (new package, pending rename)

New package `netplan-bridge` (public, general), pending rename.

- Blocked on Randy confirming the rename `host-net` -> `netplan-bridge` (or
  `linux-host-network` if non-Netplan backends are planned) and on the
  `host-net` version above being published (its head is the base).
- New package from that head: manifest, model type, README, LOGBOOK with the
  five naming answers and the literal declarations, `release.yaml` stanza.
- Full live matrix on bare metal under the new name: bridge, VLAN, MTU,
  `revert_now`, revert by expiry.
- Deprecate the public `host-net` versions afterwards (never delete).
