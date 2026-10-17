# Spec: P2 — `@randybias/kea-dhcp`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone running ISC Kea as a DHCP server on a Linux host.

Q3: Yes. `kea-dhcp` names the product (Kea) and the protocol (DHCP); short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `kea-dhcp` as a Kea DHCP server manager, which is what it does, and guesses wrong about nothing.

Status: approved (see `docs/CLEANROOM.md`); written from public docs only, no prior implementation consulted. The next-version scope is at the end.
RFC 2119 keywords.
Sources: ISC Kea Administrator Reference Manual (kea.readthedocs.io, 2.4/2.6
lines), Debian/Ubuntu `kea` package documentation, this repo's CONVENTIONS and
specs. Net-new; nothing outside public docs and this repo was read.

## 1. Purpose

Install and configure an ISC Kea **DHCPv4** server on a Linux host over SSH:
subnets, address pools, host reservations (MAC → IPv4), and DHCP options.
Every candidate configuration is validated by Kea itself before it reaches the
running server, applied without a restart, and — because a bad DHCP change can
strand every host that renews on the network it serves, including a management
network — applied under an **armed revert** that restores the previous
configuration unless the operator commits. Leases are readable, never writable.

Generic: interfaces, subnets, pools, reservations and options are inputs. No
network, host or MAC is baked in. DHCPv6, DDNS (`kea-dhcp-ddns`), HA and SQL
lease backends are out of scope (open question 4).

## 2. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host` byte-identical to
the reviewed copy (record its source commit and sha256 in the LOGBOOK). All
remote exec/upload goes through it: `host_key_policy` required (`strict` +
pinned `host_keys`, or explicit `insecure_tofu`); key as `ssh_key_ref` resolved
through `context.vaultService`, delivered over stdin, never argv. No
`ControlMaster`/`ControlPersist`: `commit` verifies over a genuinely new
connection.

## 3. Apply mechanism (decided)

Kea offers three ways to change a running server: edit the file and restart,
edit the file and `config-reload` (or SIGHUP), or push JSON with `config-set`.
The manual states that `config-set` on an invalid configuration **retains the
current configuration**, but that `config-reload` "can raise an error which
leaves the server in an unusable state", and that `config-set` is held **in
memory only** until written. Hence, decided:

1. The **file is the source of truth** (`/etc/kea/kea-dhcp4.conf`), so a reboot
   or package restart comes up on the committed config.
2. The live change is a **`config-set` of the exact same JSON** over the
   server's local UNIX control socket — never `config-reload`, never a restart,
   never the Control Agent.
3. **`config-write` is not used.** It writes Kea's expanded form (not our
   canonical render) and is path-restricted from 2.6.3; we write the file
   ourselves, atomically.

The model renders `control-socket` (`socket-type: unix`, path under
`/run/kea/`) into every config so it can always reach the server. It talks to
the socket with `socat` (installed by `install`); the Control Agent
(`kea-ctrl-agent`) is not installed or enabled — it is deprecated in Kea 3.0
and opens an HTTP API we do not need.

## 4. Model contract

- **Type** `@randybias/kea-dhcp`. CalVer == manifest version.
- **`globalArguments` empty.** SSH target + DHCP inputs per call.
- **State keyed by canonical target** `{host, port, user}` (host lowercased);
  one managed DHCPv4 server per host.
- **Factory with overridable deps** (transport runner, clock, sleep,
  `resolveSecret`, token generator). Unit tests render configs and assemble the
  step stream only.
- Resources: `config` (rendered sha256, Kea's own config hash, committed_at),
  `revert` (token, armed_at, expires_at, armed sha256, committed_at |
  cancelled_at | fired_at), `observation` (last `get`/`sync` probe), `leases`
  (last lease query). Lifetime and GC declared for each; `leases` short-lived
  (e.g. 7d, keep 5).
- **RULINGS convention:** `get` and `sync` are READ-ONLY with respect to the
  host but **persist their observation** as the `observation` resource, written
  only after every probe succeeds; a failed or truncated probe throws and writes
  nothing.

### Methods (every mutating one `kind:"action"`; none is named `delete`)

| Method | Kind | Description |
|---|---|---|
| `install` | action | Idempotent. Install `kea-dhcp4-server` and `socat` from the distribution, leave the service disabled until the first `apply`. Returns `{host, kea_version, installed[]}`. |
| `render` | — | READ-ONLY. Return the `kea-dhcp4.conf` JSON for the inputs, its sha256 and the step plan. Deterministic (stable key, subnet and reservation order). Touches no host. |
| `apply` | action | DESTRUCTIVE (network service). Validate, snapshot, **arm the revert**, write the file, `config-set`, verify. Idempotent: identical live hash = no-op that arms nothing. Returns `{host, revert_token, expires_at, config_sha256, verify}`; not permanent until `commit`. |
| `commit` | action | Over a fresh connection re-verify, then cancel the armed revert. Refuses after expiry, after the revert fired, or when the live config hash differs from the armed one. Returns `{host, committed:true, verify}`. |
| `get` | — | READ-ONLY. Recorded config + revert and a live probe: service state, Kea version, `config-hash-get`, sockets listening on UDP 67, revert timer state. Persists `observation`. |
| `sync` | — | READ-ONLY. Re-probe and reconcile: adopt a fired revert, report drift (file sha ≠ committed, running hash ≠ file). Never rewrites. Persists `observation`. |
| `leases` | — | READ-ONLY. Query current leases, optionally filtered by subnet id, IP or MAC (§7). Persists `leases`. Never adds, deletes or edits a lease. |
| `remove` | action | DESTRUCTIVE. Stop and disable the server and restore the package's original config file (from the first snapshot). Same armed-revert protocol; needs `commit`. Leaves the lease file. Second call is a clean no-op. |

## 5. Inputs and grammars

- `ssh` block: `host`, `port` (22), `user`, `host_key_policy`, `host_keys[]`,
  `ssh_key_ref` (sensitive), `connect_timeout_s`.
- `interfaces[]` — REQUIRED, 1–8 names, grammar `^[A-Za-z][A-Za-z0-9_.-]{0,14}$`,
  optionally `/<ipv4>` to pin the address. The wildcard `*` is **refused**. The
  interface carrying the SSH session (discovered host-side from
  `SSH_CONNECTION` via `ip -j route get`) is refused unless
  `serve_on_management_ack: true` (§11 trap: DHCP on a provider network).
- `socket_type` — `raw` (default; directly attached clients) or `udp`
  (relayed-only networks).
- `valid_lifetime_s` 60–604800 (default 3600); `renew_timer_s` /
  `rebind_timer_s` optional, renew < rebind < valid.
- `subnets[]` (≤ 64): `{id, subnet, pools[], reservations[], options[],
  valid_lifetime_s?, relay_addresses[]?}`.
  - `id` — REQUIRED integer 1–4294967294, unique. Never auto-numbered (§11).
  - `subnet` — IPv4 CIDR, network form, prefix /8–/30; subnets MUST NOT overlap.
  - `pools[]` (≤ 16) — `"a.b.c.d - a.b.c.e"` ranges or CIDRs, inside the
    subnet, excluding network and broadcast, non-overlapping.
  - `reservations[]` (≤ 1024) — `{hw_address, ip_address, hostname?}`. MAC
    `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$` lowercased, not multicast; IP inside the
    subnet; `hostname` RFC 1123 label (≤ 63) or FQDN (≤ 253). MACs and IPs
    unique within a subnet. An IP inside a pool is allowed but reported as a
    warning (out-of-pool reservations are the recommended layout).
- `options[]` (global and per subnet) — a closed allowlist, typed:
  `routers` (IPv4 list, inside the subnet when per-subnet),
  `domain-name-servers` (IPv4 list), `domain-name` (FQDN), `domain-search`
  (FQDN list), `ntp-servers` (IPv4 list), `interface-mtu` (576–9216),
  `classless-static-route` (`{prefix, router}` list). Unknown option names are
  refused; raw `code`/`data` hex is not accepted in this version.
- `revert_after_s` — default 600, bounded 120–3600.
- `canary_hosts[]` (≤ 16) — IPv4 addresses the Kea host must still reach
  (ICMP) for `commit` to succeed; optional.
- Strict `z.object`, no `.passthrough()`. Grammars are re-enforced in every
  host-side script the value reaches.

### Outputs

Typed objects as in the methods table. `verify` is `{service: pass|fail,
hash_match: pass|fail, sockets: pass|fail, fresh_connection: pass|fail,
canaries: pass|fail|skipped}`. Lease rows `{ip_address, hw_address, hostname?,
subnet_id, expires_at, state}`. No secret in any output or rendered file
(the config holds none: memfile only, no database credentials).

## 6. The armed-revert protocol (specialised from server-host/host-net)

1. **Pre-check (nothing armed):** stage the render in a temp file under
   `/etc/kea/` and run `kea-dhcp4 -t <staged>`; non-zero stops here. Then
   `config-test` the same JSON over the socket when the server is running.
2. **Refuse stacking:** an active revert timer or marker refuses the apply.
3. **Snapshot** the live file (bytes, mode, owner) and the running hash into
   `/var/lib/kea-dhcp-revert/<token>/`, under `flock`.
4. **Arm**: `systemd-run --on-active=<revert_after_s>` a restore script.
   **Persist the `revert` record before the first apply step.**
5. **Apply**: atomic write (temp + `mv`, mode 0640, owner root, group of the
   Kea service user), then `config-set` with the same JSON, then
   `config-hash-get`. A rejected `config-set` (Kea keeps its running config)
   restores the file from the snapshot, disarms its own timer and records
   `cancelled_at`.
6. **Restore** (timer fires): restore the file, `config-set` it; if the socket
   does not answer, `systemctl restart` the service as last resort; record
   `fired_at` and pass/fail in the marker.

Invariant tested offline: the timer-activation step precedes every write and
`config-set`, and the `revert` record write precedes the first apply step.

## 7. Lease query (read-only)

Preferred: the `lease_cmds` hook (`lease4-get-all`, `lease4-get-by-hw-address`,
`lease4-get`) over the control socket, rendered into the config only when
`lease_api: true` and the hook library exists in Kea's hooks directory.
Fallback (default): parse the memfile CSV (`/var/lib/kea/kea-leases4.csv` and
the `.2` file present during lease-file cleanup), collapsing the append log to
the latest row per address and dropping expired rows. The CSV parser is a pure
function with recorded, sanitized fixtures. Neither path ever writes.

## 8. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| Bad interface / CIDR / pool / MAC / option / id | Rejected by schema before any remote call. |
| Wildcard interface; management interface without ack | Refused. |
| Overlapping subnets or pools; pool outside subnet; duplicate MAC/IP | Rejected by schema. |
| `kea-dhcp4 -t` rejects the render | Stops before arming; nothing written. |
| `config-set` rejected | File restored, timer disarmed, `cancelled_at`; running config unchanged. |
| Revert already armed | Refused with the active token and expiry. |
| Not committed | Host restores at `expires_at`; `sync` records `fired_at`. |
| `commit` after expiry / after fire / hash drift | Clean error; nothing recorded as committed. |
| Canary unreachable at commit | `commit` refuses; revert stays armed. |
| `apply` idempotent | Same hash = no steps, no timer. |
| Control socket absent (service down) | `apply` starts the service on the staged-validated file under the armed revert; `get` reports `service: inactive`. |
| SSH drops after arm | Timer fires host-side. |
| Injection in any remote-bound value | Rejected by grammar; argv-quoted; literal in scripts and JSON. |

## 9. Tests (offline, increasing risk)

1. Schema/secret/license; every grammar above, bounds, uniqueness and overlap
   rules.
2. Pure mapping: golden renders (one subnet + pool; reservations + options;
   two subnets with relay; `lease_api`); render stability under input
   reordering; **arm-before-apply ordering**; lease CSV collapse (duplicate
   rows, expired rows, `.2` file).
3. Failure + adversarial: §8 rows; injection (`; rm -rf /`, `$(...)`,
   backticks, newline, quote, JSON `"` and `\`) on every input; host scripts
   under a real `sh` with stub `kea-dhcp4`, `socat`, `systemd-run`,
   `systemctl`, `flock`.
4. Packaging.

Fixtures synthetic: RFC 5737 subnets, placeholder MACs (`02:00:00:…`),
`example.com`.

## 10. Live e2e matrix (maintainer-run; throwaway VPS tagged `swamp-e2e=<run-id>`)

**Kea MUST NOT serve the VPS's provider-facing NIC.** The target builds an
isolated segment first: a veth pair (`kea0` in the root namespace with
`198.51.100.1/24`, its peer in a network namespace), and a DHCP client in the
namespace (`dhcpcd` or `busybox udhcpc`) with a fixed placeholder MAC.
Ubuntu 24.04 (distro Kea 2.4.x); a Debian 13 cell if time allows.

| Cell | Expected |
|---|---|
| install / install again | Kea + socat present; second is a no-op |
| render | matches golden |
| apply + commit | client in netns gets an address from the pool |
| apply idempotent | no steps, no timer |
| reservation | reserved MAC gets the reserved IP |
| options | client sees routers / DNS / domain as rendered |
| **revert fires** | apply a change, do not commit → previous config live again; `sync` shows `fired_at` |
| `kea-dhcp4 -t` rejection | deliberately invalid (forced past schema in a test build) → nothing written |
| commit after expiry | clean error |
| canary failure | unreachable canary → commit refuses |
| management interface refused | apply on the SSH interface without ack refuses |
| leases (memfile and lease_api) | client lease listed; filters work |
| get / sync | live state and drift reported; observation persisted |
| remove / remove again | service disabled, original config back; no-op |
| injection literal | metacharacters land literally |

Receipts into `kea-dhcp/LOGBOOK.md`. No `stable` while any cell is `untested`,
`skip` or `blocked`.

## 11. Credential policy (repo-wide policy)

The SSH key is sensitive, stdin-only, and shown only as a vault reference;
never `--json` on a run carrying it (lab 3555). The model holds no other
secret: lease backends with credentials (MySQL/PostgreSQL) are refused, and
`config-get` output (which Kea does not redact) is never returned or persisted
— only its hash.

## 12. Known traps

- **`config-reload` can leave Kea unusable on a bad file;** `config-set`
  retains the running config. Hence §3.
- **`config-set` is memory-only.** A restart reverts to the file; the file and
  the live config must always be written together.
- **Path restrictions (2.4.2 / 2.6.3 security releases and later):** the
  control socket, lease file, hooks and `config-write` targets are confined to
  Kea's own directories. Render only default paths; verify on the live host.
- **Subnet ids:** auto-numbered ids change when subnets are reordered, which
  re-associates leases and reservations. Ids are always explicit inputs.
- **DHCP on a shared/provider L2** can answer other tenants' DISCOVERs. Never
  wildcard; refuse the management NIC without ack.
- **The revert window is shorter than lease time.** Clients only see a change
  at renewal (`renew_timer`, default half the valid lifetime); a broken option
  may surface after `commit`. Recommend short lifetimes during change windows;
  canaries help only for already-addressed hosts.
- **Reserved IP inside a pool** may already be leased to another client; Kea
  will not hand it to the reserved MAC until that lease ends.
- Ubuntu runs Kea as an unprivileged service user; file group/mode must let it
  read the config. The package may start the service on install — `install`
  stops/disables it until the first `apply`.

## 13. Carry-overs

- Mutating verbs are `kind:"action"`; no method named `delete`.
- `context.vaultService` is an object with `get`/`put`; test without the
  injected resolver too.

## 14. Open questions for Randy

1. **Is an armed revert the right safety model for DHCP at all**, given lease
   timescales (§12)? Alternative: synchronous validate + `config-set` (Kea
   keeps the old config on rejection) and an explicit `rollback` action.
2. Lease query: memfile CSV parse by default, `lease_cmds` opt-in — or require
   the hook?
3. Distro Kea (Ubuntu 2.4.x / Debian 2.6.x) only, or also ISC's 3.0 packages?
4. DHCPv6 and DDNS to a Knot zone: later version, or a separate model?

## Next version scope: next

Next `kea-dhcp` version (public, beta).

- Re-vendor the canonical transport (`8f132c4329c9e64bed686731cd5a0e02980194ea`).
- Residual Mediums, all in the armed revert: the commit script stops the timer
  before the drift check; commit enables the unit before taking the lock; the
  service-active and hash re-check run outside the lock; post-claim writes sit
  outside the cleanup try, and `abortClaim` marks cancelled even when remote
  cleanup failed; `disarmAndRestore` reports "timer left armed" after a restore
  that already cleared the state file; the restore copies over the live config
  non-atomically.
- Fix the class once (one lock, one ordering, atomic restore) rather than six
  patches.
- Live in the veth lab: apply, commit, uncommitted apply reverting, a late
  commit racing the timer, remove.
