# Spec: `@randybias/server-host`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone hardening a freshly provisioned Linux host.

Q3: No. "server" and "host" are both banned nouns and no system is named; it hardens a Linux host (packages and users, nftables firewall, SSH lockdown under an armed revert). Naming audit verdict: rename to `linux-host-hardening`, pending Randy's confirmation; until confirmed the published name stays `server-host`.

Q4: Not applicable (public and general).

Q5: No. A stranger cannot tell from `server-host` what it does to a host (`nftables-baseline` misses two of three phases; `linux-host-harden` puts a verb in a package name). The proposed name fixes that.

Status: implemented and published (beta); the next-version scope is at the end.
Not clean-room (net-new). RFC 2119 keywords.

## 1. Purpose

Take a freshly provisioned Linux host and bring it to a hardened baseline in
three phases: **base** (packages, users, sysctl, time, journald), **firewall**
(an nftables ruleset rendered from inputs), and **lockdown** (close public SSH
to an allowlist / management CIDR). Lockdown is the dangerous phase, so an
**automatic revert is armed before the change is applied** — a dead-man's
switch that restores reachability if the operator does not confirm.

No existing extension is generic for this (`@kitquiet/homelab-ingress` is
SSH+nftables but site-specific). Net new.

## 2. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host` into this
extension's `_lib/`, byte-identical to the reviewed copy. All remote exec/upload
goes through it (strict host-key policy required; key over stdin).

## 3. Model contract

- **Type** `@randybias/server-host`. CalVer == manifest version.
- **`globalArguments` empty.** Every method takes its SSH target + phase inputs
  per call. One definition hardens any host. State keyed by `host`.
- **Factory with overridable deps** (transport spawner, clock, sleep). Unit
  tests render rulesets and assemble argv only — no host, no sockets.

### Methods

| Method | Kind | Description |
|---|---|---|
| `apply_base` | action | Idempotent. Install the named base packages, create the admin user + authorized keys, apply sysctl and journald/timesync settings. Returns `{host, applied[], changed[]}`. |
| `render_firewall` | — | READ-ONLY. Return the nftables ruleset text for the given inputs. Deterministic (stable rule order). |
| `apply_firewall` | action | Idempotent. Push the rendered ruleset and `nft -f` it atomically; verify with `nft list ruleset`. **Arms the revert first** (see §4). Returns `{host, ruleset_sha256, revert_token}`. |
| `lockdown` | action | DESTRUCTIVE (reachability). Close public SSH except the management allowlist. **Arms revert first**, applies, then requires `commit` to make permanent. Returns `{host, revert_token, expires_at}`. |
| `commit` | action | Cancel the armed revert after the operator confirms the host is still reachable. Returns `{host, committed:true}`. |
| `get` | — | READ-ONLY. Current phase state: base applied?, active ruleset sha, SSH exposure, any armed revert + its expiry. |
| `sync` | — | READ-ONLY. Reconcile recorded state with the host. |

### The armed-revert protocol (the core safety property)

For `apply_firewall` and `lockdown`, in order:

1. Snapshot the current ruleset / sshd exposure.
2. **Arm** a host-side revert that restores the snapshot after
   `revert_after_s` (default 300, bounded 60–1800) **unless cancelled** —
   implemented as a `systemd-run --on-active` transient timer (preferred) or an
   `at` job; it runs even if the SSH session dies.
3. Apply the new ruleset / lockdown.
4. Return a `revert_token` and `expires_at`. The change is **not permanent**
   until `commit` cancels the timer.
5. If the operator never calls `commit`, the host reverts itself — a locked-out
   operator recovers without console access.

Invariant tested offline: **the arm step is emitted before the apply step in
the command stream**, always. A reordering is a test failure.

### Inputs (selected)

- `ssh` — transport target block (host, user, port, `host_key_policy` + pinned
  `host_keys`, key over stdin, sensitive).
- base: `packages[]`, `admin_user`, `authorized_keys[]` (public keys; not
  secret), `sysctl{}`, `timezone`.
- firewall: `management_cidrs[]` (CIDRs allowed to reach SSH/admin),
  `allow_tcp[]`/`allow_udp[]` (ports), `default_policy` (`drop`),
  `ssh_port`. Validated: CIDRs well-formed, ports bounded, no `0.0.0.0/0` on the
  SSH allow rule unless an explicit `allow_ssh_from_anywhere:true` acknowledgement.
- `revert_after_s` — see protocol.
- Strict `z.object`, no `.passthrough()`.

### Outputs

Typed objects as above. No secret in any output or in the rendered ruleset
written to the host.

## 4. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| Invalid CIDR / port | Rejected by schema before any remote call. |
| SSH allow = anywhere without ack | Rejected. |
| Revert not committed | Host auto-reverts at `expires_at`; `get` shows original exposure. |
| `commit` after expiry | Clean error; nothing to cancel. |
| `apply_firewall` idempotent | Re-apply identical ruleset = no-op by sha. |
| nft syntax error in render | Caught by `nft -c` pre-check before apply; no partial ruleset. |
| Host unreachable mid-apply | Transport error; armed revert still fires host-side. |
| Injection in user/package/port | Rejected by grammar; argv-quoted. |

## 5. Tests (offline, increasing risk)

1. Schema/secret/license.
2. Pure mapping: golden-file nftables renders (base allow set, management-only
   SSH, extra service ports); **assert arm-before-apply ordering** in the emitted
   command stream; argv has no secret, no shell-metachar interpolation.
3. Failure + adversarial: §4 rows; injection on every remote-bound input.
4. Packaging.

Fixtures synthetic: RFC 5737 CIDRs for management ranges, `example.com`.

## 6. Live e2e matrix (throwaway host, revert makes this SAFE)

Target: hourly throwaway VPS. The armed revert means a
wrong lockdown self-heals — but still test on throwaway only.

| Cell | Expected |
|---|---|
| apply_base | packages present, admin user + keys, sysctl applied |
| apply_base idempotent | no-op second run |
| render_firewall | matches golden for the live inputs |
| apply_firewall | ruleset active (`nft list ruleset`), revert armed |
| commit | timer cancelled, ruleset persists |
| **revert fires** | apply_firewall then DON'T commit → after `revert_after_s` the original ruleset is back (the headline safety test) |
| lockdown + commit | SSH reachable only from management CIDR, still reachable to us |
| lockdown no-commit → revert | public SSH restored automatically |
| get/sync | reflect real host state |
| injection literal | metacharacters land as literal argv |

Receipts into `server-host/LOGBOOK.md`. No `stable` while any cell `untested`.

## 7. Carry-overs

- Deletes/mutating verbs are `kind:"action"` (model `delete` tombstones all).
- Never capture `--json` of a run carrying the SSH key (lab 3555).
- Ubuntu 24.04 socket-activates sshd: a port change must restart `ssh.socket`,
  and the firewall phase must not strand the active session before the revert
  is armed.

## Next version scope: 2026.10.17.4

Version 2026.10.17.4 of `server-host` (public, beta).

- Transport: replace the forked `_lib/ssh.ts` with the canonical blob
  (`8f132c4329c9e64bed686731cd5a0e02980194ea`) and stream every script and secret over exec
  stdin: no remote temp files, remote deadlines on long steps, as the other
  stdin convergences did.
- Residual Mediums: an NSS lookup exit 2 during a backend outage drops an
  account from the pending-revoke set while its keys file remains; keys removal
  runs before sudo removal, so an unwritable `~/.ssh` stops the revoke half-way
  (fail closed, in one order); an `ssh_port` change can bypass the guard
  against widening SSH from management-only to open; `forget` is not idempotent
  and does not check the revert identity.
- Live: the full armed-revert matrix on a throwaway host, plus the
  identity-mismatch refusal cell that was never run.
- This head is the base for the renamed package below.

## Next version scope: linux-host-hardening (new package, pending rename)

New package `linux-host-hardening` (public, general), pending rename.

- Blocked on Randy confirming the rename `server-host` -> `linux-host-hardening`
  and on `server-host` 2026.10.17.4 being published (its head is the base).
- New package from that head: manifest, model type, README, LOGBOOK opening with
  the five naming answers and the literal `visibility:`/`audience:` lines, and a
  `release.yaml` stanza. No behaviour change.
- Live matrix re-run in full under the new name before beta.
- Deprecate the public `server-host` versions on the registry afterwards (never
  delete). Dependents (the private stack) are updated in their own items.
