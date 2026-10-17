# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

## Clean-room provenance

Built from the approved spec `docs/specs/kea-dhcp.md` (sha256
`1bd3383b8fb51d619cf563da767fb5b15706a052fc570a2f0fb55aca497eb84d`), public ISC
Kea documentation and house conventions only. No prior or ex-employer
implementation was read. The canonical transport is vendored byte-identical from
`ssh-host` on `origin/main`: `extensions/models/_lib/ssh.ts`, git blob
`fe0139f08c42e3fdae0061b9688fb5c534174957`.

## Decisions for Randy's review

The approved spec leaves open questions in §14. Where it states a decision it is
followed; where it does not, the simplest safe option was taken:

1. **Armed revert (open question 1).** Implemented as the spec body decided:
   validate, snapshot, arm a host-side timer, write, `config-set`, verify; the
   change is not permanent until `commit`. `commit` refuses after expiry, after
   a fired revert, on hash drift and when a canary is unreachable.
2. **Lease query (open question 2).** Default is the memfile CSV parser; the
   `lease_cmds` hook is opt-in with `lease_api` plus an explicit
   `lease_cmds_path`. The hook is only rendered when the loader asks for it and
   names the library; this extension does not guess an architecture-specific
   path.
3. **Distro Kea only (open question 3).** Targets the distribution package
   (`kea-dhcp4-server`, Ubuntu 24.04 / Debian), not ISC's 3.0 packages.
4. **DHCPv6 and DDNS (open question 4).** Out of scope; DHCPv4 only.
5. **Host-key policy.** The spec allows explicit `insecure_tofu`. House ruling
   4g permits TOFU only when the first-seen key is persisted and pinned later;
   this model does not persist it, so the transport is **strict-only with
   required `host_keys`**. This is the safe reading of the spec and the house
   rule.
6. **Apply idempotency.** "Identical live hash" is read as the live config
   file's SHA-256 equalling the rendered JSON's, with the service active; that
   is a no-op that arms nothing.
7. **`remove`.** Implemented as stop, disable and restore the package's original
   config (captured once by `install`). Superseded in round 1: `remove` now runs
   the full arm/verify/commit protocol (see the round-1 notes).
8. **Factory export.** The spec asks for a factory with overridable deps; the
   registry requires a plain `export const model`. The plain literal is used,
   and `setDeps` overrides the seams for tests.

## Notes

- 2026-10-17: initial release. Pure modules: `_lib/grammar.ts` (IPv4, CIDR, MAC,
  interface, FQDN, pools, options, target key), `_lib/render.ts` (deterministic
  render and the ordered apply plan), `_lib/lease.ts` (memfile CSV collapse and
  lease_cmds JSON). The model is strict zod throughout, marks `ssh_key_ref`
  sensitive and resolves it through `context.vaultService`.
- Tests: grammar/render/lease unit tests, a model test that drives the real
  plain-object context shape (including `vaultService`), the arm-before-write
  ordering, the no-op and refusal paths, and a `kea-dhcp4 -t` check on a
  rendered golden when the tool is installed.
- Live testing is the lead's slot on a throwaway VPS with an isolated veth
  segment; Kea must never serve the provider-facing NIC.

## Review round 1 (HEAD 27960f3)

Verified against real Kea `2.4.1-3ubuntu0.2` (Ubuntu 24.04). Every finding was
fixed at HEAD:

- **HIGH config-set shape.** `configSetRequest` now sends the whole object
  (`arguments: {"Dhcp4": {...}}`); the inner body answered
  `Missing mandatory
  'Dhcp4' parameter.` A test asserts the shape.
- **HIGH file group.** The group is resolved from the unit
  (`systemctl show -p User`, fallback `/var/lib/kea`), set on the staged file,
  then `mv -T` into place; a failed `chgrp`/`chmod`/`mv` fails the apply.
- **HIGH `classless-static-route`.** Dropped from the allowlist and schema: the
  stock Kea 2.4 dictionary has no definition, so `kea-dhcp4 -t` rejects it. A
  golden with every supported option is validated by the real tool.
- **HIGH management interface.** Resolved with `ip -o route get` (fallback:
  local addresses with the prefix stripped). An undeterminable interface is
  refused unless `serve_on_management_ack` is set.
- **HIGH service lifecycle.** When the service is inactive, apply starts it on
  the staged-validated file under the armed revert; `commit` enables it so a
  committed config survives a reboot. The restore script returns the service to
  its prior state.
- **HIGH restore script.** It now restores the file, returns the service to its
  prior state, decides pass/fail from the post-state (file sha, service state,
  socket answer), records `{token, fired_at, result, detail}` in fired.json,
  always clears active.json and writes a recovery note on failure.
- **HIGH commit race.** commit refuses when the revert record is missing, checks
  the fired marker and the live hash, checks the running hash and canaries,
  stops the timer (it must succeed), re-checks the race and only then clears the
  marker; `verify` is derived from the post-cancel observation and a real
  fresh-connection probe. `sync` adopts fired markers into revert records.
- **HIGH remove.** Now runs the same claim/arm/install/stop/disable protocol and
  requires `commit` (revert intent `remove`), converging disable + original
  config regardless of prior state and checking every exit code.
- **MEDIUM hook path.** `lease_cmds_path` must be an absolute `libdhcp_*.so`
  under a `hooks/` directory, and the host-side check requires the packaged
  library in the discovered hooks dir, owned by root and not group/world
  writable (a hook runs as root during `-t`).
- **MEDIUM arm failure.** Removes the token dir and active.json and records the
  revert as cancelled.
- **MEDIUM no-op/race.** The staged file is removed in `finally`; refuse-active
  and snapshot are one `flock`-serialized claim.
- **MEDIUM vault test.** A test with `resolveSecret` undefined drives
  `context.vaultService.get` and the agent (key on stdin, never argv).
- **MEDIUM lease expiry.** `lease_cmds` expiry is `cltt + valid-lft`.
- **MEDIUM privilege.** The `user` field and README now state that the remote
  user must be root; no `sudo` is used.

### Real-tool validation (2026-10-17)

Built a local `ubuntu:24.04` image with `kea-dhcp4-server 2.4.1-3ubuntu0.2` and
validated with the real tools, not just goldens:

- `kea-dhcp4 -t` accepts a golden exercising every supported option (routers,
  domain-name-servers, ntp-servers, domain-name, domain-search, interface-mtu,
  per-subnet options, relay, per-subnet lifetime) and a `lease_api` golden whose
  hook loads from the discovered hooks directory.
- Against a running Kea over the control socket, `config-set` with
  `arguments: {"Dhcp4": {...}}` answered
  `result: 0, "Configuration
  successful."`, while the inner `Dhcp4` body
  answered `result: 1, "Missing
  mandatory 'Dhcp4' parameter."` (the H1 bug,
  reproduced and fixed).
- Every rendered host script was executed under `sh -eu` (dash) in that
  container with fakes for `systemctl`/`socat`/`ip`/`ping`: management resolved
  `eth0`; group resolved `_kea`; the hook path validated `ok`; the first claim
  created active.json and a second claim exited 9; install produced
  `root:_kea 640` atomically; disarm restored the previous file and restarted;
  restore (active) recorded `result: pass` and cleared active.json; restore
  (inactive) stopped and removed the config; a forced socket failure recorded
  `result: fail` and wrote `recovery.txt`.
- The hooks directory is architecture-specific (`/usr/lib/<triplet>/kea/hooks`
  on arm64 vs `/usr/lib/kea/hooks` on amd64). Hook discovery reads the
  `kea-common`/`kea-dhcp4-server` package contents and falls back to
  `find /usr/lib -maxdepth 6 -path '*/kea/hooks/libdhcp_*.so'`.

## Review round 2/3 (HEAD 4f15006)

- **HIGH spaced result.** Real Kea answers `"result": 0`; the restore's socket
  match is now `grep -Eq '"result": *0'`, and the restore config-set answer is
  checked the same way with a `systemctl restart` fallback when it is not a 0.
- **HIGH commit/revert race.** `restore.sh` and the new `commitScript` share
  `/run/kea-dhcp-revert.lock` via `flock`. The restore exits early when a
  `committed` marker exists; the commit critical section (stop timer, re-check
  fired, check the transient `.service`/`.timer` are inactive, re-check the
  armed sha, write `committed`, clear active) runs under the same lock.
- **HIGH verify gate.** Before the commit critical section: the service must be
  active (apply), a stored `kea_hash` must exist and equal a fresh
  `config-hash-get`, `systemctl enable` must return 0, canaries must answer, and
  a fresh-connection probe must yield no `fail` verify field; otherwise the
  commit refuses and the revert stays armed.
- **HIGH failed-apply disarm.** `disarmAndRestore` now runs the uploaded
  `restore.sh` synchronously and only stops the timer, clears active and marks
  the record cancelled when `fired.json` says `pass`; otherwise the timer stays
  armed and the recovery note is surfaced.
- **HIGH commented stock config.** `remove` no longer `JSON.parse`s the captured
  original (the stock config has ~300 `//` lines); `kea-dhcp4 -t` on the staged
  copy is the validation. A test uses a commented original.
- **HIGH enabled state.** The claim records `prior.json` with
  `systemctl is-enabled`; the revert record keeps `prior_enabled`; `restore.sh`
  re-enables/disables to the prior state and checks it in the post-state.
- **MEDIUM post-claim failure.** A failure between the claim and `systemd-run`
  now removes the token dir and active.json and marks the record cancelled
  (`abortClaim`).

### Real-tool validation, rounds 2-3

- **restore.sh against a RUNNING Kea** (real `socat`, Kea's spaced answer) in
  `ubuntu:24.04` + Kea 2.4.1: `fired.json` `result: pass`, the config file
  restored to the previous sha, the running config restored (previous pool
  present, the bad pool gone via `config-get`), active.json cleared, no recovery
  note.
- **Stock config**: the packaged `/etc/kea/kea-dhcp4.conf` has 302 `//` comment
  lines and `kea-dhcp4 -t` accepts the staged copy.
- **Every host script** (`management`, `group`, `hook`, `claim`, `install`,
  `restore` active/inactive, `commit`) run under `sh -eu` with fakes: claim
  writes `prior.json`, a second claim exits 9, install is `root:_kea 640`,
  restore pass clears active, the inactive path stops and disables, a `result:1`
  socket answer triggers the restart fallback and a failed restore writes the
  recovery note, commit returns `committed`/`drifted`/`fired` correctly, and a
  restore after a commit does not revert.

## Quality pass (standing order, 2026-10-17)

One deliberate simplify/split pass after the patch rounds:

- **Split by concern.** `kea_dhcp.ts` is now only the model definition, the
  read-only methods and the public re-exports (313 lines). The rest moved to
  `_lib/`: `deps.ts` (injectable deps, `MethodContext`), `schemas.ts` (zod plus
  inferred state types and `toRenderInput`), `host_scripts.ts` (every remote
  shell body and the paths it acts on), `transport.ts` (SSH and control-socket
  I/O, typed markers, `configSetRequest`), `probe.ts` (live probe and verify),
  `apply.ts` (install/apply/commit/remove orchestration), `install.ts`. Every
  file is under 800 lines and every function under ~75.
- **Consolidated duplication.** One `refineConfig` shared by the render and
  apply schemas; one `claimAndArm` shared by apply and remove; one
  `parseFiredMarker` replacing the two fired.json readers; one `lastLine`; one
  `posixQuote` for every remote string.
- **Typed state.** `ActiveMarker`, `FiredMarker`, `VerifyResult`/`VerifyField`
  and `MethodOutcome` replace `Record<string, unknown>` and stringly results.
- **No dead code.** The unused `disarmScript` and `productionDeps` export are
  gone; the test suite now drives the model through one shared `fakeHost` runner
  instead of copy-pasted per-test matchers.

Re-validated in the real container after the split: all host scripts under
`sh -eu` pass the harness, `restore.sh` against a running Kea restores the
previous pool and records `result: pass`, `config-set` with `{"Dhcp4": ...}` is
accepted while the inner body is refused, and the stock `//`-commented config
passes `kea-dhcp4 -t`.

## Live round (VPS, HEAD 540be3c): 10/11

- **HIGH resource names.** Every resource was written under the same data name,
  so `config`, `observation` and `leases` replaced one another (an apply then a
  lease query then a commit failed with "no applied config hash is recorded").
  Each kind now has its own instance name via `_lib/schemas.ts` helpers:
  `config-<key>`, `pending-<key>`, `observation-<key>`, `leases-<key>`,
  `render-<sha256>`, `revert-<key>-<token>`, and `<method>-<key>` for action
  outcomes. A test runs apply, leases, get and commit and asserts each name.
- **MEDIUM committed vs pending.** Apply now writes a `pending-<key>` record and
  only `commit` writes the committed `config-<key>`; a commit (or a fired
  revert) discards the pending record. `sync` reports drift only against the
  committed record and not while an apply is in flight, so a fired revert is no
  longer false drift.
- **MEDIUM visibility.** `render` persists its output as `render-<sha256>` and
  install/apply/commit/remove persist their outcomes as `<method>-<key>` action
  records (RULINGS: swamp does not show method results).
- **LOW sockets.** The probe records the local socket (`ss` field 4), not the
  peer (`0.0.0.0:*`). Verified in the container: field 4 is the local
  `address:port`.
- **LOW kea_version.** Kea 2.4 `-V` prints a bare `2.4.1`; the parser now takes
  the first `x.y.z` token and is unit-tested.

Re-validated in the container after the change: the full `sh -eu` harness, the
running-Kea restore, and the config-set shape all still pass.
