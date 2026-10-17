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
