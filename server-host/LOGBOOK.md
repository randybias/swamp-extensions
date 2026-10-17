# LOGBOOK — @randybias/server-host

Maintainer notes. Not shipped; not listed in `additionalFiles`.

## Provenance

- Net-new extension (`server-host/`). No upstream extension was generic for
  this; the closest existing package is site-specific.
- The SSH transport in `extensions/models/_lib/ssh.ts` and its test are vendored
  byte-identical from the reviewed `@randybias/ssh-host` transport (source
  commit `2a9e2207f50e6d81b40b03bc5127e211a9f32714`, sha256
  `0b75423d6bb34547db43863c483de8c267efad5b675e7076ceb8e56706263e29`). The lead
  re-vendors the final reviewed copy; this extension imports only its public API
  (`exec`, `upload`, `withSession`, `SshDeps`, `Target`, `SshError`).
- Everything else is new. All remote exec and upload goes through the vendored
  transport; no `Deno.Command` appears outside it.

## Design decisions

- The armed-revert protocol is the core safety property. Both `apply_firewall`
  and `lockdown` build one ordered step stream: snapshot, upload the revert
  script, arm the `systemd-run --on-active` timer, `nft -c` pre-check, `nft -f`
  apply, read back. `planFirewallChange` calls `assertArmedBeforeApply` before
  returning, and a model-level test asserts both the step order and the order of
  emitted `ssh` command strings (`systemd-run` before `nft -f`).
- The revert script runs `nft flush ruleset` and then reloads the snapshot
  captured before the change. Flushing first restores reachability even if the
  connection was lost; reloading the snapshot returns the host to its exact
  prior firewall state. An empty snapshot means the prior state had no rules.
- `nft -c -f -` and `nft -f -` read the rendered ruleset from stdin, so no
  ruleset file is written on the host that a revert would have to clean up. The
  rendered script begins with `destroy table inet server_host`, which makes
  `nft -f` atomic and idempotent whether or not the table already exists.
- The renderer always removes the SSH port from `allow_tcp`/`allow_udp`, so a
  blanket port list can never open SSH around the management rules.
- `render_firewall` sorts CIDRs and ports and the sysctl drop-in sorts keys, so
  the same inputs always render identical bytes and hash to the same SHA-256.
  `apply_firewall` treats a matching recorded SHA-256 as a no-op and emits no
  commands. `sync` is the reconciliation method when the host changed outside
  this model.
- All remote file writes (sysctl, journald, revert script) are sudo-wrapped
  `sh -c` steps that read the content on stdin and leave the file untouched when
  its bytes already match. They do not use the transport `upload` helper, which
  writes as the login user and would fail for a non-root login writing under
  `/etc` or `/var/lib`.
- `default_policy` is fixed to `drop`. A policy of `accept` would make the SSH
  allow rules additive rather than restrictive, defeating lockdown, so the
  schema does not offer it.
- The management CIDRs gate the SSH port only, matching the spec's "SSH allow
  rule" wording; `allow_tcp`/`allow_udp` are open to every source and the SSH
  port is always stripped from those sets.
- `commit` records `committed_at` on the revert resource rather than deleting
  it, so the evidence of a cancel is retained and a second commit is a clean
  error. `get` and `sync` only treat a revert as active when `committed_at` is
  absent.
- Mutating methods with irreversible reachability impact (`apply_firewall`,
  `lockdown`) are `kind` default actions; no method is named `delete`. All
  methods are actions by swamp's default; none tombstones the model.

## Testing

- Offline gates 0-6 pass (`scripts/gates.sh --offline server-host`).

- Offline gate coverage: schema/secret/grammar, golden nftables renders,
  arm-before-apply ordering in the emitted command stream, no-op idempotency,
  `/0` without acknowledgement refused, invalid CIDR/port refused before any
  call, `nft -c` failure stops the plan before `nft -f`, strict host-key policy
  without pins refused before any spawn, commit after expiry refused, keys on
  stdin and never argv, injection on every remote-bound input.
- Fixtures are synthetic: RFC 5737 CIDRs and `example.com` / `.test` names.

## Live matrix

| Cell                      | Status   |
| ------------------------- | -------- |
| apply_base                | untested |
| apply_base idempotent     | untested |
| render_firewall           | untested |
| apply_firewall            | untested |
| commit                    | untested |
| revert fires              | untested |
| lockdown + commit         | untested |
| lockdown no-commit revert | untested |
| get/sync                  | untested |
| injection literal         | untested |

Not `stable` while any cell is `untested`.

## Review findings

Round 1 (codex astra + terra on ae4850a; ocr seats timed out):

- HIGH-1 raw SSH private key as a method argument. Fixed: methods now take
  `ssh_key_ref` (vault name + key), resolved at execution through the injected
  `resolveSecret` seam and, in production, `context.vaultService().get(...)`.
- HIGH-2 a failed ruleset probe was written as state. Fixed: `probeState` throws
  `HostOpsError` on a non-zero or truncated `nft list ruleset`, and on an
  unexpected timer-probe exit; `get`/`sync` only persist after all probes.
- HIGH-3 commit lifecycle unsafe. Fixed: `commit` probes that the timer is
  active and that the live managed table still matches the armed revert before
  cancelling; cancellation failure is fatal; committed state is written only
  after a re-probe shows the timer is gone.
- HIGH-4 rollback not atomic. Fixed: the revert script submits `flush ruleset`
  plus the snapshot as one `nft -f -` transaction, never flush-then-restore.
- MEDIUM-5 false drift. Fixed: compare canonical managed-table hashes (comments
  and `destroy table` stripped, whitespace removed), stored as `managed_sha256`.
- MEDIUM-6 non-atomic file install. Fixed: parent directory created; the temp
  file is created in the destination directory and `mv`-ed into place.
- MEDIUM-7 `kind: "action"` on all four mutating methods. Confirmed.
- MEDIUM-8 `apply_base` no-op. Fixed: steps are built only for changed
  components; an unchanged re-run emits no steps.
- MEDIUM-9 sysctl entry count bounded to 128.
- MEDIUM-10 model description added; `apply_firewall` marked DESTRUCTIVE.
- LOW-11 scripts quote every embedded path and unit.
- LOW-12 the revert script write is now kind `stage`; only the timer activation
  is kind `arm`, and the ordering invariant asserts that step.
- LOW tightness: shared grammar regexes moved to `_lib/validate.ts` and reused
  by the schemas.

Round 3 (codex astra + terra on cbe62a8):

- HIGH-1 stacked reverts. Fixed: `apply_firewall` and `lockdown` read the
  recorded uncommitted revert and probe its timer before arming; an active
  revert refuses the new change with a clear message. An identical ruleset that
  is still live is a true no-op (returning the existing token) and never arms a
  second timer.
- HIGH-2 commit race. Fixed: the restore script and the commit script take the
  same host-side `flock` lock; commit fails unless the timer is active at cancel
  time, stops the timer and any started service, and then re-probes that the
  timer is gone AND the live managed-table hash still equals the armed hash
  before recording `committed_at`. A fired revert therefore cannot be recorded
  as committed.
- MEDIUM-3 cleared managed files. Fixed: a changed `authorized_keys` or `sysctl`
  always runs the managed-file update, including an empty file, so clearing
  sticks.
- MEDIUM-4 account change. Fixed: when `admin_user` changes, `authorized_keys`
  is forced into the changed set so the new account receives the managed keys.
- MEDIUM-5 `apply_base` marked `DESTRUCTIVE.` (it replaces the managed keys).
- LOW: `LockdownArgs`/`ApplyFirewallArgs` merged into `FirewallChangeArgs`; the
  model reuses `rulesetSha256` instead of a private hash helper.

Round 4 (escalation fixer, on d4 8b292f5; findings from codex astra + terra):

- HIGH-1 persist-before-arm. Fixed: the syntax check (`nft -c`) now runs before
  anything is armed. The model writes the `revert` record the moment the arm
  step succeeds, before the apply. A definitely rejected apply disarms its own
  timer and marks the record `cancelled_at`; any other failure after arming
  (including a lost connection) leaves the timer armed and the record open.
  `commit` also finds a revert the model never recorded through the host's own
  marker.
- HIGH-2 apply vs restore. Fixed: the apply is a single script that takes the
  host lock and runs `nft -f -` only while its token is the current revert, its
  snapshot exists, it has not expired and its timer is active (exit 70-73
  otherwise). The restore holds the same lock for its whole run, so they cannot
  interleave. The apply step has a 30 s transport timeout.
- HIGH-3 timer vs service window. Fixed: arm runs under the same lock and
  refuses (exit 75) while the previous revert's timer OR service is active, or
  its files remain within 120 s of expiry; only then are dead leftovers cleared.
  The restore is a no-op unless it is still the current revert, so a late or
  superseded restore cannot overwrite newer rules. The snapshot is now taken by
  the arm step, under the lock.
- HIGH-4 per-step TOFU. Fixed with `pinHostKeys`: under `insecure_tofu` the host
  keys are scanned once per method and every step runs with strict pinning to
  them. Not done: vendoring item 2's `_lib/ssh.ts` byte-identically, as the spec
  asks; this transport keeps its own `Target`/`exec` API, so swapping it is a
  separate change that rewrites every call site and the 600-line transport
  suite.
- HIGH-5 `/0`. Fixed: `isDefaultRoute` now tests for a numerically zero prefix
  after CIDR validation, so `0:0:0:0:0:0:0:0/0`, `::/00` and `192.0.2.0/0` need
  the acknowledgement. Not covered: two halves such as `0.0.0.0/1` plus
  `128.0.0.0/1`, which also cover everything.
- LOW-6 `commit` description starts with `DESTRUCTIVE.`.
- LOW: the model now uses `isTimerActive` instead of a second timer parser, and
  `apply_firewall`/`lockdown` share one lifecycle function.
- The host scripts are exercised under a real `sh` with stub `nft`, `systemctl`
  and `systemd-run` (`armed_revert_shell_test.ts`); breaking the busy check or
  the snapshot-exists check makes those tests fail. Not exercised: real systemd
  timer behaviour, which needs the live matrix.

Round 5 (review of 99871aa):

- HIGH `/1` halves bypassed the anywhere check. Fixed: `isEffectivelyAnywhere`
  asks for `allow_ssh_from_anywhere` when a CIDR is wider than /8 (IPv4) or /16
  (IPv6), or when a family's CIDRs together cover the whole address space.
- HIGH `isCidr` accepted `2001:db8::1]/x/64` through `new URL`. Fixed: a strict
  IPv4/IPv6 parser (hex groups, one `::`, dotted tail only last); `]`, `/`, `#`,
  `@`, `%` and whitespace are refused. Callers get the parsed network too.
- MEDIUM commit fallback skipped the ruleset checks. Fixed: the arm step writes
  the managed-table hash into the host marker, and the fallback uses it, or
  refuses when it is absent.
- MEDIUM marker read hid failures. Fixed: only an absent file reads as empty; a
  read error, truncated output or an unparseable marker throws.

Round 6 (lead's requirements):

- The revert restored with `flush ruleset` from a snapshot of the whole ruleset,
  which would have wiped other software's tables (k0s, kube-proxy, CNI, Docker)
  whenever a revert fired. Fixed: the arm step snapshots only `inet server_host`
  (empty when it does not exist) and the restore is
  `destroy table inet server_host` plus that snapshot in one `nft -f -`
  transaction. The applied script already began with
  `destroy table inet
  server_host`. Tests run the scripts under `sh` with a
  multi-table `nft` stub: foreign tables survive the snapshot, the apply and the
  restore, including a table added after the apply; turning the restore back
  into `flush ruleset` fails them.
- `apply_base`: an `admin_user` change now rewrites `authorized_keys` even when
  the key list is empty, so the new account cannot keep the old keys.
- A lockdown re-run with identical inputs, after commit and with foreign tables
  in the live ruleset, is a no-op (guarded by the stored hash and the live
  managed-table hash; `changeFirewall` in `server_host.ts`).

Round 7: the arm step listed tables through `nft list tables | grep`, so a
failing `nft` read as "no managed table", the snapshot was left empty, and a
later restore would have destroyed the managed table instead of restoring it.
Fixed: the listing is captured on its own (`tables=$(nft list tables)`) under
`set -e`, so a failure aborts the arm step before the marker or the timer exist.
Tested under `sh` with an `nft` stub whose listing fails.

Round 8: live blocker found on a871a24. `resolvePrivateKey` treated
`context.vaultService` as a factory function, but swamp 20261013 passes an
object with `get` and `put`, so every real run failed at `ssh_key_ref`
resolution; the unit tests only passed because they inject `deps.resolveSecret`.
Fixed to use the object directly. New tests drive the method with a context
whose `vaultService` is a plain `{get, put}` object and no injected resolver,
and reject the old factory shape, a missing service, a service without `get` and
an empty secret without echoing any secret.

Round 9: second live blocker. The expected managed-table hash came from the
RENDERED text but was compared with the hash of nft's own listing, and nft
normalizes: one-element sets lose their braces, a /32 prints as the bare
address, and set elements and port lists are ordered numerically. So every real
commit and every identical re-apply saw "the live ruleset no longer matches".
Unit tests passed because they compared render to render.

Fixed by comparing structures read back from nft, not text:

- The probe and the verify step now use `nft -j list ...`. The managed table is
  normalized (handles and metainfo dropped, sets and single values read the
  same, addresses compared numerically, sets ordered numerically) and hashed;
  the host marker, the revert record and the no-op check all carry that
  structural hash, which `expectedManagedSha256(rules)` also computes from the
  inputs alone.
- After `nft -f`, the verify step requires the live table to equal the rendered
  rules as a structure (chains, hooks, policies, every rule, in order), so a
  wrong apply is still caught. On a mismatch the revert stays armed.
- The fixtures `_lib/fixtures/nft-real-listings.json` are real nftables 1.0.9
  listings (single CIDR, /32, numeric versus lexical order) with the addresses
  mapped to RFC 5737. Tests assert that the live text differs from the render
  and that apply, commit and an identical re-apply still succeed.
- The revert path is unchanged (it never hashes). Not covered: IPv6 sets, ranges
  and rule shapes nft might print differently on other versions; an unfamiliar
  shape fails the verify rather than passing.

Round 10 (delta review of 749819d):

- HIGH nft merges overlapping and adjacent entries of a source-address set and
  prints a union that is not prefix-aligned as a range, so the rendered elements
  and the listing differed after `nft -f`. Fixed: address sets (`saddr` and
  `daddr`) are compared as the sorted, merged intervals they cover, from bare
  addresses, prefixes and `{"range": [a, b]}` alike, on both sides. Real
  nftables 1.0.9 listings for contained, adjacent, non-aligned and same-network
  (host bits) IPv4 and a contained IPv6 case, taken in a network namespace on a
  throwaway VPS, are fixtures (RFC 5737 addresses), and a hole in a union still
  changes the hash.
- MEDIUM table flags and extra sets or maps were dropped from the normalized
  table, so a dormant or altered table hashed as clean. Fixed: flags and any
  other object of the table are part of the structure; unexpected ones fail the
  verify and change the hash.
- MEDIUM the commit tests for "timer not active" and "rules no longer match"
  answered with rendered text, so they failed on a JSON parse error. They now
  return real-shaped JSON and assert the specific messages.
- MEDIUM `destroy table` needs kernel 6.3. Fixed: the script and the revert use
  `add table` then `delete table` in the same batch, which works on older
  kernels too (applied for real on nftables 1.0.9 here; not run on a 6.1
  kernel).

Round 11 (live findings):

- `get` and `sync` returned their findings only in the method result, which
  swamp does not show. They now also write an `observation` resource per host
  (`observed_by`, revert armed, token and expiry, managed hash, drift, SSH
  exposure); no secret is in it.
- An `admin_user` change left the previous account's `authorized_keys` and sudo
  membership in place. Now the first step is a revoke of what this tool granted
  that account: remove the managed `authorized_keys`, and remove the sudo
  membership only if a marker (`/var/lib/server-host/sudo-granted-<user>`,
  written when the tool added the membership) says it did. The account stays.
  Skipped for root and for the account the run logs in with, so the management
  path cannot be cut. Tested under `sh` with stubs, and disabling it fails the
  tests. Accounts created before this version have no marker, so their sudo
  membership is not revoked (only the keys file).
