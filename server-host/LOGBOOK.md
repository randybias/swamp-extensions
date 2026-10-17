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

Live e2e 2026-10-17 (folded from the run receipts; real addresses, hostnames and
ids redacted: `<vps1>` target, `<vps2>` outside probe source, `<control-egress>`
the control host's egress /32; the other CIDRs are the RFC 5737 / test values
actually used). Every head was installed from `git archive` into a separate
repo, never the working tree. Target `<vps1>` (root, key via `ssh_key_ref` from
a local vault, strict pins), nftables 1.0.9, kernel 6.8. Management CIDRs always
included `<control-egress>`; `revert_after_s` 60-90. Outside-source probes ran
from `<vps2>` (`/dev/tcp` to `<vps1>`:22). All runs through
`swamp model method run` (no `--json` except get/sync, whose arguments carry no
secret); no private key in any output. A foreign table `inet foreign_test` (a
rule on tcp 9999) was present for the revert cells.

Earlier run on bc9992d (superseded): the revert cell passed, but commit reported
failure and the committed table did not survive (the render-vs-live comparison
bug fixed in 749819d/e7dc3f3).

### Final matrix on e17a609

| Cell                                                          | Result                    | Detail                                                                                                                                                |
| ------------------------------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 apply_base                                                  | PASS                      | user ops (sudo group), authorized_keys written, sysctl drop-in applied (`tcp_syncookies = 1`), curl present, timezone UTC                             |
| 2 apply_base identical                                        | PASS                      | 83 ms, no remote command issued                                                                                                                       |
| 3 admin_user change with an empty key list                    | PASS (superseded by 3')   | ops2 created with a 0-byte keys file; the previous account kept its keys and sudo (fixed in f66c8d0)                                                  |
| 4 single CIDR: apply, commit, identical re-apply              | PASS                      | live `ip saddr <control-egress>`; timer armed then 0 after commit; re-apply armed no new timer                                                        |
| 5 a /32 plus a second /32                                     | PASS                      | live `ip saddr { <control-egress>, 192.0.2.7 }`                                                                                                       |
| 6 numeric-vs-lexical pair plus ports                          | PASS                      | `198.51.100.64/26` + `198.51.100.128/25` listed by nft as `198.51.100.64-198.51.100.255`, ports `{ 80, 443 }`; apply verified, commit and re-apply ok |
| 7 overlapping (/16 containing a /24)                          | PASS                      | nft listed `198.51.0.0/16` only                                                                                                                       |
| 8 adjacent (two /25s -> /24)                                  | PASS                      | nft listed `203.0.113.0/24`                                                                                                                           |
| 9 lockdown                                                    | PASS                      | armed window: `<vps2>` -> :22 blocked, timer armed                                                                                                    |
| 10 fresh-connection verify                                    | PASS                      | a new process and SSH connection (`get`) works during the armed window                                                                                |
| 11 commit, survives past revert_after_s                       | PASS                      | timer cancelled; after 100 s the table is present and `<vps2>` still blocked                                                                          |
| 12 revert FIRES, apply_firewall no commit                     | PASS                      | previous managed table back, foreign table and rule intact, timer inactive, state dir clean                                                           |
| 13 stacking refused while armed                               | PASS                      | `An earlier armed revert is still active or firing`; one timer, live table unchanged                                                                  |
| 14 commit after expiry                                        | PASS                      | `The armed revert ... expired at ...; nothing to cancel`                                                                                              |
| 15 revert FIRES, lockdown no commit (no managed table before) | PASS                      | managed table gone, foreign table intact, :22 open from `<vps2>` again                                                                                |
| 16 `0.0.0.0/0` refused                                        | PASS                      | refused before any contact                                                                                                                            |
| 17 two /1 halves refused                                      | PASS                      | same refusal                                                                                                                                          |
| 18 lockdown with allow_ssh_from_anywhere refused              | PASS                      | refused before any contact                                                                                                                            |
| 19 get                                                        | PARTIAL (resolved by 19') | result not readable through the CLI                                                                                                                   |
| 20 sync                                                       | PARTIAL (resolved by 20') | same                                                                                                                                                  |
| 21 final state                                                | PASS                      | no managed or foreign table, no timers, no state dir, test users and drop-ins removed                                                                 |

19 pass, 0 fail, 2 partial.

### Re-run cells on f66c8d0, 2aade6d, 0cfe601

| Cell                                                                   | Result | Detail                                                                                                   | Head    |
| ---------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------- | ------- |
| 19' get persists an observation (armed window)                         | PASS   | `swamp data query` shows revert_armed=true with token and expiry, drift [], ssh_exposure management-only | f66c8d0 |
| 20' sync persists an observation (after the revert fired)              | PASS   | revert_armed=false, drift ["ruleset","revert_fired"]; after a commit managed_table=true, drift []        | f66c8d0 |
| 3' admin_user change revokes the previous account                      | PASS   | old account: keys file removed, sudo and marker removed, account kept; new account: keys, sudo, marker   | f66c8d0 |
| 22 only `strict` accepted, host_keys required                          | PASS   | `insecure_tofu` and missing host_keys rejected by validation; nothing contacted                          | 2aade6d |
| 23 logging in AS the previous admin defers the revoke                  | PASS   | old admin keeps keys and sudo for now; state records pending_revoke                                      | 2aade6d |
| 24 the next run completes it                                           | PASS   | root login: keys, sudo, marker removed, pending list cleared; old admin can no longer log in             | 2aade6d |
| 25 symlinked ~/.ssh is left alone                                      | PASS   | decoy file intact, sudo still removed, account stays pending                                             | 2aade6d |
| 26 observation lists pending_revoke, ssh_exposure unknown on drift     | PASS   | `{"drift":["ruleset","revert_fired"],"ssh_exposure":"unknown","pending_revoke":[...]}`                   | 2aade6d |
| 27 firewall smoke: apply + commit + identical re-apply                 | PASS   | range + ports listed by nft; re-apply armed no timer                                                     | 2aade6d |
| 28 lockdown no commit -> revert fires                                  | PASS   | previous table restored, no timers                                                                       | 2aade6d |
| 29 revoke removes keys as the account (runuser), verified sudo removal | PASS   | old admin groups [self], keys none, marker none                                                          | 0cfe601 |
| 30 final state                                                         | PASS   | no managed or foreign table, no test users, no server-host state, :22 open                               | 0cfe601 |

12 pass, 0 fail. The two earlier PARTIALs are resolved by the persisted
observation resource.

Untested live: a failing `gpasswd`, a failing `id -nG` and a failing account
lookup on the revoke path (covered only by tests under `sh` with failing stubs).
Not stable until those are exercised or ruled out.

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

Round 12 (delta review of f66c8d0, lead ruling 4g):

- HIGH revoke ignored a failing `gpasswd` and deleted its marker. Fixed: the
  marker is removed only after `id -nG` no longer lists sudo (or the account is
  gone); otherwise the step exits non-zero and the plan stops before the new
  account is granted anything, so nothing is recorded and a rerun retries.
- HIGH logging in as the previous admin skipped the revoke and forgot it. Fixed:
  `host_state.pending_revoke` keeps those accounts; the next run that logs in as
  another account revokes them first and clears the list. The observation shows
  the list.
- MEDIUM the keys removal could follow a symlinked `~/.ssh`. Fixed: it is left
  alone, with exit 3 (reported, kept pending), unless `~/.ssh` is a real
  directory owned by the account.
- MEDIUM `ssh_exposure` in the observation was the recorded intent; it is now
  `unknown` whenever drift is reported.
- Ruling 4g: `insecure_tofu` is gone. `host_key_policy` accepts only `strict`
  and `host_keys` is required (at least one), in the schema and the transport;
  `pinHostKeys` and the first-contact scan are removed.

Round 13 (delta review of 2aade6d):

- HIGH the revoke verification failed open: if `id` itself failed, no output
  meant "not in sudo" and the marker was deleted. Fixed: existence is decided
  first from `getent passwd` (exit 2 is the only "absent"; any other failure
  exits 1 with the marker kept), and for an existing account `id -nG` must
  succeed and must not list sudo. Tested with a failing gpasswd AND failing id,
  and with a failing lookup.
- MEDIUM the keys removal could race a symlink swap. Fixed: it runs as the
  account (`runuser -u USER -- rm -f`), so no root-owned path follows the
  account's links; the earlier checks remain as a cheap guard.
- MEDIUM README lockdown and commit examples lacked the now-required
  `host_keys`. Added.
- LOW comment about the revoke steps corrected.

Round 14 (merge-prep delta review of 0cfe601, base 2aade6d; codex astra and
terra seats): 0 Critical/High after verification at 0cfe601. Residuals, not
blocking beta:

- MEDIUM (astra, filed High) `getent` exits 2 whenever the lookup returns no
  entry, including an unavailable NSS backend, so the comment's "only for no
  such entry" is too strong. Downgraded: the sudo marker is only written after
  `usermod -aG sudo` succeeds, and usermod refuses accounts that are not in the
  local /etc/passwd, so every marker belongs to a local account that the `files`
  source answers. Residual: an account from a remote NSS source that got a
  managed keys file is treated as gone during a backend outage and dropped from
  pending_revoke while its keys file remains. Follow-up: on exit 2 keep the
  account pending unless /etc/passwd also lacks it, and fix the comment.
- MEDIUM (terra, filed High) the keys removal runs before the sudo removal; if
  the revoked account makes its own `~/.ssh` unwritable, `runuser ... rm` fails
  and the step stops before `gpasswd`. Downgraded: the run fails loudly with the
  account kept pending (fail-closed), and the premise is an account that still
  holds sudo, which can defeat any revoke. Follow-up: revoke and verify sudo
  first, then the keys.
- LOW (terra, filed High) an account recreated by another root actor between the
  lookup and the marker removal keeps a sudo membership with no marker.
  Downgraded under the run rulings: concurrent account management on the target
  is outside the single-orchestrator model.

2026.10.17.2: found by the first end-to-end run of the server stack on a fresh
host. With the table's `input` and `forward` policies at `drop`, a k0s node came
up Ready but its pods never did: a trace showed pod traffic from `kube-bridge`
to the node (apiserver, konnectivity) dropped by `inet server_host input` and
pod egress dropped by `inet server_host forward`, although kube-router's own
`ip filter FORWARD` accepted it. An accept in another table cannot override a
drop, so the table itself had to grow.

- New optional input `trusted_interfaces` (up to 16 names or `prefix*` patterns,
  one wildcard at the end, at least one literal character, 15 characters at
  most). Each renders as `iifname` in input and `iifname` plus `oifname` in
  forward; sorted and deduplicated. Unset or empty renders byte-identically to
  17.1, so the hash and the goldens are unchanged.
- The expected structure, the verify read-back and the drift hash include the
  forward rules. New real-nft fixtures (single interface; wildcards and dotted
  names) are listings of nftables 1.0.9 after applying the rendered script
  twice.
- `nft_real_test.ts` feeds every shape to a real `nft -c`, applies it twice and
  compares the table's JSON read-back with the rendered rules. It runs `nft`
  when present, else the container `nft-check:local` (ubuntu:24.04 plus nftables
  and netbase; without netbase `ip6 nexthdr ipv6-icmp` does not resolve), else
  it is skipped. It ran in this round.
- No forward_policy input: trusting the CNI interfaces in both directions covers
  pod to node and pod egress (checked live with the equivalent hand-added
  rules), so the forward policy stays `drop`.

Review of 16f38c5:

- HIGH `trusted_interfaces` accepted the uplink (`eth0`, `e*`, `wg*`): the
  input-chain accept comes before the SSH rules, so it would have opened every
  port and bypassed `management_cidrs`. Fixed: with any trusted interface set, a
  read-only script reports the interfaces of the IPv4 and IPv6 default routes
  and of the route to the SSH client (`$SSH_CLIENT`); an entry that matches one
  (exact, or `x*` as a prefix) is refused with a `HostConfigError` before the
  revert is armed, and a probe that fails or returns junk refuses too. `lo` and
  patterns matching it, a leading `-`, and a `*` after fewer than two literal
  characters are refused by the grammar. With none set no probe runs.
- MEDIUM the real-nft test could apply the drop-policy table in the host's own
  netns when run as root with nft installed. It now always uses the container,
  with a `mktemp` file.
- LOW the leading `-` rule is part of the schema regex.

2026.10.17.3 (first adopt re-run and review of cec6bfd):

- The first adopt re-run of the stack re-applied `allow_ssh_from_anywhere` to a
  locked-down host for about 20 seconds before lockdown closed it again.
  `apply_firewall` now reads the live managed table and refuses to replace a
  management-only SSH rule with an open one unless `allow_widening_ssh_exposure`
  is set. This is the model's own guard; the stack workflow also stops asking
  for it.
- A rebuilt server that Cherry gave the address of a deleted one inherited the
  deleted one's record, so `apply_base` ran 0 steps. Records now carry an
  optional `identity` (the provider server id); every method refuses a record
  for another identity, and the new `forget` action empties the records of a
  machine that is gone. Records written without an identity are accepted and
  then stamped.
- HIGH (review): the uplink probe ran under `sudo`, whose env_reset strips
  `SSH_CLIENT`, so a management NIC that was not the default route could be
  trusted. The probe now runs without sudo (checked against a real shell: exit 3
  when `SSH_CLIENT` is empty or when run under `sudo -n`), and fails closed:
  `set
  -e`, no `2>/dev/null`, a missing `ip`, no default route or no session
  route all refuse; ECMP `nexthops[].dev` are read. The test fake now returns no
  session route when the probe is wrapped in sudo. The apply script does not
  repeat the check (a small window between probe and apply, accepted and
  documented).
- The shell tests ignore a broken stdin pipe when the script exits before
  reading.

### Live e2e 2026-10-17: the server stack (2026.10.17.2 and 2026.10.17.3)

Folded from the server-stack acceptance receipts (run sp-20261017). Real
addresses, hostnames, DNS names and provider ids are redacted: `<stack1>` and
`<stack2>` are the throwaway hosts, `<mesh-hub>` the WireGuard hub, `<control>`
the control host, `<outside>` the outside probe source, `<mesh-addr>` the host's
mesh address. server-host ran inside the `@randybias/server-stack` workflows
(apply-base, apply-firewall + commit, lockdown + commit), installed from local
sources, never the registry.

| Part | Head                          | Cells               | server-host result                                                                                                                                                                                                                             |
| ---- | ----------------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | 0cfe601 (17.1) on `<stack1>`  | 13 pass, 2 fail, 15 | apply-base, firewall and lockdown committed over the mesh; the `input`/`forward` drop policies cut a k0s node's pods off (`kube-bridge`); passed only with a manual firewall workaround (fixed in 17.2)                                        |
| 2    | 16f38c5, cec6bfd (17.2)       | offline             | `trusted_interfaces`; 163 of 163 tests including real `nft -c`, a double apply and the JSON read-back on nftables 1.0.9; unset input byte-identical to 17.1                                                                                    |
| 3    | cec6bfd (17.2) on `<stack2>`  | 14 pass, 3 fail, 17 | k0s Ready with no manual rule; public 22/4222/6443/8222/10250 closed from `<outside>`; FAIL: a rebuilt host handed a deleted host's address inherited its record (apply-base 0 steps); FAIL: adopt re-applied SSH-from-anywhere for about 20 s |
| 4    | fd3716d (17.3), stack e8aad54 | 8 pass, 0 fail, 8   | see below                                                                                                                                                                                                                                      |

Part 4 on fd3716d, a fresh `<stack2>`:

| Cell                                                  | Result | Detail                                                                                                            |
| ----------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------- |
| fresh provision, one uninterrupted run, no workaround | PASS   | 8m55s: apply-base 9 steps, firewall + lockdown committed, k0s Ready, NATS over the mesh, DNS created              |
| adopt: no second server, no second record             | PASS   | `Ensuring server`, no order; DNS create skipped                                                                   |
| adopt: firewall and lockdown are no-ops               | PASS   | `firewall on <mesh-addr>: ruleset already live, no-op`; same for lockdown; both commits skipped (no revert armed) |
| adopt never reopens public SSH                        | PASS   | `<outside>` probed public :22 once a second for the whole run: 57 probes, 0 open                                  |
| adopt: NATS still answers, k0s still Ready            | PASS   | probe-nats, check-nats, wait-k0s                                                                                  |
| teardown runs `forget` on both records                | PASS   | the public-address and mesh-address records hold only `host, forgotten_at, observed_at`                           |
| teardown proof against the providers                  | PASS   | server and DNS record deleted; provider server and record counts equal the before snapshots                       |
| teardown again                                        | PASS   | delete steps skipped, verify steps pass                                                                           |

Not exercised live: a record carrying a mismatching identity (refusal covered by
tests only) and a rebuilt host receiving a deleted host's address (the provider
handed out a new address in Part 4).

Residuals on 2026.10.17.3 (beta):

- `forget` does not check the record's revert identity, is not idempotent, and
  can be left half-written if it fails between records.
- Revert records drop the identity when it is omitted.
- Records written before 17.3 (no identity) are adopted silently and stamped.
- Widening guard: a deliberate `ssh_port` change can bypass the management-only
  to open check.
- `_lib/ssh.ts` is not the canonical transport (see 7860bb0); convergence debt.

## Prior art

Prior art terms: hardening, firewall, nftables, sshd

Registry search on stable and beta (`swamp extension search`, whole-word
matches in the package name or description). The package name's own segments
(`server`, `host`) are plain English words that match dozens of unrelated
packages, so the terms name what this extension does: harden a Linux host
(packages and users, an nftables firewall, an SSH lockdown under an armed
revert).

- hardening:
  - `@dougschaefer/cisco-ios-switch` (stable): baselines a Cisco IOS switch
    over SSH; a network appliance, not a Linux host. NONE.
  - `@svendowideit/sudo` (stable): runs one privileged operation on a host
    (install a package, restart a unit, set a sysctl); a primitive, not a
    hardening profile, and no firewall or SSH policy. NONE.
  - `@randybias/server-stack` (beta): ours; composes this extension. Not
    prior art.
  - `@kneel/super-productivity` (beta): a task-app integration; word match
    only. NONE.
- firewall:
  - `@dougschaefer/opnsense-firewall` (stable): drives an OPNsense appliance
    over its REST API; no Linux host ruleset. NONE.
  - `@swamp/cloudflare/firewall` (stable), `@webframp/cloudflare` (stable),
    `@webframp/cloudflare-audit` (stable): Cloudflare edge firewall and WAF
    rules; nothing on a host. NONE.
  - `@mgreten/unifi` (stable), `@dmc/unifi-networks` (stable),
    `@shrug/unifi-networks` (stable): UniFi controller firewall policies over
    the UniFi API; nothing on a host. NONE.
  - `@kitquiet/homelab-ingress` (stable): reconciles nftables and Docker
    chains on an ingress host, but only for its own Traefik and WireGuard
    stack; no user or package phase, no SSH lockdown, no armed revert.
    OVERLAP, justified (recorded in the spec as well).
  - `@adam/cfgmgmt` (stable): user, authorized_key and apt types plus a
    `firewall` type for ufw, firewalld and iptables (no nftables); host keys
    default to accept-new; no armed revert and no SSH lockdown phase.
    OVERLAP (minor), justified: none of its types renders an nftables ruleset
    checked with `nft -c` or locks SSH down under a revert.
  - `@dougschaefer/apple-business-manager` (stable): Apple device
    management; word match only. NONE.
  - `@svendowideit/otel-backend` (beta): an observability backend profile;
    word match only. NONE.
- nftables: no hits.
- sshd: no hits.

Also judged in the sweep although not a whole-word hit for these terms:
`@psftw/pets` (beta, apt, systemd and template primitives over `@swamp/ssh`,
marked by its author as not for use) has no firewall or SSH lockdown. NONE.

Verdict: OVERLAP (minor), justified. No package combines an nftables ruleset,
users and packages, and an SSH lockdown under an armed revert. Worth filing
upstream: an nftables backend for `@adam/cfgmgmt`'s `firewall` type.
