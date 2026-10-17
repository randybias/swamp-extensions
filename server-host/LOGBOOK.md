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
