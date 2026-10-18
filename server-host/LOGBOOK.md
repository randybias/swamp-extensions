# LOGBOOK — @randybias/server-host

visibility: public audience: general

Naming answers (from the spec): Q1 public. Q2 general usage, anyone hardening a
freshly provisioned Linux host. Q3 no: "server" and "host" are both banned nouns
and no system is named; the naming audit proposes `linux-host-hardening`,
pending confirmation, so the published name stays `server-host`. Q4 not
applicable (public and general). Q5 no: a stranger cannot tell from the name
what it does to a host.

Maintainer notes. Not shipped; not listed in `additionalFiles`.

## Provenance

- Net-new extension (`server-host/`). No upstream extension was generic for
  this; the closest existing package is site-specific.
- The SSH transport in `extensions/models/_lib/ssh.ts` and its test are
  byte-identical to the canonical `@randybias/ssh-host` copy (see "##
  Vendored"); this extension imports its public API (`exec`, `SshDeps`,
  `SshTarget`, `SshError`) and nothing else.
- Everything else is new. All remote exec goes through the vendored transport;
  no `Deno.Command` appears outside it.

## Vendored

| File                                                  | Blob                                       |
| ----------------------------------------------------- | ------------------------------------------ |
| `extensions/models/_lib/ssh.ts`                       | `8f132c4329c9e64bed686731cd5a0e02980194ea` |
| `extensions/models/_lib/ssh_test.ts`                  | `4e8ac15fcd6bce797c523a221fe58fe9a8d9b386` |
| `extensions/models/_lib/bogworks/recording-runner.ts` | `943857c8b6dbbc365523ee0cfafd1b0fe0c0054f` |
| `extensions/models/_lib/bogworks/remote-script.ts`    | `fd692dfb897fadc2c3dfcbae68d11d470e2f303b` |
| `extensions/models/_lib/bogworks/containers.ts`       | `53ebb3ab561dc6afdb9b0043522ef96015377d12` |
| `extensions/models/_lib/bogworks/mod.ts`              | `9ae3ee762fa3f912db2bea8230c9a9b31bd6ee99` |

The harness is excluded from `deno fmt` and `deno lint` (`deno.json`) so the
copies stay byte-identical; `bogworks-harness-version` records the blobs.

## Decisions

- 2026-10-17 harness-gap: the lane seed names `testing/harness/`, the harness
  README and `vendor.sh` name `extensions/models/_lib/bogworks/`. The latter is
  used, because `remote-script.ts` is production code (the quoting helper, the
  prologue, the remote timeout) and must sit inside the packaged tree.
- 2026-10-17 harness-gap: `recording-runner.ts` recognises a stdin script only
  behind a bare `sh -s`, not behind `sudo -n sh -s`. `_lib/test_support.ts`
  mirrors every sudo-wrapped call to a second recording runner without the
  `sudo -n`, so the scripts still reach `BOGWORKS_CAPTURE_SCRIPTS`.
- 2026-10-17 Every remote call is one `RemoteCall` (`_lib/remote.ts`): the
  script is streamed over the SSH session's stdin to `sh -s` (behind `sudo -n`
  when asked), caller values are `set --` positional parameters quoted by
  `posixQuote`, and file content is base64 text read through `bw_data`. Nothing
  but `sh -s` is on the remote command line.
- 2026-10-17 Remote deadlines: each call runs under `timeout -k 5 <sec>` inside
  the surviving outer shell (30 s apply, 60 s arm/cancel/listing, 120 s base
  steps, 900 s package installs); the local ssh deadline is 25 s later. An exit
  of 124 or 137 is an unknown outcome: the plan throws, and a deadline on the
  apply step leaves the revert armed and the record open (never disarmed).
- 2026-10-17 Locks are bounded: arm and cancel wait 20 s, the guarded apply 10
  s, then exit 75 (reported as "earlier revert still active or firing"). The
  on-host restore script waits 120 s and then restores anyway, because every
  other holder is bounded below that.
- 2026-10-17 Config files the tool owns (sysctl and journald drop-ins, the
  revert script, `authorized_keys`) are still written through a same-directory
  `mktemp` file and an atomic `mv`, removed by the EXIT trap. They carry no
  secret (public keys and fixed settings); the SSH key itself never touches the
  host. This is the one place a remote file is created besides the files the
  tool installs.
- 2026-10-17 revoke: sudo is taken back before the keys file, and a lookup that
  answers "no such account" (getent exit 2) counts as gone only when `id` and
  the local passwd file agree and `nsswitch.conf` lists no network source for
  passwd; otherwise the step fails (exit 1) and the account stays pending.
- 2026-10-17 widening guard: any source-limited rule in the live managed input
  chain counts as management-only SSH, whatever port it names, so changing
  `ssh_port` cannot bypass it.
- 2026-10-17 forget: checks the revert record's identity too, and a repeat on an
  already-empty record writes nothing and reports `changed: false`.
- 2026-10-17 registry-lint MEDIUM accepted: the model literal spreads
  `createModel()` with literal `type` and `version` repeated, the repo
  convention; the spec requires the factory with overridable dependencies.
- 2026-10-17 Goldens moved from `fixtures/` to `goldens/` (the extension's own
  output, validated by the real-tool gate); `nft-real-listings.json` keeps a
  `.source` sidecar.

- 2026-10-17 tightness pass: COULD-BE-TIGHTER. The new code is small
  (`remote.ts` about 110 lines, one `RemoteCall` shape replacing the
  argv/stdin/timeout triple) and nothing exported is unused, but
  `server_host.ts` (about 1270 lines) and its test file (about 2400) are past
  the size guideline from earlier versions; splitting the method bodies out is a
  separate change.
- 2026-10-17 blocked: swamp gates 2 (swamp fmt), 3 (quality) and 7 (registry dry
  run) need a swamp account and the lane environment has no credential; the seed
  forbids `swamp auth login`. Everything else in the self-check is green. The
  gate-7 rules are met by construction (literal `type`, `version` and
  `upgrades[]` with a 17.4 entry, a sibling test, no new secret-like names).

## Residuals

| Sev    | What                                                                                              | Why accepted                                                                                 |
| ------ | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Medium | A revert records the identity only when one was given; records written before 17.3 carry none     | Identity stays optional; adopting an unstamped record is the documented first-run path       |
| Low    | The on-host restore judges success by `nft -f` (one atomic transaction), with no post-state retry | A failed restore leaves the snapshot and the unit failed; the LOGBOOK recovery below applies |
| Low    | An account that is gone from a host with a network passwd source stays pending                    | Fail closed; a rerun once the backend answers completes it                                   |

Recovery after a failed restore: the snapshot is
`/var/lib/server-host/revert-<token>.nft` and the script `revert-<token>.sh`;
run the script by hand as root, or `nft delete table inet
server_host`.

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

## 2026-10-18 live e2e (2026.10.17.4, head 89f7a47)

Run sp-2 on 89f7a47, contentHash
`371317a6c90a64b765708c5eb873c795697ed825c0887ab2dc6c137f0c02a2af`,
2026-10-18T00:05Z to 00:30Z. Result is `pass`, `fail`, `untested` or
`inconclusive`; only `pass` counts. Real addresses, hostnames, provider ids and
revert tokens are redacted: `<vps1>` is the target, a throwaway hourly VPS (1
vCPU, 1 GB, Ubuntu 24.04, kernel 6.8.0-142, nftables 1.0.9); `<vps2>` a second
throwaway VPS in the same project used only as an outside SSH source, never a
target; `<control-egress>` the control host's egress address, the only
management CIDR (/32); `<server-id>` the provider id of `<vps1>` and
`<other-id>` a made-up one; `<token1>` to `<token4>` the four revert tokens in
order. No container cells: the control host is aarch64 with docker only, and the
armed-revert cells need systemd as PID 1 driving transient timers behind a real
netfilter input hook on a host that can lock the operator out, which spec
section 6 places on a throwaway VPS. Fresh scratch repo with the head's
`extensions/models` copied in unchanged; model `sh` with empty globalArguments;
the SSH key a vault reference; host keys pinned from the first contact, policy
strict; every run with `--input-file`, no `--json` on any run carrying an SSH
target. `content_hash_proved` is the first 12 characters of the hash above.

| method_or_workflow | scenario     | result   | run_id | test_cell | content_hash_proved | note                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------ | ------------ | -------- | ------ | --------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| apply_base         | bad-input    | pass     | sp-2   | vps-small | 371317a6c90a        | 4 runs against an unroutable RFC 5737 target: `curl; id` package, `ops$(id)` user, a backticked key line and `0; reboot` sysctl each refused at validation by name (`packages.0`, `admin_user`, `authorized_keys.0`, `sysctl.*`); nothing dialled (1.7 s each = CLI start)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| apply_firewall     | bad-input    | pass     | sp-2   | vps-small | 371317a6c90a        | 6 runs, unroutable target: `/33` CIDR, port 70000 and revert_after_s 30 refused by schema; `0.0.0.0/0` and the two /1 halves refused by the wide-range rule without allow_ssh_from_anywhere; host_key_policy insecure_tofu refused (`expected "strict"`); nothing dialled                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| lockdown           | bad-input    | pass     | sp-2   | vps-small | 371317a6c90a        | allow_ssh_from_anywhere refused (`lockdown ... never allows SSH from anywhere`), empty management_cidrs refused; nothing dialled                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| get                | bad-input    | pass     | sp-2   | vps-small | 371317a6c90a        | missing host_keys refused at validation (`expected array ... at "host_keys"`); nothing dialled                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| render_firewall    | fresh        | pass     | sp-2   | vps-small | 371317a6c90a        | no host touched; the `render-golden-mgmt` resource read back with `swamp data query` is byte-identical to goldens/mgmt-only.nft (sha ebf5911b…) and the service-ports inputs (ssh_port 2222, tcp 8443/443/22, udp 51820) to goldens/service-ports.nft (6d0791e1…); the live-input render is compared with the applied table in the apply_firewall rerun row                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| render_firewall    | rerun        | pass     | sp-2   | vps-small | 371317a6c90a        | same inputs rendered again: same ruleset_sha256 ebf5911b…, same managed_sha256 71050a53…, only observed_at moved                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| apply_base         | fresh        | pass     | sp-2   | vps-small | 371317a6c90a        | 9 steps, 14.4 s; read back over a separate SSH session: ops uid 1000 in group sudo, /home/ops/.ssh 700 and authorized_keys 600 whose sha256 equals the public key line's, jq `install ok installed` (already on the image), sysctl tcp_syncookies=1 live and in /etc/sysctl.d/99-server-host.conf, journald drop-in, Timezone=UTC NTP=yes, marker /var/lib/server-host/sudo-granted-ops; listeners sampled twice: 22 and loopback 53 only                                                                                                                                                                                                                                                                                                                                                                                                                         |
| apply_base         | rerun        | pass     | sp-2   | vps-small | 371317a6c90a        | identical inputs: `0 steps`, 61 ms; sshd's `Accepted publickey` count moved only by the read-back session and the mtimes of authorized_keys, both drop-ins, /etc/group and the sudo marker are unchanged                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| apply_base         | existing     | pass     | sp-2   | vps-small | 371317a6c90a        | admin_user ops -> ops2 with `tree` added (absent on the image): 4 steps, 47.6 s; read back: ops keeps its account but has no authorized_keys file, is out of group sudo and its marker is gone; ops2 uid 1001 in sudo, keys 600 with the same sha256, marker sudo-granted-ops2; tree `install ok installed`; no new listener. Observation only: the emptied /home/ops/.ssh is left with group root                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| apply_firewall     | fresh        | pass     | sp-2   | vps-small | 371317a6c90a        | management `<control-egress>`/32, tcp 80, revert_after_s 60: armed `<token1>`, 5 steps, 7.7 s (00:16:46Z); `nft list table inet server_host` 2 s later shows policy drop, `ip saddr <control-egress> tcp dport 22 accept` and tcp 80; `server-host-revert-<token1>.timer` active/waiting and its .service inactive; state dir holds current, revert-<token1>.nft/.sh and revert.lock; a foreign table `inet foreign_test` and its rule untouched; from `<vps2>`: port 22 blocked, port 80 answered (RST = reaches the host); no new listener                                                                                                                                                                                                                                                                                                                      |
| get                | fresh        | pass     | sp-2   | vps-small | 371317a6c90a        | run inside the armed window (00:17:03Z): observation-<vps1> read back with `swamp data query` records what the host showed: observed_by get, base_applied true, admin_user ops2, firewall_mode firewall, ssh_exposure management-only, managed_table true, revert_armed true, revert_expires_at 00:17:38.909Z (= armed_at + 60 s), drift [], pending_revoke [], ruleset_sha256 ebf8c082…                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| commit             | fresh        | pass     | sp-2   | vps-small | 371317a6c90a        | `revert <token1> cancelled`, 10.8 s (00:17:16Z); 2 s later the timer and its service are gone from systemctl, the revert-<token1> files are gone (revert.lock stays), the table listing has the same sha (b92b775c…) as after the apply; read again 93 s after arming: same sha, no server-host timer or unit, state dir holds only revert.lock and the sudo marker                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| apply_firewall     | rerun        | pass     | sp-2   | vps-small | 371317a6c90a        | identical inputs over the committed table: `ruleset already live, no-op`, 3.2 s; read back: same table sha b92b775c…, no timer, no unit, no revert files; the live-input render (render-live) has the state's ruleset_sha256 75c4c368… and managed_sha256 92a53483…                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| apply_firewall     | existing     | pass     | sp-2   | vps-small | 371317a6c90a        | over the live management-only rule: allow_ssh_from_anywhere with ssh_port 2222 and no management CIDR refused (`locked down to its management CIDRs; refusing to open SSH to anywhere again. Set allow_widening_ssh_exposure`), 4.9 s; table sha unchanged, no timer armed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| apply_firewall     | failure-path | pass     | sp-2   | vps-small | 371317a6c90a        | revert fires: tcp 8080 added over the committed table, never committed. armed_at 00:19:02.6Z (`<token2>`); at 00:19:07Z the table had `tcp dport { 80, 8080 }` (sha b3504160…), timer active/waiting, `<vps2>` still blocked on 22, a fresh control-host SSH worked; host journal: timer started 00:19:02, service ran and deactivated 00:20:03 (61 s); at 00:20:19Z the table is byte-identical to the committed one (sha b92b775c…, tcp 80 only), no timer or unit, state dir back to revert.lock + marker, foreign table and rule intact, listeners unchanged                                                                                                                                                                                                                                                                                                  |
| sync               | existing     | pass     | sp-2   | vps-small | 371317a6c90a        | run after the fired revert: observation-<vps1> read back shows observed_by sync, drift ["ruleset","revert_fired"], revert_armed false with the fired `<token2>` and its expiry 00:19:58Z, ssh_exposure unknown, managed_table true; the recorded state keeps the intended (8080) ruleset_sha256 187c2c3f…, which is the drift                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| sync               | rerun        | pass     | sp-2   | vps-small | 371317a6c90a        | second sync 11 s later: identical observation (same drift, token, expiry, hashes), only observed_at moved; host untouched (table sha, no timer)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| commit             | failure-path | pass     | sp-2   | vps-small | 371317a6c90a        | commit after expiry: `The armed revert for <vps1> expired at 2026-10-18T00:19:58.061Z; nothing to cancel`, exit 1 in 1.7 s; table sha unchanged, no timer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| lockdown           | fresh        | pass     | sp-2   | vps-small | 371317a6c90a        | management `<control-egress>`/32, revert 60: armed `<token3>`, 8.5 s (00:22:00Z); table now holds only `ip saddr <control-egress> tcp dport 22 accept` (sha eff86030…, the tcp 80 allow of the firewall phase is gone), timer active; `<vps2>` -> 22 blocked while the control host still connects; commit at 00:22:20Z cancelled the timer, table unchanged after it; foreign table intact; no new listener                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| lockdown           | rerun        | pass     | sp-2   | vps-small | 371317a6c90a        | identical lockdown over the committed one: `ruleset already live, no-op`, 3.0 s; same table sha, no timer, no revert files; `<vps2>` still blocked                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| lockdown           | failure-path | pass     | sp-2   | vps-small | 371317a6c90a        | lockout, revert fires: management 198.51.100.0/24 (excludes the control host), revert 60, never committed. armed_at 00:23:06.1Z (`<token4>`); the run itself then could not reconnect (`Change on <vps1> failed after arming; revert <token4> stays armed and will restore the host`, exit 1 in 22.9 s); control-host poll (ssh every 2 s, 4 s timeout): ok 00:22:55, failed 00:23:12 through 00:24:35 (14 attempts), ok again 00:24:37; `<vps2>` blocked throughout; host journal: timer started 00:23:06, service fired 00:24:33 (87 s after arming, 31 s after the recorded expires_at 00:24:01.6Z: systemd's default timer AccuracySec of 1 min); at 00:24:37Z the committed lockdown table is back (sha eff86030…, saddr `<control-egress>` only), no timer, state dir clean, foreign table intact; the firewall-phase revert fired 5 s after its expires_at |
| get                | rerun        | pass     | sp-2   | vps-small | 371317a6c90a        | after the lockout revert: observation read back shows observed_by get, firewall_mode lockdown, drift ["revert_fired"], revert_armed false, `<token4>`, expires 00:24:01.6Z, ssh_exposure unknown; host not changed by the read (table sha, no timer)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| get                | failure-path | pass     | sp-2   | vps-small | 371317a6c90a        | wrong pinned host key: `host key verification failed for <vps1>:22; refusing to connect`, exit 1 in 2.2 s; sshd journal shows that connection `closed ... [preauth]`, so no authentication was attempted; wrong identity: `The records for <vps1> were made for another machine (<server-id>, not <other-id>); run forget for it first`, 1.7 s, nothing dialled                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| forget             | existing     | pass     | sp-2   | vps-small | 371317a6c90a        | identity mismatch refused before any write: same `made for another machine (<server-id>, not <other-id>)` error, exit 1; record versions unchanged (state v12, revert v6)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| forget             | fresh        | pass     | sp-2   | vps-small | 371317a6c90a        | right identity: `Forgot the records of <vps1>`, 73 ms, no remote call (forget never dials); state-<vps1> rewritten (v13) to host + forgotten_at only, revert-<vps1> (v7) gets cancelled_at; the observation record is left as the last probe wrote it (hashes and the opaque token, no key)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| forget             | rerun        | pass     | sp-2   | vps-small | 371317a6c90a        | second forget 3 s later: succeeded in 28 ms and wrote nothing (state still v13, revert still v7)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| commit             | rerun        | untested | sp-2   | vps-small | 371317a6c90a        | omission: a second commit over the same already-cancelled revert was not scheduled before the target was deleted (the commit failure-path row covers the nothing-to-cancel path for a fired revert)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

Result: pass 26, fail 0, untested 1, inconclusive 0. Stays on beta (one cell
untested).

Host before/after baseline (84 diff lines, every one accounted for): the package
tree; users ops and ops2 with home directories, group sudo = ops2; the sysctl
and journald drop-ins; the image's default timezone -> UTC;
`/var/lib/server-host` with `revert.lock` and the sudo marker;
`table inet
server_host` (the committed lockdown) and the foreign table added
for the non-interference checks; no change in enabled or running units,
listeners, timers, cron, mounts, netplan or interfaces. Listener samples: 10
across baseline, every apply, every revert and every commit, always 22 plus
loopback 53. Argv scan: 74 logged swamp commands and 173 scratch files scanned
in memory against every line of the private key and both API tokens: 0 hits (the
only matches were the generic `-----BEGIN/END OPENSSH PRIVATE KEY-----` lines of
the head's own synthetic fixtures). Both servers deleted at the provider (204
each); the project listing afterwards shows 0 servers carrying this lane's tag.
Secrets: none printed, none rotated; the key copy was deleted from the scratch
vault. The unredacted receipts are the maintainer's `receipts/server-host.md`,
kept outside git.

Findings for the maintainer (no cell failed):

- The transient timer fires up to a minute after `expires_at`:
  `systemd-run
  --on-active` inherits the default `AccuracySec=1min` (observed
  +5 s and +31 s). In that slack `commit` already answers "expired; nothing to
  cancel" while the host is about to revert. Passing
  `--timer-property=AccuracySec=1s` would make the fire time match the recorded
  expiry. Residual Low for the next version.
- `forget` leaves the observation record as the last probe wrote it (hashes and
  the opaque token, no key).
- An emptied `~/.ssh` of a revoked account keeps group root.

Triage dispositions at 89f7a47 (review CLEAN: conformance, adversarial and
tightness seats each rc=0, tightness COULD-BE-TIGHTER at about 50 lines; the GLM
advisory seat was read, not counted):

- Refuted High (conformance) `_lib/armed_revert.ts:94`, "restore proceeds after
  the 120 s lock wait": by design. Every lock holder (arm 60 s, apply 30 s,
  cancel 60 s, lock waits 10-20 s) is killed by its own remote timeout long
  before the wait expires, so a lock still held belongs to a wedged process;
  failing the restore on contention would leave the host unreachable with no
  recovery, the opposite of the dead-man property. The marker and snapshot
  re-check runs after the wait either way.
- Refuted High (conformance) `_lib/plans.ts:150`, "absence detection trusts grep
  errors and unknown NSS backends": the sudo marker is written only when
  `usermod -aG sudo` succeeded, which it does only for a local `/etc/passwd`
  account, and such an account is found by `id -u` or the passwd grep before any
  NSS reasoning. The remaining "stays pending" case is the accepted Low residual
  in "## Residuals".
- High (conformance) naming: kept as Low. The rename to `linux-host-hardening`
  is a separate item awaiting the owner (spec Q3); nothing renamed here.
- Medium kept `_lib/remote.ts:74`: the base64 data literal and the body become
  one argv word of the inner `sh -c` under `timeout`; schema-legal inputs (64
  authorized keys of 4096 bytes, about 350 KiB base64) exceed Linux
  `MAX_ARG_STRLEN` (128 KiB) and fail opaquely ("Argument list too long"
  reported as a plain step failure); the module doc's "never on the remote
  command line" overstates the guarantee. Next version: cap the rendered body
  before any remote call with a clear error naming the input, or read data as a
  stdin segment; correct the doc comment; add an oversize test.
- Medium kept `_lib/test_support.ts:93` (test gap): the harness's
  `stdinIsScript` recognises only a bare `sh -s`, so `assertNoRemoteSecretWrite`
  never scans sudo-delivered stdin scripts and the sudo-stripped mirror
  recording that would be scanned is discarded. Next version: expose the
  mirror's recording and assert on it too; `sudo -n` recognition is filed for
  the harness.
- Medium "live matrix untested, gates 2/3/7 blocked": resolved by this entry and
  by the merge-prep gates below.
- Low kept `server_host.ts:1270`: the exported `model` spreads `createModel()`,
  so the literal carries no `upgrades: [` (it lives inside the factory); same
  shape as the published 2026.10.17.3, and gate 7 passes.
- Low kept `server_host.ts:1162`: `forget` checks identity only against an open
  revert and leaves a closed (committed or cancelled) revert record of a reused
  address in place; harmless (closed records are inert for `currentRevert`), but
  the description says the revert record is deleted.
- Low kept `_lib/armed_revert_shell_test.ts:142` (tightness): six repeated
  guarded-apply constructions, about 40 lines; an `apply(b, token, suffix, now)`
  helper next time.
- Downgraded or refuted: the adversarial Medium on `forget` and a closed revert
  is the Low above (a closed record is never adopted); the adversarial Low
  "forget tombstones instead of deleting" is a platform limit (records cannot be
  removed from inside a method; the tombstone carries only host and timestamps);
  the tightness Low on `bogworks/containers.ts` (unused stdin parameter) is in
  the vendored harness, reported to the harness owner; the advisory items on the
  vendored transport are judged in its owner, and the advisory "widening guard
  refuses on third-party rules" is refuted because the managed input chain
  belongs to this extension's own table, which the next apply replaces whole.

Merge-prep 2026-10-18 (main): merged `--no-ff` from lane/b2-server-host 89f7a47,
server-host/ only; no code change after the live-tested head, so the published
bytes are the live-tested bytes. Gates 2, 3 and 7, blocked in the lane for lack
of a credential, ran green on main with the dry run reporting the same
contentHash 371317a6….

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
- `_lib/ssh.ts` is not the canonical transport (see 7860bb0); convergence debt
  (closed in 2026.10.17.4).

## Factory events

Run sp-2, item server-host 2026.10.17.4, from the conductor's event log (UTC).
The sibling item `linux-host-hardening` was parked at the start of the run until
this version is published; its head is the base for the renamed package.

| At                   | Stage      | Rung      | Head    | Reason            |
| -------------------- | ---------- | --------- | ------- | ----------------- |
| 2026-10-17T21:58:08Z | spec       | prior-art |         | spec-ok           |
| 2026-10-17T22:39:17Z | building   | build     |         | prior-art:overlap |
| 2026-10-17T23:21:49Z | checks     | gates     | b4c0be3 | head-reported     |
| 2026-10-17T23:25:17Z | checks     | gates     | 496d71e | head-moved        |
| 2026-10-17T23:30:13Z | checks     | gates     | 89f7a47 | head-moved        |
| 2026-10-17T23:35:33Z | checks     | realtool  | 89f7a47 | gates-pass        |
| 2026-10-17T23:47:43Z | review     | review    | 89f7a47 | realtool-pass     |
| 2026-10-18T00:04:33Z | live test  | live      | 89f7a47 | triage:clean      |
| 2026-10-18T00:35:55Z | publishing | merge     | 89f7a47 | live-pass         |

## Prior art

Prior art terms: hardening, firewall, nftables, sshd

Registry search on stable and beta (`swamp extension search`, whole-word matches
in the package name or description). The package name's own segments (`server`,
`host`) are plain English words that match dozens of unrelated packages, so the
terms name what this extension does: harden a Linux host (packages and users, an
nftables firewall, an SSH lockdown under an armed revert).

- hardening:
  - `@dougschaefer/cisco-ios-switch` (stable): baselines a Cisco IOS switch over
    SSH; a network appliance, not a Linux host. NONE.
  - `@svendowideit/sudo` (stable): runs one privileged operation on a host
    (install a package, restart a unit, set a sysctl); a primitive, not a
    hardening profile, and no firewall or SSH policy. NONE.
  - `@randybias/server-stack` (beta): ours; composes this extension. Not prior
    art.
  - `@kneel/super-productivity` (beta): a task-app integration; word match only.
    NONE.
- firewall:
  - `@dougschaefer/opnsense-firewall` (stable): drives an OPNsense appliance
    over its REST API; no Linux host ruleset. NONE.
  - `@swamp/cloudflare/firewall` (stable), `@webframp/cloudflare` (stable),
    `@webframp/cloudflare-audit` (stable): Cloudflare edge firewall and WAF
    rules; nothing on a host. NONE.
  - `@mgreten/unifi` (stable), `@dmc/unifi-networks` (stable),
    `@shrug/unifi-networks` (stable): UniFi controller firewall policies over
    the UniFi API; nothing on a host. NONE.
  - `@kitquiet/homelab-ingress` (stable): reconciles nftables and Docker chains
    on an ingress host, but only for its own Traefik and WireGuard stack; no
    user or package phase, no SSH lockdown, no armed revert. OVERLAP, justified
    (recorded in the spec as well).
  - `@adam/cfgmgmt` (stable): user, authorized_key and apt types plus a
    `firewall` type for ufw, firewalld and iptables (no nftables); host keys
    default to accept-new; no armed revert and no SSH lockdown phase. OVERLAP
    (minor), justified: none of its types renders an nftables ruleset checked
    with `nft -c` or locks SSH down under a revert.
  - `@dougschaefer/apple-business-manager` (stable): Apple device management;
    word match only. NONE.
  - `@svendowideit/otel-backend` (beta): an observability backend profile; word
    match only. NONE.
- nftables: no hits.
- sshd: no hits.

Also judged in the sweep although not a whole-word hit for these terms:
`@psftw/pets` (beta, apt, systemd and template primitives over `@swamp/ssh`,
marked by its author as not for use) has no firewall or SSH lockdown. NONE.

Verdict: OVERLAP (minor), justified. No package combines an nftables ruleset,
users and packages, and an SSH lockdown under an armed revert. Worth filing
upstream: an nftables backend for `@adam/cfgmgmt`'s `firewall` type.
