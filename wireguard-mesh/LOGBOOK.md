# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17: adopted the head start from lane/b3 commit `92e3531`
  (`wip(wireguard-mesh): render + push seam, tests, README`), which this lane
  reviewed, corrected and finished. It shipped 33 tests; there are 54 now plus
  an env-gated netns behavioural test.

## Design

- One generic type, empty `globalArguments`; the mesh data and target node
  arrive as method arguments, so one definition renders any node of any mesh.
  State is keyed by the node's `name`.
- `render` is pure and offline. The returned `wg0.conf` never contains the
  private key. `[Interface]` carries a `PostUp` line that loads the key from
  `/etc/wireguard/<interface>.key` instead, and `apply` writes that key file
  (0600) from stdin. This is what lets render output be stored and displayed
  without a secret.
- Verified locally, in an isolated `ip netns` with wireguard-tools
  v1.0.20210914, that `wg-quick up` accepts a config with no `PrivateKey` and
  brings the interface up with the key loaded by that `PostUp` line. The push
  scripts were then exercised the same way in the namespace: apply created the
  interface and set the key (`changed=1`), a second identical apply reported
  `changed=0`, an `Address` change recreated the interface with the new address,
  `delete` removed it and reported `changed=1`, and a second `delete` reported
  `changed=0`. Those checks are encoded as
  `extensions/models/_lib/netns_test.ts`, ignored unless `WG_MESH_NETNS=1`
  because they need root and a network namespace. This is a script-level check
  only; it is not the two-node e2e matrix below.
- Determinism: peers, `AllowedIPs`, and excluded lists are sorted by name /
  bytes; the same inputs give byte-identical output regardless of input order.
- `relay_exclusion` rule `{exclude, for_nodes, via?}`: for a node matching
  `for_nodes` (`"*"` = every node except the relay), the `exclude` peers leave
  the direct set; with `via`, their addresses are added to the relay peer's
  `AllowedIPs`, so a spoke peers with the relay, not with every other spoke.
- Mutating verbs are `kind: "action"` because a method literally named `delete`
  tombstones the whole model and every node record it holds.

## Push half and the live matrix

- `apply`/`get`/`delete` run through an injectable `Transport` (spawner seam).
  Unit tests drive the seam; they spawn no process, open no socket and use no
  secret. The plan is that item 2's reviewed `_lib/ssh.ts` replaces the local
  transport; the seam and scripts are unchanged.
- Live e2e cells (`sp-20261017`, two throwaway nodes, transport from item 2) are
  all `blocked` on item 2's adopt/build outcome. None is `pass` or `skip`.

  | Cell                       | Result           |
  | -------------------------- | ---------------- |
  | render                     | blocked (item 2) |
  | apply node A               | blocked (item 2) |
  | apply node B               | blocked (item 2) |
  | handshake A<->B            | blocked (item 2) |
  | apply idempotent           | blocked (item 2) |
  | allowlist rejection (live) | blocked (item 2) |
  | delete node A              | blocked (item 2) |
  | delete again               | blocked (item 2) |
  | push to unreachable        | blocked (item 2) |

## Security

- The node's private key and the SSH private key are
  `.meta({ sensitive: true })` and travel over stdin (key file / `ssh-add -`),
  never on argv. `--json` output of a run whose arguments carry a literal key
  must not be captured (swamp lab 3555); the README says so.
- Every value that reaches the remote shell is validated against a grammar and
  quoted; the remote scripts are fixed templates. `apply` writes the config and
  key atomically (mktemp + `mv`, `umask 077`).
- `host_key_policy` is a required input with no default; `strict` needs pinned
  `host_keys`.

## Review ledger

Findings from the codex astra + terra review, all fixed for `2026.10.17.2`:

- HIGH-1 (TOFU was not real): `accept-new` now persists the accepted keys as a
  `hostkeys` resource keyed `<node>-hostkeys` and pins them as `strict` on later
  runs, so a changed key is refused instead of retrusted. `insecure` records
  nothing.
- HIGH-2 (Address/routes not reconciled): `apply` compares the old and new
  `Address`; a change recreates the interface (down/up) instead of `syncconf`,
  which left the node's addressing stale.
- HIGH-3 (failed reload looked converged): `apply` stages the new files, reloads
  from the staged copy, and commits the durable files only after the reload
  succeeds. A failure leaves the old files, so a retry reattempts.
- HIGH-4 (delete could sever its own path): `delete` requires
  `acknowledge_reachability_risk=true`, arms a detached rollback (`setsid`, else
  `nohup`) before `wg-quick down`, and disarms only after the interface and
  files are verified gone. The interface-recreation path in `apply` arms the
  same rollback.
- MEDIUM-5 (unquoted interpolation): shell-bound interface values and paths are
  quoted everywhere, including the rendered `PostUp`.
- MEDIUM-6 (no-op wrote state): `apply` and `delete` parse `changed` and return
  without writing a new resource version when nothing changed.
- MEDIUM-7 (no model description): added.
- MEDIUM-8 (unbounded arrays): `ssh.host_keys` capped at 64, relay `exclude` and
  `for_nodes` at 512.
- LOW (triple parse): `renderNode` takes validated data; `renderMesh` is the
  single validating entry point.

Round 3 (codex astra + terra on `c79944c`), all fixed for `2026.10.17.3`:

- HIGH-1 (get private key): `get` uses `wg show <iface> dump` and `parseDump`
  drops the interface line, so the interface private key is never returned or
  persisted. Confirmed by a test whose dump carries the key in line 0.
- HIGH-2 (non-atomic commit): `apply` backs up both durable files before the
  commit and restores BOTH on any failure; the commit is one guarded `mv && mv`,
  so a half-commit cannot pair an old config with a new key.
- HIGH-3 (rollback did not restore live): the rollback now tears the replacement
  interface down first, restores both files, and brings the saved config back
  up; the caller checks the interface afterwards.
- HIGH-4 (no-op not proven): a no-op requires the live peers to match after an
  idempotent `wg syncconf` and every desired `Address` to be present; a drifted
  interface is reconciled and reported as a change.
- MEDIUM-5: `apply` is now described as DESTRUCTIVE (it can recreate the
  interface and drop peers).
- MEDIUM-6: a remote `flock` serializes compare -> reload -> commit -> rollback.
- LOW: `delete` description trimmed to three sentences; `node.endpoint` is now
  echoed as `node_endpoint` in the render result; the ip-netns apply/no-op/
  recreate/delete checks are encoded as an env-gated behavioural test
  (`extensions/models/_lib/netns_test.ts`, run with `WG_MESH_NETNS=1`).

Round 4 (codex astra + terra on `3c74892`), all fixed for `2026.10.17.4`:

- HIGH-1 (routes not reconciled): a change to `Address` OR to any routed
  `AllowedIPs` now recreates the interface rather than `wg syncconf`-only,
  because syncconf updates peers but not wg-quick's routes. After reload the
  routes are checked with `ip route get` (which sees both explicit and connected
  routes).
- HIGH-2 (rollback ignored the lock): the detached rollback now takes the same
  `flock` before checking disarm, and the mutation stamps a generation into
  `$rb/epoch` while the rollback only restores if that still equals
  `$d/.<iface>.epoch`, so an expired rollback cannot overwrite a later apply.
- HIGH-3 (disarm without proven reachability): `apply`/`delete` now leave the
  rollback armed and print `rb=<dir>`; the model opens a FRESH SSH connection
  (`confirmScript`) and disarms only the matching generation. If that connection
  or the disarm fails, the rollback stays armed and restores.
- MEDIUM-4 (`for_nodes` typo): every `for_nodes` entry must be `"*"`, the
  rendering node's name, or a known mesh peer; anything else is rejected.
- Credential ruling acknowledged: examples use vault references and no `--json`
  on key-bearing runs; sensitive marking plus stdin delivery is the mitigation
  for the known swamp CLI limit (lab 3555).

Render golden tests and the allowlist/relay-exclusion invariants were called out
as good and are unchanged except for the quoted `PostUp` line.

Round 5 (escalation fixer, on d3 5bdd12e):

- HIGH-1 `confirmScript` skipped the lock and always printed "confirmed". Fixed:
  it takes the same lock as the rollback and requires the rollback directory to
  exist with the CURRENT generation; otherwise it exits 3 (the rollback already
  ran) or 4 (superseded), 75 when the lock is busy or `flock` is missing. The
  model turns those into typed errors and records nothing. A repeat confirm
  while the rollback is still pending is harmless. The rollback itself exits
  quietly when its directory has been removed.
- HIGH-2 the no-op-with-live-drift path ran `wg syncconf` and `wg set` before
  any rollback was armed. Fixed: `arm_rollback` runs before any live change on
  every path. The drift probe arms the current generation without bumping it (so
  an earlier unconfirmed rollback stays live), disarms it when nothing drifted,
  and the main path then starts a new generation. The drift check now compares
  peers, endpoints, allowed IPs, keepalive and listen port, not handshake or
  traffic counters, so a busy node is not reported as drifting. Cost: each
  converged re-apply leaves one sleeping, already-disarmed process for 120 s.
- TOFU: under `accept-new` the first operation used a fresh, empty known_hosts
  for each step, so the confirmation connection could accept a different key.
  Fixed: the key accepted by the first connection is pinned (strict) for the
  rest of the operation, and an `accept-new` connection that recorded no key
  stops the operation. The key is also persisted for later runs, as before. Not
  done: swapping in the canonical `_lib/ssh.ts`; this extension keeps its own
  transport.
- Evidence: `netns_test.ts`, run with `WG_MESH_NETNS=1` against real WireGuard
  in a network namespace, passes: apply, no-op, address and route recreation,
  delete, delete again, plus drift repair (peer removed behind the script's
  back), double confirm, and a confirm after the rollback ran (exit 3, previous
  address restored). It is skipped in the default test run.

Round 6 (review r5 at 19016ab):

- HIGH retry inside the rollback window reported a no-op and left the old
  rollback live. Fixed: under the lock, both `apply` and `delete` look for a
  rollback directory of the current generation that has not been disarmed
  (`pending_rb`) before any `changed=0` exit. If one exists the run is a change:
  it starts a new generation, which retires the old rollback, and returns its
  own `rb=` for the fresh-connection confirmation. The old directory's confirm
  now fails with "superseded" (exit 4). Run against real WireGuard in a
  namespace: apply without confirming, retry, confirm the retry, and the first
  rollback restores nothing; the same for delete.
- MEDIUM stale extra address survived `changed=0`. Fixed: `addr_check` compares
  the count of global addresses as well as the presence of each desired one, and
  the same check decides between syncconf and recreation. Extra routes are still
  not detected (only missing ones are).
- MEDIUM drift probe on an adopted interface had no epoch file. Fixed:
  `arm_rollback` writes `0` first when the file is missing.
- MEDIUM missing `flock`: apply and delete now refuse up front (exit 75), as
  confirm does.
- MEDIUM delete failed under `set -e` when the config was gone or corrupt.
  Fixed: `wg-quick down` falls back to `ip link delete`, then the interface is
  verified gone.
- LOW apply description cut to three sentences; `ssh.private_key` and CIDR
  strings are bounded.

## 2026-10-17 live e2e: 19 pass, 0 fail, 2 untested

Head under test: lane/b3-wireguard 588a882 (`@randybias/wireguard-mesh`
2026.10.17.4), installed from that tree into a separate scratch repo. Targets:
two throwaway VPS, `<vps3>` (node-a) and `<vps4>` (node-b), Ubuntu 24.04, kernel
6.8, wireguard-tools 1.0.20210914. Mesh addresses <wg-a>/32 and <wg-b>/32 (RFC
1918, redacted) over the public addresses, UDP 51820. Every apply, get and
delete ran through `swamp model method run` (never `--json`) with strict pinned
host keys and the SSH key and WireGuard keys as vault references. The management
SSH path stayed on eth0, never on wg0. Cells marked (manual) ran the extension's
real `applyScript` / `confirmScript` over SSH without the confirmation step,
which is what a failed confirmation looks like to the node. No private key
appeared in any run's console output.

| Cell                                                | Result   | Detail                                                                                                                                             |
| --------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 render                                            | pass     | config built from the live mesh inputs, no PrivateKey line, `PostUp` reads the key file                                                            |
| 2 apply node-a                                      | pass     | interface up, <wg-a>/32, one peer, route to <wg-b>, files 0600, state recorded after confirmation                                                  |
| 3 apply node-b                                      | pass     | interface up, <wg-b>/32                                                                                                                            |
| 4 handshake both ways                               | pass     | ping over wg0 0% loss; `latest-handshakes` non-zero on both nodes                                                                                  |
| 5 get                                               | pass     | live peers read back on both nodes                                                                                                                 |
| 6 confirm over a fresh connection                   | pass     | after each apply the matching rollback directory holds `disarm`                                                                                    |
| 7 apply idempotent                                  | pass     | "No change" on both; generation counter unchanged; the probe's disarmed rollback directory is removed after its window                             |
| 8 allowlist rejection                               | pass     | `peer node-b is not on peers_allowlist`; nothing contacted                                                                                         |
| 9 AllowedIPs change recreates                       | pass     | ifindex 4 -> 5; `10.99.0.0/24` route and allowed-ips present                                                                                       |
| 10 Address change recreates                         | pass     | ifindex 5 -> 6; address <wg-a2>/32                                                                                                                 |
| 11 restore to desired                               | pass     | <wg-a>/32, route to <wg-b>, ping OK                                                                                                                |
| 12 apply rollback fires when not confirmed (manual) | pass     | unconfirmed ListenPort 51821; after the 120 s window port back to 51820, config restored, peer kept, ping OK                                       |
| 13 retry retires the old rollback (manual)          | pass     | identical retry reports `changed=1` with its own rollback; old confirm refused (exit 4), new one ok; after 130 s the old rollback did not fire     |
| 14 delete without acknowledgement                   | pass     | refused before any contact                                                                                                                         |
| 15 delete node-a                                    | pass     | wg0 gone, config and key removed, confirmation ok                                                                                                  |
| 16 delete again                                     | pass     | "No change on node-a"                                                                                                                              |
| 17 delete node-b, and again                         | pass     | wg0 gone; second delete "No change on node-b"                                                                                                      |
| 18 push to unreachable                              | pass     | 203.0.113.10 with a pinned key: typed `ssh failed (exit 255): unreachable`, nothing recorded                                                       |
| 19 private key never in output                      | pass     | 0 occurrences in any run's output                                                                                                                  |
| 20 delete over the wg path (self-severing)          | untested | the management path was kept off wg0 by design of this run, so delete's rollback was never exercised against a connection the delete itself severs |
| 21 delete's own rollback firing                     | untested | only the apply rollback was forced to fire (cell 12); delete's rollback was never left unconfirmed                                                 |

Cleanup: both nodes have no wg0, an empty /etc/wireguard and no rollback
processes; the SSH agent was killed and the vault copies of the keys deleted.
The VPS are left for deletion by the live lane.

Cells 20 and 21 block promotion to stable; they do not block beta.
