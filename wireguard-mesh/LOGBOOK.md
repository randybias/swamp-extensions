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
