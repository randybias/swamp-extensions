# Spec: `@randybias/wireguard-mesh`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone building a WireGuard mesh between Linux hosts.

Q3: Yes. `wireguard-mesh` names the system (WireGuard) and what it builds (a mesh); short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `wireguard-mesh` as a WireGuard mesh builder (render one node's config and push it), which is what it does, and guesses wrong about nothing.

Status: implemented and published (beta); the next-version scope is at the end.
Not clean-room (net-new). RFC 2119 keywords.

## 1. Purpose

Render a single WireGuard node's config from mesh inputs and push it to that one
node. The mesh is described as data (a set of peers, an allowlist, relay rules);
the extension renders **one node's** `wg0.conf` deterministically and applies it
over SSH. Generic: no host, key or address is baked into the definition.

Registry search found no WireGuard extension — this is net new.

## 2. Two separable halves — build and test the render FIRST

- **Render (pure, offline-testable):** mesh inputs → one node's config text.
  This is the bulk of the work and needs no network. Build and fully unit-test
  it before any SSH.
- **Push (needs the transport):** write the rendered config to the node and bring
  the interface up. The transport comes from `ssh-host` (`docs/specs/ssh-host.md`);
  until its adopt/build outcome is settled, build `push` against an injectable
  transport seam (a spawner dependency) and mark its live cells `blocked` on the
  transport, not `skip`.

## 3. Model contract

- **Type** `@randybias/wireguard-mesh`. CalVer == manifest version.
- **`globalArguments` empty.** Methods take the mesh data and the target node as
  arguments; one definition renders any node of any mesh.
- State keyed by the node's `name` (instance value), never the definition name.
- **Factory with overridable deps** (transport spawner, clock) — unit tests
  render and diff text only.

### Methods

| Method | Kind | Description |
|---|---|---|
| `render` | — | READ-ONLY. Return the `wg0.conf` text for `node` given the mesh, plus the resolved peer list. Deterministic: same inputs → byte-identical output (stable peer ordering). No private key in the returned text unless explicitly requested; prefer a `PostUp`/key-file reference. |
| `apply` | action | Render for `node` and push: write the config atomically, set the private key from a vault ref over stdin, `wg syncconf`/`wg-quick` up. Idempotent: re-apply of identical config is a no-op. Returns `{node, interface, peers, config_sha256}`. |
| `get` | — | READ-ONLY. Return the node's current interface state (`wg show` parsed): peers, latest handshake, allowed IPs. |
| `delete` | action | DESTRUCTIVE. Bring the interface down and remove the config. `kind: "action"`. |

### Inputs

- `node` — object: `name`, `address` (the node's mesh IP/CIDR), `listen_port`,
  `endpoint` (public host:port, optional for relay-only reachable nodes).
- `private_key` — `.meta({ sensitive: true })`, vault ref, delivered over
  stdin; never argv, never in rendered output written to a world-readable path.
- `peers` — list of `{name, public_key, allowed_ips[], endpoint?, keepalive?}`.
- `peers_allowlist` — the names (or public keys) permitted in this mesh; a peer
  not on the allowlist is rejected, not silently dropped.
- `relay_exclusion` — rules that remove relay nodes from a node's direct peer
  set (so a spoke peers with the relay, not with every other spoke).
- `ssh` — the transport target block from `ssh-host` (host, user, port,
  `host_key_policy` + pinned `host_keys`, key over stdin). `render` ignores it.
- Strict `z.object`, no `.passthrough()`. `allowed_ips` validated as CIDRs;
  public keys validated as 44-char base64; ports bounded.

### Outputs

`render` → config text + resolved peers. `apply`/`get`/`delete` → typed state.
Private keys never appear in any returned object.

## 4. Invariants / failure modes (test + cell each)

| Mode | Expected |
|---|---|
| Peer not on allowlist | Rejected with a typed error naming the peer. |
| Relay exclusion | Excluded relay never appears as a direct peer in the render. |
| Deterministic render | Same inputs → identical bytes; peer order stable. |
| Duplicate/overlapping `allowed_ips` | Rejected by validation. |
| Invalid public key / CIDR | Rejected by schema. |
| apply idempotent | Re-apply identical config = no-op (`config_sha256` match). |
| Private key never in output | `render` output and logs contain no private key. |
| Push to unreachable node | Typed transport error (from the transport seam). |
| delete already-down | Clean no-op. |

## 5. Tests (offline, increasing risk)

1. Schema/secret/license: private key sensitive; strict object.
2. Pure mapping: golden-file render tests for several mesh shapes (hub+spoke
   with relay, full mesh, allowlist rejection), byte-exact; assert no private
   key leaks into the config written to a shared path.
3. Failure + adversarial: §4 rows; injection on `name`/`endpoint` reaching the
   remote shell.
4. Packaging.

Fixtures synthetic: RFC 5737 IPs for endpoints, mesh addresses in the WireGuard
doc range or RFC 5737, placeholder (clearly fake) keys.

## 6. Live e2e matrix (needs two reachable nodes)

Target: two throwaway VPS. Transport via `ssh-host`.

| Cell | Expected |
|---|---|
| render | config text matches golden for the live mesh shape |
| apply node A | interface up, `wg show` lists expected peers |
| apply node B | interface up |
| handshake A↔B | `get` shows a recent handshake both ways |
| apply idempotent | no-op by config hash |
| allowlist rejection (live) | a non-allowlisted peer is refused |
| delete node A | interface down, config gone |
| delete again | clean no-op |
| push to unreachable | typed error |

Live cells `blocked` until the transport is settled. Receipts into
`wireguard-mesh/LOGBOOK.md`.

## 7. Carry-overs

- `delete` must be `kind: "action"` (model `delete` tombstones everything).
- Never capture `--json` of an `apply` carrying the private key (lab 3555).
- Write the config atomically (temp + rename, mode 0600) so a half-written
  `wg0.conf` never applies.

## Next version scope: next

Next `wireguard-mesh` version (public, beta; the two cells below block stable).

- Residual Mediums: a retry inside the rollback window does not carry the
  original pre-change backup; extra routes through the interface are not
  detected, and route verification happens after the no-op exit; `delete` can
  remove files before noticing the interface is still up; legacy per-node
  host-key records persist after migration, and re-learning after a key
  rotation reads the old record; a host-case mismatch between record name and
  stored host fails closed instead of reusing the pin.
- Live, on two small servers: a `delete` over the mesh path itself and that
  delete's rollback firing; plus the upgrade from the published version.
