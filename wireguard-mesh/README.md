# @randybias/wireguard-mesh

[Swamp](https://github.com/swamp-club/swamp) extension that renders one
WireGuard node's `wg0.conf` from mesh data and applies it to that node over SSH.
The mesh is data (peers, an allowlist, relay rules), so one definition serves
any node of any mesh.

## Models

### `@randybias/wireguard-mesh`

| Method   | Description                                                                                                                        |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `render` | Render the node's config and resolved peers, without touching it (read-only)                                                       |
| `apply`  | Write the config and key atomically (mode 0600), recreating the interface when its address changes; a proven no-op changes nothing |
| `get`    | Read peers, endpoints and latest handshakes with `wg show` (read-only)                                                             |
| `delete` | Bring the interface down and remove its config and key file                                                                        |

## Dependencies

- OpenSSH client (`ssh`, plus `ssh-agent` and `ssh-add` when `ssh.private_key`
  is given) on the control host, a POSIX host.
- `wg` and `wg-quick` on the node, and a user that may write `/etc/wireguard`.

## Install

```bash
swamp extension pull @randybias/wireguard-mesh
```

## Example

One definition with no global arguments. Each node is a set of method arguments;
stored data is keyed by the node name, so the same definition serves every node.

```bash
swamp model create @randybias/wireguard-mesh wg-node --json
```

`spoke-1.yaml` is one node's view of the mesh. `private_key` is a vault
reference, so the file holds no secret:

```yaml
node: { name: spoke-1, address: 192.0.2.2/32, listen_port: 51820 }
peers:
  - name: hub
    public_key: HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHA=
    allowed_ips: [192.0.2.1/32]
    endpoint: hub.example.com:51820
    keepalive: 25
  - name: spoke-2
    public_key: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    allowed_ips: [192.0.2.3/32]
peers_allowlist: [hub, spoke-2]
relay_exclusion:
  - { exclude: [spoke-2], for_nodes: ["*"], via: hub }
private_key: ${{ vault.get("default", "SPOKE1_WG_KEY") }}
ssh:
  host: spoke-1.example.com
  user: root
  host_key_policy: strict
  host_keys:
    - { type: ssh-ed25519, key: AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE }
```

```bash
swamp model method run wg-node render --input-file spoke-1.yaml
swamp model method run wg-node apply --input-file spoke-1.yaml
```

`get` and `delete` take only the node, interface and `ssh`, so give them a small
file:

```yaml
# ssh-only.yaml
node: spoke-1
ssh:
  host: spoke-1.example.com
  user: root
  host_key_policy: strict
  host_keys:
    - { type: ssh-ed25519, key: AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE }
```

```bash
swamp model method run wg-node get --input-file ssh-only.yaml
swamp model method run wg-node delete --input-file ssh-only.yaml \
  --input acknowledge_reachability_risk=true
```

`delete` takes the interface down, which can cut the very SSH path it runs over,
so it requires `acknowledge_reachability_risk=true`. It also arms a remote
rollback (default 120 seconds, `rollback_seconds` to change it) that restores
the saved config if the session dies before teardown is verified.

Run the same three commands for another node with that node's file. Do not save
`--json` output of an `apply` whose arguments carry a literal key: the swamp CLI
echoes method arguments, so pass the key as a vault reference only.

## How it works

- Rendering is pure and offline. The same inputs give the same bytes: peers and
  allowed IPs are sorted by name, and input order does not matter. The private
  key never appears in the text; `[Interface]` uses
  `PostUp = wg set '%i' private-key '/etc/wireguard/%i.key'` instead, and
  `apply` writes that key file from stdin at mode 0600.
- A peer that is not on `peers_allowlist` (matched by name or by public key) is
  rejected with an error naming it, not silently dropped. Duplicate names or
  keys, overlapping `allowed_ips`, and a peer that claims the node's own address
  are rejected too.
- A `relay_exclusion` rule removes the `exclude` peers from the direct peer set
  of the nodes in `for_nodes` (`"*"` means every node except the relay) and,
  with `via`, adds their addresses to the relay peer's `AllowedIPs`. A spoke
  then peers with the relay instead of with every other spoke. List only the
  relay's own addresses in its `allowed_ips`; they must not overlap the spokes'.
- `apply` backs up both durable files, stages the new config and key at mode
  0600, commits both as one guarded step, and restores both — and re-establishes
  the previous live config — if any step fails. A peer or key change uses
  `wg syncconf`; a change to the node's `Address` or to any routed `AllowedIPs`
  recreates the interface, because `wg syncconf` does not update wg-quick's
  routes, and the routes are checked afterwards. A remote `flock` serializes
  concurrent runs when available.
- A re-apply is a no-op only after the live peers and addresses are shown to
  match; a drifted interface is reconciled and reported as a change. A no-op
  writes no new state.
- `apply` and `delete` leave a detached rollback armed and disarm it only after
  a fresh management SSH connection reaches the node. The rollback takes the
  same lock and restores only its own generation, so an expired rollback cannot
  overwrite a later successful run.
- Rendering one node echoes that node's own `endpoint` back as `node_endpoint`,
  ready to paste into the other nodes' peer entries.
- SSH host keys are pinned (`strict`) or handled through `host_key_policy`,
  which has no default. `strict` requires `ssh.host_keys`. With `insecure_tofu`,
  the first accepted key is stored under `<node>-hostkeys` and pinned as
  `strict` on every later run, so a key that changes is refused rather than
  retrusted. The transport is the canonical vendored `_lib/ssh.ts`: an ssh exit
  255 is a typed error, supplied pins that apply to no host are refused, and no
  config, key or digest is ever placed on `argv`. The key and config are written
  to a private `mktemp -d` directory and the script unlinks the file as soon as
  it opens it, so they are never left at rest.
- Upgrading from 2026.10.17.4: `host_key_policy: accept-new` now maps to
  `insecure_tofu` and `insecure` is refused (the transport cannot honour it
  safely); `ssh.host_keys` entries that are `{type, key}` objects are accepted
  and converted to ssh-keyscan lines; and a stored `<node>-hostkeys` record is
  migrated to port-aware (`[host]:port`) lines on first use.
- Data is stored under the node name, e.g.
  `data.latest("wg-node", "spoke-1").attributes.config_sha256`.

## License

Apache-2.0.
