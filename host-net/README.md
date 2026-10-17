# @randybias/host-net

[Swamp](https://github.com/swamp-club/swamp) extension for configuring Linux
host networking over SSH under an **automatic revert armed before anything is
changed**. It manages a bridge (Linux or Open vSwitch), a VLAN-tagged storage
plane and jumbo MTU on the physical NIC → VLAN → bridge chain. Built for the
case where a bad network change costs an out-of-band console visit: the
host-side revert timer restores the previous configuration unless the operator
confirms over a fresh connection that the management path still works.

Generic: interface names, MACs, VLAN ids, MTUs and addresses are inputs, and one
definition serves any host. The remote exec and upload path is the reviewed SSH
transport shared by these extensions.

## Models

### `@randybias/host-net`

| Method                | Kind   | Description                                                                                      |
| --------------------- | ------ | ------------------------------------------------------------------------------------------------ |
| `render`              | query  | READ-ONLY. Return the files the backend would write, the ordered step plan and the config sha256 |
| `apply`               | action | DESTRUCTIVE. Pre-check, snapshot, **arm the revert**, apply with MTU ordering, verify            |
| `commit`              | action | DESTRUCTIVE. Verify over a fresh connection, then cancel the armed revert                        |
| `get`                 | query  | READ-ONLY. Recorded config and revert plus a live link/addr/route probe                          |
| `sync`                | query  | READ-ONLY. Re-probe and reconcile recorded state with the host                                   |
| `remove`              | action | DESTRUCTIVE. Remove managed devices and files, MTUs in reverse order, same armed revert          |
| `revert_now`          | action | DESTRUCTIVE. Fire the armed revert immediately (tests and operator recovery)                     |
| `clear_failed_revert` | action | DESTRUCTIVE. Clear a revert whose restore recorded `fail`, once the host checks pass again       |

The revert removes **only** the virtual devices this change created and restores
the managed config files from the snapshot; it never flushes the OVS database or
touches devices it did not create. `bridge_type` is a required input with no
default (`linux` or `ovs`), so the bridge implementation is never chosen
silently.

## Inputs

- **SSH target** — `host`, `port`, `user`, `host_key_policy` (required,
  `strict`), `host_keys[]` (required, at least one pinned key), `ssh_key_ref` (a
  sensitive vault reference), `connect_timeout_s`. Only the pinned keys are
  trusted: the model does not persist a first-seen key, so trust-on-first-use is
  not offered.
- **`backend`** — `netplan` (default) or `networkd`. `networkd` supports Linux
  bridges only.
- **`bridge_type`** — `linux` or `ovs`, required.
- **`management_interface`** — the interface carrying the SSH session and the
  default route, required. The model also discovers it host-side from
  `SSH_CONNECTION` and refuses on mismatch.
- **`mode`** — `additive` (default) or `takeover` (which also requires
  `management_change_ack: true`).
- **`ethernets[]`**, **`vlans[]`**, **`bridge`**, **`mtu_peer`**,
  **`revert_after_s`** (default 300, 120–1800), **`require_mtu_verify`**.

Names follow `IFNAMSIZ` (`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`); MACs are lowercase
unicast; VLAN ids are 1–4094; MTUs are 1280–9216; addresses are strict host
CIDRs with no `/0`. A VLAN's MTU may not exceed its link's, and a bridge's may
not exceed its smallest port's. The storage plane carries no gateway, default
route, DHCP or IPv6 RA. A storage address that overlaps a management address is
refused.

## The armed revert

`apply` and `remove` build one ordered step stream. The `arm` step (the
`systemd-run` timer activation — not the `stage` of the script) precedes every
`mtu`, `write` and `apply` step, and the model persists the `revert` record
before the first write. Tests assert both. The timer lives on the host, so it
fires even if the SSH session dies; `commit` cancels it only after a fresh
connection proves the management path, and `revert_now` fires it early. If the
restore itself fails, the marker records `fail` and further applies are refused
until an operator clears it — the model never reboots the host.

The restore judges itself by the management path the SSH session actually used.
At arm time the host records the peer address and the device, gateway and source
address `ip route get <peer>` picks for it (IPv4 or IPv6), plus the source's
prefix length, and refuses to arm (exit 77, nothing changed) if it cannot or if
that path does not pass its own checks. After the restore the same route lookup
must give the same device, gateway and source, the source must still be
configured with the same prefix length, and the route must not be `linkdown` or
`dead`. A default route or address on another NIC proves nothing. The exit
status of `netplan apply` / `networkctl reconfigure` is only logged (stderr and
the journal as `host-net`), because a cloud-init netplan that matches an
already-renamed NIC by MAC can exit non-zero on a host that is in fact restored.

### Clearing a failed restore

1. Inspect the host: `ip -br addr`, `ip route show default`,
   `journalctl -t host-net -u 'host-net-revert-*'`, and
   `cat /var/lib/host-net/revert/*/marker.json` (look for `"result":"fail"`).
   Repair the network by hand if the checks above do not hold.
2. Run the `clear_failed_revert` method with the same target arguments. It
   refuses unless the host marker says `fail` and the same checks (recorded at
   arm time) pass right now; then it stops any leftover revert timer and removes
   the marker and revert state, so the next `apply` is accepted. It never edits
   the network.

By hand, the equivalent is: take the lock (`flock /run/host-net.lock sh`), read
the token in `/var/lib/host-net/current`, confirm that
`/var/lib/host-net/revert/<token>/marker.json` says `"result":"fail"` and that
the checks hold, then
`systemctl stop host-net-revert-<token>.timer
host-net-revert-<token>.service`,
remove `/var/lib/host-net/current` and remove only
`/var/lib/host-net/revert/<token>`. Never remove all of `/var/lib/host-net`:
that also destroys an armed revert's snapshot and restore script.

## Dependencies

- A POSIX control host with the OpenSSH client.
- A target with `ip`, `flock` and `systemd-run`; `netplan` (Ubuntu) or
  `systemd-networkd` (Debian); and for `bridge_type: ovs`, `ovs-vsctl` and
  `openvswitch-switch`.

## Example

```yaml
type: "@randybias/host-net"
name: host-net
globalArguments: {}
```

```bash
swamp behavior run @randybias/host-net apply host-net \
  --input host=192.0.2.20 --input user=root \
  --input host_key_policy=strict \
  --input 'host_keys=["192.0.2.20 ssh-ed25519 AAAA..."]' \
  --input 'ssh_key_ref={"vault":"prod","key":"host-net-key"}' \
  --input bridge_type=linux --input management_interface=enp1s0 \
  --input 'ethernets=[{"name":"enp1s0","mtu":9000}]' \
  --input 'vlans=[{"id":100,"link":"enp1s0","mtu":9000,"addresses":["198.51.100.10/24"]}]'
```

## License

Apache-2.0. See LICENSE.txt.
