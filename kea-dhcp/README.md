# @randybias/kea-dhcp

[Swamp](https://github.com/swamp-club/swamp) extension for an ISC Kea DHCPv4
server on one Linux host. Built against the ISC Kea 2.4 line as shipped by
Ubuntu 24.04 and Debian.

## Models

### `@randybias/kea-dhcp`

One DHCPv4 server. The definition holds no host, network or MAC: every method
takes its target and DHCP inputs as arguments, and state is keyed by the target.

| Method    | Description                                                                                                                                                  |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `install` | DESTRUCTIVE. Install Kea and socat; leave the service disabled until the first apply                                                                         |
| `render`  | READ-ONLY. Render the config JSON, its sha256 and the ordered apply plan; touches no host                                                                    |
| `apply`   | DESTRUCTIVE. Validate, arm the revert, write the file and config-set it; not permanent until commit                                                          |
| `commit`  | DESTRUCTIVE. Re-verify over a fresh connection and cancel the armed revert                                                                                   |
| `get`     | READ-ONLY. Probe the service, config, sockets and revert, then persist the observation                                                                       |
| `sync`    | READ-ONLY. Re-probe, adopt a fired revert and report drift                                                                                                   |
| `leases`  | READ-ONLY. Query current leases (memfile or lease_cmds), optionally filtered                                                                                 |
| `remove`  | DESTRUCTIVE. Stop and disable, converge to the package's original config under the armed-revert protocol; run `commit` to finalize. A second call is a no-op |

## Dependencies

- A Linux host on the Debian family with `systemd`, `apt`, `socat`, `flock`
  (util-linux) and the OpenSSH client tools on the runner.
- The `kea-dhcp4-server` package. DHCPv6, DDNS, HA and SQL lease backends are
  out of scope.
- The remote user must be `root`: every step (apt, systemd, `/etc/kea`, the
  control socket) is privileged and this extension does not invoke `sudo`.

## Install

```bash
swamp extension pull @randybias/kea-dhcp
```

## Example

Create one definition and configure any host. The private key is a vault
reference, resolved through the vault service and delivered over stdin:

```bash
swamp model create @randybias/kea-dhcp kea-dhcp
```

```bash
swamp model method run kea-dhcp render \
  --input interfaces:json='["eth1"]' \
  --input 'subnets:json=[{"id":10,"subnet":"192.0.2.0/24","pools":["192.0.2.10 - 192.0.2.50"],"reservations":[{"hw_address":"02:00:00:00:00:01","ip_address":"192.0.2.9"}],"options":[{"name":"routers","value":["192.0.2.1"]}]}]'

swamp model method run kea-dhcp apply \
  --input host=192.0.2.10 --input user=root \
  --input host_key_policy=strict \
  --input 'host_keys:json=["192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"]' \
  --input ssh_key_ref=default/SSH_KEY \
  --input interfaces:json='["eth1"]' \
  --input 'subnets:json=[{"id":10,"subnet":"192.0.2.0/24","pools":["192.0.2.10 - 192.0.2.50"],"reservations":[],"options":[]}]'
```

`apply` (and `remove`) returns a revert token and expiry; run `commit` before
the window ends to make the change permanent. Otherwise the host restores the
previous config.

## How it works

- The config file (`/etc/kea/kea-dhcp4.conf`) is the source of truth; the live
  change is a `config-set` of the same JSON over the local control socket. It
  never uses `config-reload`, a restart or `config-write`. When the service is
  not running yet (the state `install` leaves), the first apply starts it on the
  new file under the armed revert, and `commit` enables it.
- The file keeps the group the service runs as: the group is read from the unit
  (`systemctl show -p User`), set on the staged file and the file is renamed
  into place atomically. A `chgrp` that fails fails the apply.
- Every apply validates the render with `kea-dhcp4 -t`, claims the revert under
  a host-side `flock` (refuse-active and snapshot together), arms a host-side
  `systemd-run` restore timer, then installs and pushes the file. On any later
  failure the file is restored and the revert disarmed. The restore script
  records pass/fail and a recovery note.
- `commit` is a gate: it requires the service active, a running config hash
  equal to the applied one, `systemctl enable` to succeed, the canaries to
  answer and a fresh-connection probe with no failed check. Only then does it
  take the shared revert lock, stop the timer, confirm the transient restore
  unit never started and write the `committed` marker, so a restore that wins
  the race can never undo a commit. `sync` adopts a fired revert.
- The restore and the commit share `/run/kea-dhcp-revert.lock`; the restore
  exits early when the `committed` marker exists. The claim records the
  service's prior `is-active` and `is-enabled` state, and the restore returns
  both, so a fired revert cannot leave the service disabled.
- `remove` runs the same arm/verify protocol, converging the service disabled
  and the package's original config back regardless of its prior state.
- `render` is deterministic: subnets sort by id, pools by start, reservations by
  address and options by name.
- `classless-static-route` (option 121) is not offered: the stock Kea 2.4 option
  dictionary has no definition for it, so a config that names it fails
  `kea-dhcp4 -t`. The `lease_cmds` hook path must be the packaged library in the
  host's hooks directory, owned by root and not writable by others (loading a
  hook runs its code as root during `-t`).
- The model holds no secret: lease backends with credentials are refused, and
  `config-get` output is never returned or persisted, only its hash.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
