# @randybias/server-host

[Swamp](https://github.com/swamp-club/swamp) extension for bringing a freshly
provisioned Linux host to a hardened baseline over SSH. Built and tested against
Debian-family hosts with `nftables` and `systemd` (Ubuntu 24.04 LTS). The remote
exec and upload path is the reviewed SSH transport shared by these extensions;
nothing here spawns `ssh` directly.

## Models

### `@randybias/server-host`

One host, described per call by its SSH target and the phase inputs.

| Method            | Description                                                                                         |
| ----------------- | --------------------------------------------------------------------------------------------------- |
| `apply_base`      | Install packages, create the admin user and keys, write sysctl and journald settings, set time sync |
| `render_firewall` | Render the deterministic nftables ruleset and its SHA-256 without touching a host                   |
| `apply_firewall`  | Pre-check with `nft -c`, arm a revert, then apply the ruleset with `nft -f`                         |
| `lockdown`        | Restrict the SSH port to management CIDRs, armed before the change and reverted unless committed    |
| `commit`          | Cancel the armed revert for good after confirming the host is still reachable                       |
| `get`             | Report recorded phase state, the live ruleset SHA-256 and whether a revert is still armed           |
| `sync`            | Probe the host and report drift between recorded state and the live ruleset and timer               |

### Armed revert

`apply_firewall` and `lockdown` check the ruleset syntax with `nft -c`, then,
under one host-side lock, snapshot the ruleset and arm a
`systemd-run
--on-active` transient timer that restores the snapshot after
`revert_after_s` seconds. The timer lives on the host, so it fires even if the
SSH session that armed it dies. The change is not permanent until `commit`
cancels the timer; an operator who locks themselves out recovers without console
access.

The firewall owns one nftables table, `inet server_host`, and never flushes or
reads other tables: the snapshot and the restore cover only that table, so rules
added by other software (a Kubernetes distribution, Docker) survive both an
apply and a revert.

The host is the source of truth. The apply runs under the same lock as the
restore and is refused once its revert has expired, fired or been superseded, so
the two never interleave. A new change is refused while an earlier revert's
timer or service is still active, or its files remain within two minutes of its
expiry. If a step fails after arming and the outcome is unknown, the timer stays
armed and restores the host; if the apply was definitely rejected, the change
cancels its own timer.

Under `insecure_tofu` the host key is read once at the start of a method and
pinned for every step of it, so a host cannot present a different key to a later
step.

## Install

```bash
swamp extension pull @randybias/server-host
```

## Dependencies

- A POSIX control host with the OpenSSH client (`ssh`, `ssh-agent`, `ssh-add`),
  which the transport uses.
- A target with `nft`, `systemd`, `sudo`, `flock` (util-linux) and a
  Debian-family package manager.
- An SSH private key, named by a vault reference (`ssh_key_ref`); the key is
  read inside the method and never appears in arguments or logs. The host-key
  policy is required on every call; `strict` also requires pinned host keys.

## Example

One definition serves any number of hosts; the target and its inputs arrive at
run time.

```yaml
type: "@randybias/server-host"
name: hardened-host
globalArguments: {}
```

```bash
swamp behavior run @randybias/server-host apply_base hardened-host \
  --input host=192.0.2.10 --input user=root \
  --input host_key_policy=strict \
  --input 'host_keys=["192.0.2.10 ssh-ed25519 AAAA..."]' \
  --input 'ssh_key_ref={"vault":"prod","key":"server-host-key"}' \
  --input admin_user=ops --input 'packages=["curl","unattended-upgrades"]' \
  --input 'authorized_keys=["ssh-ed25519 AAAA... ops@example.com"]' \
  --input 'sysctl={"net.ipv4.ip_forward":"0"}' --input timezone=UTC

swamp behavior run @randybias/server-host lockdown hardened-host \
  --input host=192.0.2.10 --input user=root \
  --input host_key_policy=insecure_tofu \
  --input 'ssh_key_ref={"vault":"prod","key":"server-host-key"}' \
  --input 'management_cidrs=["192.0.2.0/24"]' --input ssh_port=22

swamp behavior run @randybias/server-host commit hardened-host \
  --input host=192.0.2.10 --input user=root \
  --input host_key_policy=insecure_tofu \
  --input 'ssh_key_ref={"vault":"prod","key":"server-host-key"}'
```

## How it works

`render_firewall` owns one table (`inet server_host`) and renders it with CIDRs
and ports sorted, so its SHA-256 is a stable idempotency key; re-applying an
identical ruleset is a no-op. The rendered set always removes the SSH port from
the blanket port lists, so an SSH allow can only come from the dedicated
management rules. Every caller value that reaches the host is validated against
an allowlist grammar and passed as a separate argv word, on stdin, or as a
positional parameter of a fixed script; a `/0` management range needs the
explicit `allow_ssh_from_anywhere` acknowledgement.

## License

Apache-2.0. See LICENSE.txt.
