# @randybias/libvirt

[Swamp](https://github.com/swamp-club/swamp) extension for managing libvirt/KVM
over SSH: virtual networks, storage volumes and domains through
`virsh -c <uri>`. Built for the golden-image workflow — keep one golden volume,
clone it per node, define each domain from its clone, and drive power and the
serial console. The remote exec and upload path is the reviewed SSH transport
shared by these extensions; nothing here spawns `ssh` directly and no `virsh` is
run over `argv` on the control host.

## Models

### `@randybias/libvirt`

One definition manages any hypervisor: the SSH target, the libvirt URI and every
operand are method arguments. State is keyed by the canonical
`{host, port, user}` plus the resource name.

| Method             | Kind   | Description                                                                                                                                         |
| ------------------ | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `define_network`   | action | Define a network (raw XML or structured), start and autostart it; `replace=true` to redefine                                                        |
| `undefine_network` | action | Stop a network if active and undefine it; use this to remove the `default` network                                                                  |
| `clone_volume`     | action | Clone a golden volume or zvol in a pool to a new volume, via the pool driver (`vol-clone`)                                                          |
| `define_domain`    | action | Define a KVM domain from a pool volume with ACPI and a pty console, plus optional extra/CD-ROM disks; optionally start it                           |
| `power`            | action | `start`, `shutdown`, `destroy`, `reboot`, `suspend`, `resume`; idempotent toward the desired state, `shutdown` waits for power-off                  |
| `console`          | query  | Attach to the serial console under a hard timeout; returns `bytes` and `sha256`, not the text                                                       |
| `undefine_domain`  | action | Destroy the domain if running, then undefine it; `remove_volumes` removes its volumes but keeps an attached seed ISO unless `remove_attached_media` |
| `get`              | query  | Report networks, domains and pool volumes from `net-list`, `list` and `vol-list`                                                                    |
| `sync`             | query  | Probe the host and report drift between the last recorded inventory and the live state                                                              |

`define_network`, `undefine_network`, `clone_volume`, `define_domain`, `power`
and `undefine_domain` are `kind: action`, so a single method call cannot mark
every record of a shared definition deleted. `undefine_network`,
`undefine_domain` and `power` with `action: destroy` are DESTRUCTIVE.

## Golden-image workflow

```text
clone_volume   pool=pool-a  source_volume=golden  target_volume=node-a-root
define_domain  pool=pool-a  volume=node-a-root  name=node-a  ...  start=true
power          name=node-a  action=shutdown
undefine_domain name=node-a remove_volumes=true
```

`clone_volume` is idempotent: an existing target is a no-op, never a second
clone. `define_domain` renders the domain XML, including a pty `<serial>` and
`<console>`, so `console` and `virsh console node-a` both attach. The boot disk
is `<disk type='file'>` with the path resolved by `virsh vol-path`: a
`type='volume'` disk is denied by AppArmor on a stock Ubuntu host, so qemu could
not open the clone. `<features><acpi/><apic/></features>` is always rendered so
the ACPI power button works and `power shutdown` can power the guest off.
`extra_disks` attaches more disks — a `cdrom` defaults to read-only, so a
cloud-init NoCloud seed ISO can be attached. `define_domain` refuses to define
from a volume that does not exist, so it always follows a successful clone.

## Idempotency and safety

- Every object name is checked against `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`, the
  guest architecture against an allowlist (`x86_64`, `aarch64`, `i686`,
  `ppc64le`, `s390x`), a DHCP DNS domain against a DNS-name grammar, and the
  libvirt URI against local schemes only (`qemu:///`, `test:///`, `xen:///`,
  `lxc:///`, `vbox:///`, `bhyve:///`), so no operand can inject a shell word or
  XML. A `+ssh`/`+tls` remote URI, a userinfo section or a URI query parameter
  is refused: the URI runs on the hypervisor, so it would open a second
  connection outside this extension's host-key policy.
- `define_network` compares a stable projection of `net-dumpxml` against the
  rendered XML; an identical network is a true no-op, a differing one is left
  untouched and reported as `drift`, and only `replace=true` destroys and
  redefines it. With raw `xml` the projection cannot be compared, so an existing
  name is a no-op unless `replace=true`, and the XML's `<name>` must equal
  `name`.
- A `net-info`, `dominfo` or `vol-info` failure is only read as absence for an
  explicit not-found; a refused connection or denied permission is a typed
  error, so a broken URI can never record `present: false` or trigger a define.
- `undefine_network` and `undefine_domain` treat an absent object as a clean
  no-op.
- Remote XML for `*-define` is written to a temp file with an allowlist-checked
  token and removed in a `finally`, so no XML is left on the hypervisor.

## Security

- `private_key` is a sensitive argument, marked `.meta({ sensitive: true })`,
  and is delivered to the remote only through the SSH agent/stdin path — never
  in remote `argv` and never in a log. Pass it from a vault reference.
- The host-key policy is required on every call: `strict` trusts only the pinned
  `host_keys`, and `insecure_tofu` is an explicit opt-in, never a default. There
  is no silent `accept-new`.
- The `console` capture can carry boot or login secrets, so the
  `console_capture` resource marks `text` sensitive. The method returns only
  `bytes` and `sha256`, never the text, because swamp has no sensitive result
  channel; read the text from the sensitive resource. Capture is bounded by a
  remote `timeout -s KILL` around `script -qec` (a pty, since `virsh console`
  needs one and has no `--timeout`), run inside an outer `sh -c` that survives
  the killed child and exits 0 on a timeout, so a timed-out capture returns the
  bytes read so far instead of an ssh transport error. A local deadline is a
  backstop, and `max_output_bytes` caps the bytes the transport returns. It
  passes `--force`, so a capture takes over the console from any operator
  already attached to it.

## Install

```bash
swamp extension pull @randybias/libvirt
```

## Dependencies

- A POSIX control host with the OpenSSH client (`ssh`, `ssh-agent`, `ssh-add`),
  which the transport uses.
- A target running libvirtd with `virsh` reachable over SSH, and permission to
  manage the selected connection URI (for example `qemu:///system`, usually as
  root or via a libvirt group). The `console` method additionally needs
  `timeout` and `script` (util-linux) on the target, because `virsh console`
  needs a pty and has no `--timeout` of its own.
- An SSH private key, passed as a sensitive argument; the host-key policy is
  required on every call.

## Example

One definition serves any number of hypervisors; the target, URI and operands
arrive at run time.

```yaml
type: "@randybias/libvirt"
name: hypervisor
globalArguments: {}
```

```bash
swamp behavior run @randybias/libvirt define_network hypervisor \
  --input host=192.0.2.20 --input user=root --input uri=qemu:///system \
  --input host_key_policy=strict \
  --input 'host_keys=["192.0.2.20 ssh-ed25519 AAAA..."]' \
  --input 'private_key={"vault":"prod","key":"hypervisor-key"}' \
  --input name=net-a --input mode=nat --input gateway=192.0.2.1 --input prefix=24 \
  --input dhcp_start=192.0.2.10 --input dhcp_end=192.0.2.99

swamp behavior run @randybias/libvirt clone_volume hypervisor \
  --input host=192.0.2.20 --input user=root --input uri=qemu:///system \
  --input host_key_policy=insecure_tofu \
  --input 'private_key={"vault":"prod","key":"hypervisor-key"}' \
  --input pool=pool-a --input source_volume=golden --input target_volume=node-a-root

swamp behavior run @randybias/libvirt define_domain hypervisor \
  --input host=192.0.2.20 --input user=root --input uri=qemu:///system \
  --input host_key_policy=insecure_tofu \
  --input 'private_key={"vault":"prod","key":"hypervisor-key"}' \
  --input name=node-a --input pool=pool-a --input volume=node-a-root \
  --input vcpus=2 --input memory_mib=2048 --input network=net-a --input start=true

swamp behavior run @randybias/libvirt console hypervisor \
  --input host=192.0.2.20 --input user=root --input uri=qemu:///system \
  --input host_key_policy=insecure_tofu \
  --input 'private_key={"vault":"prod","key":"hypervisor-key"}' \
  --input name=node-a --input timeout_s=10
```

## License

Apache-2.0. See LICENSE.txt.
