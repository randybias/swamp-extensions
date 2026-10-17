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

| Method             | Kind   | Description                                                                                                                                                                                                        |
| ------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `define_network`   | action | Define a network (raw XML or structured), start and autostart it; `replace=true` to redefine                                                                                                                       |
| `undefine_network` | action | Stop a network if active and undefine it; use this to remove the `default` network                                                                                                                                 |
| `clone_volume`     | action | Clone a golden volume or zvol in a pool to a new volume, via the pool driver (`vol-clone`)                                                                                                                         |
| `define_domain`    | action | Define a KVM domain from a pool volume with ACPI and a pty console, plus optional extra/CD-ROM disks; optionally start it                                                                                          |
| `power`            | action | `start`, `shutdown`, `destroy`, `reboot`, `suspend`, `resume`; idempotent toward the desired state, `shutdown` waits for power-off                                                                                 |
| `console`          | query  | Attach to the serial console under a hard timeout; returns `bytes` and `sha256`, not the text                                                                                                                      |
| `undefine_domain`  | action | Destroy the domain if running, then undefine it; `remove_volumes` removes only the boot volume recorded by `define_domain` (plus read-only media with `remove_attached_media`) and detaches every other disk first |
| `get`              | query  | Report networks, domains and pool volumes from `net-list`, `list` and `vol-list`                                                                                                                                   |
| `sync`             | query  | Probe the host and report drift between the last recorded inventory and the live state                                                                                                                             |

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

`define_domain` records the resolved boot volume as `root_disk` on the
`domain_state` record, but only after `domblklist --inactive` shows the domain's
persistent config really uses it: an existing domain left alone (no `replace`)
that boots from another disk keeps its earlier record instead. `power` refreshes
the record and carries `root_disk` forward (unless the domain's uuid changed),
so `undefine_domain remove_volumes=true` after `power shutdown` still finds it.

`undefine_domain` destroys the domain whenever it is not fully off (running,
paused, `in shutdown`, `dying`), so the undefine always acts on the persistent
XML. With `remove_volumes=true` it first checks that the `domain_state` record's
uuid equals the live domain's uuid and that the recorded root is attached in the
persistent config, then detaches disks and runs `undefine --remove-all-storage`.
Every refusal happens before anything is destroyed, detached or deleted.

Exactly what is deleted versus kept:

| Disk                                                   | `remove_attached_media=false` | `remove_attached_media=true` |
| ------------------------------------------------------ | ----------------------------- | ---------------------------- |
| Recorded root (`root_disk`)                            | deleted                       | deleted                      |
| CD-ROM or floppy with a source (seed ISO, install ISO) | detached, kept                | deleted                      |
| Disk marked `<readonly/>` (file source)                | detached, kept                | deleted                      |
| Any other disk (data disk, shared image)               | detached, kept                | detached, kept               |
| Empty CD-ROM/floppy (no source)                        | nothing to delete             | nothing to delete            |

"Deleted" means left attached for `--remove-all-storage`, which only deletes a
path that libvirt manages as a storage-pool volume. So with
`remove_attached_media=false`, a CD-ROM is never deleted, even when its source
is a pool-managed volume, because it is detached first. A root or medium whose
path is not in any pool is reported by virsh as "not managed by libvirt" and is
left on disk. A read-only disk with a block-device (`dev=`) source is not
recognised as media and is always detached and kept.

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
- The host-key policy is `strict` only, with a required non-empty `host_keys`
  list. The model persists no learned keys, so `insecure_tofu` is not offered
  and there is no silent trust-on-first-use.
- The `console` capture can carry boot or login secrets, so the
  `console_capture` resource marks `text` sensitive. The method returns only
  `bytes` and `sha256`, never the text, because swamp has no sensitive result
  channel; read the text from the sensitive resource. Capture is bounded by a
  remote `timeout -s KILL` around `script -qec` (a pty, since `virsh console`
  needs one and has no `--timeout`), run inside an outer `sh -c` that survives
  the killed child and exits 0 on a timeout, so a timed-out capture returns the
  bytes read so far instead of an ssh transport error. A local deadline is a
  backstop, and `max_output_bytes` caps the bytes the transport returns. A
  SIGKILL exit counts as the timeout only when the elapsed whole seconds reach
  `timeout_s`, so an early kill (e.g. the OOM killer) is an error; `timeout_s`
  has a 5-second floor to keep that one-second ambiguity small. It passes
  `--force`, so a capture takes over the console from any operator already
  attached to it.

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
  --input host_key_policy=strict \
  --input 'host_keys=["192.0.2.20 ssh-ed25519 AAAA..."]' \
  --input 'private_key={"vault":"prod","key":"hypervisor-key"}' \
  --input pool=pool-a --input source_volume=golden --input target_volume=node-a-root

swamp behavior run @randybias/libvirt define_domain hypervisor \
  --input host=192.0.2.20 --input user=root --input uri=qemu:///system \
  --input host_key_policy=strict \
  --input 'host_keys=["192.0.2.20 ssh-ed25519 AAAA..."]' \
  --input 'private_key={"vault":"prod","key":"hypervisor-key"}' \
  --input name=node-a --input pool=pool-a --input volume=node-a-root \
  --input vcpus=2 --input memory_mib=2048 --input network=net-a --input start=true

swamp behavior run @randybias/libvirt console hypervisor \
  --input host=192.0.2.20 --input user=root --input uri=qemu:///system \
  --input host_key_policy=strict \
  --input 'host_keys=["192.0.2.20 ssh-ed25519 AAAA..."]' \
  --input 'private_key={"vault":"prod","key":"hypervisor-key"}' \
  --input name=node-a --input timeout_s=10
```

## License

Apache-2.0. See LICENSE.txt.
