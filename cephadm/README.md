# @randybias/cephadm

[Swamp](https://github.com/swamp-club/swamp) extension for installing and
operating a standalone Ceph cluster managed by `cephadm` on Debian-family Linux
hosts reached over SSH. Built against the Ceph Squid release (19.2.x) and apt,
dpkg and systemd; the exact cephadm point release is pinned by the caller.

## Models

### `@randybias/cephadm`

One cluster and its hosts. The model's global arguments are empty: every method
takes its own target, so one definition serves any number of hosts and clusters,
and stored state is keyed by host.

| Method                    | Description                                                             |
| ------------------------- | ----------------------------------------------------------------------- |
| `cephHostPrep`            | Ensure packages, the pinned cephadm and a time-sync service on one host |
| `cephVerifyPackageSource` | Check that each apt mirror and the cephadm URL resolve and answer       |
| `wipeDiskToRaw`           | Tear down LVM, md-RAID, filesystem and partition state on named disks   |

## Dependencies

- A control machine with the OpenSSH client (`ssh`).
- Targets on a Debian-family OS with apt, dpkg and systemd, and an SSH user that
  has passwordless `sudo`.
- The private key never travels on a command line: pass `privateKey` as a vault
  reference, and it is written to a mode-0600 file for the duration of one call.

## Install

```bash
swamp extension pull @randybias/cephadm
```

## Example

Create one generic definition and give it an `inputs` schema; run it for each
host with `--input`. Never create one definition per host.

```bash
swamp model create @randybias/cephadm cephadm --json
```

```yaml
type: "@randybias/cephadm"
name: cephadm
globalArguments: {}
```

Prepare one host, with the key kept in a vault:

```bash
swamp behavior run cephadm cephHostPrep --input host=node1.example.com \
  --input sshUser=admin --input port=22 \
  --input 'privateKey=${{ vault.get("default", "NODE1_KEY") }}' \
  --input 'packages:json=["chrony","lvm2","podman"]' \
  --input cephadmUrl=https://download.example.com/ceph/19.2.1/el9/noarch/cephadm \
  --input cephadmVersion=19.2.1 --input timeSyncService=chrony.service
```

## How it works

- Every remote action goes through the system OpenSSH client, with key-only
  authentication and `BatchMode=yes`; it never prompts for a password or a host
  key. Host-key checking is strict by default (`strictHostKeyChecking=yes`), and
  `no` is explicit and consults no real known_hosts.
- The host-key policy and port are accepted by every SSH method. A lost session
  is classified: a drop before authentication proves the command never ran and
  may be re-sent, while a mid-session loss is never re-sent blindly.
- `cephHostPrep` judges packages by `dpkg`, never by the install command's exit
  status, and never installs over a running apt or dpkg. A re-run on a ready
  host issues no apt, download or enable call.
- `wipeDiskToRaw` selects disks by serial and resolves them to a stable by-id
  path, proving each serial names exactly one device. Every safety gate runs
  before anything destructive, and a device nobody could observe is never
  reported raw. The disk wiper refuses any device that is, contains, is a member
  of or is an ancestor of whatever backs the root or boot filesystems, an
  `/etc/fstab` entry, swap, an md array, an LVM volume group or a ZFS pool, and
  it refuses everything when a read of the host fails or is empty. Its reads run
  as root, so a host without udev still reports types and UUIDs. Limits: an
  external filesystem journal or log device, and a `resume=` partition named
  only on the kernel command line, are not modelled; the kernel refuses a write
  to a device that is mounted, swapped on or claimed by an assembled array.
- Records are strict and declare every field written. No secret reaches a
  record, a log line or an error message.

## License

Apache-2.0.
