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

## Workflows

The catalog runs against a model definition named `cephadm`. Every mutating
workflow asks for approval, then proves its effect with an independent read-back
and reports a failure without remediating. Every workflow requires an explicit
`port` and a `strictHostKeyChecking` of `yes` or `no`.

| Workflow                        | Description                                                              |
| ------------------------------- | ------------------------------------------------------------------------ |
| `cephadm-prep-host`             | Install packages, pinned cephadm and time sync on one host               |
| `cephadm-wipe-disks`            | Wipe one host's named data disks to raw, with a dry-run mode             |
| `cephadm-bootstrap-cluster`     | Bootstrap a new cluster on one host and prove the first mon is in quorum |
| `cephadm-distribute-key`        | Install the cluster public key on hosts and prove cephadm can reach them |
| `cephadm-add-host`              | Register one host with the orchestrator and read the host list back      |
| `cephadm-apply-mon`             | Converge mons to an explicit host list and wait for quorum to settle     |
| `cephadm-apply-mgr`             | Converge mgr daemons to an explicit host list after a placement check    |
| `cephadm-apply-osds`            | Apply OSDs on named disks or all available ones, then prove the counts   |
| `cephadm-create-pool`           | Create or converge a replicated or erasure-coded pool and verify it      |
| `cephadm-create-fs`             | Create or adopt a CephFS volume with MDS daemons on named hosts          |
| `cephadm-apply-mds`             | Place a filesystem's MDS daemons on an explicit list of hosts            |
| `cephadm-create-csi-user`       | Create or converge a client entity's caps and prove that it exists       |
| `cephadm-get-conn-bundle`       | Capture the cluster's non-secret client connection facts                 |
| `cephadm-fetch-csi-key`         | Read one client entity's key into a vaulted record                       |
| `cephadm-delete-fs`             | Delete one CephFS volume and its pools after a typed confirmation        |
| `cephadm-remove-osds`           | Remove OSDs by id after a health gate and prove the remaining counts     |
| `cephadm-inventory-rgw-buckets` | List RGW buckets with per-bucket stats and flag any that cannot be read  |
| `cephadm-verify-health`         | Check cluster health against an allowlist of warning checks              |
| `cephadm-verify-host-prep`      | Check one host's packages, cephadm version and time-sync service         |
| `cephadm-verify-mgr`            | Check that the mgr count matches and one mgr is active                   |
| `cephadm-verify-mon-quorum`     | Check that the mon count matches and every mon is in quorum              |
| `cephadm-verify-osds`           | Check OSD up and in counts and the CRUSH failure domain                  |

Read-only workflows halt on a failed verdict; mutating ones write evidence and
never roll back. `cephadm-fetch-csi-key` vaults the key it reads and no workflow
reads that field.

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
  --input sshUser=admin --input port=22 --input strictHostKeyChecking=yes \
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
  reported raw.
- Records are strict and declare every field written. No secret reaches a
  record, a log line or an error message.

## License

Apache-2.0.
