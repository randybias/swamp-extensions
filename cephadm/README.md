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

| Method                          | Description                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| `cephHostPrep`                  | Ensure packages, the pinned cephadm and a time-sync service on one host             |
| `cephVerifyPackageSource`       | Check that each apt mirror and the cephadm URL resolve and answer (read-only)       |
| `wipeDiskToRaw`                 | Tear down LVM, md-RAID, filesystem and partition state on named disks (destructive) |
| `cephBootstrap`                 | Bootstrap a new standalone cluster on one host, or do nothing when one exists       |
| `cephDistributeKey`             | Append the cluster public key to authorized_keys on every listed host               |
| `cephHostAdd`                   | Enrol a host with the orchestrator and read the host list back                      |
| `cephApplyMon`                  | Converge mon placement to an explicit host list, keeping a quorum majority          |
| `cephApplyMgr`                  | Converge mgr placement to an explicit host list                                     |
| `cephApplyMds`                  | Converge one filesystem's MDS placement to an explicit host list                    |
| `cephApplyOsd`                  | Apply an OSD service, fleet-wide or one by-serial service per host                  |
| `cephCreatePool`                | Ensure a replicated or erasure-coded pool exists with the requested shape           |
| `cephCreateFs`                  | Ensure a CephFS volume exists with its MDS daemons on an explicit host list         |
| `cephCreateCsiUser`             | Create a client entity or set its caps exactly, then read the caps back             |
| `cephGetConnBundle`             | Produce the non-secret connection facts a client needs (read-only)                  |
| `cephFetchCsiKey`               | Read one client entity's key into a sensitive, vaulted field                        |
| `cephDeleteFs`                  | Delete a CephFS volume and its pools after double confirmation (destructive)        |
| `cephRemoveOsds`                | Remove OSDs through the orchestrator and prove they are gone (destructive)          |
| `cephVerifyMonQuorum`           | Assert the monmap size and that every mon is in quorum (read-only)                  |
| `cephVerifyMgr`                 | Assert the mgr count and that one mgr is active (read-only)                         |
| `cephVerifyOsd`                 | Assert OSD up and in counts and the CRUSH failure domain (read-only)                |
| `cephVerifyCsiUsers`            | Assert every expected client entity exists and report its caps (read-only)          |
| `cephVerifyHealth`              | Assert cluster health in a stated direction, naming the checks (read-only)          |
| `cephVerifyHostNoout`           | Check the host-subtree noout flag against a stated expectation (read-only)          |
| `cephVerifyHostPrep`            | Assert packages, pinned cephadm and time sync without changing anything (read-only) |
| `cephVerifyDisksRaw`            | Assert each named device has no signature, children or mountpoint (read-only)       |
| `cephVerifyKeyDistributed`      | Re-read each host's authorized_keys and report per-host key state (read-only)       |
| `cephCapacityReport`            | Report cluster and per-pool capacity with the durability margin (read-only)         |
| `cephVerifyMonPlacement`        | Judge a proposed mon host list against live quorum, applying nothing (read-only)    |
| `cephVerifyMgrPlacement`        | Judge a proposed mgr host list, applying nothing (read-only)                        |
| `cephVerifyPool`                | Assert a pool's size and that every PG is active+clean (read-only)                  |
| `cephVerifyRbdSmoke`            | Create and remove one throwaway RBD image to prove the data path                    |
| `cephVerifyOsdClaimable`        | Judge which disks cephadm would claim, applying nothing (read-only)                 |
| `cephHostMaintenanceEnter`      | Put one host into maintenance and prove the effect                                  |
| `cephHostMaintenanceExit`       | Take one host out of maintenance and prove its OSDs are restored                    |
| `cephHostMaintenanceState`      | Report which hosts are out by maintenance status or noout flag (read-only)          |
| `cephOsdOkToStop`               | Ask the orchestrator whether one host can be stopped safely (read-only)             |
| `cephCephadmCheckHost`          | Run cephadm check-host for one host and classify the result (read-only)             |
| `cephHostNooutClear`            | Clear an orphaned host-subtree noout flag for one host                              |
| `cephOsdActivate`               | Re-create OSD daemons for existing OSD volumes on one host                          |
| `cephHostClusterState`          | Report what Ceph state one host carries on its OS disk (read-only)                  |
| `cephVerifyClusterFsid`         | Refuse unless every fsid on the host is the named one (read-only)                   |
| `cephDisableOrchestration`      | Disable the cephadm mgr module so no daemons are deployed, and prove it             |
| `cephRmCluster`                 | Purge a named cluster from one host and prove its state is gone (destructive)       |
| `cephVerifyHostTornDown`        | Verify one host's OS disk carries no Ceph cluster state (read-only)                 |
| `cephRgwBucketInventory`        | List every RGW bucket with owner, size and placement (read-only)                    |
| `cephRgwUserEnsure`             | Ensure an RGW user exists; keys are generated and returned only vaulted             |
| `cephRgwBucketInspect`          | Read one bucket's ACL, policy, versioning and Public Access Block (read-only)       |
| `cephRgwBucketEnsure`           | Ensure a bucket exists, is private and fully Public-Access-Blocked (destructive)    |
| `cephRgwBucketPolicyEnsure`     | Replace a bucket's policy with the caller's document (destructive)                  |
| `cephRgwBucketVersioningEnsure` | Converge a bucket's versioning to Enabled or Suspended and re-read it               |

## Workflows

The catalog runs against a model definition named `cephadm`. Every mutating
workflow asks for approval, then proves its effect with an independent read-back
and reports a failure without remediating. Every workflow requires an explicit
`port` and a `host_key_policy` of `strict` or `insecure_tofu`; `strict` also
needs `host_keys` (ssh-keyscan lines, each naming its host).

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

Known limits, checked before approval where they can be:

- `cephadm-distribute-key` re-reads keys with one port, so every `hosts[].port`
  must equal the single `port` input; a pre-approval assert enforces that.
- `cephadm-add-host` proves the host is present in the orchestrator host list;
  the host-list record carries no address, so the requested address is not
  re-read.
- `cephadm-create-csi-user` proves the entity exists; the requested caps are set
  by the mutation and are not independently re-read.

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
  --input sshUser=admin --input port=22 --input host_key_policy=strict \
  --input 'host_keys:json=["node1.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"]' \
  --input 'privateKey=${{ vault.get("default", "NODE1_KEY") }}' \
  --input 'packages:json=["chrony","lvm2","podman"]' \
  --input cephadmUrl=https://download.example.com/ceph/19.2.1/el9/noarch/cephadm \
  --input cephadmVersion=19.2.1 --input timeSyncService=chrony.service
```

## How it works

- Every remote action goes through the canonical vendored `_lib/ssh.ts`: the
  system OpenSSH client with `-F /dev/null` (so `~/.ssh/config`, ProxyJump and
  the like are ignored), `BatchMode=yes`, and the private key loaded into a
  short-lived ssh-agent over stdin. Nothing secret is on disk or argv, and there
  is no ControlMaster/multiplex. Host-key checking is `strict` (pinned
  `host_keys`) or `insecure_tofu` (learn and pin the first key per host:port in
  the `hostkeys` resource); every pinned line must name its host.
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
  as root, so a host without udev still reports types and UUIDs. A boot-type
  partition (BIOS boot, EFI System, and similar) on any disk is refused too,
  because the firmware's boot device cannot be found from the root topology;
  `acknowledgeBootPartitions` on a data device's serial lifts that one refusal
  for that disk and nothing else. Boot code in sector 0 of a candidate disk (a
  non-zero code area with the 55 AA signature, as GRUB leaves in an msdos MBR
  gap) is treated the same way, and an unreadable sector 0 or partition type
  refuses. On an EFI host the entries named by BootCurrent, BootNext and
  BootOrder, in GPT or MBR form, are protected even when acknowledged. The
  acknowledgement cannot lift a multipath data disk (its partitions sit on the
  path devices); that is fail-closed. A serial may be listed once in
  `dataDevices`. Limits: an external filesystem journal or log device, and a
  `resume=` partition named only on the kernel command line, are not modelled;
  the kernel refuses a write to a device that is mounted, swapped on or claimed
  by an assembled array.
- Records are strict and declare every field written. No secret reaches a
  record, a log line or an error message.

## License

Apache-2.0.
