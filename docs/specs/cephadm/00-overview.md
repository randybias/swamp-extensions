# `@randybias/cephadm`: behaviour specification

Status: draft for review · Date: 2026-10-14 · Clean-room spec (see
`docs/CLEANROOM.md`)

This specification is the **only** description of the behaviour that
implementers may use. It says what the extension must do and why. How to do it
is the implementer's choice, within the conventions in `CONVENTIONS.md`.

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Reading order

| File | Contents |
|---|---|
| `00-overview.md` | Scope, model contract, method registry, resource catalog, cross-cutting conventions, **decisions D1–D76** |
| `01-transport.md` | SSH execution, cephadm-shell execution, retry rules, input grammars, error taxonomy, backoff, serial→device resolution |
| `02-hostprep.md` | Host preparation, package-source pre-flight, disk wiping |
| `03-lifecycle.md` | Bootstrap, key distribution, host add, mon/mgr/mds/OSD placement |
| `04-dataplane.md` | Pools, CephFS, client entities, connection bundle, key fetch, FS delete, OSD removal |
| `05-verify.md` | Verification methods, placement pre-checks, capacity report |
| `06-maintenance-teardown.md` | Maintenance enter/exit, noout, ok-to-stop, check-host, OSD activate, teardown chain |
| `07-rgw.md` | RGW users (admin plane) and buckets (S3 plane) |
| `08-workflows.md` | The workflow catalog shipped with the extension |

Where this overview's **Decisions** section and a group file disagree, the
decision wins. Fix the group file when that happens.

## 1. Scope

**In scope.** One model type, `@randybias/cephadm`. It installs and operates a
standalone Ceph cluster managed by `cephadm` on Linux hosts reached over SSH:

- host preparation;
- disk wiping;
- bootstrap;
- daemon placement;
- pools, CephFS and client entities;
- RGW users and buckets;
- maintenance;
- teardown;
- read-only verification for every mutating step.

It ships with a set of workflows that wrap these methods with approval gates
and read-back proofs.

**Target.**
- **Ceph:** the Squid release (19.2.x), with the exact point release pinned by
  the caller.
- **OS:** Debian-family hosts using apt, dpkg and systemd.
- **Runner:** a control machine with OpenSSH.
- **Testing:** the README states the exact versions tested on the twin
  environment.

**Out of scope for v1.**
- Rook or Kubernetes (that is `@randybias/rook-ceph`).
- IPv6 addressing.
- Non-apt distributions.
- Non-default CRUSH roots.
- Device classes.
- Multisite RGW.
- Upgrading Ceph versions.

## 2. Model contract

- **Type** is `@randybias/cephadm`. **Version** is CalVer and MUST equal the
  manifest version (D55).
- **`globalArguments` is an empty object.** Every method takes its own target
  as arguments: an SSH target, or an S3 endpoint for the four bucket methods.
  So one instance serves any number of hosts and clusters, and nothing about a
  deployment is stored on the instance.
- **Dependency seams.** The model is built by a factory with overridable
  dependencies, so unit tests never open a socket or touch a host:
  - SSH process spawner;
  - clock;
  - sleep;
  - randomness source;
  - HTTP fetch, used by the S3 methods only.

  The production export is the factory called with no overrides.
- **HTTP for S3** opens a fresh connection per request, with no keep-alive
  reuse. Reason: at least one RGW build was seen answering the request that
  follows a denied small-body PUT on a reused connection with a spurious 405.
- **Pre-flight check.** One check, `ssh-installed`, labelled `live`. It passes
  if the `ssh` binary can be spawned (`ssh -V`; the exit code is ignored). It
  applies to every SSH-using method and **not** to the four S3 methods.
  - Test: the set of methods the check applies to equals exactly the set of
    SSH methods. Both directions are checked, so no method can be added
    without being classified.
- **Upgrades.** The first published version has an upgrade chain whose last
  `toVersion` equals the model version (D56). Every later version bump appends
  an entry in the same change.
  - Test: the last `toVersion` equals the factory's version. Never compare
    against a literal.
- **Logging.** Structured templates with named placeholders. `info` marks
  operation and phase boundaries. `warn` covers anything a reader must know
  even though the run continued, for example:
  - a retried transport blip;
  - a poll budget raised to its floor;
  - a busy package lock;
  - a reinstalled binary;
  - a recovered bootstrap;
  - an apt proxy;
  - versioning enabled on a bucket;
  - an unreachable orchestrator;
  - leftover LVM;
  - a ControlMaster close failure.

  **No secret ever reaches a log, a resource or an error message.**

## 3. Shared argument family (every SSH method)

| Argument | Type | Rule |
|---|---|---|
| `host` / `adminHost` / `hosts[]` | string(s) | hostname or IPv4 grammar (01-transport) |
| `sshUser` | string | required; POSIX username grammar (D1) |
| `port` | integer, nullish | 1–65535; absent means 22. Workflows MUST pass it explicitly (D57) |
| `keyPath` | string, nullish | local absolute path, no control characters (D2) |
| `privateKey` | string, nullish, **sensitive** | key content from a vault reference |
| `strictHostKeyChecking` | `yes` \| `no`, nullish | absent means `yes` |

- `keyPath` and `privateKey` together MUST be refused.
- An empty string means absent, and so does null.
- Every optional argument is **nullish**, not just optional. Workflows pass
  `has(x) ? x : null`, and an optional-only schema rejects an explicit null.

## 4. Conventions every method follows

- **Errors.**
  - Every thrown error starts with `cephadm[<phase>]:`, followed by
    `key=value` pairs that are never secret: host, expected, actual and so on.
    A halted workflow's message alone must say which step failed, and with
    which values.
  - The error taxonomy is in 01-transport.
- **Verify-result contract.** Every method in the verify group returns and
  records `{pass, expected, actual, detail, subject?}`.
  - `actual` is null when nothing was observed.
  - `throwOnFail` defaults to `true`.
  - **The record is written first, then the method throws** (D40), so failing
    evidence is always kept.
- **Record keys** are stable and can be built by a caller, never timestamped:
  - `<method>-<host>`;
  - `<method>-<host>-<subject>` when the check is about one pool, filesystem,
    entity or host name;
  - for multi-host methods, `<method>-<host:port,…>`, sorted and joined with
    commas.
- **Description leads:**
  - read-only methods start with `READ-ONLY.`;
  - destructive methods start with `DESTRUCTIVE.`;
  - `cephFetchCsiKey` starts with `SENSITIVE.`
- **Data lifetime.**
  - Every resource is `lifetime: infinite` and keeps the last 10 versions.
  - `cephCapacityReport` has lifetime `7d`.
  - `csiKey` keeps 2 versions (D33).
  - Every resource schema is strict and declares **every** field that is
    written (D41, D49).

## 5. Method registry (50 methods)

Safety classes:
- **RO**: read-only.
- **M**: mutating, an idempotent converge.
- **M!**: mutating, fail-closed.
- **D**: destructive.
- **S**: sensitive read.
- **W**: read-only verdict, but writes a throwaway object and removes it.

| # | Method | Class | Purpose | Spec |
|---|---|---|---|---|
| 1 | cephHostPrep | M | Ensure named packages, pinned cephadm and an active time-sync service on one host | 02 |
| 2 | wipeDiskToRaw | D | Tear down LVM/md/filesystem/partition state on disks named by serial; dryRun supported | 02 |
| 3 | cephVerifyPackageSource | RO | From the host, check each apt mirror and the cephadm URL: does it resolve, does it answer | 02 |
| 4 | cephBootstrap | M | `cephadm bootstrap` a new cluster, or no-op when one exists on the host | 03 |
| 5 | cephDistributeKey | M | Append ceph.pub to each host's authorized_keys, deduplicated, with a backup | 03 |
| 6 | cephHostAdd | M | `ceph orch host add` after verifying the cluster fsid | 03 |
| 7 | cephApplyMon | M | Converge mon placement to an explicit host list, with a quorum-safety pre-check | 03 |
| 8 | cephApplyMgr | M | Converge mgr placement to an explicit host list | 03 |
| 9 | cephApplyMds | M | Converge one filesystem's MDS placement to an explicit host list | 03 |
| 10 | cephApplyOsd | M | Apply OSDs: all-available fleet-wide, or one by-serial service per host | 03 |
| 11 | cephCreatePool | M | Create or converge a replicated or EC pool, its size, rule/profile and application | 04 |
| 12 | cephCreateFs | M | Create or adopt a CephFS volume and place its MDS on explicit hosts | 04 |
| 13 | cephCreateCsiUser | M | Create a client entity, or set its caps authoritatively; never returns a key | 04 |
| 14 | cephGetConnBundle | RO | Non-secret connection facts: fsid, mon v2 endpoints, pools, filesystems, client names | 04 |
| 15 | cephFetchCsiKey | S | Read one client entity's key into a sensitive (vaulted) field | 04 |
| 16 | cephDeleteFs | D | Delete a CephFS volume and its pools; double confirm; the pool-delete gate is always restored | 04 |
| 17 | cephRemoveOsds | D | Remove OSDs by id (zap by default) and verify they are gone from the OSD tree | 04 |
| 18 | cephVerifyMonQuorum | RO | Mon count matches and every monmap mon is in quorum | 05 |
| 19 | cephVerifyOsd | RO | OSD up and in counts, and the CRUSH failure domain | 05 |
| 20 | cephVerifyHealth | RO | Health against wantOk, with a warning allowlist | 05 |
| 21 | cephVerifyHostNoout | RO | Whether a host-subtree noout is set, read from health detail | 05 |
| 22 | cephVerifyPool | RO | Pool exists; size, min_size, EC profile, PGs active+clean, optional MDS | 05 |
| 23 | cephVerifyRbdSmoke | W | RBD create, info and remove with a uniquely named throwaway image | 05 |
| 24 | cephVerifyHostPrep | RO | Packages, cephadm at the exact version, and time-sync active | 05 |
| 25 | cephVerifyDisksRaw | RO | Each serial-resolved device is raw and unmounted | 05 |
| 26 | cephVerifyMgr | RO | Mgr count matches and one mgr is active | 05 |
| 27 | cephVerifyCsiUsers | RO | Expected client entities exist; caps reported, keys never | 05 |
| 28 | cephVerifyKeyDistributed | RO | Re-read authorized_keys on a fresh connection, per host | 05 |
| 29 | cephVerifyMonPlacement | RO | Judge a proposed mon host list against live quorum, applying nothing | 05 |
| 30 | cephVerifyMgrPlacement | RO | Judge a proposed mgr host list | 05 |
| 31 | cephVerifyOsdClaimable | RO | Judge what cephadm would claim against the excludes or selector | 05 |
| 32 | cephCapacityReport | RO | Cluster and per-pool capacity, minSizeMargin, atRiskPools | 05 |
| 33 | cephHostMaintenanceEnter | M | Enter maintenance and prove the effect by polling | 06 |
| 34 | cephHostMaintenanceExit | M | Exit maintenance and prove the OSDs are restored | 06 |
| 35 | cephHostMaintenanceState | RO | Every host's maintenance status and subtree noout | 06 |
| 36 | cephOsdOkToStop | RO | `ceph orch host ok-to-stop`; a refusal is safe:false, never an error | 06 |
| 37 | cephCephadmCheckHost | RO | `ceph cephadm check-host`; ok only on the tool's healthy result | 06 |
| 38 | cephHostNooutClear | M! | Clear a stuck host noout; refuses an unknown host, one in maintenance, or a down OSD | 06 |
| 39 | cephOsdActivate | M | `ceph cephadm osd activate`; "created" and "already created" are both success | 06 |
| 40 | cephHostClusterState | RO | What Ceph state a host carries: fsids, units, VGs/LVs, md arrays | 06 |
| 41 | cephVerifyClusterFsid | RO | Refuse unless every fsid on the host is the named one | 06 |
| 42 | cephDisableOrchestration | M | Disable the cephadm mgr module before a purge | 06 |
| 43 | cephRmCluster | D | `cephadm rm-cluster` for one fsid on one host; refuses a foreign fsid | 06 |
| 44 | cephVerifyHostTornDown | RO | Teardown gate: no cluster dirs, units, or ceph VGs/LVs | 06 |
| 45 | cephRgwUserEnsure | M | Converge an RGW user with a caller-supplied S3 key | 07 |
| 46 | cephRgwBucketInventory | RO | Bucket list plus per-bucket stats, paged; totals; unstattable list | 07 |
| 47 | cephRgwBucketInspect | RO | Classify presence; report ACL, policy, versioning, public access block (S3) | 07 |
| 48 | cephRgwBucketEnsure | M | Create if absent, private, full public access block; probe for leaks (S3) | 07 |
| 49 | cephRgwBucketPolicyEnsure | M | Validate, write and read back a bucket policy; refuse public grants (S3) | 07 |
| 50 | cephRgwBucketVersioningEnsure | M | Converge versioning; flag that conditional writes become unsafe (S3) | 07 |

Method names and argument names are the functional interface, and implementers
MUST use them as specified.

## 6. Decisions

These settle the open points raised while the behaviour was extracted. Each one
is a requirement. Items marked **[twin]** MUST also be confirmed on the twin
environment before stable release.

### Transport and validation
- **D1** `sshUser` MUST match the POSIX portable username grammar: starts with a
  letter or underscore, then letters, digits, `_`, `-` or `.`, and at most 32
  characters.
- **D2** `keyPath` MUST be an absolute local path with no control characters. It
  is only ever passed as a single argv element.
- **D3** The serial→device resolver MUST re-validate the serial grammar itself
  and MUST NOT rely on the caller. Serials MUST NOT reach a remote glob
  unquoted.
- **D4** A serial matches a by-id link only when the link name **ends with**
  `_<serial>` or `-<serial>`. Partition links are ignored. Zero matches, or
  several distinct devices, MUST fail. Substring matches anywhere else are not
  matches. **[twin]**
- **D5** The resolver MUST return the by-id link path. It MUST first prove that
  every matching link resolves to the same single block device. Kernel device
  names MUST NOT appear in OSD specs, because they reorder across reboots.
  **[twin: confirm cephadm accepts by-id paths in a drive-group spec on Squid]**
- **D6** The two character sets are stated explicitly in 01-transport: by-id
  link names, and final device paths. They are tested independently.
- **D7** Remote scripts for cephadm-shell execution MUST be written to a fresh
  `mktemp -d` directory with mode 0700, never directly into a world-writable
  directory. The directory MUST be removed afterwards, best effort, with a
  warning on failure.
- **D8** An SSH exit of 255, a connection-level failure or a timeout MUST
  surface as a **typed transport error**, even when the caller allows non-zero
  exits. A command's own non-zero exit is never a transport error.
- **D9** IPv6 is out of scope. The IPv4 grammar refuses it with a clear error.

### Host preparation and disks
- **D10** On `mdadm --zero-superblock`, "no md superblock" on a device MUST count
  as success. Only a busy device is retried. **[twin: capture the exact
  messages and exit codes for the pinned mdadm]**
- **D11** The `mdadm.conf` backup and edit run only when that file exists. If it
  is absent, the md-config steps are skipped and this is recorded in the
  result.
- **D12** The md config is rewritten and the initramfs rebuilt **only if** an
  array was stopped or the config content changed.
- **D13** `cephHostPrep` and `cephVerifyHostPrep` MUST run `cephadm version` the
  same way, under sudo.
- **D14** The cephadm version check MUST compare the exact version token parsed
  from `cephadm version` with the pinned version. Substring matching is not
  allowed.
- **D15** Package names MUST match the Debian package-name grammar, and are
  still quoted.
- **D16** `cephVerifyPackageSource` follows the verify-result contract,
  including `throwOnFail`.
- **D17** `cephVerifyDisksRaw` reports child devices by their type (part, lvm,
  md, …), not all as "partitions".
- **D18** `wipeDiskToRaw` uses connection multiplexing when the caller enables
  it, and follows the shared retry rule from 01-transport for every step.

### Lifecycle
- **D19** `excludeDevices` (all-available OSD mode) is **enforced**. Before
  applying, resolve each excluded serial on every enrolled host. If
  `ceph orch device ls` reports any excluded device as available, refuse.
- **D20** Mode rules for every method MUST be re-validated when the method runs,
  not only by the schema.
- **D21** `cephApplyOsd` resolves every serial **before** removing any legacy
  service. If resolution fails, the cluster MUST be left untouched.
- **D22** The bootstrap recovery probe runs **only after a transport error**
  (D8). Any other non-zero exit from bootstrap is a failure.
- **D23** The bootstrap config file path is unique per run (random).
- **D24** `clusterNet` MUST be a valid IPv4 CIDR. `cephImage` MUST match the
  container image reference grammar (registry/name[:tag][@digest]).
- **D25** `cephApplyMon` replaces a count-based spec like mgr and mds do, and
  records `replacedCountSpec` and `previousCount`.
- **D26** `cephApplyMon` MUST refuse a placement that would leave fewer than a
  strict majority of the current in-quorum mons, unless `allowQuorumRisk: true`
  is passed. It uses the same predicate as `cephVerifyMonPlacement`.
- **D27** `cephHostAdd`: if the hostname is already registered at a different
  address, the method MUST refuse with both addresses. After adding, it MUST
  read `orch host ls` back.
- **D28** `cephDistributeKey` processes every host and collects per-host
  outcomes. It fails at the end if any host failed. The result schema declares
  every field it writes.
- **D29** Keeping mgr and MDS on separate hosts is the caller's responsibility.
  No method enforces it. `cephVerifyMgrPlacement` reports it.
- **D30** Idempotency in all-available OSD mode is presence-only. It is stated
  as such in the method description.

### Data plane
- **D31** `cephCreatePool` on an existing pool whose scheme (replicated or EC),
  CRUSH rule or EC profile differs from the request MUST refuse with
  expected/actual. It MUST NOT converge only the application.
- **D32** `cephCreateFs`: when the data pool is EC, the method requires
  `allow_ec_overwrites=true` and refuses with an actionable error if it is not
  set. It takes MDS placement as an explicit host list, consistent with
  `cephApplyMds`. The result schema declares `creationPath`.
- **D33** `csiKey` keeps 2 versions.
- **D34** `cephDeleteFs` MUST fail if either backing pool is still present after
  removal. A failure to restore the pool-delete gate MUST be surfaced: the
  record gets `gateRestored: false` and the method then throws.
- **D35** `atRiskPools` lists EC pools whose min_size margin is ≤ 1. The
  description says this precisely.
- **D36** Pools always use the default CRUSH root. Device classes are out of
  scope.
- **D37** Every cephadm-shell call has a minimum budget of 5 minutes. A method
  MAY use a longer default (pool and FS creation: 10 minutes).

### Verification
- **D38** `cephVerifyHealth` MUST fail, for any `wantOk`, on an unknown health
  status, a missing status, or HEALTH_WARN with no named checks. `wantOk: false`
  together with a non-empty allowlist MUST be refused as contradictory.
- **D39** `cephVerifyRbdSmoke` asserts that the image's name and size (1 MiB)
  match what it created. Image names use the prefix `cephadm-smoke-`.
- **D40** Verify methods write their record **before** throwing (§4).
- **D41** The verify-result schema declares `subject`.
- **D42** In mon placement, "majority kept" is computed over **monmap entries**
  and their hosts, not over orchestrator daemon listings.
- **D43** `cephVerifyPool` reports which sub-reads were skipped (and why) when
  size or min_size mismatch.

### Maintenance and teardown
- **D44** All status comparisons are case-insensitive.
- **D45** Maintenance records declare `didIssueCommand` and track the real
  `pollAttempts`. The always-true `succeeded` field is dropped.
- **D46** Detecting noout parses `checks.OSD_FLAGS` from both the summary and
  `detail[]`, and treats flag lists as unordered sets. **[twin]**
- **D47** In poll loops, only transport errors are retried. An evaluator
  refusal (for example "state not observed") stops the loop at once.

### RGW
- **D48** Both RGW credentials (`accessKey`, `secretKey`) are sensitive on every
  method that accepts them.
- **D49** RGW result schemas declare every field they write, and never a
  secret, not even its field name.
- **D50** The admin-plane secret MUST NOT appear on any command line. If the
  pinned `radosgw-admin` cannot read it from a file or stdin, the user-ensure
  method uses the RGW Admin Ops API over HTTPS instead. **[twin: decide which
  path works on Squid]**
- **D51** The probe object prefix is `.cephadm-pab-probe/` and is not
  configurable. "The probe could not run" and "a leak was detected" are
  distinct error kinds.
- **D52** `cephRgwBucketInventory` pages bucket listing (`--max-entries` with a
  marker) until it is exhausted.
- **D53** S3 XML is parsed with a real, pinned XML parser that handles
  namespaces and entities. The access-key charset stays permissive: any
  printable non-space character.
- **D54** Checking a bucket's placement against the inventory is a workflow
  concern, and `cephRgwBucketEnsure` does not do it.

### Surface and workflows
- **D55** Model version = manifest version, bumped together.
- **D56** The upgrade chain starts fresh with this type. It has a single first
  entry ending at the first published version. No history is carried over.
- **D57** Workflows address the model by one instance name, `cephadm`. Fan-outs
  that would contend on the platform's per-model lock use per-item instances
  `cephadm-<purpose>-<item>`. Every workflow requires `port` explicitly,
  because several nodes behind one gateway address can differ only by port.
- **D58** The `distribute-key` workflow proves its result with
  `cephVerifyKeyDistributed`.
- **D59** The known defects in the extracted workflows are fixed: mismatched
  instances between a step and its assert, a host-key option the method
  rejects, and a fixed size on EC pools (see 08-workflows).
- **D60** Every workflow file is listed in the manifest. A test fails if
  `extensions/workflows/` and the manifest disagree.

### Resolutions of section-level open points (round 2)
- **D61** (amends D4) A serial also matches a by-id link ending in
  `_<serial>_<n>`, where `<n>` is a decimal NVMe namespace number. If several
  links resolve to the one proven device, the resolver returns the
  lexicographically smallest link name. **[twin]**
- **D62** (amends D19) Excluded serials are checked against the orchestrator's
  device inventory, `ceph orch device ls --format json`, across all enrolled
  hosts. No per-host SSH is involved, so nodes behind one gateway address work.
  An excluded serial found on no host is refused. The check runs even when the
  OSD service is already present.
- **D63** The leftover-OSD-service guard is as specified in 03-lifecycle: a
  candidate counts only if its placement is exactly `[targetHost]`.
  `cephHostAdd` also refuses an `addr` already registered under a different
  hostname.
- **D64** `cephCreateCsiUser` refuses the entity names `admin` and
  `bootstrap-*`. `cephDeleteFs` always leaves the pool-delete gate `false`,
  whatever its value was before.
- **D65** `cephCreateFs` takes its MDS host list under the same argument name as
  `cephApplyMds` (03-lifecycle wins), and has no count argument.
- **D66** Every input grammar is defined once, in 01-transport (V1–V15). Group
  files reference V-numbers. If a group file restates a grammar differently,
  01-transport wins.
- **D67** The shared SSH argument family (§3) gains `multiplex` (boolean,
  nullish, default `false`). The serial resolver returns both the chosen by-id
  link and the proven canonical device. The by-id link goes into Ceph specs;
  the canonical device is used for local `lsblk` lookups and comparisons.
- **D68** Package names: no architecture qualifiers and no version pins (V14).
  Container images: a tag or digest is required, never an implicit `latest`
  (V15). CIDRs: host bits must be zero (V13).
- **D69** `cephVerifyMgr` gains `settleBudgetMs`, like the other settle-capable
  verifies.
  - `cephVerifyPool`'s MDS sub-check gains optional `expectedMdsHosts`,
    compared against `ceph orch ps --daemon-type mds`.
  - The create-fs and apply-mds workflows prove placement with it.
- **D70** Workflows:
  - `cephadm-prep-host` runs `cephVerifyPackageSource` as a pre-gate.
  - `cephadm-distribute-key` requires `hosts[]` in sorted order and asserts this
    before approval.
  - Workflows take `keyPath` only, and vault-held key content is used by calling
    methods directly. This is revisited once vault references inside workflow
    inputs are confirmed against the swamp docs.
  - Add `cephadm-teardown-cluster`. It wraps the 06 §1 chain with the standard
    gate shape: per-host fsid pre-gate, approval, then the chain, then proof
    with both torn-down verifiers, then report-failure.
- **D71** (amends D47) Poll loops also retry a read that fails with the
  transport taxonomy's **cluster-transient** class: mgr or orchestrator
  temporarily unavailable, or a monitor-client timeout. Every other non-zero
  exit stops the loop. **[twin: capture the exit codes and messages on Squid]**
  The D37 floor also applies to `cephDisableOrchestration`.
- **D72** `cephVerifyClusterFsid` and `cephVerifyHostTornDown` follow the
  verify-result contract: `throwOnFail`, record first, then throw.
- **D73** `cephCapacityReport` puts EC pools with an unknown margin into
  `unjudgedPools`, never silently omits them.
  - `cephVerifyHostPrep` requires the dpkg status `install ok installed`.
- **D74** A contradictory `cephVerifyHealth` request (`wantOk: false` with an
  allowlist) is rejected at validation, before any read, and writes no record.
  - A failing `cephVerifyMgrPlacement` verdict is how D29 "reports".
  - `cephVerifyKeyDistributed` records every host, then raises the typed
    transport error for any unreachable host, whatever `throwOnFail` says.
- **D75** `pollDurationMs` on maintenance records is the verification-poll
  duration only. Records also carry `elapsedMs` for the whole method.
- **D76** RGW user records are keyed `rgwUser-<host>-<uid>`.
  - Bucket-list paging behaviour (marker exclusivity, truncation indicator) is
    **[twin]**.
  - So is the owner-list control under all four public access block flags. If
    the control fails there, it uses an owner object HEAD instead.

### Pending Randy's decision
- **P1. RGW secret delivery (D50).** Options:
  - **(a)** RGW generates the key (`--gen-access-key --gen-secret`) and the
    method stores it in a sensitive, vaulted field, like `cephFetchCsiKey`.
  - **(b)** Admin Ops API. The secret travels in the query string and can land
    in RGW debug logs.
  - **(c)** `radosgw-admin metadata get/put -i <file>`. This replaces the whole
    user object.
  - **(d)** Accept the secret on the command line inside the container,
    documented as residual risk.

  Recommended: (a).
- **P2. RGW service deployment.** No method deploys an RGW daemon. Options:
  - **(a)** Add `cephApplyRgw` plus a `cephadm-apply-rgw` workflow, converging
    `ceph orch apply rgw` to an explicit host list like mon, mgr and mds, with
    `cephVerifyRgw`.
  - **(b)** Deploy RGW out of band on the twin.

  Recommended: (a).

## 7. Acceptance criteria (implementation)

1. Every method in §5 exists with its specified arguments, safety class and
   description lead. Each has unit tests for:
   - success;
   - an idempotent re-run;
   - every failure mode in its group file;
   - injection attempts on every input that reaches a remote host.
2. Every decision D1–D76 has at least one test that names it, e.g. a test
   title containing `D21`.
3. `scripts/gates.sh cephadm` passes (CONVENTIONS §9).
4. On the twin environment, before promotion to stable:
   - Every **[twin]** decision is confirmed.
   - Every workflow in 08-workflows runs end to end on the twin, one at a time
     in its listed order, followed by the teardown chain.
