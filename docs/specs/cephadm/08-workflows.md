# 08 · Workflows

This file specifies the workflow catalog shipped with `@randybias/cephadm`. The
model contract, method registry and resource catalog are in `00-overview.md`;
each method's behaviour is in the group file that owns it. Where a workflow
reads a record, the key pattern given here follows the owning method's spec. If
the two ever disagree, the method's spec wins and the workflow MUST follow it.

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Shared workflow conventions

### 1.1 Naming, descriptions and packaging

- Every workflow MUST be named `cephadm-<verb>-<object>` (CONVENTIONS §2), using
  single hyphens only.
- Every workflow description MUST be one line of 40–90 characters, verb first,
  with no markdown, block scalar, second sentence or template syntax
  (CONVENTIONS §5). The descriptions in §2 are normative and already comply.
- Every step MUST have a description of the form `<Verb> <what> [via
  <mechanism>]`. Every input MUST have a description that is a noun phrase plus
  its unit or format.
- Every workflow file MUST be listed in the manifest, and a test MUST fail if
  `extensions/workflows/` and the manifest's `workflows` list disagree (D60).
  - **Why:** a workflow that exists on disk but is missing from the manifest is
    silently never published.

### 1.2 Model addressing

- Every step MUST address the model by the single instance name `cephadm`
  (D57).
- A fan-out (`forEach`) whose items would otherwise serialise on the platform's
  per-model lock MUST use a per-item instance named
  `cephadm-<purpose>-<item>` (D57), for example `cephadm-checkhost-<hostName>`.
- An assert that reads a record MUST read it from **the same instance** that
  the producing step wrote it to (D59). For a per-item fan-out this means the
  assert is itself a per-item `forEach` reading from
  `cephadm-<purpose>-<item>`.
  - **Why:** the platform stores records by (instance, name). A record read from
    the wrong instance is missing or stale, and a null-safe assert then reports
    a result that was never measured.
- **Why per-item instances:** calls serialised on one instance's lock queue
  behind each other, and the ones at the back ran past their own time budget.

### 1.3 SSH input block

Every workflow that calls an SSH method takes this block of inputs and passes
it through unchanged.

| Input | Type | Required | Default | Rule |
|---|---|---|---|---|
| `host` or `adminHost` | string | yes | none | the admin or target host, hostname or IPv4 |
| `port` | integer 1–65535 | **yes** | **none** | MUST NOT be defaulted, not even to 22 (D57) |
| `sshUser` | string | yes | none | POSIX username (D1) |
| `keyPath` | string | no | `""` | absolute local path; empty means the runner's default identity or agent |
| `strictHostKeyChecking` | enum `yes` \| `no` | **yes** | none | no other value is offered (D59, CONVENTIONS §7) |

- `port` is required in **every** workflow, including bootstrap, host prep and
  disk wiping (D57).
  - **Why:** behind a gateway, several nodes share one address and differ only
    by port, and port 22 on that address is the gateway itself. A defaulted 22
    silently targets a different machine.
- `strictHostKeyChecking` MUST offer exactly `yes` and `no`. Values that the
  method schema rejects, such as `accept-new`, MUST NOT appear (D59).
  - **Why:** an option the method rejects makes the workflow fail validation on
    a value the workflow itself offered.
- Optional inputs MUST be passed to the method as `has(x) ? x : null`, and
  empty strings MUST be passed as null. The method reads null as "not given"
  (00-overview §3).
- Each workflow below lists only its **own** inputs; the SSH block is implied
  wherever the entry says "SSH block".

### 1.4 Gate shape for mutating workflows

Every workflow that calls a mutating (M, M!) or destructive (D) method MUST
have this shape. Read-only workflows (§1.6) are exempt.

1. **Pre-gate (optional).** A read-only method called with
   `throwOnFail: false`, followed by an assert on its record. This makes an
   unsafe request fail **before** a human is asked to approve it. A pre-gate MAY
   also be a pure input-consistency assert with no method call (for example
   mode rules that the method would reject anyway).
   - **Why:** an approval spent on a request that is going to be refused trains
     operators to approve without reading.
2. **Approval.** A `manual_approval` step with a timeout of 3600 s.
3. **Mutation.** The mutating or destructive method.
4. **Prove job.** A **separate job**, depending on the mutation job, that calls
   an independent read-back method with `throwOnFail: false` and then asserts
   on `data.latest(...)` of that read's record. The assert message MUST state
   both the expected and the observed values.
   - The prove job MUST be a separate job so that the read's record exists when
     the assert is evaluated.
   - The read-back MUST use a settle budget sized to the physical event when the
     operation is declarative or asynchronous (mon and OSD apply, PG peering),
     and MUST be single-shot when the command is synchronous (host add, pool
     create, auth, first-mon bootstrap). See L8.
   - The assert MUST be null-safe in the failing direction: a missing record or
     missing field is a failure, never a pass.
   - Where the record carries `capturedAt`, the assert SHOULD also require that
     it is at or after the run's start.
   - Every mutating workflow MUST have a prove job. No workflow asserts its
     effect only inline in the mutation job, and the argument that a
     one-method workflow needs no read-back MUST NOT be used.
5. **Report-failure job.** A job that runs when the prove job **failed or was
   skipped**. It asserts a constant `true` at low severity with `allowFailure`,
   and its message MUST state:
   - that nothing was rolled back, retried or remediated;
   - that a run which stopped at the pre-gate or at approval changed nothing;
   - that any host which was in maintenance is still in maintenance;
   - where to read the failing method's error (L11).
   - **Why "or skipped":** a plain "failed" condition never matches a skipped
     job, and a prove job is skipped exactly when an earlier job stopped the
     run.
   - **Why no auto-remediation:** an automatic fix is a second, uncontrolled
     mutation on a cluster in an unknown state. For example, an EC pool sized
     exactly to the host count sits at min_size with zero margin when one host
     is out, and a remediation that takes another host out loses data
     availability.

### 1.5 Approval prompts

- An approval prompt MUST name the inputs being acted on (hosts, ids, names,
  image, version) and, when there is a pre-gate, the pre-gate record **by its
  key**.
- An approval prompt MUST NOT embed `data.latest(...)` or any other record
  content.
  - **Why:** a prompt is rendered before the run's own steps write, so
    `data.latest` inside a prompt shows the **previous** run's record and the
    operator approves on stale evidence.
- A destructive workflow's prompt MUST say that the action cannot be undone.

### 1.6 Read-only workflows

- A read-only workflow MAY be a single step that calls a verify method with the
  default `throwOnFail: true`, so the run halts on a failed verdict. The record
  is written before the method throws (D40), so the failing evidence is kept.
- A read-only workflow MUST NOT have an approval step.
- When a read-only workflow asserts on a record, the assert MUST be in a
  separate job (as in §1.4 step 4) and SHOULD have a report-failure job stating
  that every command was a read.

### 1.7 Secrets

- No workflow message, assert, prompt or step description may contain a secret
  or a record field that holds one. The only sensitive record is `csiKey`; no
  workflow reads its `key` field.
- No workflow passes a secret as a literal. Credentials arrive only as vault
  references.

### 1.8 Test obligations (whole catalog)

- [ ] Manifest `workflows` list and `extensions/workflows/` differ by one entry →
  test fails (D60).
- [ ] Every workflow name matches `cephadm-<verb>-<object>` with single hyphens →
  pass; any `ceph-` prefixed or `--` name → test fails.
- [ ] Every workflow description is one line of 40–90 characters with no
  template syntax → pass; one of 39 or 91 characters → test fails.
- [ ] Every step's model reference is `cephadm` or matches
  `cephadm-<purpose>-<item>` → pass; any other instance name → test fails (D57).
- [ ] Every assert that reads a record reads it from the instance its producing
  step wrote to → pass; a mismatched pair → test fails (D59).
- [ ] Every workflow with an SSH step declares `port` as required with no
  default → pass; a default of 22 → test fails (D57).
- [ ] Every `strictHostKeyChecking` input has enum exactly `yes`, `no` → pass;
  `accept-new` present → test fails (D59).
- [ ] Every workflow calling an M, M! or D method has approval, prove and
  report-failure jobs, and report-failure triggers on failed **or** skipped →
  pass.
- [ ] Every verify call inside a pre-gate or prove job passes
  `throwOnFail: false` → pass.
- [ ] No approval prompt contains `data.latest` → pass.
- [ ] Every workflow validates with `swamp workflow validate` against the
  model's current schema → pass.

## 2. Workflow catalog

Each entry gives: name, description, purpose, inputs, steps, guards, and what
the workflow cannot see. "SSH block" means the inputs of §1.3.

### 2.1 `cephadm-prep-host`

- **Description:** `Install packages, pinned cephadm and time sync on one host`
- **Purpose:** prepare one host so that cephadm can bootstrap or adopt it.
- **Inputs:** SSH block (`host`); `packages[]`, `cephadmUrl`, `cephadmVersion`,
  `timeSyncService` (required); `installRetryBudgetMs` (optional, no default;
  absent means one pass with no retry).
- **Steps:**
  1. Approval naming the host, the packages and the cephadm version.
  2. `cephHostPrep`.
  3. Prove job: `cephVerifyHostPrep` with the expected packages, cephadm version
     and time-sync service, `throwOnFail: false`, single-shot.
  4. Assert `cephVerifyHostPrep-<host>`.pass.
  5. Report-failure.
- **Guards:** the version check is an exact-token comparison (D14); the
  `cephHostPrep` record's package-phase accounting (attempts, transport
  failures, busy waits) is named in the success message so a retried run is not
  hidden.
- **Cannot see:** whether the host's package mirrors are reachable before the
  install starts (see Unresolved); anything about disks or the cluster.

### 2.2 `cephadm-wipe-disks`

- **Description:** `Wipe one host's named data disks to raw, with a dry-run mode`
- **Purpose:** the most destructive workflow: return one host's selected data
  disks to raw.
- **Inputs:** SSH block (`host`); `dataDevices[]` and `excludeDevices[]` (both
  required, by serial; the excludes MUST list every boot or system disk);
  `dryRun` (default `false`).
- **Steps:**
  1. Pre-gate: `cephVerifyDisksRaw(dataDevices, throwOnFail: false)`.
  2. Assert that the `cephVerifyDisksRaw-<host>` record's `detail.mounted` and
     `detail.unobserved` lists are both empty.
  3. Approval, required for **every** value of `dryRun`, stating that a real run
     cannot be undone.
  4. `wipeDiskToRaw`.
  5. Prove job: `cephVerifyDisksRaw(throwOnFail: false)`, run in **both** modes.
  6. One assert whose expectation depends on `dryRun`:
     - `dryRun: true` → the `wipeDiskToRaw-<host>` record reports `dryRun: true`
       and its `plannedDevices` count equals the `dataDevices` count;
     - `dryRun: false` → `cephVerifyDisksRaw-<host>`.pass is true and the wipe
       record reports `dryRun: false`.
  7. Report-failure.
- **Guards:**
  - The pre-gate stops the run on mounted or unobserved serials before an
    approval is spent; the wipe would refuse them anyway.
  - **Why assert in both modes:** "disks are raw" is wrong in both directions
    under a dry run. It passes on disks that were already raw and fails on a
    correct dry run. Skipping the prove job in one mode would leave that mode
    unproven.
- **Cannot see:** holders in another mount namespace that the wipe will refuse
  (L13); whether an excluded serial was mistyped (an exclude that matches
  nothing is not detected here).

### 2.3 `cephadm-bootstrap-cluster`

- **Description:** `Bootstrap a new cluster on one host and prove the first mon is in quorum`
- **Purpose:** create a new cluster on one host, or no-op when one already
  exists there.
- **Inputs:** SSH block (`host`); `monIp`, `publicNet`, `clusterNet`,
  `cephImage` (pinned, never defaulted; D24) and `expectedMonCount` (all
  required).
- **Steps:**
  1. Approval naming the host, `monIp` and `cephImage`.
  2. `cephBootstrap`.
  3. Prove job: `cephVerifyMonQuorum(expectedMonCount, throwOnFail: false)`,
     single-shot, because the first mon is synchronous.
  4. Assert `cephVerifyMonQuorum-<host>`.pass.
  5. Report-failure.
- **Guards:** the success message MUST say when the `cephBootstrap-<host>`
  record reports a cluster recovered after a transport error (D22), so a
  recovered run is not presented as a clean one.
- **Cannot see:** mgr state, dashboard state, or whether an existing cluster on
  the host is the one the caller meant (a pre-existing cluster is a no-op).

### 2.4 `cephadm-distribute-key`

- **Description:** `Install the cluster public key on hosts and prove cephadm can reach them`
- **Purpose:** append the cluster's public key to each host's authorized_keys,
  then prove that the key is present and that cephadm can reach each host.
- **Inputs:** SSH block (`adminHost`, `port` for the admin host);
  `cephPubKey` (required); `hosts[]` of `{host, port}` (required, at least one
  entry; each target has its own port).
- **Steps:**
  1. Approval naming the hosts and ports.
  2. `cephDistributeKey(hosts, …)`.
  3. Prove job A: `cephVerifyKeyDistributed(hosts, throwOnFail: false)` (D58).
  4. Assert the `cephVerifyKeyDistributed` record (multi-host key, §4 of
     00-overview) has `pass: true`; the message lists hosts that are absent or
     unreadable.
  5. Prove job B, depending on job A: `forEach` over the host names,
     `cephCephadmCheckHost(host = adminHost, hostName = item)` on the per-item
     instance `cephadm-checkhost-<hostName>` (D57).
  6. A separate job, `forEach` over the same host names: assert that
     `checkHost-<hostName>` **read from instance
     `cephadm-checkhost-<hostName>`** has `ok: true` (D59).
  7. Report-failure, triggered when job A, job B or the assert job failed or was
     skipped.
- **Guards:**
  - The per-item asserts are in a separate job because a `forEach` step's
    runtime id becomes `<step>-<item>`, and a step-level dependency on it never
    resolves.
  - **Gate asymmetry:** a check-host pass proves cephadm's key works. A
    check-host fail does not prove the key is missing, because check-host also
    fails on a missing container runtime, lvm2 or time sync. Job A is the proof
    of key presence; job B is the proof of reachability.
- **Cannot see:** whether hosts not listed still carry an old cluster key.

### 2.5 `cephadm-add-host`

- **Description:** `Register one host with the orchestrator and read the host list back`
- **Purpose:** register one host with the orchestrator.
- **Inputs:** SSH block (`adminHost`); `fsid`, `host`, `addr` (all required).
- **Steps:**
  1. Approval naming the host, address, fsid and admin host.
  2. `cephHostAdd`. The method refuses a different cluster fsid, and refuses a
     hostname already registered at a different address (D27).
  3. Prove job: `cephHostMaintenanceState` through `adminHost`, as a single-shot
     read-back of `orch host ls` (host add is synchronous).
  4. Assert that the `maintenanceState-<adminHost>` record's hosts contain an
     entry whose hostname equals `host` **and** whose address equals `addr`.
  5. Report-failure.
- **Guards:** the read-back fails closed on an empty host list; the failure
  message lists the hosts present and omits the fsid.
- **Cannot see:** whether the host is usable by cephadm (check-host is not
  consulted; run `cephadm-distribute-key` first).

### 2.6 `cephadm-apply-mon`

- **Description:** `Converge mons to an explicit host list and wait for quorum to settle`
- **Purpose:** converge the mon set to a complete, explicit host list. A list
  that omits a running mon shrinks the mon set.
- **Inputs:** SSH block (`adminHost`); `placement[]` (required);
  `quorumSettleMs` (default 300000); `quorumPollIntervalMs` (default 10000; the
  ceiling of the backoff, see 01-transport).
- **Steps:**
  1. Pre-gate: `cephVerifyMonPlacement(placement, throwOnFail: false)`.
  2. Assert `cephVerifyMonPlacement-<adminHost>`.pass; the message shows the
     reasons, the current mon hosts, and the hosts removed and added.
  3. Approval naming the placement and the pre-gate record key.
  4. `cephApplyMon`, without `allowQuorumRisk` (D26).
  5. Prove job: `cephVerifyMonQuorum(expectedMonCount = size(placement),
     quorumSettleMs, quorumPollIntervalMs, throwOnFail: false)`. This read-back
     uses a **settle budget**, because mon placement is declarative and mons
     start after the method returns. Its step description MUST say so.
  6. Assert `cephVerifyMonQuorum-<adminHost>`.pass.
  7. Report-failure.
- **Guards:** a quorum-risking placement is refused by the pre-gate and by the
  method (D26); the workflow MUST NOT offer an override.
- **Cannot see:** whether the mons run on the **requested** hosts. The quorum
  check compares counts and quorum membership and does not map mon names to
  hosts.

### 2.7 `cephadm-apply-mgr`

- **Description:** `Converge mgr daemons to an explicit host list after a placement check`
- **Purpose:** converge mgr placement to a complete, explicit host list. The
  list is declarative, so dropping a host removes its mgr.
- **Inputs:** SSH block (`adminHost`); `placement[]` (required).
- **Steps:**
  1. Pre-gate: `cephVerifyMgrPlacement(placement, throwOnFail: false)`.
  2. Assert `cephVerifyMgrPlacement-<adminHost>`.pass; the message shows the
     reasons, the active MDS, the hosts beside the active MDS (D29) and the
     active mgr.
  3. Approval naming the placement and the pre-gate record key.
  4. `cephApplyMgr`.
  5. Prove job: `cephVerifyMgr(expectedCount = size(placement),
     throwOnFail: false)`.
  6. Assert `cephVerifyMgr-<adminHost>`.pass.
  7. Report-failure.
- **Guards:** the workflow input is `placement`, matching the method argument.
  - **Why:** a workflow input that does not match the method's argument name
    makes the workflow unrunnable.
- **Cannot see:** whether the mgrs run on the requested hosts (count and active
  only); see Unresolved on the settle window.

### 2.8 `cephadm-apply-osds`

- **Description:** `Apply OSDs on named disks or all available ones, then prove the counts`
- **Purpose:** apply an OSD service in one of two mutually exclusive modes:
  - fleet-wide `allAvailableDevices: true`, which requires a non-empty
    `excludeDevices` (D19);
  - by-serial `dataDevices` on `targetHost`.
- **Inputs:** SSH block (`adminHost`); `expectedUpAfter`, `expectedInAfter`,
  `expectedFailureDomain` (required, integers for the counts);
  `allAvailableDevices` (default `false`); `excludeDevices[]`; `targetHost`;
  `targetAddr` (defaults to `targetHost`); `targetPort` (**required whenever
  `targetHost` is given**, never defaulted to the admin port; D57);
  `dataDevices[]`; `crushRuleName` (default `""`, meaning the default rule);
  `osdSettleMs` (default 1800000); `osdPollIntervalMs` (default 15000).
- **Steps:**
  1. Pre-gate assert on inputs: exactly one mode is selected; all-available
     mode has a non-empty `excludeDevices`; by-serial mode has `targetHost`,
     `targetPort` and a non-empty `dataDevices`. The method re-validates (D20).
  2. Pre-gate: `cephVerifyOsdClaimable` with exactly the same selection inputs
     as the apply, `throwOnFail: false`.
  3. Assert pass; the message shows the reasons, any excluded devices that are
     claimable, and per-serial results.
  4. Approval naming the mode, the target and the pre-gate record key.
  5. `cephApplyOsd`.
  6. Prove job: `cephVerifyOsd(expectedUpAfter, expectedInAfter,
     expectedFailureDomain, osdSettleMs, osdPollIntervalMs,
     throwOnFail: false)`.
  7. Assert `cephVerifyOsd-<adminHost>`.pass.
  8. Report-failure.
- **Guards:**
  - **Why the settle budget:** the apply is declarative. OSDs are zapped and
    started minutes after the method returns, so a single-shot read fails on
    exactly the run the gate exists for.
  - **Why excludes are required:** cephadm's "available" means empty, not safe
    to claim.
- **Cannot see:** which disks became which OSDs (counts only); idempotency in
  all-available mode is presence-only (D30).

### 2.9 `cephadm-create-pool`

- **Description:** `Create or converge a replicated or erasure-coded pool and verify it`
- **Purpose:** create or converge one replicated or EC pool.
- **Inputs:** SSH block (`host`); `name`, `scheme` (`replicated` \|
  `erasure`), `application`, `failureDomain` (required); `size` (replicated
  only); `erasureProfile` `{k, m}` (erasure only).
- **Steps:**
  1. Pre-gate assert on inputs (D59): `scheme: replicated` requires `size` and
     forbids `erasureProfile`; `scheme: erasure` requires `erasureProfile` and
     forbids `size`. The message names the missing or extra input.
  2. Approval naming the pool, scheme and size or profile.
  3. `cephCreatePool`, passing `size` as the input or **null**, and
     `erasureProfile` as the input or **null** (D59). No constant or zero
     placeholder is ever passed.
  4. Prove job: `cephVerifyPool(expectedSize = size` for replicated, `k + m`
     for erasure`, throwOnFail: false)`, single-shot.
  5. Assert `cephVerifyPool-<host>-<name>`.pass.
  6. Report-failure.
- **Guards:** an existing pool with a different scheme, rule or profile is
  refused by the method (D31).
  - **Why null, not a placeholder:** a placeholder value either fails the
    method's minimum with an error that names the wrong cause, or asserts a
    size the caller never asked for.
  - **Why single-shot:** pool create is synchronous; PG lag on a backfilling
    cluster is reported, not waited out.
- **Cannot see:** client usability of the pool (see `cephVerifyRbdSmoke`,
  which no workflow wraps).

### 2.10 `cephadm-create-fs`

- **Description:** `Create or adopt a CephFS volume with MDS daemons on named hosts`
- **Purpose:** create or adopt one CephFS volume and place its MDS daemons on
  an explicit host list (D32).
- **Inputs:** SSH block (`host`); `name`, `placement[]` (explicit MDS hosts) and
  `expectedDataPoolSize` (required).
- **Steps:**
  1. Approval naming the volume and the MDS hosts.
  2. `cephCreateFs` with the explicit MDS host list (D32).
  3. Prove job: `cephVerifyPool` on the data pool `cephfs.<name>.data` with
     `expectedSize = expectedDataPoolSize`, the MDS sub-check enabled for
     `name`, and `throwOnFail: false`.
  4. Assert `cephVerifyPool-<host>-cephfs.<name>.data`.pass.
  5. Report-failure.
- **Guards:** an EC data pool without `allow_ec_overwrites` is refused by the
  method (D32). `expectedDataPoolSize` is a separate input because the mutation
  neither sets nor reports the data pool size.
- **Cannot see:** the data pool of a volume adopted under non-conventional pool
  names (the prove job then fails rather than passes); MDS host mapping.

### 2.11 `cephadm-apply-mds`

- **Description:** `Place a filesystem's MDS daemons on an explicit list of hosts`
- **Purpose:** converge MDS placement for an existing filesystem.
- **Inputs:** SSH block (`adminHost`); `fsName`, `placement[]` (required).
- **Steps:**
  1. Approval naming the filesystem and placement.
  2. `cephApplyMds`.
  3. Prove job: `cephVerifyPool` on `cephfs.<fsName>.data` with the MDS
     sub-check enabled for `fsName`, `throwOnFail: false`.
  4. Assert `cephVerifyPool-<adminHost>-cephfs.<fsName>.data`.pass.
  5. Report-failure.
- **Guards:** keeping MDS off the mgr hosts is the caller's choice (D29).
- **Cannot see:** whether MDS daemons run on the requested hosts (no method maps
  MDS daemons to hosts; see Unresolved).

### 2.12 `cephadm-create-csi-user`

- **Description:** `Create or converge a client entity's caps and prove that it exists`
- **Purpose:** create a client entity, or set its caps authoritatively.
- **Inputs:** SSH block (`host`); `name` (bare, without `client.`) and `caps`
  object (required).
- **Steps:**
  1. Approval naming the entity and its caps.
  2. `cephCreateCsiUser`.
  3. Prove job: `cephVerifyCsiUsers(expectedUserNames = [name],
     throwOnFail: false)`.
  4. Assert `cephVerifyCsiUsers-<host>`.pass. The assert SHOULD also compare
     the caps reported in the record with the `caps` input.
  5. Report-failure.
- **Cannot see:** the key (never read); if the caps comparison is not done,
  that the caps in force equal those requested.

### 2.13 `cephadm-get-conn-bundle`

- **Description:** `Capture the cluster's non-secret client connection facts`
- **Purpose:** a read-only capture of fsid, mon v2 endpoints, pools,
  filesystems and client names. It is used for inventory and as before/after
  evidence around destructive workflows.
- **Inputs:** SSH block (`host`).
- **Steps:** one `cephGetConnBundle` step writing `connBundle-<host>`.
- **Cannot see:** any key.

### 2.14 `cephadm-fetch-csi-key`

- **Description:** `Read one client entity's key into a vaulted record`
- **Purpose:** a sensitive read of one client key, which the platform vaults.
- **Inputs:** SSH block (`host`); `userName` (bare; the method adds
  `client.`).
- **Steps:** one `cephFetchCsiKey` step writing `<userName>-csi-key`.
- **Guards:** no step, assert or message reads or prints the `key` field
  (§1.7).
- **Cannot see:** whether the key is the one a consumer holds.

### 2.15 `cephadm-delete-fs`

- **Description:** `Delete one CephFS volume and its pools after a typed confirmation`
- **Purpose:** destructive, approval-gated deletion of one volume and its
  pools.
- **Inputs:** SSH block (`host`); `fsName` and `confirmFsName` (both required,
  **separate inputs**).
- **Steps:**
  1. Evidence: `cephGetConnBundle` (before).
  2. Pre-gate assert: `confirmFsName` equals `fsName`, and `fsName` is in the
     `connBundle-<host>` record's filesystems.
  3. Approval naming the volume and host, naming the before-evidence record by
     key, and stating that the deletion cannot be undone.
  4. `cephDeleteFs(fsName, confirmFsName)`. The two values come from two
     separate inputs (D59).
  5. Prove job: `cephGetConnBundle` (after).
  6. Assert that the `connBundle-<host>` record's `capturedAt` is at or after
     the run's start **and** `fsName` is not in its filesystems. A missing
     record counts as "still present" and fails.
  7. Report-failure.
- **Guards:** the method fails if a backing pool survives, and surfaces a
  pool-delete gate that could not be restored (D34).
  - **Why separate confirmation inputs:** feeding one input to both arguments
    reduces the double confirmation to approval alone.
- **Cannot see:** clients still holding mounts of the volume.

### 2.16 `cephadm-remove-osds`

- **Description:** `Remove OSDs by id after a health gate and prove the remaining counts`
- **Purpose:** destructive, approval-gated removal of OSDs by id.
- **Inputs:** SSH block (`host`); `osdIds[]` (integers), `zap`, `expectedUp`,
  `expectedIn` (integers) and `expectedFailureDomain` (required);
  `allowedWarnings[]` (absent means only HEALTH_OK passes); `osdSettleMs`
  (default 1800000); `osdPollIntervalMs` (default 15000).
- **Steps:**
  1. Pre-gate: `cephVerifyHealth(wantOk: true, allowedWarnings,
     throwOnFail: false)`.
  2. Assert `cephVerifyHealth-<host>`.pass; the message shows the status, the
     checks that are not allowed, and their summaries.
  3. Approval naming the ids, the zap behaviour, the pre-gate record key, and
     that removal cannot be undone.
  4. `cephRemoveOsds`.
  5. Prove job: `cephVerifyOsd(expectedUp, expectedIn, expectedFailureDomain,
     osdSettleMs, osdPollIntervalMs, throwOnFail: false)`.
  6. Assert `cephVerifyOsd-<host>`.pass.
  7. Report-failure.
- **Guards:**
  - **Why the health pre-gate:** removing OSDs while PGs are not clean can drop
    a PG below min_size.
  - Counts are integers because the method rejects fractions.
- **Cannot see:** capacity headroom after removal (`cephCapacityReport` is not
  consulted).

### 2.17 `cephadm-inventory-rgw-buckets`

- **Description:** `List RGW buckets with per-bucket stats and flag any that cannot be read`
- **Purpose:** a read-only RGW bucket inventory, for example as the before/after
  pair of a migration.
- **Inputs:** SSH block (`host`; `strictHostKeyChecking` enum `yes` \| `no`
  only, D59); `realm` (optional).
- **Steps:**
  1. `cephRgwBucketInventory`.
  2. A separate job asserts that the `rgwBucketInventory-<host>[-<realm>]`
     record's `unstattable` list is empty. It reads the record's attributes
     without a null-safe default on purpose, because the job depends on the
     read having succeeded. Zero buckets is a pass.
  3. Report-failure on failed or skipped, stating that every command was a
     read.
- **Guards:** a non-empty `unstattable` list means the totals are lower bounds,
  and a before/after comparison would compare two different populations.
- **Cannot see:** whether the S3 endpoint is reachable or serving. On a cluster
  with no RGW, the bucket listing fails rather than returning an empty list.

### 2.18 `cephadm-verify-health`

- **Description:** `Check cluster health against an allowlist of warning checks`
- **Inputs:** SSH block (`host`); `wantOk`, `allowedWarnings[]` (required).
  `wantOk: false` with a non-empty allowlist is refused (D38).
- **Steps:** one `cephVerifyHealth` step that halts on failure.

### 2.19 `cephadm-verify-host-prep`

- **Description:** `Check one host's packages, cephadm version and time-sync service`
- **Inputs:** SSH block (`host`); `packages[]`, `cephadmVersion`,
  `timeSyncService` (required).
- **Steps:** one `cephVerifyHostPrep` step that halts on failure.

### 2.20 `cephadm-verify-mgr`

- **Description:** `Check that the mgr count matches and one mgr is active`
- **Inputs:** SSH block (`host`); `expectedCount` (required).
- **Steps:** one `cephVerifyMgr` step that halts on failure.

### 2.21 `cephadm-verify-mon-quorum`

- **Description:** `Check that the mon count matches and every mon is in quorum`
- **Inputs:** SSH block (`host`); `expectedMonCount` (required).
- **Steps:** one `cephVerifyMonQuorum` step, single-shot, that halts on
  failure.

### 2.22 `cephadm-verify-osds`

- **Description:** `Check OSD up and in counts and the CRUSH failure domain`
- **Inputs:** SSH block (`host`); `expectedUp`, `expectedIn` (integers),
  `expectedFailureDomain` (required).
- **Steps:** one `cephVerifyOsd` step, single-shot, that halts on failure.

### 2.23 Methods with no workflow

These methods are composed directly or by external orchestrators, and no
workflow in this catalog wraps them:

- verify: `cephVerifyRbdSmoke`, `cephVerifyHostNoout`,
  `cephVerifyPackageSource`, `cephCapacityReport`;
- maintenance: `cephHostMaintenanceEnter`, `cephHostMaintenanceExit`,
  `cephOsdOkToStop`, `cephHostNooutClear`, `cephOsdActivate`;
- teardown: `cephHostClusterState`, `cephVerifyClusterFsid`,
  `cephDisableOrchestration`, `cephRmCluster`, `cephVerifyHostTornDown`;
- rgw: `cephRgwUserEnsure` and the four S3 bucket methods.

`cephHostMaintenanceState`, `cephCephadmCheckHost` and
`cephVerifyKeyDistributed` appear only as read-backs.

## 3. End-to-end order on the twin

Acceptance (00-overview §7) runs every workflow once, one at a time, in this
order. A step marked *per host* runs once for each host. Each step MUST pass
before the next one starts.

### 3.1 Canonical bring-up order

1. `cephadm-prep-host` (per host).
2. `cephadm-verify-host-prep` (per host).
3. `cephadm-wipe-disks` with `dryRun: true` (per host), then with
   `dryRun: false` (per host).
4. `cephadm-bootstrap-cluster` on the first host.
5. `cephadm-verify-mon-quorum` on the first host (`expectedMonCount: 1`).
6. `cephadm-get-conn-bundle`, to learn the fsid used by later steps.
7. `cephadm-distribute-key` to every other host.
8. `cephadm-add-host` (per other host).
9. `cephadm-apply-mon`.
10. `cephadm-apply-mgr`.
11. `cephadm-verify-mgr`.
12. `cephadm-apply-osds` (by-serial mode, per host).
13. `cephadm-verify-osds`.
14. `cephadm-create-pool` (one replicated pool, one erasure pool).
15. `cephadm-create-fs`.
16. `cephadm-apply-mds` (re-place the filesystem's MDS on a different explicit
    list).
17. `cephadm-create-csi-user`.
18. `cephadm-fetch-csi-key`.
19. `cephadm-verify-health`.
20. `cephadm-get-conn-bundle` (final inventory).
21. `cephadm-inventory-rgw-buckets`, only when an RGW service is deployed (see
    Unresolved).
22. `cephadm-remove-osds` on one host's OSDs, followed by `cephadm-apply-osds`
    for that host again and `cephadm-verify-osds` with the original counts.

### 3.2 Teardown order

1. `cephadm-get-conn-bundle` (before-evidence).
2. `cephadm-delete-fs` (per filesystem).
3. The teardown chain, by direct method calls (no workflow wraps it, see
   06-maintenance-teardown):
   1. `cephHostClusterState` (per host);
   2. `cephVerifyClusterFsid` (per host), which MUST pass on every host before
      any mutating step;
   3. `cephDisableOrchestration` (once, through the admin host);
   4. `cephRmCluster` (per host, admin host last);
   5. `cephVerifyHostTornDown` (per host).
4. `cephadm-wipe-disks` with `dryRun: false` (per host), whose prove job shows
   the disks are raw.

- **Why identity gates first:** a refusal must leave the system exactly as it
  found it, so the fsid check runs before the first mutating teardown step
  (L9).
- **Why orchestration is disabled before the purge:** otherwise the
  orchestrator redeploys the daemons that the purge removes.

## 4. Operational requirements

Lessons that are owned by a method spec are referenced there and restated here
only as far as workflows depend on them.

- **L1. Identity as key content.** Every SSH method accepts a sensitive
  `privateKey` as an alternative to `keyPath` (01-transport).
  - **Why:** with only a path, a credential that lives in a vault cannot be
    supplied, and an empty path falls back to a default identity that fails as
    an unexplained authentication error.
- **L2. Poll loops back off.** Every settle or poll loop uses capped exponential
  backoff with jitter, and the workflow's poll-interval input is the
  **ceiling** of that backoff (01-transport). A settle budget of 0 means
  single-shot.
  - **Why:** a fixed beat hammers a cluster mid-restart at a constant rate and
    proves nothing by its length.
- **L3. Package install is idempotent on every entry**, and its verdict comes
  from dpkg state on a fresh connection (02-hostprep). Workflows MUST NOT add a
  retry around `cephHostPrep`; the retry budget is the method input
  `installRetryBudgetMs`.
  - **Why:** a lost session mid-install was followed by dpkg finishing the
    work, so an outer retry re-sends an install behind a lock that is still
    held.
- **L4. A mid-session SSH drop is not a pre-session drop** (01-transport). A
  workflow MUST NOT re-run a mutating step to "retry" a transport failure; it
  stops and reports.
  - **Why:** after a mid-session loss the remote write may have run, and a
    second send can collide with it.
- **L5. Version and upgrade chain move together** (D55, D56). A workflow test
  MUST validate the catalog against the model's current version, never a
  literal.
  - **Why:** a chain that ends at the wrong version makes the whole type stop
    resolving, and every workflow then fails validation with "type not found".
- **L6. Every record a workflow reads has a name the workflow can build.** No
  timestamps in keys, no fact the reader is trying to learn (such as the fsid),
  and a subject wherever two calls in one run could collide.
  - **Why:** `data.latest` needs the exact name; a key the workflow cannot build
    cannot be asserted on.
- **L7. Optional inputs are passed as null when absent**, and null means "not
  asserted".
  - **Why:** an optional-only schema rejects an explicit null, and a check that
    treats null as a value fails correct clusters.
- **L8. A method's success is not its effect.** Every mutation is followed by an
  independent read-back (§1.4 step 4), with a settle budget sized to the
  physical event for declarative or asynchronous operations and single-shot for
  synchronous ones. A settle window is not an amnesty: state that never
  settles still fails.
  - **Why:** declarative applies return before anything happens, so the return
    code proves only that the request was accepted.
- **L9. A refusal leaves the system as it found it.** Identity gates run before
  the first mutating step. A gate that refuses writes no record, so the
  existence of a record is never mistaken for a check that ran. A host with no
  cluster passes an identity gate, so a partial teardown can be re-run.
  - **Why:** a teardown that mutates before checking identity can destroy the
    wrong cluster.
- **L10. Residue planes are separate.** cephadm state (cluster directories,
  units) and LVM state (ceph VGs and LVs) are cleared by different remedies. A
  purge's own effect poll covers only cephadm's plane; the final torn-down gate
  requires both (06-maintenance-teardown).
  - **Why:** demanding both planes inside the purge deadlocks, because the zap
    that frees the disks waits on a poll that is waiting for the disks.
- **L11. Read the error before re-running.** When a step fails, the operator
  MUST read the method's error from the platform's method-summary report for
  that model instance (including a per-item instance) before re-running.
  Report-failure messages MUST say this. A destructive workflow MUST NOT be
  re-run as a debugging instrument.
  - **Why:** the run record shows only which step failed, not the error text,
    and idempotency does not make a second destructive run safe on a cluster in
    an unknown state.
- **L12. A residue poll timeout is not a tool failure.** A purge error naming
  its own residue condition timing out means the removal ran and verification
  timed out; there is no tool error output to look for.
  - **Why:** operators otherwise search for a tool failure that never happened
    and re-run the purge.
- **L13. Platform facts a workflow caller must respect:**
  - `cephadmUrl` MUST point at the standalone cephadm executable, not the raw
    Python script, which imports a library it lacks.
  - A filesystem bind-mounted into another mount namespace is not released by a
    systemd unmount; the wipe refuses it and the caller must free holders
    first.
  - Some kernel ceph clients accept only an inline secret.
  - `fs volume create` fails with EINVAL when pools of the conventional names
    already exist; adoption goes through `fs new` (04-dataplane).
  - **Why:** each of these failed a first live run with an error that pointed
    elsewhere.
- **L14. Tests derive counts and versions from registries, never literals.** The
  catalog tests in §1.8 enumerate the manifest and the workflow directory.
  - **Why:** ordinary growth must not break the suite, and real drift still
    must.

## Unresolved

1. **Mgr settle window.** `cephVerifyMgr` has no settle budget, but mgr apply is
   declarative. Should `cephVerifyMgr` gain a settle window for the
   `cephadm-apply-mgr` prove job, or is a single shot acceptable?
2. **MDS host proof.** No method maps MDS daemons to hosts, so
   `cephadm-apply-mds` and `cephadm-create-fs` prove only that an MDS is
   active. Add a placement read-back method, or accept the gap?
3. **Package-source pre-gate.** Should `cephadm-prep-host` call
   `cephVerifyPackageSource` as an optional pre-gate before approval?
4. **Multi-host record key in `cephadm-distribute-key`.** The
   `cephVerifyKeyDistributed` key is the sorted `host:port` list. If the
   workflow expression language cannot sort, should the workflow require
   `hosts[]` in sorted order and assert that before approval?
5. **`privateKey` in workflows.** Should workflows expose a vault-referenced
   `privateKey` input as well as `keyPath`?
6. **RGW on the twin.** No workflow deploys an RGW service, and the inventory
   fails on a cluster without one. Should the twin run deploy RGW out of band,
   or should `cephadm-inventory-rgw-buckets` be excluded from the end-to-end
   order?
7. **Teardown workflow.** Should a `cephadm-teardown-cluster` workflow wrap the
   teardown chain of §3.2, with the gate shape of §1.4?
