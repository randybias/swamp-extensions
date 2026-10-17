# 06: Maintenance and teardown

Status: draft for review · Part of the `@randybias/cephadm` behaviour
specification. Read `00-overview.md` first; its decisions win over this file.

This file specifies registry methods #33–#44:

| # | Method | Class |
|---|---|---|
| 33 | cephHostMaintenanceEnter | M |
| 34 | cephHostMaintenanceExit | M |
| 35 | cephHostMaintenanceState | RO |
| 36 | cephOsdOkToStop | RO |
| 37 | cephCephadmCheckHost | RO |
| 38 | cephHostNooutClear | M! |
| 39 | cephOsdActivate | M |
| 40 | cephHostClusterState | RO |
| 41 | cephVerifyClusterFsid | RO |
| 42 | cephDisableOrchestration | M |
| 43 | cephRmCluster | D |
| 44 | cephVerifyHostTornDown | RO |

`cephVerifyHostNoout` (#21) is specified in 05-verify. It MUST use the
host-subtree noout predicate defined in §3 of this file.

---

## 1. Teardown chain order

**Why teardown exists.** Wiping data disks does not remove a cephadm cluster.
The cluster directory, its config and its systemd units live on the OS disk and
survive. A later bootstrap then finds the surviving cluster and returns its old
fsid almost at once, the bootstrap gate rightly refuses, and the bring-up chain
cannot be re-run after a partial success. Teardown is the way forward.

A teardown MUST run in this order. It follows the upstream Ceph cluster-purge
procedure, with the fsid check moved to the front.

1. **`cephVerifyClusterFsid` on every host**, before any mutation on any host.
   If any host carries an fsid the caller did not name, the chain stops.
   *Why:* a refusal must leave the cluster as it found it. A refusal that comes
   only inside the purge step arrives after orchestration has been disabled and
   the mgr failed over on a live cluster, which then has to be undone by hand.
2. **`cephDisableOrchestration`** through one admin host. *Why:* otherwise
   cephadm redeploys daemons onto a purged host, per-host verification flaps,
   and a green result does not stay green. A `clusterUnreachable` outcome does
   not stop the chain, but the caller MUST surface it.
3. **`cephRmCluster`** on each host.
4. **Data-disk wipe** (`wipeDiskToRaw`, 02-hostprep) for any LVM still holding
   disks. This step MUST be gated on the safety question (step 1's fsid
   verdict), **not** on step 3 succeeding. *Why:* gating the wipe on a clean
   purge creates a circular wait. The purge cannot finish while LVM holds the
   disks, and the wipe that frees them never runs.
5. **`cephVerifyHostTornDown` on each host** (OS-disk plane) **and**
   `cephVerifyDisksRaw` (05-verify, data-disk plane). Neither alone is
   sufficient. *Why:* a volume group whose physical volumes are gone is visible
   to `vgs` but not to `lsblk`, and on-device OSD signatures are visible to
   `lsblk` but not to the OS-disk observation.

**Identity.** The fsid gate proves *which cluster* is on the machine. It does
not prove *which machine* was reached. That needs a separate identity check
outside this group. Neither check replaces the other.

---

## 2. Poll-until-verified contract

This contract is shared by `cephHostMaintenanceEnter`,
`cephHostMaintenanceExit`, `cephHostNooutClear`, `cephDisableOrchestration`
and `cephRmCluster`. Other groups that poll for an effect SHOULD use the same
loop.

### 2.1 Rules

- An exit code of 0 from a mutating command is **acceptance, not effect**.
  Every mutating method in this group MUST re-read state until the effect is
  observed or the budget runs out. *Why:* the orchestrator acknowledges a
  request before acting on it, so one immediate re-read can still show the
  previous state.
- Each poll has a **label**, a **phase tag**, an **interval ceiling** and a
  **budget**. The caller supplies the phase tag, so a timeout is always
  attributed to the operation that was waiting.

### 2.2 Loop semantics

1. **Read** the state, then **evaluate** the condition.
2. If the read succeeds and the condition holds, return the observed data at
   once.
3. If the read succeeds and the condition does not hold, that is not a failure
   yet. Keep polling.
4. If the read fails with a **typed transport error** (D8, 01-transport), it is
   a retry, not a failure. Log a `warn` naming the label, the attempt number
   and the error. Retries MUST never be silent.
5. **Any other error stops the loop at once and propagates (D47).** This
   includes:
   - an evaluator refusal, such as "state not observed";
   - a parse failure;
   - a read command's own non-zero exit.
   
   *Why:* a refusal says the method cannot judge the state. Retrying it until
   the deadline only delays the true error and makes it look like a slow
   effect.
6. Sleep (§2.3), then repeat while the deadline has not passed.
7. After the deadline, perform **exactly one final read**. This guards against
   the deadline racing a slow read.
   - If it satisfies the condition, return success.
   - If it throws, that error propagates.
   - Otherwise fail with
     `cephadm[<phase>]: <label> condition not satisfied within timeout budgetMs=<n> attempts=<n>`.
8. The loop MUST report the number of reads it performed, including the final
   read. Methods that record `pollAttempts` record this number (D45).

### 2.3 Backoff

The poll uses the shared backoff of 01-transport. The following properties are
restated here because poll correctness depends on them:

- There are no fixed sleeps. The interval argument is a **ceiling**, not a
  period.
- Let `base = max(1, ceil(ceiling / 16))`. The raw interval before sleep *n*
  (counting from zero) is `max(1, min(ceiling, base × 2^n))`.
- The actual sleep is `round(raw/2 + jitter × raw/2)`, with jitter drawn from
  [0, 1) using the injected randomness seam. The minimum sleep is 1 ms.
- Each sleep is clamped to the remaining budget, so a sleep never overshoots
  the deadline. If no budget remains, there is no sleep.
- The sleep and randomness seams are injectable (§2 of the overview), so tests
  are deterministic.

### 2.4 Cephadm poll-budget floor

This floor applies to `cephHostMaintenanceEnter`, `cephHostMaintenanceExit`
and `cephHostNooutClear`.

- If the caller's `pollTimeoutMs` is below 300 000 ms, the method MUST raise
  it to 300 000 ms and log a `warn` naming the requested and floor values.
- A larger budget is never lowered and produces no log.

*Why:* one `cephadm shell` invocation costs tens of seconds even for a no-op
read, because it starts a container. A short budget that looks reasonable runs
out before a single read returns. That failure points the dangerous way: the
gate reports "never entered" for a host that is actually draining. The budget
is only consulted on failure, so raising it costs a correct run nothing. This
is consistent with D37.

---

## 3. Other cross-cutting rules for this group

### 3.1 Transport and targeting

- Every method takes the shared SSH argument family (overview §3) and follows
  its rules: `sshUser`, `port`, `keyPath`, `privateKey` (sensitive),
  `strictHostKeyChecking`.
  - Test: a schema sweep confirms that every method in this group declares
    them.
- **`host` / `adminHost` versus `hostName`.**
  - `host` (or `adminHost`) is the machine the command runs **on**. It follows
    the hostname-or-IPv4 grammar.
  - `hostName` is the Ceph-registered name of the host being acted **about**.
    It follows the hostname grammar (01-transport).
  - The two may differ. A method MUST NOT assume they are the same string.
  - Both are validated before they are interpolated into any remote command.
- **`ceph …` commands** run inside `cephadm shell` on the admin host, under
  passwordless sudo (01-transport).
  - The transport adds the `ceph` prefix. A call site passes only the
    sub-command, for example `orch host maintenance enter <hostName>`.
  - Tests MUST pin the exact command text sent, with exactly one `ceph`
    prefix, and include a positive control.
  - *Why:* a doubled prefix is not a visible syntax error. The CLI answers with
    usage text, which a classifier then reads as "a problem was named", giving
    the wrong verdict.
- **Host-OS observations** for teardown run as one script piped to `bash -s`
  under `sudo -n`, not through `cephadm shell` (§3.6).

### 3.2 Records

- Every record carries `capturedAt`, an ISO-8601 timestamp from the injected
  clock. Freshness is judged by `capturedAt`, never by the key.
- Instance keys follow overview §4:
  - `<method>-<host>` for methods about the target machine itself;
  - `<method>-<host>-<hostName>` for methods that act on one Ceph host through
    an admin host.

  Keys are stable, can be built by a caller, and are never timestamped.
  Running twice with the same arguments writes the same key, and two subjects
  write independent keys.

  *Why:* workflows read evidence back by exact name and cannot construct a
  timestamp. A timestamped key is unreadable, and it also defeats the
  platform's own per-write versioning.
- Every resource has `lifetime: infinite` and keeps the last 10 versions.
- Every resource schema is strict and declares every field written (D41, D45).
  - Test: a sweep validates each written record against its declared schema.
- **Refusals and fail-closed errors write no record.** So the existence of a
  row can never be mistaken for a check that passed or a purge that happened.
  - Exceptions are stated per method: `cephVerifyHostTornDown` records a dirty
    host, and `cephDisableOrchestration` records `clusterUnreachable`.
- A missing record is evidence only that the method did not complete. It is
  never evidence about cluster state.

### 3.3 Status comparisons (D44)

- Every comparison of a host status is **case-insensitive**. For example,
  `ceph orch host ls -f json` prints `maintenance`, and the table form prints
  `Maintenance`.
- Host lookups MUST select the entry whose `hostname` equals `hostName`
  exactly. A method MUST NOT take the first entry, and MUST NOT accept a prefix
  match.

### 3.4 Host-subtree noout predicate (D46)

The `noout` flag set by maintenance is a **subtree flag on the host's CRUSH
node**. It does not appear in the flags of `ceph osd dump`. One shared
predicate decides "is host-subtree noout set for `hostName`", and these methods
MUST all use it:

- `cephHostMaintenanceEnter`
- `cephHostMaintenanceState`
- `cephHostNooutClear`
- `cephVerifyHostNoout` (05-verify)

The predicate works as follows:

- **Input:** the JSON from `ceph health detail -f json`.
- **Where to look:** read `checks.OSD_FLAGS.summary.message` **and** the
  `message` of every entry in `checks.OSD_FLAGS.detail[]`.
- **What a statement looks like:** in any of those messages, find statements
  of the form `host <name> has flags <list>`. `<list>` is a comma-separated
  list of flag names.
- **Flag lists are unordered sets.** `noout`, `noin,noout` and `noout,noin`
  all contain `noout`. Flag names compare case-insensitively.
- **Result:** the predicate is true when some statement names exactly
  `hostName` and its flag set contains `noout`.
  - Exact name: a statement for `node-b2` does not set the flag for `node-b`.
  - Messages that do not have the per-host shape are ignored, for example a
    count-only summary such as "1 host(s) have flags noout".
- If `OSD_FLAGS` is absent, the predicate is false.
- If the health JSON cannot be parsed, that is an error, never "false".

**[twin]** Confirm the exact summary and detail message shapes on the pinned
Squid release.

*Why:* reading `osd dump` flags gives a confident, wrong "not set".
Order-dependent or summary-only matching misses real per-host lines.

### 3.5 Phase tags

Errors use `cephadm[<phase>]:` (overview §4). The phase tags in this group are:

- `maintenance-enter`
- `maintenance-exit`
- `maintenance-state`
- `ok-to-stop`
- `check-host`
- `noout-clear`
- `osd-activate`
- `host-cluster-state`
- `verify-cluster-fsid`
- `disable-orchestration`
- `rm-cluster`
- `verify-host-torn-down`

### 3.6 Host observation (shared by #40, #41, #43, #44)

**One script, one round trip, privileged.**

- The observation is a single script sent over one SSH connection and run as
  `sudo -n -- bash -s`. *Why:* during teardown things disappear between
  separate reads, so the reads must be consistent with each other.
- Privilege is mandatory. *Why:* `/var/lib/ceph/<fsid>` is readable only by
  root, and `vgs`/`lvs` report nothing useful without privilege. An
  unprivileged read reports an empty host that looks clean, which is exactly
  the false negative this design prevents.

**Script content, in order:**

1. **Tool-presence probes**, using `command -v`.
   - Print a systemctl-presence marker if `systemctl` exists.
   - Print an LVM-presence marker only if **both** `vgs` and `lvs` exist.
2. **Six sections.** Each starts with its own marker line, and each marker MUST
   be printed with `echo`:

   | Section | Command | What is kept |
   |---|---|---|
   | fsid directories | `ls -1 /var/lib/ceph` | each line |
   | loaded units | `systemctl list-units --all --plain --no-legend --no-pager 'ceph*'` | first column |
   | unit files | `systemctl list-unit-files --no-legend --no-pager 'ceph*'` | first column |
   | volume groups | `vgs --noheadings -o vg_name` | each line |
   | logical volumes | `lvs --noheadings -o vg_name,lv_name --separator /` | each line |
   | md status | `cat /proc/mdstat` | each line |

3. Each read discards stderr and is guarded, so a failed read yields an empty
   section. The script as a whole MUST exit 0.

**Marker rules.**

- Marker text MUST NOT collide with any possible section content.
- *Why markers must be echoed:* a bare marker line beginning with `#` is a bash
  comment when the script is piped to bash, so it never reaches stdout. The
  directory listing then falls under no section, and a host that still carries
  a cluster directory reads clean.
- Test: run the real script through a real `bash` with stubbed tools, and
  assert that every marker appears and that content lands in the right
  section.

**Parsing.**

- Split stdout on marker lines. A recognised section marker starts that
  section.
- Any other marker-shaped line, including the presence markers, files the
  lines after it under **no section**. They are never added to the previous
  section. *Why:* an extra line filed under fsid directories would read as an
  extra cluster.
- Lines are trimmed, and blank lines are dropped.
- **Fail closed:** if any of the six section markers is missing from stdout,
  throw `cephadm[<phase>]: host state not observed host=<host> missing=<sections>`.
  - Empty stdout is refused. It is never read as clean.
  - A non-zero script exit also throws.

**Derived host state.** These are the fields `host`, `fsids`, `cephUnits`,
`clusterUnits`, `cephVolumeGroups`, `cephLogicalVolumes`, `mdArrays`,
`toolsSeen` and `capturedAt`:

- **`fsids`** are the fsid-directory entries that match the **UUID grammar**,
  sorted. The UUID grammar is five groups of hex digits of lengths 8-4-4-4-12,
  joined by hyphens. Hex digits are case-insensitive, and there is no other
  text.
  - Accept: `0b1d4c6e-3f2a-4e8b-9c7d-1a2b3c4d5e6f`, and the same with
    uppercase hex.
  - Reject: `crash`, `osd`, `mon`, `0b1d4c6e3f2a4e8b9c7d1a2b3c4d5e6f`, and a
    UUID with a suffix.
  - Package directories are not clusters.
- **`cephUnits`** is the union of loaded units and unit files, de-duplicated
  and sorted. *Why:* a unit file that was never loaded is invisible to
  `list-units` but is still residue.
- **`clusterUnits`** are the `cephUnits` whose name contains a UUID, such as
  `ceph-<fsid>@mon.<h>.service` or `ceph-<fsid>.target`.
  - Package units such as `ceph.target`, `ceph-crash.service` and
    `ceph-volume@lvm-…` legitimately survive and are not residue.
- **`cephVolumeGroups`** are the VG names starting with `ceph-`.
- **`cephLogicalVolumes`** are the `vg/lv` entries starting with `ceph-`.
- **`mdArrays`** are the names on `mdN :` lines of mdstat.
  - They are evidence only and are never asserted. *Why:* the boot array is
    commonly md and must survive, so a naive "no md arrays" check would fail a
    correct teardown.
- **`toolsSeen`** has exactly three independent booleans:
  - `systemctl` and `lvm` come from the presence markers **only**;
  - `mdstat` is true when the md section is non-empty.

**Residue evaluation.** This single definition is used by `cephRmCluster`,
`cephVerifyClusterFsid` and `cephVerifyHostTornDown`.

- **cephadm plane:**
  - If `toolsSeen.systemctl` is false, throw "not observed".
  - Otherwise there is one finding per fsid directory and one per cluster
    unit.
- **LVM plane:**
  - If `toolsSeen.lvm` is false, throw "not observed".
  - Otherwise there is one finding per ceph VG and one per ceph LV.
- **Whole host** is the cephadm plane plus the LVM plane.
- Each finding names its item individually. *Why:* an operator fixing a host
  by hand needs the list, not a count.
- An absent tool MUST NOT be treated as a clean host. *Why:* an absent tool and
  a clean host produce the same empty section, and only the presence marker
  tells them apart.
- Each plane's refusal is independent. A missing LVM toolset does not block
  the cephadm-plane answer, and vice versa.

**Fsid classification.** `cephRmCluster` and `cephVerifyClusterFsid` MUST use
this same function. Fsid comparison is case-insensitive.

1. If any fsid other than the named one is present, even alongside the named
   one, the result is **refuse**.
2. Otherwise evaluate residue. Missing tools throw "not observed", which fails
   closed before any mutation. Then:
   - whole-host residue is empty: **no-op**;
   - cephadm-plane residue is empty but LVM residue is present: **stranded**;
   - otherwise: **purge**. This includes the half-removed case of cluster
     units with no directory.

---

## 4. Methods: maintenance

### 4.1 cephHostMaintenanceEnter

- **Safety class:** M (idempotent converge). It is operationally disruptive,
  because it stops the host's OSDs.
- **Purpose:** put one Ceph host into maintenance and prove the effect, or
  prove that an existing maintenance state is complete.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | admin host the ceph commands run on |
| hostName | string | yes | – | hostname | Ceph host to put into maintenance |
| osdCount | integer | yes | – | ≥ 1 | number of OSDs on that host, used for the OSD-down proof |
| pollIntervalMs | integer, nullish | no | 15000 | ≥ 1 | backoff ceiling |
| pollTimeoutMs | integer, nullish | no | 600000 | ≥ 1, floored to 300000 (§2.4) | poll budget |
| SSH family | | | | overview §3 | |

- **Preconditions:**
  - The admin host is reachable.
  - Callers MUST NOT run two enters at once against one cluster. *Why:* with
    an erasure-coded pool whose size equals the host count and whose
    `min_size` is size − 1, one host out leaves the pool at exactly
    `min_size`, with zero margin.
  - The method MUST NOT change `min_size`, and callers MUST NOT lower it to
    make room.
  - Pairing this method with `cephOsdOkToStop` and `cephHostMaintenanceState`
    is the workflow's job. This method does not call ok-to-stop itself.
- **Behaviour:**
  1. Read `ceph orch host ls -f json` and find the entry for `hostName`
     (§3.3).
  2. Decide whether to issue the command:
     - If its status is not `maintenance` (case-insensitive, D44), issue
       `ceph orch host maintenance enter <hostName>` and set
       `didIssueCommand = true`.
     - Otherwise log `info` that the host is already in maintenance, and go
       straight to verification.
  3. Poll (§2) with phase `maintenance-enter`. Each read fetches
     `ceph orch host ls -f json`, `ceph health detail -f json` and
     `ceph osd stat -f json`. The three reads MAY run in parallel.
  4. The condition is **all** of the following:
     - the host's status is `maintenance` (case-insensitive);
     - the host-subtree noout predicate (§3.4) is true for `hostName`;
     - the host's OSDs are down: `num_up_osds ≤ num_in_osds − osdCount`;
     - every OSD stayed in: `num_in_osds ≥ num_osds`. If an OSD went out,
       noout failed to prevent a rebalance and the window is wrong.
  5. HEALTH_WARN MUST NOT fail the gate.
  6. Write the record.
- **Idempotency:** on a second run the method sees `maintenance`, issues
  nothing, and still runs the full three-proof verification.
- **Output / record:**
  - Spec `cephMaintenanceResult`, key
    `cephHostMaintenanceEnter-<host>-<hostName>`.
  - Fields: `method`, `host`, `hostName`, `action` (`"enter"`),
    `didIssueCommand`, `pollAttempts` (the real read count, D45),
    `pollDurationMs` (elapsed time of the verification poll),
    `hostInMaintenance`, `nooutFlagFound`, `hostOsdsDown`, `hostOsdsStayIn`,
    `numUpOsds`, `numInOsds`, `capturedAt`.
  - There is no `succeeded` field (D45).
  - The record is written only on success.
- **Post-verification:** the poll above. The evaluation detail used in error
  messages includes:
  - the host status, or `not_found`;
  - the health status;
  - the OSD_FLAGS messages;
  - the up and in counts;
  - the expected maximum up count.
- **Failure modes:**
  - The pre-check read fails: throw. The pre-check is outside the poll and is
    not retried.
  - The enter command exits non-zero: throw.
  - A transport error during the poll: retry (§2.2). Any other poll error:
    stop and throw (D47).
  - The condition never holds within the floored budget: throw a timeout that
    includes the last evaluation detail. No record is written.
  - Partial effects make the condition false and end in a timeout. These
    include:
    - status `maintenance` but noout absent;
    - noout present only for a different host;
    - all OSDs still up;
    - OSDs out;
    - the host missing from the list.
- **Security:** `host` and `hostName` are validated by grammar before any
  interpolation.
- **Why:**
  - Exit 0 of `maintenance enter` is acceptance, so three independent proofs
    are required.
  - noout is a subtree flag (§3.4).
  - A gate that demands HEALTH_OK fails a correct maintenance window.
  - The cluster can be briefly unreachable during enter, so a transport error
    is a retry.
- **Test obligations:**
  - [ ] All three proofs met → pass, and the record is written under the
    stable key.
  - [ ] Status not maintenance, but noout and OSD state correct → timeout, no
    record.
  - [ ] Status maintenance but noout absent → timeout. A partial effect never
    reads as success.
  - [ ] noout present only in health detail, with `osd dump`-style flags empty
    → detected.
  - [ ] noout only in `OSD_FLAGS.detail[]`, with a count-only summary →
    detected (D46).
  - [ ] Flag list `noin,noout` → detected (D46).
  - [ ] noout for `<hostName>2` only → not detected (D46).
  - [ ] N − osdCount up with all in → pass. Any OSD out → fail.
  - [ ] HEALTH_WARN with everything else correct → pass.
  - [ ] Target inside a mixed host list → the correct entry is used. Host
    absent → fail, with detail `not_found`.
  - [ ] Noout for a different host → fail. All OSDs still up → fail.
  - [ ] Status `Maintenance` (TitleCase) → treated as maintenance (D44).
  - [ ] Already in maintenance → no enter command, and `didIssueCommand`
    false.
  - [ ] `pollAttempts` equals the number of reads performed, and the record
    has no `succeeded` field (D45).
  - [ ] A transport error on one poll read → retried with a `warn`. A
    non-zero ceph exit or a parse error → stops at once and throws (D47).
  - [ ] `pollTimeoutMs` 30000 → raised to 300000 with a `warn`. 900000 → kept,
    no log.
  - [ ] The command text has exactly one `ceph` prefix.

### 4.2 cephHostMaintenanceExit

- **Safety class:** M (idempotent converge). It restores the host's OSDs.
- **Purpose:** take one host out of maintenance and prove its OSDs are
  restored, or prove recovery if the host is not in maintenance.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | admin host |
| hostName | string | yes | – | hostname | Ceph host to take out of maintenance |
| pollIntervalMs | integer, nullish | no | 15000 | ≥ 1 | backoff ceiling |
| pollTimeoutMs | integer, nullish | no | 600000 | ≥ 1, floored to 300000 (§2.4) | poll budget |
| SSH family | | | | overview §3 | |

  The method takes no OSD-count argument. An argument whose description claims
  a verification the method does not perform MUST NOT be added.
- **Preconditions:** the admin host is reachable.
- **Behaviour:**
  1. Read `ceph orch host ls -f json`.
     - If the status of `hostName` is `maintenance` (case-insensitive, D44),
       run the exit procedure in step 2 and set `didIssueCommand = true`.
     - Otherwise log `info` and go to verification.
  2. **Exit procedure:**
     a. Issue `ceph orch host maintenance exit <hostName>`. If it succeeds, go
        to step 3.
     b. If it fails, classify the failure:
        - **A typed transport error of any kind other than "failed before
          authentication"** (01-transport error taxonomy): the outcome is
          **unknown**, because the exit may already have been applied.
          - Throw `cephadm[maintenance-exit]: outcome unknown kind=outcome-unknown host=<hostName> transport=<kind> error=<first error>`.
            The message tells the operator to re-read `ceph orch host ls`.
          - Do **not** run check-host, and do **not** re-issue the exit.
          - If the transport cannot tell a pre-authentication failure apart,
            every transport error MUST be treated as outcome-unknown.
        - **A delivered command failure, or a pre-authentication failure**
          (which proves nothing ran): run
          `ceph cephadm check-host <hostName>`, allowing a non-zero exit.
          Combine its stdout and stderr, and classify the text as
          `cephCephadmCheckHost` does.
     c. If check-host reports `Host looks OK`, retry the exit **exactly once**.
        If the retry fails, its error propagates. There is no loop.
     d. Any other check-host result: throw
        `cephadm[maintenance-exit]: … kind=check-host-failed`, carrying the
        check-host text verbatim and the first error.
  3. Poll (§2) with phase `maintenance-exit`. Each read fetches
     `ceph orch host ls -f json` and `ceph osd stat -f json`.
     The condition is all of:
     - the host is present;
     - its status is not `maintenance` (case-insensitive);
     - `num_up_osds ≥ num_osds`;
     - `num_in_osds ≥ num_osds`.
  4. Write the record.
- **Idempotency:** if the host is not in maintenance, no command is issued, and
  the method still verifies that every OSD is up and in.
- **Output / record:**
  - Spec `cephMaintenanceResult`, key
    `cephHostMaintenanceExit-<host>-<hostName>`.
  - Fields: `method`, `host`, `hostName`, `action` (`"exit"`),
    `didIssueCommand`, `pollAttempts` (the real read count, D45),
    `pollDurationMs`, `hostExitedMaintenance`, `osdsRestored`, `numUpOsds`,
    `numInOsds`, `capturedAt`.
  - There is no `succeeded` field (D45). The record is written only on
    success.
- **Post-verification:** the poll.
- **Failure modes:**
  - The pre-check read fails: throw.
  - Outcome-unknown: throw.
  - check-host names a problem: throw `check-host-failed`.
  - The single retry fails: throw.
  - A poll timeout, or a non-transport poll error (D47): throw.
- **Security:** `host` and `hostName` are validated before interpolation.
- **Why:**
  - The same misleading first-attempt error has two root causes with opposite
    remedies. The error is a Python `TypeError` about missing constructor
    arguments, which hides a host-connection failure.
    - Cause one: cephadm has not yet noticed the host. One retry fixes it.
    - Cause two: the container engine is absent from the host. A retry never
      fixes it.

    check-host is the only discriminator between the two. Distributing the
    cephadm SSH key in advance does not prevent the error.
  - Exactly one retry, by construction. *Why:* a loop would hang in the state
    "check-host OK but exit keeps failing" instead of producing a named error.
  - A command that may have reached the host MUST NOT be repeated blindly.
    Unknown outcome is reported as unknown.
- **What it cannot see:** the gate uses cluster-wide counts.
  - An unrelated down OSD on another host fails it. That is a false negative,
    in the safe direction.
  - It cannot prove that *this* host's OSDs are the ones that returned.
- **Test obligations:**
  - [ ] Not in maintenance, all up and in → pass.
  - [ ] Still in maintenance → fail. OSDs not all up → fail. OSDs out → fail.
  - [ ] Status `Maintenance` (TitleCase) → recognised as in maintenance, and
    the exit is issued (D44).
  - [ ] First exit fails, check-host says `Host looks OK` → exactly one retry,
    success, no failure surfaced.
  - [ ] First exit fails, check-host names a missing container engine → throws
    `check-host-failed` naming the problem, with no retry.
  - [ ] Transport drop mid-session on the first exit → throws outcome-unknown.
    Exactly one exit command is issued, and no check-host.
  - [ ] Pre-authentication failure on the first exit → the check-host path is
    taken.
  - [ ] First-attempt success → no check-host is issued.
  - [ ] Both attempts fail with `Host looks OK` between them → throws, and the
    exit command was issued exactly twice. Count by the command text in the
    script body, not by argv.
  - [ ] The check-host command text has exactly one `ceph` prefix, so a
    healthy host classifies as retryable.
  - [ ] `pollAttempts` is recorded, and the record matches the declared
    schema (D45).
  - [ ] Evaluator or parse error in the poll → stops at once (D47).

### 4.3 cephHostMaintenanceState

- **Safety class:** RO, fail-closed. The description starts with `READ-ONLY.`
- **Purpose:** in one call, report which hosts are already out, by maintenance
  status or by host-subtree noout. It serves a quorum or removal interlock that
  must know how many hosts are down before allowing one more.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | admin host |
| SSH family | | | | overview §3 | |

- **Preconditions:** the admin host is reachable.
- **Behaviour:**
  1. Read `ceph orch host ls -f json` and `ceph health detail -f json`. The
     reads MAY run in parallel.
  2. If the host list is not an array, or is empty, throw. *Why:* a cluster
     always has at least one host, so an empty list means the read did not see
     what it thinks it saw.
  3. For each host, compute:
     - `status` (raw);
     - `nooutFlag`, using the predicate in §3.4;
     - `out` = (status equals `maintenance` case-insensitively) **OR**
       `nooutFlag`.
  4. Derive `hostsOut`, `numHosts` and `numHostsOut`.
- **Idempotency:** pure read.
- **Output / record:**
  - Spec `cephHostMaintenanceStateResult`, key
    `cephHostMaintenanceState-<host>`.
  - Fields: `method`, `host`, `hosts[]` (each `{hostname, status, nooutFlag,
    out}`), `hostsOut[]`, `numHosts`, `numHostsOut`, `capturedAt`.
  - No record is written for an empty or invalid list.
- **Post-verification:** not applicable.
- **Failure modes:**
  - A transport or parse failure: throw.
  - An empty or invalid host list: throw, with no record.
- **Security:** `host` is validated by grammar.
- **Why:**
  - OR, never AND. *Why:* a window that failed part-way leaves noout set
    without the maintenance status, which is exactly the state this method
    exists to find.
  - "Could not tell" MUST NOT render as "all clear" on a gate whose false
    negative is a second host down.
- **Test obligations:**
  - [ ] Maintenance status alone marks a host out. noout alone marks a host
    out.
  - [ ] `Maintenance` and `maintenance` both match (D44).
  - [ ] Healthy cluster → nobody out, and each entry carries both raw inputs.
  - [ ] A host whose name is a prefix of a flagged host is not marked out
    (D46).
  - [ ] noout reported only in `detail[]`, or in a multi-flag list → detected
    (D46).
  - [ ] Empty host list → throws, with no record.

### 4.4 cephOsdOkToStop

- **Safety class:** RO. The description starts with `READ-ONLY.`
- **Purpose:** ask the orchestrator whether a host can be stopped safely.
  Report the verdict, the cluster's verbatim reason on refusal, and the daemons
  it names.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | admin host |
| hostName | string | yes | – | hostname | host to ask about |
| SSH family | | | | overview §3 | |

- **Preconditions:** the admin host is reachable.
- **Behaviour:**
  1. Run `ceph orch host ok-to-stop <hostName>`, allowing a non-zero exit.
     *Why:* a refusal exits non-zero, but its output **is** the answer.
  2. Concatenate stdout and stderr. *Why:* on refusal, ceph writes nothing to
     stdout and writes the ALERT to stderr.
  3. Decide the verdict:
     - If the text contains `presumed safe` (case-insensitive): `safe = true`,
       `reason = "presumed safe"`, and the daemons are parsed as in step 4.
     - Otherwise: `safe = false`, `reason` = the text with the banner stripped
       (step 5) and trimmed, and `daemons = []`.
     - Empty output → `safe = false`, `reason = ""`. The method never assumes
       safe without the explicit marker.
  4. **Daemon parsing** of a safe answer recognises these line shapes:
     - A header, `It is presumed safe to stop host <h>. Note the following:`.
       It is skipped, because it names the host, not a daemon.
     - `It appears safe to stop <daemon>`.
     - `<a>,<b>,… are safe to restart`, a comma-separated list (for example
       OSDs).
     - `It is presumed safe to stop ['<d1>', '<d2>']`, a bracketed list of
       quoted names.
     - Legacy bullet lines, `- <daemon>`.

     For each name: trim it, and remove surrounding quotes and a trailing
     period. Then de-duplicate the names, keeping the order of first
     appearance.
  5. **Banner stripping** removes only the known `cephadm shell` preamble
     lines:
     - "Inferring fsid …";
     - "Inferring config …";
     - "Using ceph image with id …";
     - the line reporting the container image digest.

     Any line it does not recognise MUST be left intact.
- **Idempotency:** pure read.
- **Output / record:**
  - Spec `cephOkToStopResult`, key `cephOsdOkToStop-<host>-<hostName>`.
  - Fields: `method`, `host`, `hostName`, `safe`, `reason`, `daemons[]`,
    `capturedAt`.
- **Post-verification:** not applicable.
- **Failure modes:**
  - A refusal is a record with `safe: false`. It is never a thrown error and
    never a bare boolean.
  - A transport failure: throw.
- **Security / privacy:** banner stripping keeps a real cluster fsid out of
  stored records and messages, which get pasted into reports and tickets.
- **Why:**
  - A refusal MUST NOT be remediated automatically, for example by failing
    over the active mgr. That is an operator decision.
  - Real output never contains bullet lines, so a bullet-only parser reports
    an empty daemon list on every host.
  - A stdout-only reader loses the refusal reason while keeping the verdict
    right. That failure is asymmetric and goes unnoticed, because the safe
    path looks fine.
- **Test obligations:**
  - [ ] Safe output → `safe: true`, with daemons from every line shape. The
    header never yields the host as a daemon. An MDS line is picked up.
    Legacy bullets are accepted.
  - [ ] Empty input → `safe: false`, `reason: ""`.
  - [ ] Refusal about an active mgr, or about too few RGW daemons →
    `safe: false`, verbatim reason, and `daemons: []` (not null).
  - [ ] Refusal with empty stdout and the ALERT on stderr → the reason carries
    the ALERT. The safe path still reads stdout and reports daemons.
  - [ ] Banner-stripped refusal → the reason leads with the ALERT,
    unrecognised text is untouched, and the safe verdict is unaffected.
  - [ ] The key is stable and not timestamped. Two hosts → independent keys.
    The same host → the same key.

### 4.5 cephCephadmCheckHost

- **Safety class:** RO. The description starts with `READ-ONLY.`
- **Purpose:** run `ceph cephadm check-host <hostName>` and classify the
  result. This is the same discriminator used inside
  `cephHostMaintenanceExit`, exposed standalone.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | admin host |
| hostName | string | yes | – | hostname | host to check |
| SSH family | | | | overview §3 | |

- **Preconditions:** the admin host is reachable.
- **Behaviour:**
  1. Run the command, allowing a non-zero exit, and combine stdout and stderr.
  2. Classify the text:
     - If it contains `Host looks OK`: `ok = true` and `detail` = that phrase.
     - Otherwise: `ok = false` and `detail` = the trimmed text, verbatim.
     - Empty output → `ok = false`.
- **Idempotency:** pure read.
- **Output / record:**
  - Spec `cephCheckHostResult`, key `cephCephadmCheckHost-<host>-<hostName>`.
    The key is never timestamped.
  - Fields: `method`, `host`, `hostName`, `ok`, `detail`, `capturedAt`.
- **Post-verification:** not applicable.
- **Failure modes:** a transport failure throws. A problem that check-host
  reports is a record with `ok: false`, not a thrown error.
- **Security:** `hostName` is validated before interpolation.
- **Why:** check-host is the only signal that tells "cephadm has not noticed
  the host yet" (retryable) apart from "the host lacks a prerequisite" (not
  retryable).
- **Test obligations:**
  - [ ] `Host looks OK`, alone or surrounded by other text → `ok: true`.
  - [ ] A missing container engine → `ok: false`, naming it.
  - [ ] Any other output → `ok: false`. Empty → `ok: false`.
  - [ ] The command text has exactly one `ceph` prefix.
  - [ ] The record is written under the stable key.

### 4.6 cephHostNooutClear

- **Safety class:** M! (fail-closed; idempotent converge).
- **Purpose:** clear an orphaned host-subtree noout flag for one host, or do
  nothing if it is already clear.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | admin host |
| hostName | string | yes | – | hostname | host whose subtree noout to clear |
| pollIntervalMs | integer, nullish | no | 15000 | ≥ 1 | backoff ceiling |
| pollTimeoutMs | integer, nullish | no | 600000 | ≥ 1, floored to 300000 (§2.4) | poll budget |
| SSH family | | | | overview §3 | |

  There is no force or override argument, by design.
- **Preconditions** (all computed by the method):
  1. Read `ceph orch host ls -f json`, `ceph health detail -f json` and
     `ceph osd tree -f json`. The reads MAY run in parallel.
  2. **Host known:** the host list has an entry whose `hostname` equals
     `hostName` exactly.
  3. **In maintenance:** that entry's status equals `maintenance`
     case-insensitively (D44).
  4. **Host OSDs:** every node of type `osd` reachable from the node of type
     `host` named `hostName` in the OSD tree, sorted ascending.
     - The search recurses through any intermediate node types, such as
       chassis or rack.
     - It keeps a visited set, so cyclic or self-referential trees terminate.
  5. **Down OSDs:** the host OSDs whose status is not `up` (case-insensitive),
     sorted.
     - A host with zero OSDs counts as all up, and there is no refusal for it.
       *Why:* no data can move off a host that has none.
- **Behaviour:**
  1. Compute the preconditions.
  2. **Refusals.** Each one throws, issues no command and writes no record.
     They are checked in this order:
     - **R1, host unknown:** `cephadm[noout-clear]: host not known to the cluster host=<hostName> (likely a typo; no action taken)`.
     - **R2, host in maintenance:** the flag is doing its job. The message
       MUST direct the caller to `cephHostMaintenanceExit`, which clears the
       flag as part of a proven restore.
     - **R3, any down OSD:** the message names the down OSD ids and the host's
       OSD ids. *Why:* clearing noout while OSDs are down lets the mon mark
       them out after the down-out interval, which starts a full rebalance off
       a host that is about to return.
  3. If the predicate (§3.4) is false, the operation is a no-op. Write the
     record with `wasSet = false`, `didIssueCommand = false` and
     `nooutClearedObserved = true`, then return.
  4. Otherwise issue `ceph osd unset-group noout <hostName>`, and set
     `didIssueCommand = true`.
  5. Poll (§2) `ceph health detail -f json` with phase `noout-clear`, until
     the predicate is false for `hostName`.
  6. Write the record.
- **Idempotency:** a second run finds the flag clear and issues nothing.
- **Output / record:**
  - Spec `cephNooutClearResult`, key `cephHostNooutClear-<host>-<hostName>`.
  - Fields: `method`, `host`, `hostName`, `wasSet`, `didIssueCommand`,
    `nooutClearedObserved`, `hostInMaintenance`, `hostOsdIds[]`,
    `downOsdIds[]`, `elapsedMs`, `capturedAt`.
  - `elapsedMs` is the whole-method wall time, including the precondition
    reads. It is deliberately not named as a poll duration, so it is not
    compared against the poll budget.
- **Post-verification:** the poll in step 5.
- **Failure modes:**
  - R1, R2 or R3: throw, with no command and no record.
  - The unset command exits non-zero: throw.
  - A poll timeout, or a non-transport poll error (D47): throw.
- **What it cannot see:**
  - whether OSDs that were down before the clear stayed down;
  - whether recovery or rebalance started afterwards.

  Those are separate verification steps.
- **Security:** `hostName` is validated before interpolation.
- **Why:** an orphaned subtree noout silently disables self-healing for that
  host, but clearing it at the wrong moment causes the rebalance it was
  protecting against. So the method refuses every unsafe state rather than
  offering an override.
- **Test obligations:**
  - [ ] Happy path: flag set, all OSDs up, not in maintenance → unset is
    issued, the effect is observed, and the record is written.
  - [ ] Preconditions:
    - one OSD down;
    - several down, all named;
    - host absent;
    - `maintenance` and `Maintenance` both detected (D44);
    - a prefix hostname is not matched;
    - a zero-OSD host → all up;
    - OSDs under a chassis are found;
    - a cyclic tree terminates.
  - [ ] R1, R2 and R3 each throw with the named content. R2 names
    `cephHostMaintenanceExit`, and R3 names the ids. No command is issued and
    no record is written.
  - [ ] Flag already clear → no unset command, `wasSet: false`,
    `didIssueCommand: false`.
  - [ ] Flag reported only in `detail[]`, or as `noin,noout` → treated as set
    (D46).
  - [ ] The unset command text is `osd unset-group noout <hostName>` with
    exactly one `ceph` prefix.
  - [ ] The first re-read still shows the flag and the second shows it clear
    → success.
  - [ ] The flag never clears → poll timeout throw. This is a slow test using
    the floor budget and injected sleep.
  - [ ] The record uses the stable key and the correct spec name.

### 4.7 cephOsdActivate

- **Safety class:** M (idempotent).
- **Purpose:** run `ceph cephadm osd activate <hostName>`, which re-creates
  OSD daemons for existing OSD volumes on the host, and parse the result.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | admin host |
| hostName | string | yes | – | hostname | host whose OSDs to activate |
| SSH family | | | | overview §3 | |

- **Preconditions:** the admin host is reachable, and `hostName` is registered
  with the orchestrator.
- **Behaviour:**
  1. Run the command. A non-zero exit is an error.
  2. Parse stdout:
     - **Created:** a line `Created osd(s) <ids>` → `activated` = the listed
       OSD ids as integers, and `alreadyPresent = false`. `<ids>` is one or
       more non-negative integers separated by commas, optionally with spaces.
       - Accept: `Created osd(s) 3`, `Created osd(s) 0,1,2`,
         `Created osd(s) 4, 7`.
       - Reject: `Created osd(s) a,b`, and `Created osd(s)` with nothing
         after it.
     - **Already created:** `Created no osd(s)` together with the
       "already created?" marker → `activated = []`, `alreadyPresent = true`.
       This is success: the units were already in place.
     - Anything else, including `Created no osd(s)` **without** the
       already-created marker: throw
       `cephadm[osd-activate]: unexpected output host=<hostName> output=<text>`,
       with the output truncated to about 2000 characters.
- **Idempotency:** a re-run reports `alreadyPresent: true`.
- **Output / record:**
  - Spec `cephOsdActivateResult`, key `cephOsdActivate-<host>-<hostName>`.
  - Fields: `method`, `host`, `hostName`, `activated[]`, `alreadyPresent`,
    `capturedAt`.
- **Post-verification:** the parse of the tool's own result. Proving that the
  OSDs are up is the caller's job (`cephVerifyOsd`, 05-verify).
- **Failure modes:**
  - A non-zero exit: throw.
  - Unrecognised output: throw.
  - A transport failure: throw.
- **Security:** `hostName` is validated before interpolation.
- **Why:** "no OSDs created" is ambiguous. It is success only when the tool
  says the OSDs already exist. Otherwise it may mean nothing was found to
  activate, which must not read as success.
- **Test obligations:**
  - [ ] An id list is parsed into integers, in every accepted spacing.
  - [ ] Already created → success, `alreadyPresent: true`, `activated: []`.
  - [ ] Unexpected output → throws, with the output truncated.
  - [ ] "No OSDs" without the marker → throws.
  - [ ] The command text has exactly one `ceph` prefix.
  - [ ] The key is stable.

---

## 5. Methods: teardown

All teardown inputs are explicit. **No teardown argument carries a schema
default.** *Why:* a default is a hard-wired choice of what gets destroyed. The
optional verify knobs on `cephRmCluster` are nullish, and they fall back to
values stated in this file.

### 5.1 cephHostClusterState

- **Safety class:** RO (privileged read). The description starts with
  `READ-ONLY.`
- **Purpose:** report what Ceph state one host carries on its OS disk. It
  answers "which cluster is on this machine" even when the cluster is not
  answering, and it is how an operator learns the fsid to name.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | host to observe |
| SSH family | | | | overview §3 | |

- **Preconditions:** the host is reachable, and passwordless sudo is
  available.
- **Behaviour:**
  1. Run the host observation (§3.6).
  2. Log `info` with the fsid count, the cluster-unit count and the VG count.
  3. Write the state.

  This method does **not** run residue evaluation, so absent tools do not
  throw here. `toolsSeen` records them.
- **Idempotency:** pure read.
- **Output / record:**
  - Spec `cephHostClusterStateResult`, key `cephHostClusterState-<host>`.
  - Fields: the derived host state (§3.6), including `toolsSeen`.
- **Post-verification:** not applicable.
- **Failure modes:** a transport error, a non-zero script exit, or missing
  section markers → throw, with no record.
- **Security:** read-only, privileged. `host` is validated.
- **Why:** an operator needs a way to learn the fsid without trusting a
  cluster that may be half-built or unreachable.
- **Test obligations:**
  - [ ] Exactly one SSH call is made, and the remote command starts with
    `sudo -n --`.
  - [ ] A configured non-default port is passed.
  - [ ] One record, with the fsids and md arrays.
  - [ ] `toolsSeen` has exactly the three independent keys.
  - [ ] Empty stdout → throws, with no record.

### 5.2 cephVerifyClusterFsid

- **Safety class:** RO gate, run before any mutation. The description starts
  with `READ-ONLY.`
- **Purpose:** refuse unless every fsid on the host is the named one.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | host to check |
| fsid | string | yes | none | UUID grammar (§3.6) | the cluster the caller intends to tear down |
| SSH family | | | | overview §3 | |

- **Preconditions:** the host is reachable, and passwordless sudo is
  available.
- **Behaviour:**
  1. Run the host observation (§3.6).
  2. Apply the fsid classification (§3.6). This is the same function
     `cephRmCluster` uses.
  3. If the result is **refuse**, throw
     `cephadm[verify-cluster-fsid]: host carries an unnamed cluster`. The
     message names:
     - the host;
     - the named fsid;
     - every fsid found;
     - the unnamed ones;
     - a remedy (check the host's state, then re-run naming the correct fsid
       or target the correct host).

     It states explicitly that nothing has been changed on any host.
  4. If the classification throws "not observed", propagate that error.
  5. Otherwise (no-op, stranded or purge), write a pass record.
- **Idempotency:** pure read.
- **Output / record:**
  - Spec `cephClusterFsidResult`, key `cephVerifyClusterFsid-<host>`.
  - Fields: `host`, `fsid`, `pass` (always true), `fsidsFound`,
    `carriesNamedFsid` (case-insensitive), `capturedAt`.
  - The record is written only on pass.
- **Post-verification:** not applicable.
- **Failure modes:**
  - A foreign fsid: throw, with no record.
  - Tools not observed: throw.
  - Observation failure: throw.
- **Security:** `fsid` is validated by grammar.
- **Why:**
  - The fsid, not the host name, address or port, separates "the cluster I
    mean" from "whatever is on this machine". A reused node, a stale rebuild,
    or a production host reached through a gateway can all look right.
  - The fsid is required and never discovered. *Why:* discovering it would
    make the refusal impossible.
  - The gate and the purge share one classification, so they cannot disagree.
- **Test obligations:**
  - [ ] Foreign fsid → refuses. The message names both fsids and says nothing
    changed. Exactly one SSH call, and no record.
  - [ ] Named fsid only → pass, `carriesNamedFsid: true`.
  - [ ] No cluster → pass, `carriesNamedFsid: false`. Absence is not
    disagreement, and refusing would block re-runs.
  - [ ] Named and foreign fsids → refuse. Uppercase named fsid → accept.
  - [ ] The same fixtures give the same refuse/accept verdict as
    `cephRmCluster`.
  - [ ] systemctl or LVM tools absent, with no foreign fsid → throws "not
    observed", with no record.

### 5.3 cephDisableOrchestration

- **Safety class:** M (idempotent converge). It tolerates an unreachable
  cluster.
- **Purpose:** disable the cephadm mgr module so the orchestrator stops
  deploying daemons, and prove it.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| adminHost | string | yes | – | hostname or IPv4 | node used to reach the cluster |
| SSH family | | | | overview §3 | |

- **Preconditions:** none beyond SSH reachability. An unreachable cluster is a
  recorded outcome, not a precondition failure.
- **Behaviour:**
  1. Read `ceph mgr module ls -f json`. cephadm counts as **enabled** if it is
     listed in `enabled_modules` or `always_on_modules`. If it appears in
     `disabled_modules`, or nowhere, it is not enabled.
  2. Not enabled → outcome `alreadyDisabled`, and no command is issued.
  3. Enabled:
     - Issue `ceph mgr module disable cephadm`.
     - Poll (§2) `ceph mgr module ls -f json` with phase
       `disable-orchestration`, interval ceiling 5 s and budget 120 s, until
       cephadm is not enabled. Transport errors are retried, because the mgr
       restarts to drop the module and is briefly unreachable.
     - Outcome `disabled`.
  4. **Any** error in steps 1–3 is caught and not rethrown. This includes a
     poll timeout and a non-transport poll error.
     - The outcome is `clusterUnreachable`, with the error message as
       `unreachableReason`.
     - A `warn` is logged stating that orchestration was **not** stopped.
  5. Write the record.
- **Idempotency:** a re-run after `disabled` yields `alreadyDisabled`.
- **Output / record:**
  - Spec `cephOrchestrationDisableResult`, key
    `cephDisableOrchestration-<adminHost>`.
  - Fields:
    - `adminHost`;
    - `outcome`, one of `disabled`, `alreadyDisabled` or
      `clusterUnreachable`;
    - `enabledBefore`, present only if the first read succeeded;
    - `unreachableReason`, present only when the cluster was unreachable;
    - `capturedAt`.
- **Post-verification:** the poll in step 3.
- **Failure modes:** none thrown for cluster-side problems. Every such problem
  becomes `clusterUnreachable`. Argument validation failures still throw.
- **Security:** `adminHost` is validated.
- **Why:**
  - Three outcomes, not a boolean. *Why:* purging a half-built cluster is
    exactly when the mgr does not answer, and the caller must know that
    orchestration was never stopped instead of reading silence as success.
  - A recorded outcome is better than an allow-failure step whose failure is
    invisible.
  - Exit 0 of the disable command is acceptance only.
- **Test obligations:**
  - [ ] Enabled → the disable is issued and the effect is polled. The module
    is still listed on the first re-reads and then gone, so there are at least
    three reads. Outcome `disabled`, `enabledBefore: true`.
  - [ ] Already disabled → no disable command, `enabledBefore: false`.
  - [ ] Listed in `always_on_modules` → treated as enabled.
  - [ ] The first read fails with a mon authentication timeout → outcome
    `clusterUnreachable`, a non-empty reason, a `warn` log, and no
    `enabledBefore` field.
  - [ ] Poll timeout → `clusterUnreachable`, not a throw.

### 5.4 cephRmCluster

- **Safety class:** D, irreversible. The description starts with
  `DESTRUCTIVE.`
- **Purpose:** purge a named cluster from one host and prove that cephadm's
  state is gone. The method can be re-run after a partial failure.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | host to purge |
| fsid | string | yes | none, never discovered | UUID grammar (§3.6) | cluster to remove. Any other fsid on the host causes a refusal |
| zapOsds | boolean | yes | none | – | add `--zap-osds`, which destroys OSD device contents. Must be stated explicitly |
| verifyTimeoutMs | integer, nullish | no | absent → 120000 | ≥ 1 | post-purge effect-poll budget. The cephadm floor does not apply, because these are host-OS reads |
| verifyPollIntervalMs | integer, nullish | no | absent → 5000 | ≥ 1 | backoff ceiling |
| SSH family | | | | overview §3 | |

- **Preconditions:**
  - The chain order in §1 is followed. In particular, `cephVerifyClusterFsid`
    has passed on every host.
  - Passwordless sudo is available.
- **Behaviour:**
  1. Run the host observation (§3.6) with the normal transport timeout.
  2. Classify (§3.6, case-insensitive fsid comparison).
     - **Refuse:** throw `cephadm[rm-cluster]: host carries an unnamed cluster`
       before any mutation. The message names the host, the named fsid, the
       fsids found, the unnamed fsids and a remedy. No command runs and no
       record is written.
     - "Not observed": throw before any mutation.
  3. **Stranded** (cephadm plane clean, LVM residue present):
     - Do **not** run rm-cluster, and do **not** throw. *Why:* with no
       cluster left, rm-cluster fails on "RADOS object not found".
     - Log a `warn` that LVM items still hold the disks and that the data-disk
       wipe must free them.
     - Write the record with `purged = false`, `alreadyAbsent = false`,
       `cephadmStateAbsent = true`, `lvmResidue` and the before-state fields,
       then return. No effect poll runs on this path.
  4. **Purge:**
     - Run `sudo -n -- cephadm rm-cluster --force [--zap-osds] --fsid '<fsid>'`.
       Include `--zap-osds` only when `zapOsds` is true. The fsid is
       single-quoted. It is one simple command under sudo, with no shell
       chaining.
     - Use a 10-minute transport timeout, sized to the physical event: the
       tool stops every daemon, waits for containers, and optionally zaps.
     - A non-zero exit throws.
  5. On the **purge** and **no-op** paths, poll (§2) the host observation with
     phase `rm-cluster`, until the cephadm-plane residue is empty.
     - Transport errors are retried. A "not observed" refusal stops the loop
       at once (D47).
     - If residue survives, a timeout throw follows, with the surviving items
       named. No record is written.
     - LVM residue does **not** block this poll.
  6. Write the record.
- **Idempotency:** a re-run on a purged host takes the no-op path
  (`alreadyAbsent: true`), and the effect check still runs, as one read.
- **Output / record:**
  - Spec `cephRmClusterResult`, key `cephRmCluster-<host>`.
  - Fields:
    - `host`, `fsid`, `zapOsds`, `purged`;
    - `alreadyAbsent`, true only on the no-op path;
    - `cephadmStateAbsent`, present only on the stranded path;
    - `lvmResidue`: the LVM items still holding disks **after** the method.
      A non-empty value is not a failure of this method;
    - `command`: present only when a purge ran. It is omitted otherwise, never
      null;
    - `fsidsBefore`, `fsidsAfter`, `clusterUnitsBefore`,
      `cephVolumeGroupsBefore`, `mdArraysAfter`;
    - `capturedAt`, taken from the final observation.
- **Post-verification:** the cephadm-plane poll in step 5.
- **Failure modes:**
  - **Thrown:**
    - a foreign fsid;
    - an unobservable host or missing tools;
    - a non-zero exit from rm-cluster;
    - cephadm-plane residue that survives the poll.
  - **Recorded, not thrown,** where a later phase can remedy the state:
    - stranded LVM (`cephadmStateAbsent`, `lvmResidue`);
    - a purge that clears cephadm but leaves LVM (a success record with
      `lvmResidue`).
- **Security:**
  - `fsid` is validated by the UUID grammar, then single-quoted.
  - `host` is validated.
  - There is no shell chaining under sudo.
- **Why:**
  - The fsid is the only reliable discriminator (see §5.2).
  - The effect poll is scoped to cephadm's plane. *Why:* requiring the whole
    host to be clean, LVM included, makes a purge that removed the cluster but
    could not free the disks time out in this method. The wipe that frees the
    LVM is then gated behind this step, a circular wait that strands the
    disks.
  - Exit 0 of rm-cluster is not evidence of effect.
  - The effect check also runs on the no-op path. *Why:* it turns "did not
    need to act" into evidence, at the cost of one read.
  - Error text MUST carry the decisive values (fsids, surviving items). *Why:*
    a workflow run record keeps the step status, and operators rely on the
    message to know what failed.
- **Test obligations:**
  - [ ] The purge command text is exact: the `sudo -n --` prefix,
    `--force --zap-osds --fsid '<fsid>'`. The record has `purged: true`,
    `alreadyAbsent: false`, `fsidsBefore: [fsid]`, `fsidsAfter: []` and
    `zapOsds: true`.
  - [ ] `zapOsds: false` → no `--zap-osds`, and `--force` is present.
  - [ ] Foreign fsid → throws with the classification naming both fsids. Zero
    rm-cluster calls and zero records.
  - [ ] Clean host → no rm-cluster. `purged: false`, `alreadyAbsent: true`,
    and no `command` field.
  - [ ] Residue survives the purge → throws in phase `rm-cluster`, with no
    record.
  - [ ] Transport error during the effect poll → retried, then success.
  - [ ] Section markers missing during the effect poll → stops at once and
    throws, without waiting for the budget (D47).
  - [ ] Stranded host → no rm-cluster and no throw. `cephadmStateAbsent: true`,
    `purged: false`, `alreadyAbsent: false`, two LVM items, and a `warn`.
  - [ ] Purge leaves only LVM → success, `purged: true`, `fsidsAfter: []`,
    and two `lvmResidue` items.
  - [ ] Classification controls:
    - refuse;
    - no-op;
    - purge;
    - stranded;
    - units without a directory → purge;
    - named and foreign fsids → refuse;
    - uppercase named fsid → purge.
  - [ ] The record is accepted by its declared schema.
  - [ ] Injection: an fsid containing a quote, `;` or whitespace is rejected
    by the grammar before any SSH call.

### 5.5 cephVerifyHostTornDown

- **Safety class:** RO gate. The description starts with `READ-ONLY.`
- **Purpose:** verify that the OS-disk plane of one host carries no Ceph
  cluster state.
- **Inputs:**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 | host to check |
| fsid | string | yes | none | UUID grammar (§3.6) | reported, so that a green verdict names the cluster it is about |
| SSH family | | | | overview §3 | |

- **Preconditions:** the host is reachable, and passwordless sudo is
  available.
- **Behaviour:**
  1. Run the host observation (§3.6).
  2. Evaluate whole-host residue (both planes). If either tool set was not
     observed, throw and write nothing.
  3. Compute `pass` = no findings.
  4. Compute `namedFsidGone` = the named fsid is not among `fsids`
     (case-insensitive).
  5. Write the record.
     - A dirty host is **not** a throw. It is recorded as `pass: false` with
       its findings, and callers MUST gate on `pass`.
     - Unobserved sections **do** throw and write nothing, so a `pass: true`
       can never be recorded for an unproven host.
- **Idempotency:** pure read.
- **Output / record:**
  - Spec `cephHostTornDownResult`, key `cephVerifyHostTornDown-<host>`.
  - Fields: the full derived host state (§3.6), plus `fsid`, `pass`,
    `namedFsidGone` and `findings[]`.
- **Post-verification:** not applicable.
- **Failure modes:** observation failure or unobserved tools: throw, with no
  record. A dirty host: a record with `pass: false`.
- **Security:** `host` and `fsid` are validated.
- **What it cannot see:** the data disks. On-device OSD signatures belong to
  `cephVerifyDisksRaw` (05-verify), and both checks are required (§1, step 5).
- **Why:** the gate is about the host being clean, not about one fsid being
  gone. Another cluster's residue still fails it.
- **Test obligations:**
  - [ ] Clean host → `pass: true`, `namedFsidGone: true`, `findings: []`, and
    `mdArrays` still reported.
  - [ ] Dirty host → `pass: false`, `namedFsidGone: false`, and five findings:
    the directory, two cluster units, a VG and an LV.
  - [ ] Another cluster's residue → `pass: false` while
    `namedFsidGone: true`.
  - [ ] Absent tools → throws "not observed", with zero records.
  - [ ] Stranded host → whole-host residue is non-empty although the cephadm
    plane is empty, so `pass: false`.
  - [ ] Only package units (`ceph.target`, `ceph-crash.service`) and the md
    boot array present → `pass: true`.

---

## Unresolved

1. **D47 and command failures during transitions.** Under D8, a read that
   exits non-zero is not a transport error. One example is `ceph orch host ls`
   failing while the mgr is briefly unavailable during enter or exit. Such a
   read therefore stops the poll at once. Is this intended? The alternative is
   to classify a specific "cluster temporarily unavailable" exit as retryable.
2. **`cephDisableOrchestration` budget.** Its fixed 120 s poll budget allows
   only a few `cephadm shell` reads, and it has no floor. Decide whether the
   D37 / §2.4 floor applies here. A timeout records `clusterUnreachable`,
   which is the safe direction.
3. **Teardown gates and the verify-result contract.**
   - `cephVerifyClusterFsid` writes no record on refusal.
   - `cephVerifyHostTornDown` records failure without throwing, and has no
     `throwOnFail`.

   Neither uses the `{pass, expected, actual, detail}` shape or D40. Confirm
   that these gates stay outside the verify-group contract.
4. **`pollDurationMs` on maintenance records** is specified here as the
   duration of the verification poll only, not the whole-method time. Confirm
   this, or rename it to `elapsedMs` to match `cephHostNooutClear`.
