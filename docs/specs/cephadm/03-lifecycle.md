# `@randybias/cephadm` — 03: Cluster lifecycle

Status: draft for review · Part of the `@randybias/cephadm` behaviour
specification. `00-overview.md` is authoritative; where this file and a
decision (D1–D60) disagree, the decision wins.

Scope: bootstrap, admin-key distribution, host enrolment, mon/mgr/mds
placement, and OSD service application.

| Method | Class | Spec |
|---|---|---|
| cephBootstrap | M | here |
| cephDistributeKey | M | here |
| cephHostAdd | M | here |
| cephApplyMon | M | here |
| cephApplyMgr | M | here |
| cephApplyMds | M | here |
| cephApplyOsd | M | here |

Related methods specified elsewhere:
- cephRemoveOsds: see 04-dataplane.
- cephOsdActivate, cephCephadmCheckHost, cephVerifyClusterFsid: see
  06-maintenance-teardown.
- cephVerifyMonPlacement, cephVerifyMgrPlacement, cephVerifyOsdClaimable,
  cephVerifyKeyDistributed: see 05-verify.

---

## 1. Cross-cutting rules for this group

### 1.1 Three kinds of SSH target

- **Bootstrap host** (`host` on cephBootstrap). Commands run against the
  host-level `cephadm` binary under `sudo -n`.
  - **Why:** before a cluster exists there is nothing for `cephadm shell` to
    attach to.
- **Admin host** (`adminHost` on cephHostAdd, cephApplyMon, cephApplyMgr,
  cephApplyMds, cephApplyOsd). Any node holding the admin keyring, from which
  `ceph orch ...` runs.
  - It MUST always be a method argument, never stored on the model instance
    (§2 of the overview).
  - It is distinct from the host(s) an orchestrator command is applied *to*.
- **Disk-owning target host** (cephApplyOsd only). A separate plain SSH
  connection to the node that physically owns the disks, used only to resolve
  serials to devices. See cephApplyOsd for name, address and port rules.

Every method accepts the shared SSH argument family (overview §3): `sshUser`,
`port`, `keyPath`, `privateKey`, `strictHostKeyChecking`. The host-key policy
MUST be applied to **every** ssh invocation a method makes, not only the first.

### 1.2 Cluster-side commands run through `cephadm shell`

The execution layer is specified in 01-transport. Reminders that matter for
safety in this group:

- Every cluster-side `ceph ...` command in this group runs through the
  cephadm-shell script-file mechanism (01-transport): the script is written to a
  fresh private `mktemp -d` directory with mode 0700 (D7), bind-mounted, run as
  `sudo -n cephadm shell --mount <file>:<file> -- bash <file>`, and removed
  afterwards whether it succeeded or not.
  - Exceptions, which run as plain host commands: the bootstrap command and its
    `cephadm ls` probe, serial→device resolution, and `authorized_keys` work.
- A method MUST NOT build `cephadm shell -- bash -c "<quoted command>"`.
  - **Why:** caps strings and other quoted arguments must survive three shell
    layers that way; a script file needs one ordinary level of quoting.
- Every cephadm-shell call has an SSH budget of at least 5 minutes (D37).
  - **Why:** each call starts a container. A no-op read against a degraded but
    serving cluster can take over 30 s, and a killed call can interrupt a
    mutation midway.
- JSON reads append `-f json`. The single human line "No <things> reported"
  that some list commands (notably `ceph orch ls`) print when empty, even with
  `-f json`, MUST be read as an empty list. Any other unparseable output is a
  classified error (01-transport).
  - **Why:** an empty `ceph orch ls` on a fresh cluster otherwise breaks
    idempotency on the very first run.
- Only individually grammar-validated values (hostnames, identifiers, serials,
  IPv4 addresses, by-id paths) may be interpolated into script content.

### 1.3 Errors and records

- Every error starts with `cephadm[<phase>]:`, where the phase names the
  method (for example `cephadm[cephHostAdd]:`), followed by non-secret
  `key=value` context: admin host, target host, placement, service id, and the
  underlying message.
- Transport failures (SSH exit 255, connection failure, timeout) surface as the
  typed transport error, even where a non-zero exit is tolerated (D8).
- A method in this group MUST NOT write its result record when it fails.
- Record keys are stable and never timestamped. Freshness is carried in a
  `capturedAt` ISO-8601 field.

| Resource | Record key |
|---|---|
| cephBootstrapResult | `cephBootstrap-<host>` |
| cephDistributeKeyResult | `cephDistributeKey-<host:port,…>` (entries sorted, comma-joined) |
| cephHostAddResult | `cephHostAdd-<host>` |
| cephApplyMonResult | `cephApplyMon-<adminHost>` |
| cephApplyMgrResult | `cephApplyMgr-<adminHost>` |
| cephApplyMdsResult | `cephApplyMds-<adminHost>-<fsName>` |
| cephApplyOsdResult | `cephApplyOsd-<adminHost>-<serviceId>` |

- Every resource: `lifetime: infinite`, keep the last 10 versions. Every
  resource schema is strict and declares every field written (D41, D49).
- **Why (distinct method prefixes):** bootstrap, host-add, apply-mon and
  apply-mgr are commonly run against the same host; a shared key would let one
  record overwrite another.
- **Why (OSD key includes the service id):** records are stored flat by name,
  so two OSD applications through one admin host for different target hosts
  would otherwise overwrite each other's evidence.

### 1.4 Placement lists (mon, mgr, mds)

- `placement` MUST be a non-empty list of hostnames (hostname grammar,
  01-transport). These are the names cephadm registered, as shown by
  `ceph orch host ls`.
- Duplicates MUST be refused.
  - **Why:** Ceph's placement parser keeps repeated hosts, so `[a, a]` asks for
    two daemons in one failure domain while looking like two-way redundancy;
    it is also the typical output of a templating bug.
- No minimum count is enforced.
  - **Why:** redundancy floors are cluster policy, belonging to the caller and
    to verification steps that can see the cluster; a floor would also block a
    legitimate single-daemon recovery.

### 1.5 Placement convergence (mon, mgr, mds)

1. Read the service with `ceph orch ls --service_name <svc> -f json` and take
   the first entry's `placement`.
2. Normalise every reported `placement.hosts` entry to a bare hostname: strip
   anything from the first `=` onward, then anything from the first `:` onward.
   Ceph may report `host`, `host:network`, `host=name` or `host:network=name`.
   - Examples: `node-a:192.0.2.0/24` → `node-a`; `node-a=mon1` → `node-a`;
     `node-a:192.0.2.0/24=mon1` → `node-a`.
   - **Why:** raw values never match, so convergence would re-apply on every
     run forever, and re-applying a correct placement looks like success.
3. The service is **converged** only if all of these hold:
   - the service exists;
   - its placement has a non-empty host list;
   - its placement has **no** `count`;
   - the normalised host set equals the requested set (order-insensitive, same
     size, same members).
4. Not converged → `ceph orch apply <svc> --placement=<h1,h2,...>` (hosts in
   the requested order). Converged → no command.
5. Record `replacedCountSpec: true` and `previousCount: <N>` when the existing
   spec had a `count`; otherwise `replacedCountSpec: false`,
   `previousCount: null`.

- **Why (count specs are never converged):** a count says how many but never
  where, so cephadm re-places daemons and placement drifts, for example onto
  the host running the active MDS. A cluster converged by count reports a count
  and no hosts; treating that as converged would be a silent no-op on exactly
  the clusters needing repair. The replacement is recorded explicitly rather
  than inferred from `applied`.
- Keeping mgr and MDS daemons on disjoint hosts is the caller's
  responsibility; no method in this group enforces it. cephVerifyMgrPlacement
  reports it (D29).

---

## 2. Method: cephBootstrap

**Safety class:** M (idempotent converge). Creates a cluster. The result
carries a path reference to the admin keyring, never its contents.

**Purpose:** Bootstrap a new standalone cephadm cluster on one host, or do
nothing if one already exists there. Return the fsid, the cluster's public SSH
key, and a reference to the admin keyring location.

**Inputs**

| Name | Type | Required | Default | Constraints | Meaning |
|---|---|---|---|---|---|
| host | string | yes | – | hostname or IPv4 grammar (01-transport) | host to bootstrap; SSH target |
| sshUser, port, keyPath, privateKey, strictHostKeyChecking | shared | sshUser yes | overview §3 | overview §3 | connection; `sshUser` is also the orchestrator's SSH user |
| monIp | string | yes | – | IPv4 address (IPv6 refused, D9) | first monitor's address |
| publicNet | string | yes | – | IPv4 CIDR that contains `monIp` | Ceph public network |
| clusterNet | string | yes | – | IPv4 CIDR (D24) | Ceph cluster network |
| cephImage | string | yes | – | container image reference grammar (D24) | image to bootstrap with |
| timeoutMs | integer, nullish | no | 900000 (15 min) | positive | SSH budget for the bootstrap command only |

`cephImage` grammar (D24): `[registry/]name[:tag][@digest]`.
- Optional registry: a hostname with an optional `:port`.
- Name: one or more `/`-separated path components of lowercase letters and
  digits, separated internally by single `.`, `_`, `__` or runs of `-`.
- Optional tag: starts with a letter, digit or `_`, then letters, digits, `_`,
  `.` or `-`, at most 128 characters.
- Optional digest: an algorithm (for example `sha256`), `:`, and at least 32
  hex characters.
- No whitespace, quotes, shell metacharacters or control characters.
- Accept: `quay.io/ceph/ceph:v19.2.3`, `registry.example.com:5000/ceph/ceph:v19.2.3`,
  `quay.io/ceph/ceph@sha256:<64 hex>`.
- Reject: empty string, `ceph:v19.2.3;reboot`, `Quay.io/Ceph/Ceph:v19` (uppercase
  name component), `quay.io/ceph/ceph:` (empty tag), `ceph ceph`.

**Preconditions**
- Passwordless non-interactive sudo for `sshUser` on `host`.
- `cephadm` installed on `host` (see cephHostPrep, 02-hostprep).

**Behaviour**

1. Validate inputs before any SSH:
   - `monIp`, `publicNet` and `clusterNet` MUST parse; `monIp` MUST lie inside
     `publicNet`. A malformed value or a monIp outside publicNet is a
     classified error.
2. **Probe** for an existing cluster with `sudo -n cephadm ls`, with **no**
   `-f` flag (cephadm prints JSON natively for `ls` and rejects `-f` there).
   The probe has exactly three outcomes:
   - **found:** exit 0, a valid JSON array, and some entry has a non-empty
     `fsid`. The outcome carries that fsid.
   - **none:** exit 0, a valid JSON array, and no entry has an fsid (for
     example `[]`).
   - **unknown:** non-zero exit, unparseable output, or JSON that is not an
     array. The outcome carries the reason, exit code and stderr.
3. **unknown** → refuse: classified error with reason, exit code and stderr.
   No bootstrap command is issued.
4. **found** → read `/etc/ceph/ceph.pub` under sudo. The read MUST succeed and
   the content MUST validate as an SSH public key (01-transport). Write the
   result with `bootstrapped: false`. No bootstrap command is issued.
5. **none** → run, under `sudo -n`, a single `sh -c` compound that:
   - creates a config file with a **unique random name per run** (D23) in a
     private temporary location, containing:
     ```
     [global]
     public_network = <publicNet>
     ```
   - runs
     `cephadm --image <cephImage> bootstrap -c <conf> --mon-ip <monIp> --cluster-network <clusterNet> --ssh-user <sshUser> --skip-monitoring-stack`;
   - removes the config file;
   - exits with the bootstrap command's exit code.

   Every interpolated value is single-quoted. The SSH budget for this one
   command is `timeoutMs`. Every other call in the method uses the transport
   default. The ssh `ConnectTimeout` MUST stay capped at the transport's
   connect-timeout maximum regardless of the command budget (01-transport).
6. If the bootstrap call fails with a **transport error** (D8), re-probe
   exactly once (D22):
   - re-probe **found** → log a `warn`, read and validate `ceph.pub` as in
     step 4, and write the result with `bootstrapped: true` and
     `recoveredAfterTransportError: true`;
   - re-probe **none**, **unknown**, or the re-probe itself fails → throw the
     original bootstrap failure (classified, naming host).
7. If the bootstrap command exits non-zero **without** a transport error, the
   method MUST fail (D22). It MUST NOT re-probe to turn that into success.
8. If bootstrap exits 0, re-probe. Anything other than **found** (including
   **unknown**) is a failure: "bootstrap succeeded but no cluster is visible".
9. Read and validate `ceph.pub`; write the result with `bootstrapped: true` and
   `recoveredAfterTransportError: false`.

**Idempotency:** a re-run sees **found**, issues no bootstrap command, re-reads
the public key and rewrites the record with `bootstrapped: false`.

**Output / record:** `cephBootstrapResult`, key `cephBootstrap-<host>`.

| Field | Meaning |
|---|---|
| host | the bootstrap host |
| fsid | cluster fsid from the probe |
| cephPubKey | the cluster's validated SSH public key; never empty |
| adminKeyringRef | `{host, path}`, with path `/etc/ceph/ceph.client.admin.keyring` |
| bootstrapped | true only if this run created the cluster |
| recoveredAfterTransportError | true only when step 6 recovered; false otherwise |
| capturedAt | ISO-8601 timestamp |

**Post-verification:** after bootstrap, `cephadm ls` MUST report an fsid
(step 8).

**Failure modes**
- monIp outside publicNet, malformed IP or CIDR, invalid `cephImage` → error
  before any SSH.
- Probe unknown (non-zero, unparseable, non-array) → error; no bootstrap.
- Bootstrap non-zero exit (not a transport error) → error naming host (D22).
- Bootstrap transport error and the recovery probe finds no cluster → original
  error naming host.
- Bootstrap exit 0 but no cluster visible → error.
- `ceph.pub` unreadable or not a valid SSH public key, on either branch →
  error; an empty key is never recorded.

**Security**
- Admin keyring contents are never read, logged or returned; only the path is
  recorded.
- `host`, `monIp`, `publicNet`, `clusterNet`, `cephImage` and `sshUser` are
  grammar-validated and single-quoted.
- The compound runs under `sh -c` because `sudo -n` executes one argv.

**Why**
- `cephadm bootstrap` has no `--public-network` flag (it exits with usage), so
  public_network is set through a `-c` config file. It must be set at
  bootstrap, because otherwise cephadm derives it from the mon IP's interface,
  and on a multi-homed host the first mon can bind the wrong subnet before
  anything can correct it.
- "Could not tell" is not "nothing here": a probe that mapped failures to "no
  cluster" would license bootstrapping over a live cluster after a transient
  sudo or SSH hiccup.
- A transport failure says nothing about the remote command's fate: bootstrap
  keeps running after its ssh client is killed, and can finish successfully.
  Hence the single recovery probe, and the flag recording which road was taken.
- A bootstrap that exits non-zero by itself may have left a partial cluster;
  reporting it as success would hide that (D22). The caller inspects the host
  (cephHostClusterState, 06) before retrying.
- Connect timeout must not scale with the command budget: connecting is fast to
  any reachable host, and scaling makes an unreachable host take 15 minutes to
  fail.
- A unique config-file name per run prevents concurrent runs on one host from
  colliding (D23).
- A failed read must never become a plausible value; an unreadable `ceph.pub`
  fails on both branches.

**Test obligations**
- [ ] Probe command contains `cephadm ls` and no `-f` after it.
- [ ] Probe `[]` → bootstrap issued; fsid from the second probe; validated key;
      `bootstrapped: true`, `recoveredAfterTransportError: false`.
- [ ] Probe finds an fsid → no bootstrap command; `bootstrapped: false`.
- [ ] Probe returns entries with no fsid → bootstraps.
- [ ] Probe non-zero exit → refuses, no bootstrap. Probe unparseable → refuses.
      Probe JSON object (not array) → refuses.
- [ ] Bootstrap command contains `-c <conf>` with `[global]` and
      `public_network = <publicNet>`, and contains no `--public-network`.
- [ ] D23: two runs produce different config-file names.
- [ ] D24: `clusterNet` that is not an IPv4 CIDR is rejected; each accept and
      reject example of the image grammar behaves as listed.
- [ ] monIp outside publicNet → error before any SSH call.
- [ ] Bootstrap call carries the capped `ConnectTimeout` both at the default
      budget and with an explicit budget above the cap; the probe call carries
      the transport default.
- [ ] D22: transport error + recovery probe finds a cluster → success,
      `recoveredAfterTransportError: true`, warning logged.
- [ ] D22: transport error + recovery probe finds none → original
      bootstrap-failed error naming host.
- [ ] D22: non-zero exit without a transport error → error; no recovery probe
      is issued, even if a probe would find a cluster.
- [ ] Bootstrap exit 0 but second probe finds none → error.
- [ ] Invalid public key on the fresh branch → error; on the existing-cluster
      branch → error. Unreadable `ceph.pub` on the existing-cluster branch →
      error, no record.
- [ ] Result never contains keyring material; only the path reference.
- [ ] Schema accepts a realistic fixture; rejects an injection hostname and a
      non-IPv4 or IPv6 `monIp`.
- [ ] `strictHostKeyChecking` appears on every ssh argv the method issues.
- [ ] IPv4 containment check: true inside the block, false outside, error on a
      malformed IP or CIDR.

---

## 3. Method: cephDistributeKey

**Safety class:** M (idempotent converge). Modifies `authorized_keys`.

**Purpose:** Append the cluster's public key to `sshUser`'s
`~/.ssh/authorized_keys` on every listed host, so cephadm can manage them.

**Inputs**

| Name | Type | Required | Default | Constraints | Meaning |
|---|---|---|---|---|---|
| cephPubKey | string | yes | – | SSH public-key grammar (01-transport): one line, no option prefix such as `command=`, no newline or control character | key to install |
| hosts | array of `{host, port}` | yes | – | at least 1 entry; `host` hostname or IPv4 grammar; `port` integer 1–65535, **required per entry** | each target with its own SSH port |
| sshUser, keyPath, privateKey, strictHostKeyChecking | shared | sshUser yes | overview §3 | overview §3 | connection; the per-entry port is used for each target |

**Preconditions:** `sshUser` can already log in to each host with the given
credentials.

**Behaviour**

For each entry, in the given order, without sudo, as `sshUser`:

1. Re-validate `cephPubKey` at the point of use, even if it came from
   cephBootstrap's record.
2. Ensure `~/.ssh` exists with mode 0700 and `authorized_keys` exists with mode
   0600, then copy it to `authorized_keys.bak` preserving attributes. This
   happens on **every** run.
3. Check for the full key line with a fixed-string match. If present, skip the
   append.
4. If absent, append the key and a newline with an append redirect fed from
   stdin. A truncating write to `authorized_keys` MUST NOT be used.
5. Verify by re-reading with a fixed-string match for a **40-character needle
   taken from the tail of the key's base64 body**. A match means verified. If
   the base64 body is shorter than 40 characters, refuse to verify (error).
6. Record the per-host outcome: `alreadyPresent`, `backedUp`, `verified`, and on
   failure a non-secret reason.

A failure on one host MUST NOT stop the run: every host is processed and its
outcome collected (D28). After all hosts:
- If every host is verified, write the record.
- Otherwise throw one error stating "not present on N of M" and listing each
  failed `host:port` with its reason. No record is written.

**Idempotency:** a re-run appends nothing when the key is present; the backup is
still taken.

**Output / record:** `cephDistributeKeyResult`, key
`cephDistributeKey-<host:port,…>` (sorted, comma-joined). The schema declares
every field (D28).

| Field | Meaning |
|---|---|
| hosts[] | `{host, port, alreadyPresent, backedUp, verified}` per target |
| capturedAt | ISO-8601 timestamp |

**Post-verification:** step 5 on every host. Workflows additionally prove the
result on a fresh connection with cephVerifyKeyDistributed (05-verify, D58).

**Failure modes**
- Invalid key (schema, and again at execution) → error before any SSH.
- SSH or command failure on a host → that host is recorded as failed; the run
  continues; the method fails at the end naming it.
- Key absent after distribution on any host → error at the end; no record.
- Key body shorter than 40 characters → refusal to verify.

**Security**
- Key validation blocks `authorized_keys` option backdoors (`command=`,
  `from=` and similar prefixes) and multi-line injection.
- The key is passed single-quoted, and appended from stdin.

**Why**
- Never verify with the key-type header: the type string and leading base64
  characters are identical for every key of a type, so such a check passes
  against a stale or foreign key. A verification with a weak needle is worse
  than none.
- The port is per entry because several nodes can sit behind one gateway
  address on different ports. One shared port makes "five hosts" the same host
  five times: the key lands on one node, the step reports success, and host-add
  fails later on the others with an authentication error far from the cause.
- Fail here, not later: append-and-return lets a later cephadm step fail two
  steps on, naming a different host.
- Processing every host before failing gives the caller the full list of
  problem hosts in one run (D28).

**Test obligations**
- [ ] Key absent → backup, append, verify. Key present → no append; backup still
      taken.
- [ ] No truncating `>` write to `authorized_keys` appears in any command.
- [ ] Key absent after distribution on two targets → error mentioning "2 of 2"
      and both `host:port`; no record.
- [ ] D28: first host fails with an SSH error, second succeeds → second host is
      still processed; error names only the first; no record.
- [ ] D28: the record schema declares `port` and `verified`; writing the record
      passes strict validation.
- [ ] Needle is 40 characters, is contained in the key, and does not contain the
      key-type string or the common RSA header; a short key body is refused;
      each target is verified exactly once with the needle.
- [ ] Each target is dialled on its own port.
- [ ] Record key is the sorted `host:port` list regardless of input order.
- [ ] Schema rejects a traversal host string, a `command=`-prefixed key and a
      newline-bearing key; direct execution with an invalid key also refuses.

---

## 4. Method: cephHostAdd

**Safety class:** M (idempotent converge).

**Purpose:** Enrol a host with the orchestrator (`ceph orch host add`), after
confirming the admin host is attached to the expected cluster.

**Inputs**

| Name | Type | Required | Default | Constraints | Meaning |
|---|---|---|---|---|---|
| adminHost | string | yes | – | hostname or IPv4 grammar | where `ceph` runs |
| sshUser, port, keyPath, privateKey, strictHostKeyChecking | shared | sshUser yes | overview §3 | overview §3 | admin connection |
| fsid | string | yes | – | UUID, 8-4-4-4-12 hex | expected cluster |
| host | string | yes | – | hostname grammar | name cephadm will register |
| addr | string | yes | – | IPv4 address | address cephadm will use for the host |

**Preconditions:** the cluster's public key is in `authorized_keys` on `host`
(cephDistributeKey).

**Behaviour**
1. **Fsid gate.** Run `ceph fsid`. The trimmed output MUST equal `fsid`
   (compared lowercase), otherwise refuse with expected and actual: "refusing
   to mutate a possibly-wrong cluster".
2. Read `ceph orch host ls -f json`. Look for an entry whose `hostname` equals
   `host`.
   - Present with `addr` equal to `addr` → no command; `added: false`.
   - Present with a different `addr` → refuse, reporting both addresses (D27).
   - Absent → `ceph orch host add <host> <addr>`.
3. After adding, read `ceph orch host ls -f json` again. It MUST contain an
   entry with `hostname` = `host` and `addr` = `addr`; otherwise error (D27).

**Idempotency:** a host already registered at the same address is a no-op.

**Output / record:** `cephHostAddResult`, key `cephHostAdd-<host>`.

| Field | Meaning |
|---|---|
| host | registered name |
| addr | registered address |
| added | true only if this run issued `ceph orch host add` |
| capturedAt | ISO-8601 timestamp |

**Post-verification:** the host-list read-back in step 3.

**Failure modes**
- Fsid mismatch → error, no mutation.
- Hostname registered at a different address → error with both addresses, no
  mutation (D27).
- Read-back does not show the host at `addr` → error.
- Any command failure → classified error naming adminHost and host.

**Security:** `adminHost`, `host`, `addr` and `fsid` are grammar-validated
before interpolation.

**Why**
- The fsid gate refuses to mutate the wrong cluster when an admin host carries
  more than one cluster's configuration.
- A hostname at a different address is a conflict, not a success: silently
  accepting it hides a renumbered or mistaken host (D27).
- Orchestrator acceptance is not enrolment; the read-back proves the effect.

**Test obligations**
- [ ] Absent host → fsid checked first, then add issued, then host list read
      back; `added: true`.
- [ ] Present at the same address → no add; `added: false`.
- [ ] Fsid mismatch → classified error carrying expected and actual; no add.
- [ ] D27: present at a different address → error naming both addresses; no add.
- [ ] D27: add succeeds but read-back lacks the host → error; no record.
- [ ] Schema rejects an injection `adminHost` or `host`, and a non-IPv4 `addr`.

---

## 5. Method: cephApplyMon

**Safety class:** M (idempotent converge). Can remove monitors when the
placement shrinks; guarded by a quorum-safety pre-check (D26).

**Purpose:** Converge the mon service placement to an explicit host list.

**Inputs**

| Name | Type | Required | Default | Constraints | Meaning |
|---|---|---|---|---|---|
| adminHost | string | yes | – | hostname or IPv4 grammar | where `ceph` runs |
| sshUser, port, keyPath, privateKey, strictHostKeyChecking | shared | sshUser yes | overview §3 | overview §3 | admin connection |
| placement | array of string | yes | – | §1.4 | hosts that must run mons |
| allowQuorumRisk | boolean, nullish | no | false | – | proceed even if the quorum check fails or cannot run |

**Preconditions:** every placement host is enrolled (cephHostAdd). Callers
SHOULD run cephVerifyMonPlacement (05-verify) first; it also checks that hosts
are known and deployable, which this method does not.

**Behaviour**
1. Read the mon service and evaluate convergence as in §1.5. Converged → no
   command, no quorum check.
2. Not converged → **quorum-safety check (D26)**, using the same predicate as
   cephVerifyMonPlacement (05-verify):
   - read the monmap (`ceph mon dump -f json`, `mons[]`) and the quorum
     (`ceph quorum_status -f json`, `quorum_names`);
   - majority is computed over **monmap entries and their hosts**, not over
     orchestrator daemon listings (D42);
   - the check passes only if the in-quorum mons whose hosts remain in
     `placement` form a strict majority of the current in-quorum mons.
     Example: 3 in quorum, placement keeps 2 → pass; keeps 1 → fail.
3. If the check fails, or cannot run (for example the quorum read fails):
   - `allowQuorumRisk` false → refuse, reporting kept and current mons. No
     command is issued.
   - `allowQuorumRisk` true → log a `warn` with the same detail and continue.
4. Issue `ceph orch apply mon --placement=<h1,h2,...>`.

**Idempotency:** converged as in §1.5; a count-based spec is replaced (D25).

**Output / record:** `cephApplyMonResult`, key `cephApplyMon-<adminHost>`.

| Field | Meaning |
|---|---|
| placement | requested hosts |
| applied | true only if `ceph orch apply` was issued |
| replacedCountSpec | true if the existing spec had a `count` (D25) |
| previousCount | that count, or null (D25) |
| quorumCheck | `{evaluated, pass, overridden, kept, current}`; `evaluated: false` when converged; `pass` null when the check could not run |
| capturedAt | ISO-8601 timestamp |

**Post-verification:** none in this method. Workflows follow it with
cephVerifyMonQuorum (05-verify).

**Failure modes**
- Quorum check fails or cannot run without `allowQuorumRisk` → error, no
  command.
- Any command failure → classified error naming adminHost and placement.

**Why**
- Shrinking or replacing mon placement can drop quorum and stop the cluster;
  the refusal must sit in the mutating method itself, not only in a separate
  step a caller might skip (D26).
- The override exists for recovery, where quorum is already lost and the check
  cannot pass.
- Mon specs by count drift for the same reason as mgr (§1.5, D25).

**Test obligations**
- [ ] Differing placement, quorum safe → apply issued; `applied: true`.
- [ ] Matching placement → no apply and no quorum reads.
- [ ] D25: existing spec with `count: 3` and no hosts → apply issued;
      `replacedCountSpec: true`, `previousCount: 3`.
- [ ] Converges when hosts are reported as `host:network` or `host=name`.
- [ ] D26: 3 in quorum, placement keeps 1 → refused, no apply.
- [ ] D26: same with `allowQuorumRisk: true` → apply issued, warning logged,
      `quorumCheck.overridden: true`.
- [ ] D26: quorum read fails → refused without the override.
- [ ] D42: majority uses monmap entries, not orchestrator daemon listings.
- [ ] Duplicate host in placement → rejected.
- [ ] Failure → classified error naming adminHost.
- [ ] Schema rejects an injection `adminHost` or placement entry.

---

## 6. Method: cephApplyMgr

**Safety class:** M (idempotent converge).

**Purpose:** Converge mgr placement to an explicit host list, never a count.

**Inputs**

| Name | Type | Required | Default | Constraints | Meaning |
|---|---|---|---|---|---|
| adminHost | string | yes | – | hostname or IPv4 grammar | where `ceph` runs |
| sshUser, port, keyPath, privateKey, strictHostKeyChecking | shared | sshUser yes | overview §3 | overview §3 | admin connection |
| placement | array of string | yes | – | §1.4 | hosts that must run mgrs |

**Preconditions:** every placement host is enrolled. Callers SHOULD run
cephVerifyMgrPlacement (05-verify) first.

**Behaviour:** read `ceph orch ls --service_name mgr -f json`; evaluate §1.5;
if not converged, `ceph orch apply mgr --placement=<h1,h2,...>`.

**Idempotency:** §1.5.

**Output / record:** `cephApplyMgrResult`, key `cephApplyMgr-<adminHost>`:
`placement`, `applied`, `replacedCountSpec`, `previousCount`, `capturedAt`.

**Post-verification:** none here; workflows follow with cephVerifyMgr
(05-verify).

**Failure modes:** any command failure → classified error naming adminHost and
placement.

**Why:** see §1.5. Mgr/MDS separation is the caller's concern (D29).

**Test obligations**
- [ ] Applies an explicit host list; never `count:N`.
- [ ] Replaces a count spec: `applied: true`, `replacedCountSpec: true`,
      `previousCount: N`.
- [ ] Same host set → no apply.
- [ ] Converges when hosts are reported as `host:network` or `host=name`.
- [ ] Duplicate host → rejected.
- [ ] Failure → classified error naming adminHost.
- [ ] Injection `adminHost` → rejected.

---

## 7. Method: cephApplyMds

**Safety class:** M (idempotent converge).

**Purpose:** Converge one CephFS filesystem's MDS placement to an explicit host
list.

**Inputs**

| Name | Type | Required | Default | Constraints | Meaning |
|---|---|---|---|---|---|
| adminHost | string | yes | – | hostname or IPv4 grammar | where `ceph` runs |
| sshUser, port, keyPath, privateKey, strictHostKeyChecking | shared | sshUser yes | overview §3 | overview §3 | admin connection |
| fsName | string | yes | – | Ceph identifier grammar (01-transport) | filesystem name |
| placement | array of string | yes | – | §1.4 | hosts that must run MDS daemons |

**Behaviour:** read `ceph orch ls --service_name mds.<fsName> -f json`;
evaluate §1.5; if not converged, `ceph orch apply mds <fsName> --placement=<h1,h2,...>`.

**Scope:** sets where MDS daemons run only. It does not change `max_mds` or
`standby_count_wanted`.

**Idempotency:** §1.5.

**Output / record:** `cephApplyMdsResult`, key
`cephApplyMds-<adminHost>-<fsName>`: `fsName`, `placement`, `applied`,
`replacedCountSpec`, `previousCount`, `capturedAt`.

**Failure modes:** any command failure → classified error naming adminHost,
fsName and placement.

**Security:** `fsName` is interpolated into commands, so a free string would be
an injection path; it is restricted to the Ceph identifier grammar.

**Why:** explicit hosts for the same drift reason as mgr (§1.5). Keeping MDS and
mgr on disjoint hosts limits a single host loss to one of them; that is the
caller's responsibility (D29).

**Test obligations**
- [ ] Applies an explicit placement for the named filesystem.
- [ ] Idempotent on a matching set.
- [ ] Replaces a count spec and records it.
- [ ] Injection `fsName` rejected; every interpolated field (`adminHost`,
      `fsName`, placement entries) rejects shell metacharacters.
- [ ] Duplicate host → rejected.
- [ ] D29: neither cephApplyMgr nor cephApplyMds refuses overlapping mgr and MDS
      placements.

---

## 8. Method: cephApplyOsd

**Safety class:** M (idempotent converge). Consumes disks. Selector mode may
force-remove leftover OSD services for the same host.

**Purpose:** Apply an OSD service in one of two modes: fleet-wide
`--all-available-devices`, or an explicit per-host selector naming disks by
serial.

The method description MUST state that all-available mode is presence-only:
once the service exists, a changed exclude list or new disks never trigger a
re-apply (D30).

**Inputs**

| Name | Type | Required | Default | Constraints | Meaning |
|---|---|---|---|---|---|
| adminHost | string | yes | – | hostname or IPv4 grammar | where `ceph orch` runs |
| sshUser, port, keyPath, privateKey, strictHostKeyChecking | shared | sshUser yes | overview §3 | overview §3 | admin connection |
| allAvailableDevices | boolean, nullish | per mode | false | see mode rules | fleet-wide claim of empty devices |
| targetHost | string, nullish | selector mode | – | hostname grammar; `""` means absent | name cephadm registered for the disk owner, as in `ceph orch host ls` |
| targetAddr | string, nullish | no | `targetHost` | hostname or IPv4 grammar; `""` means absent | how the control host reaches `targetHost` over SSH |
| targetPort | integer, nullish | no | `port` | 1–65535 | SSH port for `targetAddr` |
| dataDevices | array of `{serial, sizeBytes?, devHint?}`, nullish | selector mode | – | serial grammar (01-transport); `[]` means absent | disks to make OSDs |
| excludeDevices | array of `{serial, reason?}`, nullish | all-available mode | – | serial grammar; non-empty in all-available mode | disks that must never be claimed |

**Mode rules.** Enforced by the schema **and** re-checked when the method runs
(D20):
- Exactly one mode: `allAvailableDevices: true` XOR non-empty `dataDevices`.
- Selector mode requires a non-empty `targetHost`.
- All-available mode MUST NOT be combined with a non-empty `targetHost`.
- All-available mode requires a non-empty `excludeDevices`.
- An empty string and an empty list count as absent.
  - **Why:** a workflow cannot omit a key conditionally and evaluates every
    expression eagerly.

**Service-spec model**
- All-available mode: service `osd.all-available-devices`.
- Selector mode: exactly **one** managed service per host, id
  `by-serial-<targetHost>`, independent of the device set and its order. The
  requested set is converged into that one spec. The id is re-validated against
  the Ceph identifier grammar (01-transport) before use; a `targetHost` that
  yields an invalid id is refused.

**Preconditions:** `targetHost` (or every enrolled host, in all-available mode)
is enrolled; disks intended for OSDs are raw (wipeDiskToRaw, 02-hostprep;
cephVerifyDisksRaw, 05-verify).

### Behaviour: all-available mode
1. Re-check the mode rules (D20).
2. Read `ceph orch ls --service_name osd.all-available-devices -f json`.
3. **Exclusion check (D19)**, using the same predicate as
   cephVerifyOsdClaimable (05-verify):
   - list enrolled hosts with `ceph orch host ls -f json`;
   - on every enrolled host, resolve each excluded serial with the
     serial→device resolver (01-transport, D3–D5). Zero matches on a host means
     the disk is not on that host. A resolver failure other than zero matches
     (ambiguous, transport error, implausible path) MUST refuse;
   - every excluded serial MUST resolve on at least one enrolled host; a serial
     found nowhere MUST refuse;
   - read `ceph orch device ls -f json`. If, for the host where an excluded
     serial resolved, any device entry with `available: true` refers to the
     same block device (its `path` equals the by-id link or the device that
     link resolves to), refuse, naming host, serial and path.
4. If the service exists → no apply (presence-only, D30). The exclusion check in
   step 3 still runs and still refuses on a violation.
5. Otherwise `ceph orch apply osd --all-available-devices`.

### Behaviour: selector mode
1. Re-check the mode rules (D20).
2. **Resolve every serial first (D21).** On the disk-owning host (SSH to
   `targetAddr`, or `targetHost` if absent, on `targetPort`, or `port` if
   absent), resolve each `dataDevices[].serial` with the resolver
   (01-transport). The resolver:
   - matches only by-id link names that **end with** `_<serial>` or
     `-<serial>`, ignoring partition links (D4);
   - proves every matching link resolves to the same single block device;
   - returns the **by-id link path**, never a kernel device name (D5).
   Zero matches, several distinct devices or an implausible path → classified
   error. Any resolution failure MUST leave the cluster untouched: no service
   removed, no spec applied (D21).
3. List OSD services: `ceph orch ls --service_type osd -f json`. A service is a
   **leftover** for this host when its name is `osd.by-serial-<targetHost>-<suffix>`
   and its normalised placement hosts are exactly `[targetHost]` (see
   Unresolved, item 4).
4. Read the live spec: `ceph orch ls --service_name osd.by-serial-<targetHost> --export`
   (non-zero exit tolerated, meaning no spec). Extract `spec.data_devices.paths`.
   **Converged** iff the export succeeded and the sorted path list equals the
   sorted list of resolved by-id paths. A spec holding kernel names counts as
   drift.
5. Remove each leftover with `ceph orch rm <name> --force` and record it.
   (`--force` leaves daemons running; management re-attaches when the converged
   spec covers their devices.)
6. Not converged → in one cephadm-shell script, write a spec file to a
   randomised path (removed by an exit trap; heredoc quoted so the body is not
   shell-expanded) and run `ceph orch apply -i <file>`. The spec shape:
   ```
   service_type: osd
   service_id: by-serial-<targetHost>
   placement:
     hosts:
       - <targetHost>
   spec:
     data_devices:
       paths:
         - /dev/disk/by-id/<link>
   ```
   - `data_devices` MUST nest under `spec:` (the shape `--export` round-trips),
     never beside `placement`.
   - Placement MUST be the single target host, never a host pattern or `*`.
   - **[twin]** Confirm that cephadm on Squid accepts by-id paths in a
     drive-group spec (D5).
7. If step 5 or 6 fails after a leftover was removed, the error MUST list the
   removed services.

**Idempotency**
- All-available: presence of the service (D30).
- Selector: exact by-id path-set equality against the exported live spec.
  Resolution always runs (read-only), because convergence needs it.

**Output / record:** `cephApplyOsdResult`, key
`cephApplyOsd-<adminHost>-<serviceId>`.

| Field | Meaning |
|---|---|
| serviceId | `all-available-devices` or `by-serial-<targetHost>` |
| allAvailableDevices | mode flag |
| targetHost | selector target, or null |
| dataDevices | as requested |
| resolvedPaths | by-id paths applied or matched (selector), or `[]` |
| excludeDevices | as requested (all-available), or `[]` |
| applied | true only if an apply was issued |
| staleServicesRemoved | leftover service names removed; `[]` when none |
| capturedAt | ISO-8601 timestamp |

**Post-verification:** none; the method does not wait for OSDs to appear.
Workflows follow with cephVerifyOsd (05-verify).

**Failure modes**
- Mode-rule violation (schema or runtime, D20) → error, no SSH to the cluster.
- Excluded device available, excluded serial found nowhere, or exclusion
  resolution inconclusive → error, no apply (D19).
- Serial resolves to zero devices, several devices or an implausible path →
  error; cluster untouched (D21).
- Any `ceph orch` failure → classified error naming adminHost and service id
  (and removed leftovers, if any).

**Security**
- Serials are validated by the schema and again by the resolver (D3); they
  never reach a remote glob unquoted.
- Resolved paths are re-validated against the device-path grammar (D6) before
  entering the spec.
- The spec file path is randomised, and the heredoc is quoted.

**Why**
- "Available" in cephadm means *empty*, not *safe to claim*: all-available mode
  enrols an unpartitioned boot-mirror disk as an OSD on every node. cephadm
  offers no exclusion surface, so the exclude list is mandatory and enforced
  before applying (D19).
- All-available with a target host silently widens one-host intent to the whole
  fleet; the scope difference is invisible in the arguments, so the combination
  is refused.
- One service per host: an id derived from the device set creates a new spec
  whenever the set changes, and the old frozen spec resurrects a just-zapped OSD
  within about a minute. Leftover specs must be removed when intent changes. An
  id built by joining serials is unbounded in length.
- Convergence, not presence: a presence-only check never notices a changed
  device set.
- Select by serial and record by-id links, never kernel names, because kernel
  names reorder across reboots (D5). `devHint` is informational only.
- Partition links that linger in udev after a GPT wipe make a serial look
  ambiguous; ignoring partition links and proving a single device fixes that,
  and NVMe namespace alias links dedupe harmlessly.
- Resolving before removing anything means a typo or a missing disk can never
  leave the cluster half-changed (D21).
- The registered name is often a bare hostname the control host cannot resolve,
  so `targetAddr` carries reachability. Where several nodes share one address on
  distinct ports, admin and target can be the same string differing only by
  port; without `targetPort`, serials resolve on the admin node and yield
  valid-looking paths from the wrong machine.
- Decommissioning a disk: drop it from `dataDevices` here, then cephRemoveOsds
  (04-dataplane), then wipeDiskToRaw (02-hostprep).

**Test obligations**
- [ ] Schema: exactly one mode; empty `targetHost` and `dataDevices` with
      all-available parse; non-empty `targetHost` with all-available rejected;
      selector with a real `targetHost` and one device parses; selector with
      `[]` rejected; all-available without excludes rejected; injection
      `adminHost`, `targetHost` and serial rejected.
- [ ] D20: direct execution (bypassing the schema) refuses all-available without
      excludes, both modes at once, and selector without `targetHost`, each with
      an explicit mode-rule error and **no** SSH call.
- [ ] All-available, no service, exclusion check clean → apply issued.
- [ ] D30: all-available, service exists → no apply.
- [ ] D19: excluded serial resolves on one host and `ceph orch device ls` lists
      that device `available: true` → refused, no apply.
- [ ] D19: excluded device present but `available: false` → apply proceeds.
- [ ] D19: excluded serial resolves on no enrolled host → refused.
- [ ] D19: resolver ambiguous or transport error on any enrolled host → refused.
- [ ] Failure → classified error naming adminHost.
- [ ] Service id is `by-serial-<host>` and independent of device order.
- [ ] Selector, no existing spec → resolution runs on the target host (not the
      admin host); spec has `service_type: osd`, the service id,
      `spec` → `data_devices` → `paths` nesting, the by-id path, placement
      listing only `targetHost`, no host pattern; `applied: true`.
- [ ] D5: the applied spec contains `/dev/disk/by-id/...` paths and no kernel
      device name; an exported spec with kernel names is treated as drift.
- [ ] Spec file path is randomised and removed by an exit trap.
- [ ] Exported paths equal resolved paths → no apply, one resolution call,
      `applied: false`, `staleServicesRemoved: []`.
- [ ] Serial → zero devices → error; → two distinct devices → error.
- [ ] D21: leftover service present and one serial fails to resolve → error and
      **no** `ceph orch rm` issued.
- [ ] Leftover `osd.by-serial-<host>-<suffix>` with placement `[host]` →
      force-removed before apply, recorded in `staleServicesRemoved`.
- [ ] A service for another host whose name shares the prefix (for example
      `osd.by-serial-node1-b` placed on `node1-b` while targeting `node1`) is
      **not** removed.
- [ ] With `targetPort` → resolution dials `targetPort`; without → dials `port`.
- [ ] With `targetAddr` → resolution dials `targetAddr`; spec placement still
      names `targetHost`.

---

## Unresolved

1. **D19 reachability of enrolled hosts.** The exclusion check must resolve
   serials on every enrolled host. This spec reaches each host at the `addr`
   that `ceph orch host ls` reports, with the method's shared SSH arguments.
   That fails where nodes sit behind one gateway address on different ports.
   Decide whether to add a per-host endpoint argument, or to match serials
   against the orchestrator's device inventory instead of SSH resolution.
2. **D19 serial found nowhere.** This spec refuses when an excluded serial
   resolves on no enrolled host (a typo protects nothing). Confirm, or allow it
   with a warning for disks already removed.
3. **D19 with the service already present.** This spec still runs the
   exclusion check and fails on a violation, although no apply would be
   issued. Confirm.
4. **Leftover-service guard.** This spec treats `osd.by-serial-<targetHost>-<suffix>`
   as a leftover only if its placement is exactly `[targetHost]`, so a host
   named `<targetHost>-<suffix>` is never swept. Confirm this rule.
5. **cephHostAdd address reuse.** No check refuses an `addr` already registered
   under a different hostname. Decide whether to add one.
