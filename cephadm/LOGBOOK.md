# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

---

## HANDOFF: group 08 workflow catalog (remaining)

**What remains.** The full catalog in `docs/specs/cephadm/08-workflows.md` §2
(`cephadm-prep-host` through `cephadm-verify-osds`), plus the §1.8 catalog
tests. This is the LAST group; all methods it needs exist except the four
S3-plane RGW methods (the S3 handoff above), so build every workflow whose
methods exist and list the S3-dependent ones as pending in the manifest.

**Where.** `cephadm/extensions/workflows/<name>/workflow.yaml`, one directory
per workflow, and each path added to `cephadm/manifest.yaml` `workflows:`. D60:
a test must fail when the manifest list and `extensions/workflows/` disagree.

**Normative shape (08 §1), non-negotiable:**

- Name `cephadm-<verb>-<object>`, single hyphens; description one line 40-90
  chars, verb first, no markdown/template.
- Every step addresses instance `cephadm`, or `cephadm-<purpose>-<item>` for a
  fan-out (D57). An assert reads the record from the SAME instance that wrote it
  (D59).
- SSH block inputs: `port` required with no default (not even 22); `sshUser`
  required; `keyPath` optional; `strictHostKeyChecking` enum exactly `yes`/`no`;
  pass optionals as `has(x) ? x : null` (D57).
- Every M/M!/D workflow: pre-gate (verify with `throwOnFail: false`) where the
  entry names one, `manual_approval` 3600s, the mutation, a SEPARATE prove job
  (independent read-back with `throwOnFail: false` + null-safe assert of
  expected vs observed), and a report-failure job that triggers on failed OR
  skipped. No approval prompt may contain `data.latest`.

**Reuse.** The method argument schemas in `extensions/models/cephadm.ts` are the
source of truth for input names; the record keys are in the owning group spec
(e.g. `cephHostMaintenanceEnter-<host>-<hostName>`). `cephadm_test.ts` shows the
model-method shape. Validate with
`SWAMP_API_KEY=$(secrets get
swamp/randybias/cli-token) swamp workflow validate <name>`
after adding each.

## HANDOFF: RGW S3 plane (clean room)

**What remains.** The four S3-plane methods only:

| Method                          | Spec                                     |
| ------------------------------- | ---------------------------------------- |
| `cephRgwBucketInspect`          | `docs/specs/cephadm/07-rgw.md` section 4 |
| `cephRgwBucketEnsure`           | `07-rgw.md` section 5                    |
| `cephRgwBucketPolicyEnsure`     | `07-rgw.md` section 6                    |
| `cephRgwBucketVersioningEnsure` | `07-rgw.md` section 7                    |

The cross-cutting rules are all of `07-rgw.md` section 1: §1.1 two access
planes, §1.2 secret-redaction contract, §1.4 effect-not-acceptance, §1.5
validation inside execute, §1.6 common S3 arguments, §1.7 S3 transport outcome
classes, §1.8 bucket presence classification, §1.9 Public Access Block, §1.10
error phases, §1.11 resource records, §1.12 probe objects. Where a group rule or
an overview decision disagrees, the overview decision wins. Do not read the old
ceph repo or any summary of it.

**Module and file layout.** Add one module
`cephadm/extensions/models/_lib/s3.ts` plus a sibling `s3_test.ts`, and wire the
four methods and their resource specs into `extensions/models/cephadm.ts` (which
already declares every other resource and method). Put the SigV4 signer, the XML
reader, the endpoint / bucket / credential grammars, the presence classifier and
the PAB helpers in `s3.ts`. Keep the model file thin: it opens a session-free
call, calls the module, writes one record with `capturedAt`, and returns a data
handle. The four S3 methods do NOT open an SSH session and are NOT in the
`ssh-installed` pre-flight check's `appliesTo` list; add a `S3_METHODS` set to
the model factory and compute
`sshMethods = Object.keys(methods).filter(m => !S3_METHODS.has(m))`.

**Dependency seam.** `07-rgw.md` and `00-overview.md` require a single
injectable HTTP fetch for the S3 methods only. Re-add it to the model's
`CephadmDeps` as `fetch: FetchFn` (see how the transport seams `spawn`, `now`,
`sleep`, `random` are declared and overridden) and pass it into `s3.ts`. Every
request opens a fresh connection: no keep-alive reuse. Pin the HTTP and XML
dependencies with exact `npm:`/`jsr:` versions in each file's import and in
`cephadm/deno.json`/`deno.lock`; no bare specifiers. Use a real, pinned XML
parser that handles default and prefixed namespaces and entity decoding — do not
hand-roll one. The four methods and their tests must inject a fake fetch so no
socket is opened.

**Reuse from this repo (all in `_lib/`):**

- `errors.ts` — `fail(phase, message, detail)` produces `cephadm[<phase>]:`
  messages with JSON/raw detail rendering; `TransportError` is the typed
  transport error. Use the phase tags from `07-rgw.md` §1.10.
- `validate.ts` — `quote()` for POSIX single-quoting and the grammar helpers;
  `truncate()` for error excerpts. Add the S3 endpoint/bucket/credential
  grammars here or in `s3.ts`, but validate every caller value and re-validate
  inside execute (§1.5), with zero transport calls on failure.
- `rgw.ts` — `redactSecrets(text, secrets?)` is the redactor required by §1.2;
  `parseUserView`, `classifyUserInfo` and `budgetInventory` show the established
  secret-free parsing style. `s3.ts` results must never contain a field named
  `secret` or `secretKey` (§1.2, D49), and headers, URLs and signatures are
  never recorded or logged.
- `hostprep.ts` / `verify.ts` — the wait/`settle` helpers and the
  `persistVerdict` pattern if a polled re-read is needed; S3 writes are verified
  by re-reading, not by status codes (§1.4, §1.9).

**Conventions established here.**

- Strict `z.strictObject` schemas; every record schema declares every field it
  writes; secret fields carry `.meta({ sensitive: true })`.
- A failing method writes no record; a success record is never written for a
  pub-lic/leaking/lifted bucket.
- Stable, non-timestamped instance keys exactly as `07-rgw.md` §1.11 lists them;
  `capturedAt` carries freshness.
- Every mutating method is `kind: "action" as const` (the S3 methods are all
  mutating, so all four need it).
- The redactor runs before any truncation and covers JSON fields, flags and
  literal secret values.

**Test helpers to reuse.** The `_test.ts` files build a scripted `SshSession`
(or, for S3, a scripted `fetch`) and assert the exact command/request text. For
S3, assert: SigV4 `Authorization` shape, `x-amz-content-sha256`, path-style
`<origin>/<bucket>`, a fresh fetch per request, the presence classifier table
(§1.8), the three transport outcome classes (§1.7), PAB read/write, the probe
prefix `.cephadm-pab-probe/` (§1.12), and that no record, log or error contains
a secret. Fixtures are synthetic only (RFC 5737 addresses, `.test` names).

---

- 2026-10-17: initial scaffold and the transport + host-preparation milestone
  (D1-D9, D13-D18, D37, D55-D57, D66-D68). One model type, empty
  `globalArguments`, factory with overridable dependencies (spawner, clock,
  sleep, randomness, fetch). Methods: `cephHostPrep`, `cephVerifyPackageSource`,
  `wipeDiskToRaw`.
- Layout mirrors cherry-servers: `extensions/models/cephadm.ts` plus `_lib/`
  helpers (`errors`, `validate`, `backoff`, `ssh`, `resolve`, `hostprep`,
  `wipe`, `schema`), each with a sibling `_test.ts`.
- The `ssh-installed` pre-flight check is labelled `live`, applies to exactly
  the SSH-using methods, and is computed from the method registry so a new
  method cannot be added without being classified.
- The test task allows `--allow-run=bash` for one real round-trip test of POSIX
  single-quoting; everything else is dependency-injected and touches no host.
- Deferred to later milestones: `_lib/shell.ts` (cephadm-shell execution and
  script delivery), the remaining method groups (lifecycle, data plane, verify,
  maintenance/teardown, RGW) and the workflow catalog.
- Clean-room: behaviour comes only from the approved spec under
  `docs/specs/cephadm/`; the SHA256SUMS of every spec file verified before
  building.
- 2026-10-17: milestone 1 offline-green. `scripts/gates.sh --offline cephadm`
  passes gates 0-6 (consistency, deno, swamp fmt, quality, leak scan, gitleaks,
  fixture guard). 103 unit tests. Gates 7-8 skipped offline; the lead runs
  conformance, adversarial review and the live end-to-end matrix.
- Test coverage in this milestone is unit/contract and pure-mapping; the live
  obligations (real cephadm binary, apt hosts, real disks, sshd throttling)
  remain for the twin and are recorded in the spec's test obligations. No spec
  file's SHA256 changed.
- 2026-10-17: milestone-1 review ledger (codex astra + terra). All High and
  Medium findings fixed before building further:
  - HIGH-1 boot-RAID destruction: added an explicit protected-device set built
    before any mutation from the mounted and configured root/boot filesystems
    and the member devices of any array that backs them (active or inactive),
    refusing a selected disk behind root/boot with `wipe.boot-protected`.
  - HIGH-2 fstab credentials: the durable wipe record now stores only a SHA-256
    of /etc/fstab and its line count, never its contents.
  - HIGH-3 proxy credentials: apt proxy lines are sanitized (userinfo and
    password/token values removed) before they reach the record.
  - HIGH-4 URL handling: V8 is now a character allowlist, userinfo-bearing URLs
    are refused, and URLs are redacted in errors.
  - HIGH-5 mdadm.conf rewrite: written to a same-directory temp file, read back
    byte-for-byte, synced, atomically renamed, with the stable backup restored
    on a later failure.
  - HIGH-6 remote-derived names: LVM VG names and md array paths get runtime
    grammars and `--` option terminators before appearing in destructive
    commands.
  - MEDIUM-7: device and backup paths are quoted everywhere.
  - MEDIUM-8: discovered apt/cephadm endpoints are allowlist-validated before
    script assembly.
  - MEDIUM-9: arrays and strings are bounded (`packages`, `dataDevices`,
    `excludeDevices`, `placement`, distribute hosts, `privateKey`, `keyPath`,
    budgets, timeout).
  - MEDIUM-10: an already-raw disk skips backup and all teardown writes; the
    mdadm.conf backup has one stable idempotent path.
  - MEDIUM-11: the model type has a description; `multiplex` is honored by
    verify/wipe/host-add/apply (hostprep forces it on as the spec requires).
  - LOW: quay.io removed from test fixtures; unused fetch/S3/resource-reader
    scaffolding removed; retry-delay calculation consolidated.
- 2026-10-17: cluster-lifecycle milestone added: cephBootstrap,
  cephDistributeKey, cephHostAdd, cephApplyMon, cephApplyMgr, cephApplyMds, with
  the cephadm-shell execution layer (`_lib/shell.ts`). cephApplyOsd and the
  data-plane, verify, maintenance and RGW groups remain.
- 2026-10-17: group 03 completed with cephApplyOsd (all-available and by-serial
  selector modes, device-inventory exclusion check, leftover-service sweep,
  by-id spec apply) and the generalised cephadm-shell script runner.
- 2026-10-17: group 04 completed: cephCreatePool, cephCreateFs,
  cephCreateCsiUser, cephGetConnBundle, cephFetchCsiKey (sensitive),
  cephDeleteFs and cephRemoveOsds. Key material from auth commands is parsed and
  discarded; the shell runner gained a redacted-stdout mode so an error from a
  key-bearing command never quotes stdout. No D-number references in packaged
  source.
- 2026-10-17: verify group started: shared `cephVerifyResult` contract
  (persist-then-throw, settle polling, key forms, unconditional faults) and the
  checks cephVerifyMonQuorum, cephVerifyMgr, cephVerifyOsd and
  cephVerifyCsiUsers. The package-source record now shares the same resource.
  Remaining verify checks, maintenance/teardown, RGW and the workflow catalog
  are next.
- 2026-10-17: checkpoint-review fixes (codex astra+terra through group 04).
  CRITICAL: the boot-protection gate now walks the whole storage dependency
  graph in both directions from every mounted and configured root/boot source,
  so root on LVM over md protects md and every physical member (previously only
  a source beginning /dev/md was interrogated). Tests: root-on-plain-md and
  root-on-LVM-over-md both refuse the member disk. HIGH: mktemp output is
  validated against a fixed /tmp/cephadm-shell.* prefix and rm -rf uses the
  validated dir; osd selector mode applies the desired spec before removing
  stale services; existing-pool convergence validates CRUSH rule structure and
  EC profile content; host_key_policy is now a required explicit input (no
  silent default); control sockets are keyed by policy and credential identity;
  URLs are never echoed in errors and the download URL travels on stdin; proxy
  redaction covers quoted assignments; every mutating method is kind:"action";
  README example no longer passes --json. MEDIUM: osdIds/maxPolls/poll-interval
  bounds added in schema and at run time. NOTE: making host_key_policy required
  deviates from 00-overview section 3 (which defaults absent to yes); done per
  the review's explicit request.
- 2026-10-17: group 06 (maintenance + teardown) complete: the shared privileged
  host-observation script (one round trip, marker sections, fail-closed parsing,
  residue and shared fsid classification), the poll-until-verified contract with
  the maintenance floor, and the twelve methods: enter/exit/state, ok-to-stop,
  check-host, noout-clear, osd activate, host-cluster-state,
  verify-cluster-fsid, disable-orchestration, rm-cluster and
  verify-host-torn-down. 210 unit tests.
- 2026-10-17: group 07 (RGW) started with the safe admin-plane parts: the secret
  redactor, the secret-free user view/classifier, and cephRgwBucketInventory
  (paged listing, safe-name charset, placement rule). cephRgwUserEnsure is
  BLOCKED on the D50 twin decision (Path A radosgw-admin secret-from-file/stdin
  vs Path B Admin Ops): a build must pick exactly one and never put the secret
  on argv, so it is not guessed here. The four S3-plane methods (SigV4, pinned
  XML parser, PAB probe) remain, as do the group 08 workflows.
- 2026-10-17: RGW secret path settled provisionally (P1 option a, per the lead;
  P1 is still listed as pending Randy in the overview, so flag it in STATUS).
  cephRgwUserEnsure has RGW generate the key (--gen-access-key --gen-secret) and
  stores it only in a sensitive, vaulted field like cephFetchCsiKey. Rationale:
  no caller secret ever reaches a command line or script text, and no Admin Ops
  path/credential is needed. Exactly one path is implemented; no runtime probing
  or fallback. Idempotent: an existing user is read, keys are not regenerated
  unless rotateKeys is set. The fetch dependency is approved for the four
  S3-plane methods only.
- The SQLite `pvs`/`mdadm` discovery, the atomic mdadm.conf rewrite and the
  boot-protection gate are unit-tested with scripted sessions; the live twin
  checks in the spec's [twin] items still apply.

- 2026-10-17: group 08 workflow catalog complete: all 22 workflows from
  `docs/specs/cephadm/08-workflows.md` §2 under
  `extensions/workflows/<name>/workflow.yaml`, listed in the manifest, and a
  `extensions/workflows/catalog_test.ts` covering §1.8 (D60 manifest-vs-disk,
  naming, 40-90 char descriptions, `cephadm`/`cephadm-*` instances, D57 port and
  host-key enum, the mutating gate shape, no `data.latest` in approval prompts,
  and every `cephVerify*` read-back passing `throwOnFail: false`). Every
  workflow validates with `swamp workflow validate`.
- Real gaps found while authoring, where the method spec wins over 08:
  - `cephadm-apply-mds` adds an `expectedDataPoolSize` input: §2.11 omits it,
    but `cephVerifyPool` requires `expectedSize`. The MDS sub-check uses
    expectedActive 1 and expectedStandby 0 (the spec gives no counts).
  - `cephadm-add-host` proves hostname presence only: the
    `cephHostMaintenanceState` record's `hosts[]` carries hostname, status,
    nooutFlag and out, but no address, so §2.5's address comparison cannot be
    made from that record.
  - `cephadm-distribute-key` re-reads with the single `port` input because
    `cephVerifyKeyDistributed` takes one port while the distribution uses
    per-host ports; its multi-host record key is the sorted `host:port` list, so
    the input documents that `hosts[]` must already be sorted (08 Unresolved 4).
  - `cephadm-apply-osds` does not expose `crushRuleName`: `cephApplyOsd` has no
    such argument (only `cephVerifyOsd` does, and the spec's prove call does not
    pass it).
  - No workflow depends on d4's four S3-plane methods. The only RGW workflow,
    `cephadm-inventory-rgw-buckets`, uses the already-present
    `cephRgwBucketInventory`; the ensure/policy/versioning methods have no
    workflow by §2.23.
  - `cephHostMaintenanceState`, `cephCephadmCheckHost` and `cephGetConnBundle`
    are plain reads with no `throwOnFail`; the gate-shape test requires it only
    on `cephVerify*` calls.

## Delta review (round 1) of the workflow catalog

- HIGH: `cephadm-create-pool` referenced the optional `size` and
  `erasureProfile` inputs unguarded in the mode assert message and the approval
  prompt, and in the verify call's `expectedSize`; a real run aborts with "No
  such key". Every reference is now inside `has(inputs.X)` ternaries (the
  `expectedSize` expression guards both branches), so either mode evaluates.
- HIGH: `cephadm-apply-osds` referenced the optional `targetPort` unguarded in
  the mode assert message and the approval prompt. Both now use
  `has(inputs.targetPort) ? ... : "unset"`.
- HIGH: the catalog test did not catch this class. Added two checks: "optional
  inputs are referenced only inside has() ternaries" (static) and "every
  workflow expression evaluates with optional inputs absent" (runs every
  `${{ }}` expression through the CEL engine with required inputs synthesised
  and optional inputs omitted, failing only on `No such key` for an optional
  input). The run-based check found the create-pool `expectedSize` case as well.
- MEDIUM: `cephadm-distribute-key` now has a pre-approval `assert-single-port`
  step requiring every `hosts[].port` to equal the single `port` input, and the
  multi-host prove assert matches the `cephVerifyKeyDistributed` record by
  `data.findBySpec` and `method` plus `capturedAt >= run.startedAt` instead of
  building a key from host order, so unsorted hosts no longer break it. The
  single-port limit is documented on the input and in the README.
- MEDIUM: `cephadm-create-csi-user` no longer claims the requested caps are
  proven; the assert description and message say the entity exists and the caps
  are set by the mutation, and the README records the limit.
- MEDIUM: the catalog gate-shape test now classifies a mutating workflow by its
  method names (anything not in the read-only set), not by the presence of an
  approval, and requires every mutating step to sit behind an approval on its
  step-dependency path. Deleting an approval now fails the test.
- add-host limit recorded in the README: only hostname presence is proven.

- 2026-10-17: group 07 RGW S3 plane complete (lane/d4-cephs3, rebased onto d6
  head 6807776). New module `extensions/models/_lib/s3.ts` + sibling
  `s3_test.ts`, wired into `cephadm.ts`. The four methods are
  `cephRgwBucketInspect` (READ-ONLY), `cephRgwBucketEnsure`,
  `cephRgwBucketPolicyEnsure` and `cephRgwBucketVersioningEnsure` (each
  `kind: action`). All four take the common S3 arguments and open no SSH
  session: a new injectable `fetch: FetchFn` seam (used by these methods only)
  carries every request on a fresh connection, and `S3_METHODS` excludes them
  from the `ssh-installed` applies-to list. The XML reader is pinned
  `jsr:@std/xml@0.2.0` (namespaces and entities); SigV4 (service `s3`) and MD5
  (for the mandated `Content-MD5`) are implemented locally.
- NOTE: the S3 handoff text said all four methods are mutating and need
  `kind: "action"`. `00-overview.md` row 47 and `07-rgw.md` §4 both classify
  `cephRgwBucketInspect` as READ-ONLY (it sends only HEAD/GET), so it is left
  without `kind`, matching the other read-only methods. Flagged for the lead.
- Behaviour: presence is the shared HEAD classifier with the ListBuckets
  tie-break; only an explicit not-found counts as absence. `cephRgwBucketEnsure`
  creates with `<region>:<placementTarget>` and `x-amz-acl: private`, converges
  the ACL and the four Public Access Block flags (with `Content-MD5`), then runs
  the signed-control/unsigned-anonymous list probe and the object-leak probe
  under the fixed `.cephadm-pab-probe/` prefix; "the probe could not run" and "a
  leak was detected" are distinct phases, and every stored probe object is
  deleted (by `versionId` when returned) before the leak is judged.
  `cephRgwBucketPolicyEnsure` refuses public and self-locking policies before
  any request, writes the document verbatim, proves it with a canonical
  read-back and the anonymous probe, lifts and restores `BlockPublicPolicy`, and
  rolls back on failure. `cephRgwBucketVersioningEnsure` converges the
  three-state versioning and warns when Enabled makes conditional writes unsafe.
- Security: the owner's `accessKey`/`secretKey` are sensitive arguments, used
  only to sign; no request URL, header or signature reaches a record, log or
  error; request transport detail is URL-stripped and truncated. 49 new unit
  tests (274 total) inject a scripted `fetch`, so no socket is opened; gates 0-6
  pass offline.
- 2026-10-17: S3-plane review round 2 (delta vs 6807776). Fixes:
  - HIGH: the object-leak public-read step was a second PutObject; it is now
    `PUT ?acl` with `x-amz-acl: public-read` (empty body), so a versioned bucket
    gains no extra version. Cleanup now lists object versions under each probe
    key (`GET ?versions&prefix=`) and deletes every version by `versionId`,
    falling back to the PutObject version id when the listing is unreadable, so
    a retried or versioned probe cannot leave a public version.
  - MEDIUM: a failed PAB lift now best-effort restores the original block and
    says in the error whether it was restored.
  - MEDIUM: a non-answered policy PUT is treated as indeterminate: the policy is
    re-read, the rollback runs if it changed (or the re-read fails), and
    RESTORED is reported only after a canonical read-back confirms it.
  - MEDIUM: cephRgwBucketEnsure and cephRgwBucketPolicyEnsure now lead with
    `DESTRUCTIVE.` and name what is replaced.
  - MEDIUM: the fetch seam caps the response body at 1 MiB and throws a URL-free
    transport error past the cap.
  - LOW: added the AWS published examplebucket SigV4 known-answer tests (GET
    Object and List Objects).
  - LEAD RULING: self-lockout detection now also refuses a Deny on
    `aws:SecureTransport` whose condition matches both true and false (it
    applies on every request and would lock the owner out).

- 2026-10-17 wipe guard, round 2: the protected-device module is pure and
  import-free (blob recorded in the ledger). lsblk, blkid and every examine run
  as root; empty type/UUID columns are filled from blkid and a mounted or
  configured filesystem with no known type refuses; md array UUIDs come from
  `mdadm --examine` of every mdstat member and candidate (stderr read for the
  not-a-member answer); candidates given as by-id/by-path links are resolved;
  expansion repeats to a fixed point; ZFS volumes map to their pool; each
  protected volume group needs a pvs row. Accepted limits: external fs
  journal/log devices and `resume=` (the kernel's exclusive open refuses a write
  to a mounted, swapped or claimed device).
- 2026-10-17 live fix of the wipe guard, from a run on a real two-disk host
  (mdadm 4.3, util-linux 2.39): (A) mdadm 4.3 reads `--` as "no devices given",
  so `--examine --`, `--stop --` and `--zero-superblock --` all did nothing and
  the guard refused every candidate; mdadm is now given bare, grammar-checked
  `/dev` paths (`--examine --scan --` happened to work and was changed too for
  uniformity; LVM tools and wipefs accept `--` and were left alone). The wipe's
  own array stop and superblock zero were affected the same way. (B) a BIOS-boot
  (EF02) or EFI System partition has no filesystem or mount, so nothing
  protected it; the lsblk probe now reads PARTTYPE/PARTTYPENAME and every
  boot-type partition of a disk that holds a protected device is protected, and
  an unreadable partition type on such a disk refuses. Tests use the real
  captured shapes (`protected_devices_real_test.ts`).
- 2026-10-17 guard r7: boot-type partitions (BIOS boot, EFI System, extended
  boot, PReP, MBR 0xef/0x41) are now refused on ANY disk, not only disks that
  hold a protected device: legacy-BIOS GRUB can live on a SATA disk with / on
  NVMe, and a fallback ESP is never in fstab. A new `boot-partition` refusal
  (`wipe.boot-partition`) is lifted only by `acknowledgeBootPartitions` on that
  data device's serial, and never lifts a protection. On an EFI host
  `efibootmgr -v` adds hard evidence (partitions named by BootCurrent/BootOrder
  are protected even when acknowledged) but a missing efibootmgr does not block
  the host. Rule 3a now covers the partitions of any protected node (a multipath
  device), `PARTTYPENAME` is dropped (util-linux 2.34 lacks it), and the GUID
  lowercasing is pinned by a test. Left as is: a foreign array named
  `/dev/md/<host>:0` fails the array-path grammar in `validate.ts` and aborts
  the wipe (fail-closed).
- 2026-10-17 guard r8: EFI entries in `HD(n,MBR,0x<sig>,...)` form map to the
  dos PARTUUID (`<sig padded to 8>-<n as 2 hex>`) and BootNext counts, so an
  acknowledged msdos ESP, or a booted 0x0c partition, is protected. Sector 0 of
  every candidate disk is read (`dd bs=512 count=1 | od`, exactly 512 bytes or
  unverifiable); a non-zero code area with 55 AA refuses as `boot-partition`
  (`mbr-boot-code`), lifted only by that disk's acknowledgement. A partition
  with no readable type is a `boot-partition` refusal too. A serial listed twice
  in `dataDevices` is refused. New tests pin the `some` and `continue` mutants.
- 2026-10-17 guard r9: the sector-0 rule also covers every disk behind a
  non-partition candidate (a multipath device is wiped through its paths); a
  missing or short read of any of them is unverifiable. The boundary is pinned
  (bytes 0-439 are boot code, 440-445 are not).
- 2026-10-17 wipe alreadyRaw (live finding): a partitionless disk with MBR boot
  code was judged already raw. `deviceIsRaw` now also needs a readable sector 0
  with zero bytes 0-439, no 55 AA, and no wipefs signature; otherwise the wipe
  runs (wipefs -a, sgdisk --zap-all, then a zeroed sector 0) and the raw check
  re-probes sector 0 and signatures, failing `wipe.raw-signatures` if they
  survive. protected_devices.ts is untouched.

## 2026-10-17: catalog A fixes (lane/d6-catfix)

- Catalog keeps lane/cephadm-int's workflows (catalog A); lane/d6's catalog was
  retired.
- HIGH: every gated destructive step now depends directly, succeeded-only, on
  every safety-gate assert and on the approval step (TRIAGE 4d). catalog_test.ts
  asserts the direct edges for every gated mutating step.
- MEDIUM (swamp lab 3583): a plain `resume --input` can run the mutation on a
  new target with the pre-gate reused. Every gated workflow now re-runs its gate
  after approval (a second gate step depending on approve) and the mutation
  depends on both gates and approve. Applied to wipe-disks, remove-osds,
  delete-fs, apply-mgr, apply-mon, apply-osds, create-pool and distribute-key.
- HIGH (4h): the control-socket name no longer contains private-key bytes. It is
  derived from host/port/user, the host-key policy, a non-secret key path, and a
  per-process random nonce; a test proves the key content cannot influence the
  socket name or the ssh argv.
- In-method destructive safety (lab 3583: workflow gates cannot be the only
  protection):
  - cephRemoveOsds refuses when cluster health is HEALTH_ERR and refuses any
    requested OSD that `osd safe-to-destroy` does not accept, before any
    mutation.
  - cephDeleteFs refuses while `fs status` reports connected clients, before any
    mutation.
  - wipeDiskToRaw already gates on the protected-device set and mount state (its
    module is untouched).
  - cephApplyOsd already enforces the D19 exclude list against the orchestrator
    device inventory before applying.
  - cephRmCluster already refuses a foreign or unobserved fsid before purging.
- LOW: the remove-osds health assert message and the distribute-key check-host
  assert message no longer interpolate a map; they name scalar observations.

## 2026-10-17: catalog A fixes, round 2

- ssh: an inline privateKey no longer shares one process-wide nonce. A process
  map keeps a fresh random nonce per distinct key, so different keys cannot ride
  one ControlMaster; key bytes and key hashes never reach a socket name or argv.
  Tests require different keys to get different socket names and the same key to
  reuse one, with no key text in argv.
- cephDeleteFs: `ceph fs status -f json` reports
  `{"clients":[{"fs":"<name>","clients":N}]}`; the method now finds the entry
  whose `fs` equals the volume and refuses when its numeric `clients` > 0, and
  fails closed when the entry or the count is missing or non-numeric. Tests
  cover 0 clients (proceeds), N clients, missing entry and malformed count.
- cephRemoveOsds: the per-OSD `osd safe-to-destroy` gate was wrong (EBUSY for
  any OSD with PGs mapped, i.e. every in-service OSD). It is replaced by ONE
  joint `osd ok-to-stop <all present ids>` before any mutation, failing closed
  on a non-zero exit; `orch osd rm` performs the drain. Tests cover a jointly
  unsafe set and an in-service OSD that proceeds.
- cephRemoveOsds health precondition now fails closed: it refuses unless the
  status is HEALTH_OK or HEALTH_WARN, so a missing or malformed status refuses.
- catalog_test: the direct-edge test now identifies pre-gate and post-approval
  re-gate asserts structurally, requires a re-gate assert whenever a job has a
  pre-gate, and requires a direct succeeded-only edge from every mutating step
  to it. Proven: deleting the re-gate edge fails the test.

- 2026-10-17: cephDeleteFs requires the reported client count to be a
  non-negative integer; -1, 1.5 and a numeric string all refuse. Tests added.

## 2026-10-17 live e2e: blocked

Reason: a real cephadm cluster needs at least three hosts with free whole disks;
the one bare-metal test box has root RAID1 members on both disks. Every cell
below is `blocked`, not skipped; run them against a throwaway three-host cluster
with spare whole disks before promoting to stable. Unit/contract tests (486,
scripted SSH and fetch, no socket) cover every path offline.

| Cell                                                                                       | Result  |
| ------------------------------------------------------------------------------------------ | ------- |
| 1 method `cephHostPrep`                                                                    | blocked |
| 2 method `cephVerifyPackageSource`                                                         | blocked |
| 3 method `wipeDiskToRaw`                                                                   | blocked |
| 4 method `cephBootstrap`                                                                   | blocked |
| 5 method `cephDistributeKey`                                                               | blocked |
| 6 method `cephHostAdd`                                                                     | blocked |
| 7 method `cephApplyMon`                                                                    | blocked |
| 8 method `cephApplyMgr`                                                                    | blocked |
| 9 method `cephApplyMds`                                                                    | blocked |
| 10 method `cephApplyOsd`                                                                   | blocked |
| 11 method `cephCreatePool`                                                                 | blocked |
| 12 method `cephCreateFs`                                                                   | blocked |
| 13 method `cephCreateCsiUser`                                                              | blocked |
| 14 method `cephGetConnBundle`                                                              | blocked |
| 15 method `cephFetchCsiKey`                                                                | blocked |
| 16 method `cephDeleteFs`                                                                   | blocked |
| 17 method `cephRemoveOsds`                                                                 | blocked |
| 18 method `cephVerifyMonQuorum`                                                            | blocked |
| 19 method `cephVerifyMgr`                                                                  | blocked |
| 20 method `cephVerifyOsd`                                                                  | blocked |
| 21 method `cephVerifyCsiUsers`                                                             | blocked |
| 22 method `cephVerifyHealth`                                                               | blocked |
| 23 method `cephVerifyHostNoout`                                                            | blocked |
| 24 method `cephVerifyHostPrep`                                                             | blocked |
| 25 method `cephVerifyDisksRaw`                                                             | blocked |
| 26 method `cephVerifyKeyDistributed`                                                       | blocked |
| 27 method `cephCapacityReport`                                                             | blocked |
| 28 method `cephVerifyMonPlacement`                                                         | blocked |
| 29 method `cephVerifyMgrPlacement`                                                         | blocked |
| 30 method `cephVerifyPool`                                                                 | blocked |
| 31 method `cephVerifyRbdSmoke`                                                             | blocked |
| 32 method `cephVerifyOsdClaimable`                                                         | blocked |
| 33 method `cephHostMaintenanceEnter`                                                       | blocked |
| 34 method `cephHostMaintenanceExit`                                                        | blocked |
| 35 method `cephHostMaintenanceState`                                                       | blocked |
| 36 method `cephOsdOkToStop`                                                                | blocked |
| 37 method `cephCephadmCheckHost`                                                           | blocked |
| 38 method `cephHostNooutClear`                                                             | blocked |
| 39 method `cephOsdActivate`                                                                | blocked |
| 40 method `cephHostClusterState`                                                           | blocked |
| 41 method `cephVerifyClusterFsid`                                                          | blocked |
| 42 method `cephDisableOrchestration`                                                       | blocked |
| 43 method `cephRmCluster`                                                                  | blocked |
| 44 method `cephVerifyHostTornDown`                                                         | blocked |
| 45 method `cephRgwBucketInventory`                                                         | blocked |
| 46 method `cephRgwUserEnsure`                                                              | blocked |
| 47 method `cephRgwBucketInspect`                                                           | blocked |
| 48 method `cephRgwBucketEnsure`                                                            | blocked |
| 49 method `cephRgwBucketPolicyEnsure`                                                      | blocked |
| 50 method `cephRgwBucketVersioningEnsure`                                                  | blocked |
| 51 workflow `cephadm-add-host` end to end                                                  | blocked |
| 52 workflow `cephadm-apply-mds` end to end                                                 | blocked |
| 53 workflow `cephadm-apply-mgr` end to end                                                 | blocked |
| 54 workflow `cephadm-apply-mon` end to end                                                 | blocked |
| 55 workflow `cephadm-apply-osds` end to end                                                | blocked |
| 56 workflow `cephadm-bootstrap-cluster` end to end                                         | blocked |
| 57 workflow `cephadm-create-csi-user` end to end                                           | blocked |
| 58 workflow `cephadm-create-fs` end to end                                                 | blocked |
| 59 workflow `cephadm-create-pool` end to end                                               | blocked |
| 60 workflow `cephadm-delete-fs` end to end                                                 | blocked |
| 61 workflow `cephadm-distribute-key` end to end                                            | blocked |
| 62 workflow `cephadm-fetch-csi-key` end to end                                             | blocked |
| 63 workflow `cephadm-get-conn-bundle` end to end                                           | blocked |
| 64 workflow `cephadm-inventory-rgw-buckets` end to end                                     | blocked |
| 65 workflow `cephadm-prep-host` end to end                                                 | blocked |
| 66 workflow `cephadm-remove-osds` end to end                                               | blocked |
| 67 workflow `cephadm-verify-health` end to end                                             | blocked |
| 68 workflow `cephadm-verify-host-prep` end to end                                          | blocked |
| 69 workflow `cephadm-verify-mgr` end to end                                                | blocked |
| 70 workflow `cephadm-verify-mon-quorum` end to end                                         | blocked |
| 71 workflow `cephadm-verify-osds` end to end                                               | blocked |
| 72 workflow `cephadm-wipe-disks` end to end                                                | blocked |
| 73 wipeDiskToRaw refuses a root RAID1 member (protected device)                            | blocked |
| 74 wipeDiskToRaw refuses when lsblk and blkid disagree                                     | blocked |
| 75 cephRgwBucketEnsure object-leak probe leaves no probe version behind (versioned bucket) | blocked |
| 76 cephRgwBucketPolicyEnsure rollback restores the prior policy on failure                 | blocked |
| 77 cephRmCluster refuses a host whose fsid differs from the named one                      | blocked |

## Review ledger: final verify and merge prep

- Integrated tree reviewed CLEAN at 7f931c2. Delta triage 7f931c2..95517dc
  (README regeneration, six integrated-review Mediums, the final shared wipe
  guard: `_lib/protected_devices.ts` blob 2a2592a4, `_lib/wipe.ts` identical to
  lane/b2-cephwipe at 8798f32), codex astra + terra seats both rc=0:
  - Refuted HIGH (terra) `_lib/s3.ts` probe cleanup "creates a delete marker
    when the PUT version id is lost": `cleanupProbeObject` lists every Version
    and DeleteMarker for the exact probe key and deletes each by id; the
    empty-id delete is only the fallback when the listing is unreadable.
  - Refuted MEDIUM (terra) `blkidUsable` "refuses blank disks": bare `blkid`
    reports every signature on the host, including the root filesystem, so it
    exits 0 on any booted host; an exit-2 answer refuses fail-closed by design
    (guard signed off at round 5).
  - Mitigated MEDIUM (astra) `curlDownloadScript` character denylist:
    `assertHttpUrl` validates the URL first in `ensureCephadm`.
- Known residuals for the next version: LOW the probe-cleanup fallback (version
  listing unreadable after an indeterminate PUT) reports success after a plain
  DELETE that on a versioned bucket only adds a delete marker; LOW `stackOf` in
  `_lib/protected_devices.ts` duplicates the `closure` traversal; LOW
  `cephadmUrl` accepts http as well as https (by spec).
- Merge prep (gate 7): plain model export so the registry catalogs the model
  type; the S3 credential grammar moved to one shared constant so
  `.meta({ sensitive: true })` sits on each field's own line (the quality
  scanner is line-based); the RGW user record's `accessKey` is now
  sensitive-marked beside `key`. No other behaviour change; 486 tests pass.
