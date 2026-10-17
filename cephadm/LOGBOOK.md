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
