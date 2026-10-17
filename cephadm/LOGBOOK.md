# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

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
- The SQLite `pvs`/`mdadm` discovery, the atomic mdadm.conf rewrite and the
  boot-protection gate are unit-tested with scripted sessions; the live twin
  checks in the spec's [twin] items still apply.
