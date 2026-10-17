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
