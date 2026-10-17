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
