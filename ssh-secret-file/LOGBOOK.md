# ssh-secret-file LOGBOOK

Not packaged. Notes for whoever maintains this extension.

visibility: public

audience: general

## Naming and visibility

Answers to the five naming questions (naming and visibility convention, §3):

1. Private or public? Public: published to swamp-club with public visibility,
   source in this repo.
2. Individual or general? General: any operator who needs a secret file on a
   host over SSH; no environment, host or deployment is baked in.
3. Does the name clearly describe and disambiguate while staying short? Yes: the
   previous `secret-file` named no system and a stranger could guess a swamp
   vault backend that reads secrets from a file (the opposite of what it does).
   `ssh-secret-file` names the system (SSH) and the artifact (a secret file);
   the rename was confirmed before this package was built.
4. Private purpose check: not applicable (public).
5. Would a stranger guess roughly right and wrong about nothing? Yes: an
   operator reads it as writing a secret file onto a host over SSH, which is
   what it does. Nothing in the name suggests a deployment or a vault backend.

This package is the confirmed rename of `secret-file`; it starts from the
`secret-file` 2026.10.17.2 code and carries the next-version hardening (the
destination directory is verified before the rename). The public `secret-file`
versions are deprecated afterwards, never deleted.

## Registry evaluation (before building)

Searched the registry for a generic secret-file/dotenv writer over SSH:

- `@mgreten/hermes-env` — manages one specific agent's `.env` over SSH or
  locally; not generic, its repository is unverified, and it is not a hardened
  stdin-delivery primitive.
- `@mgreten/contained-git-write`, `@mgreten/github-file-track` — write or
  materialise files locally, not over SSH.
- No `@swamp/*` model covers it; `@swamp/ssh` is a fleet exec/copy model with no
  secret-file, stdin-delivery or content-hash-convergence contract.

Decision: build a thin generic model, vendoring the canonical `_lib/ssh.ts` from
`ssh-host` (blob `cb61c4adfbedee0a6c9914deae52d3864d5a1afb`) so the transport is
reviewed once and shared.

## Vendored

- `extensions/models/_lib/ssh.ts` — canonical SSH transport, blob
  `8f132c4329c9e64bed686731cd5a0e02980194ea` (ssh-host 2026.10.17.3),
  byte-identical. Verified with `git hash-object`.
- `extensions/models/_lib/ssh_test.ts` — the canonical transport's own tests,
  vendored with it so the helper stays covered here.
- `extensions/models/_lib/bogworks/recording-runner.ts` — blob
  `943857c8b6dbbc365523ee0cfafd1b0fe0c0054f`. Only the recording runner is
  vendored: this package renders no config for a real-tool validator and uses
  the transport's own quoting helper, so `remote-script.ts`, `containers.ts` and
  `mod.ts` would be dead code in the archive.

## Notes

- 2026-10-17: initial release. `_lib/ssh.ts` is vendored byte-identical from
  `ssh-host` at the blob above; `_lib/ssh_test.ts` comes with it so the helper
  stays covered here. The model adds `write`, `verify` and `remove`, keyed by
  host, port, user and a hash of the path.
- The value reaches the target only over the helper's stdin upload. State keeps
  metadata, a change flag, and a keyed HMAC only when `hmac_key` is supplied —
  never the content or a plain hash. Logs and method results carry only path,
  mode, byte count and flags.
- Live testing is pending a target host for the run; the design is exercised by
  unit/contract tests with a scripted runner (no process, no socket).

## Review round 1

- HIGH: `insecure_tofu` was advertised as trust-on-first-use but never recorded
  the learned key, so every run accepted a new key and a MITM could take the
  secret. Fixed by dropping it: `host_key_policy` now accepts only `strict`, and
  `host_keys` is required, so the host is verified against the pinned keys on
  every run. `_lib/ssh.ts` was resynced to the 2026.10.17.2 blob
  (`fe0139f08c42e3fdae0061b9688fb5c534174957`), which no longer sends a content
  hash to the remote.
- MEDIUM: state key is now `sha256(host, port, user, path)` (`secret-<32 hex>`),
  not a 32-bit fnv of the path, so two paths cannot collide.
- MEDIUM: owner and group are applied to a staged file before the rename (with
  `chown -h`), and the stage is removed on failure; a published file is never
  briefly owned by the wrong account and a swapped symlink is not followed.
- MEDIUM: `stat` now also reads `%u`/`%g`, so a numeric owner or group converges
  instead of re-chowning every run.
- MEDIUM: a `stat` failure after the file is known to exist is an error, not a
  silent `not_found`; nothing is written to state.
- MEDIUM: existence checks use `test -e || test -L`, so a dangling symlink is
  removed rather than reported absent.
- MEDIUM: `verify` rejects more than one content form instead of skipping the
  comparison.
- MEDIUM: `entries` is capped at 256 keys and 1 MiB rendered, values are
  single-quoted with `'` escaped for POSIX-shell sourcing, and the dialect is
  documented.
- LOW: README dotenv example uses vault references only and documents the real
  `secret-<32 hex>` key; `verify` no longer accepts `hmac_key`; the `write`
  description is three sentences.

- 2026-10-17 live cell 8 (symlink destination): `write` staged to
  `<path>.secret-stage-<uuid>` and renamed with `mv -T`, so the canonical
  upload's symlink/directory guard only ever saw the stage path and a symlink
  destination was replaced. `write` now checks the destination with no-follow
  (`test -L`, then `test -d`) before staging and again immediately before the
  rename, refusing a symlink or directory with a typed `SshError`. Tests cover
  both. The rest of the live matrix passed 12/13; the process scan was clean.

## 2026-10-17 live e2e

Run sp-20261017. Target `<vps3>` (one Linux VPS), user root, strict host-key
pins, key from the vault; every run was `swamp model method run ... --log`
(never `--json`) with vault references only. Content checks compared a SHA-256
computed from the vault value with one computed on the target; only MATCH or
MISMATCH was printed.

First pass on 770114a (model 2026.10.17.1):

| Cell                       | Result | Detail                                                                                                                                                                           |
| -------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 write single value       | PASS   | changed=true; `600 root root`, 32 bytes, sha256 MATCH                                                                                                                            |
| 2 identical re-write       | PASS   | changed=false; inode and mtime unchanged                                                                                                                                         |
| 3 value change             | PASS   | changed=true, new inode, sha256 MATCH; no stage file left                                                                                                                        |
| 4 mode change only         | PASS   | 0600 to 0640 changed=true, content MATCH; re-run changed=false                                                                                                                   |
| 5 owner/group              | PASS   | named and numeric owner/group (throwaway uid/gid 4711) converge and re-runs are no-ops; unknown user gives a typed `chown` error with no stage file left                         |
| 6 dotenv hostile value     | PASS   | value holding `'`, `\`, `$`, backtick, `#`, spaces; sourcing with sh and bash yields MATCH, prints nothing; re-run changed=false                                                 |
| 7 verify read-only         | PASS   | match, wrong content/mode/owner and absent path reported correctly; file inode and mtime unchanged                                                                               |
| 8 destination is a symlink | FAIL   | symlink replaced by a regular file (no write-through); the destination guard only saw the stage path. Fixed in 34dd922                                                           |
| 9 destination is a dir     | PASS   | refused (incidentally, via the sha256sum probe); nothing written                                                                                                                 |
| 10 remove, remove again    | PASS   | removed; second run `already absent` (removed=false)                                                                                                                             |
| 11 wrong host-key pin      | PASS   | `host key verification failed ...; refusing to connect`; nothing written                                                                                                         |
| 12 unreachable host        | PASS   | 192.0.2.1, connect_timeout_s 5: `could not connect` in about 7 s                                                                                                                 |
| 13 ps scan during writes   | PASS   | `ps -efww` every 50 ms on the control host and `<vps3>` during a single-value and a dotenv write; 16 in-memory patterns (values, substrings, hashes): 0 hits; positive control 1 |

Result 12/13. Re-run on 34dd922 (cells touched by the fix plus the regression
set):

| Cell                       | Result | Detail                                                                                                                        |
| -------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------- |
| 1 normal write             | PASS   | changed=true; `600 root root`, sha256 MATCH                                                                                   |
| 2 idempotent re-write      | PASS   | changed=false; inode and mtime identical                                                                                      |
| 8 destination is a symlink | PASS   | typed refusal `... is a symlink; refusing to replace it`; link and its target unchanged, no stage file; dangling link too     |
| 9 destination is a dir     | PASS   | empty and non-empty dir: typed `... is a directory` refusal from the dedicated check; contents intact, no stage file          |
| 13 ps/argv scan            | PASS   | about 780 samples per host over three writes; 10 patterns, 0 hits; no 64-hex string in target samples; positive control 1 hit |

Result 5/5. Cleanup: work dir and throwaway user removed on `<vps3>`, test vault
keys deleted, no cloud resource ordered or changed.

## 2026-10-17 merge review (34dd922)

Delta review of 34dd922 over 770114a: 0 Critical/High. Residuals carried:

- MEDIUM/LOW (astra, terra): the destination checks and `mv -T` are separate
  operations, so a symlink planted between the second check and the rename is
  replaced (rename does not follow it, so no write-through). Closing the race
  needs a parent directory the attacker cannot write.
- LOW: a symlinked parent directory is not detected; same precondition (a
  writable parent).
- LOW (astra): no test drives the second (pre-rename) check with a destination
  that changes during staging.
- LOW (astra): the symlink test's fake runner returns the same result on both
  branches of its condition (dead code).

## 2026.10.17.2 transport and delivery hardening

- Re-vendored the canonical `_lib/ssh.ts` byte-identical from `ssh-host` on
  `origin/main` (blob `8f132c4329c9e64bed686731cd5a0e02980194ea`) plus its
  `ssh_test.ts` (`4e8ac15f`); the test task now allows `--allow-run=sh` for the
  canonical runner tests.
- Dropped the transport upload temp file for the secret. `write` now streams the
  value on `exec` stdin straight into one remote `sh -c` script
  (`stageWriteScript`) that creates a 0600 temp with `mktemp`, `cat`s stdin into
  it, `chmod`s and `chown -h`s it, re-checks the destination with no-follow and
  renames with `mv -T`; the `trap` removes the temp on any failure. No
  transport-level temp file is created. A file destination needs a temp in its
  own directory for the atomic rename, so the verified `mktemp` + `trap` path is
  kept and this is why.
- The write and the `sha256sum` read now carry `timeoutMs` (120s and 60s).
- Version `2026.10.17.2`; inputs unchanged, so the `upgrades[]` entry (literal
  on the export) is a no-op identity.

### Old vs new command recording

A recording `CommandRunner` drove `write`, `verify` and `remove` against the
pre-change tree and the new tree. The write stage went from the transport upload
flow to one stdin-fed script:

- OLD (19 commands): `assertReplaceable` (`test -L`, `test -d`), the `sshUpload`
  probe and its write to `<path>.secret-stage-<uuid>`, a separate `chown -h`, a
  second `test -L`/`test -d` before the rename, `mv -T`, then `stat` and
  `sha256sum`.
- NEW (14 commands): the same pre-staging `test -L`/`test -d`, ONE `sh -c`
  script carrying the secret on stdin (its own `mktemp`/`trap`, `chmod`,
  `chown -h`, no-follow checks, `mv -T`), then the same `stat` and `sha256sum`.

Every non-secret external command that remains external is byte-identical
(`test`, `stat`, `sha256sum`, `rm`); only the pre-rename `test -L`/`test -d`
pair moved inside the write script, and the upload/chown/mv argv are now in it.
The value is on stdin in both, never on argv, and never in state.

## 2026-10-17 live e2e (2026.10.17.2)

Run sp-20261017 on lane/d1-secret-file-stdin ec4cbd5 (`git archive` into a
scratch repo), swamp 20261013.025835.0, model typeVersion 2026.10.17.2. One
throwaway VPS `<vps5>`, user root, strict host-key pins only. Every secret input
was a vault reference and no run used `--json`. Values: two 32-character base64
values and three 1,000,000-character base64 values (the `content` cap is 1 MiB).
Content was checked by comparing sha256 of the vault value with sha256 on the
host, MATCH or MISMATCH only.

| Cell                               | Result | Detail                                                                                                                                                                                                  |
| ---------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 normal write                     | PASS   | `changed=true`, `600 root root`, 32 bytes, sha256 MATCH (negative control MISMATCH)                                                                                                                     |
| 2 idempotent re-write              | PASS   | `changed=false`; inode and mtime identical, no stray file                                                                                                                                               |
| 3 symlink destination              | PASS   | refused (`is a symlink; refusing to replace it`), exit 1; link and target unchanged; a dangling link is refused the same way                                                                            |
| 4 directory destination            | PASS   | non-empty and empty directories refused (`is a directory`), exit 1; both intact, no stage file                                                                                                          |
| 5 atomic publish of a changed file | PASS   | a host poller hashed the destination about every 30 ms over two 1 MB switches: 2730 samples, each pass one transition from old to new, 0 missing, 0 partial; the stage file was removed after publish   |
| 6 short stdin (killed local ssh)   | PASS   | local ssh `kill -9` mid-stream (three runs): `write ... failed (exit 137)`, exit 1; the partial stage was removed by the trap, destination still the old value (MATCH), inode and mtime unchanged       |
| 7 argv and transport temp scan     | PASS   | `ps -efww` every 50 ms on control and target across six writes, 22 patterns (substrings, sha256): 0 hits, no 64-hex string on the target; no `.ssh-host-upload*` file ever appeared, 0 stage files left |
| 8 remove                           | PASS   | `Removed secret file`, then `already absent`; remove on a symlink removed only the link                                                                                                                 |

Result 8/8 PASS, 0 FAIL, 0 BLOCKED. The test paths on `<vps5>` were removed and
the scratch vault emptied afterwards; no provider resource changed.

- 2026-10-17 (merge-prep, main): review at b34692d routed one Critical
  (`set -o
  pipefail` rejected by dash, so every changed write failed) and one
  High (a short stdin published a truncated file); ec4cbd5 fixed both
  (`set -eu`, a staged byte-count check before the rename,
  `trap 'exit 1' HUP INT TERM`) and added a test that runs the generated script
  under a real dash for the normal, short-read, symlink and directory cases.
  Live above is on ec4cbd5, and the published bytes are that code. The staged
  length on the remote script is a byte count, not a content-derived hash.
  Residuals:
  - LOW (open): the remote write keeps running after a local timeout until its
    stdin closes; it then fails the length check and keeps the old file.
  - LOW (open): `deno.json` grants `--allow-run=sh,dash` to the whole test task,
    not only the runner tests.
  - LOW (open, tightness COULD-BE-TIGHTER): the single-use `f` local in
    `stageWriteScript` could be inlined.
  - Refuted: a relative destination path (the schema requires an absolute path);
    findings located only in the canonical `_lib/ssh.ts` (reviewed in ssh-host).
  - Pending Randy: rename to `ssh-secret-file` (see Naming and visibility).

## Prior art

Prior art terms: secret, scp, sftp, rsync

Registry search on stable and beta (`swamp extension search`, whole-word matches
in the package name or description). The package name's segment `file` is a
plain English word that matches dozens of unrelated packages, so the terms name
the job: deliver a secret from a vault onto a host as a file, the way `scp`,
`sftp` or `rsync` would, without the value touching argv or a local file. This
extends the "Registry evaluation (before building)" section above with the full
hit list.

- secret:
  - Vault backends and secret stores: `@sntxrr/scaleway-secret-manager`
    (stable), `@sntxrr/scaleway-secret-manager-vault` (stable),
    `@webframp/griptape/secrets` (stable), `@swamp/gcp-sm` (stable),
    `@swamp/azure-kv` (stable), `@swamp/aws-sm` (stable),
    `@webframp/hashicorp-vault` (stable), `@swamp/1password` (stable),
    `@dataverket/sops` (stable), `@zocc/sops-age` (stable),
    `@svendowideit/systemd-creds` (stable and beta). Each reads and writes
    secrets in a store; none writes a file onto a remote host. They are sources
    this extension consumes, not alternatives. NONE.
  - `@thomas/woodpecker` (stable), `@thomas/forgejo` (stable): CI and forge
    administration that sets repository secrets through an API; no host file.
    NONE.
  - `@mgreten/notification-outbox` (stable): a secret-redacting notification
    queue; word match only. NONE.
  - `@sntxrr/scaleway-object-storage` (stable): S3 buckets signed with an access
    key and secret; word match only. NONE.
  - `@randybias/secret-file` (beta): the package this one renames. It is the
    same model under the previous name — the successor, not prior art — and its
    public versions are deprecated after this package publishes.
  - `@randybias/k8s-secret` (beta), `@randybias/server-stack` (beta): ours; the
    Kubernetes counterpart and the stack that composes this extension. Not prior
    art.
  - `@kneel/super-productivity` (beta), `@kneel/jlcpcb` (beta),
    `@svendowideit/test-factory` (beta): API integrations and a test harness
    that take a secret as input; word matches only. NONE.
- scp:
  - `@adam/cfgmgmt` (stable): its `file` type converges content by sha256, but
    the content is a plain model argument (not vault-oriented) and travels
    through its SSH session as an argument. OVERLAP (minor), justified: it is
    not built for vault values and offers no stdin-only delivery.
  - `@swamp/ssh` (stable): `copy` is scp or rsync from a local file; the secret
    would have to exist on local disk first and the copy is not hash-converged
    or atomic. OVERLAP (minor), justified.
  - `@sntxrr/tailcat-probe` (stable): a Tailscale path probe whose transfer test
    uses scp; not a file manager. NONE.
  - `@jentz/aws-vpc-inventory` (stable), `@jentz/aws-vpc-inventory-report`
    (stable), `@jentz/aws-default-sg-audit` (stable),
    `@jentz/aws-default-sg-audit-report` (stable), `@jentz/aws-rds-reservations`
    (stable): "SCP" as in AWS service control policies; word matches only. NONE.
- sftp: no hits.
- rsync:
  - `@wendy/rsync` (stable): local rsync src/dst pairs, run on the host where
    swamp runs; no vault, no remote target over SSH, no owner or mode
    convergence. NONE.
- ssh (the proposed rename's segment):
  - `@keeb/ssh` (stable): general-purpose SSH operations (exec, upload, wait)
    for a host, now shipped as skills. It offers no vault-to-file contract: no
    atomic, content-hash-converged write, no mode/owner convergence and no
    stdin-only secret delivery, so the value would be just another uploaded
    file. NONE.
  - `@randybias/ssh-host` (stable): our own host-hardening model and the source
    of the `_lib/ssh.ts` transport this extension vendors. It hardens a host and
    manages keys; it is not a generic secret-file writer. This extension borrows
    its transport, not its model.
  - `@evrardjp/ssh-ca` (stable): an SSH certificate-authority workflow that
    signs host and user keys. It issues credentials rather than writing a file
    on a target, and has no atomic, hash-converged write. NONE.
  - `@nedbellavance/azure-ssh-key` (stable): manages Azure SSH public-key
    resources and VM access through the cloud control plane. It is provider-API
    management, not a per-host file delivery, and holds no vault-sourced
    secret-file contract. NONE.
- file:
  - `@swamp/gcp/file` (stable): models Google Cloud Filestore as Swamp
    resources. It is provider-API management for a cloud filesystem; it writes
    no file onto a host and has no vault, mode/owner or atomic-rename surface.
    NONE.
  - `@sntxrr/scaleway-file-storage` (stable): manages Scaleway File Storage
    (managed NFS) filesystems through the File Storage API. Cloud filesystem
    lifecycle only; not a per-host file with content-hash and mode/owner
    convergence. NONE.
  - `@mgreten/github-file-track` (stable): tracks files in GitHub repositories
    and materialises them on the local filesystem, deduplicated on the upstream
    Git blob SHA. It writes local files from a repository over the `gh` CLI, not
    a vault secret onto a remote host over SSH. NONE.

The remaining `ssh` and `file` hits are description-only word matches — network,
virtualization and estate tools that mention SSH access in passing
(`@josephholsten/tailscale/device`, `@shelson/k3s`, `@randybias/k0s-cluster`,
`@randybias/server-host`, `@psftw/pets`, the `@randybias/*` ZFS/libvirt/mesh
models) and object-storage or repository tooling that uses "file" for its own
outputs (`@sntxrr/b2-files`, `@jamesakeech/forgejo-code`,
`@webframp/falai/storage`, `@magistr/telegram-send`, the SBOM/settings
packages). None delivers a vault value onto a host as a file.

Verdict: OVERLAP (minor), justified. No package delivers a vault value onto a
remote host over stdin with nothing on disk or argv, atomically and idempotently
by content hash. Worth filing upstream: an atomic, hash-verified, stdin-fed copy
mode for `@swamp/ssh`.

## Decisions

- 2026-10-17: built as a new package from the `secret-file` 2026.10.17.2 head
  under the confirmed name `ssh-secret-file`; the public `secret-file` versions
  are deprecated afterwards and never deleted.
- 2026-10-17: implemented the next-version Medium from the spec and the review's
  security High. The remote write script `cd`s into the destination directory
  and refuses a path whose `pwd -P` differs (a symlinked component at any
  depth), then anchors every later operation on the current directory inode: the
  mode/owner checks read `.`, the stage file is created with
  `mktemp ./.secret-stage-XXXXXXXX`, and the rename targets `./<basename>`. A
  directory that is group- or world-writable, or not owned by the running user
  or root, is refused.
- 2026-10-17: every short remote probe (`stat`, `test`, `rm`) now carries a 30 s
  `PROBE_TIMEOUT_MS`; only the write script and the `sha256sum` read were
  bounded before.
- 2026-10-17: `exists` no longer treats exit 1 from `test` as absent when the
  parent is unsearchable; it probes the parent and raises a typed `SshError`.
- 2026-10-17: only `recording-runner.ts` is vendored from the harness; the
  unused `remote-script.ts`, `containers.ts` and `mod.ts` would ship dead code.
- 2026-10-17: the argument types are inferred from the zod schemas and the
  content cap is enforced on the resolved bytes (1 MiB), with the base64 max
  sized for that cap.
- 2026-10-17: kept the branch scope to this package (reverted the predecessor
  edits); a secret-file registry-lint fix, if wanted, belongs on main.
- 2026-10-17: the value is still delivered only over stdin; no content hash,
  plain or keyed, reaches argv or a remote command line.
- residual low: `export const model` still spreads `createModel()` rather than
  being a plain object literal (registry-lint MEDIUM; rulings L8) — fix before
  merge-prep if a plain literal can avoid duplicating the definition.
- residual low: the spec file and LOGBOOK lineage still say `secret-file`; a
  `docs/specs/ssh-secret-file.md` rename is a separate docs change and would
  widen this branch's diff scope.
- residual low: after a local timeout the remote write script runs until stdin
  closes (the transport timeout kills the local ssh, not the remote shell).
- residual low: `dash-runner` reports one LOW because its container has no
  `/etc/example` directory; the script refuses fail-closed there.

## Live test matrix

One row per public method and the symlink-race attempt; the live lane fills
`result`, `run_id`, `test_cell` and `content_hash_proved`. `untested` is never a
pass.

| method_or_workflow | scenario     | result   | run_id | test_cell | content_hash_proved | note                          |
| ------------------ | ------------ | -------- | ------ | --------- | ------------------- | ----------------------------- |
| write              | fresh        | untested |        |           |                     | write a new file, mode 0600   |
| write              | rerun        | untested |        |           |                     | identical re-write is a no-op |
| write              | existing     | untested |        |           |                     | value change replaces content |
| write              | existing     | untested |        |           |                     | mode change only re-stages    |
| write              | existing     | untested |        |           |                     | owner/group converge          |
| write              | failure-path | untested |        |           |                     | symlink race attempt refused  |
| verify             | existing     | untested |        |           |                     | match and mismatch            |
| verify             | failure-path | untested |        |           |                     | two content forms refused     |
| remove             | fresh        | untested |        |           |                     | file removed                  |
| remove             | rerun        | untested |        |           |                     | already absent is a no-op     |

## Factory events

Merge-prep copies the item's events here from the conductor's event records.
