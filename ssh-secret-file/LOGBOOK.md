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

## secret-file 2026.10.17.2 transport and delivery hardening (lineage)

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
- That release was `secret-file` `2026.10.17.2`; its inputs were unchanged, so
  its `upgrades[]` entry was a no-op identity. This package first ships
  `2026.10.17.1` with `upgrades: []` (no prior version under its own name).

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
- 2026-10-18: `export const model` is now a plain object literal with literal
  `type`, `version` and `upgrades: []`; the methods are built by `methodsFor`
  and `createModel` spreads the literal for tests. registry-lint is clean.
- 2026-10-18: `remove` runs one anchored `sh -c` script (`cd` + `pwd -P` +
  relative unlink) and `verify`/`write` read metadata and SHA-256 from one
  anchored script, so a symlinked ancestor can no longer redirect the unlink or
  make `matches` wrong.
- 2026-10-18: `requireOk` no longer embeds remote stderr, and the remote scripts
  use distinct exit codes (2 symlinked component, 3 writable directory, 4
  ownership, 5 short read, 6 destination changed); a hostile target cannot
  reflect stdin or file bytes into the operator's error output.
- 2026-10-18: the README names GNU coreutils (`stat -c`, `sha256sum`, `mv -T`)
  and drops the unused `shasum` alternative.
- 2026-10-18: the `entries` key cap is enforced in the schema and
  `resolveContent` runs before the first remote probe.
- 2026-10-18: `stageWriteScript` applies owner and group before the mode. A
  chown clears the set-ID bits, so chmod last publishes the requested mode
  exactly; the staged file stays mktemp's 0600 until the rename, so a mode with
  a group or other read bit is never briefly readable under the wrong group.
- 2026-10-18: `readFileScript` refuses a symlink before stat and sha256sum, so
  the metadata and the content hash always describe the same regular file.
- 2026-10-18: `readFile` validates every stat token (mode, owner, group, ids,
  bytes) and `FileStateSchema` bounds owner and group, so a hostile target
  cannot land an arbitrary token in state or `--json`.
- 2026-10-18: `verify` resolves the supplied content form before it probes the
  host and stores `""` (not the requested mode) in a not_found record.
- 2026-10-18: the live run found `write` failing for modes `0060` and `0040`:
  GNU `stat %a` prints `60` and `40`, and the stat-token check required three
  octal digits. The read check now accepts 1-4 octal digits (the input schema
  still requires 3-4), so those modes converge and are recorded. The two files
  the fail cells left on the throwaway host are noted in the live baseline.
- residual low: spec section 4 says a dangling symlink destination is replaced,
  while the code refuses any symlink destination (the security property the
  reviewers required). The live receipt records the refusal as the observed
  behaviour; the spec wording is a separate spec edit.
- residual low: the spec file and LOGBOOK lineage still say `secret-file`; a
  `docs/specs/ssh-secret-file.md` rename is a separate docs change and would
  widen this branch's diff scope.
- residual low: after a local timeout the remote write script runs until stdin
  closes (the transport timeout kills the local ssh, not the remote shell).
- residual low: `dash-runner` reports three LOWs because its container has no
  `/etc/example` directory; the anchored scripts refuse fail-closed there.

## Moving from secret-file

`@randybias/ssh-secret-file` is `@randybias/secret-file` under its confirmed
name. The model type, methods (`write`, `verify`, `remove`), inputs and stored
record shape are the same, so a definition moves by changing the type name;
state does not carry over, because the record names are keyed by the type's own
instance key and this package starts at version 2026.10.17.1 with
`upgrades: []`. Re-run `write` once per file under the new type: the content,
mode, owner and group already converge, so the first run is a no-op on the host
and only creates the record. The public `secret-file` versions stay published
and are deprecated afterwards, never deleted.

## Review rounds (run sp-2) dispositions

Five triage rounds on `lane/d1-secret-file-stdin`, each with the conformance,
adversarial and tightness seats at rc=0 plus an advisory seat. Findings in the
vendored `_lib/ssh.ts` at the canonical blob `8f132c43...` (an IPv6 host
grammar, `SSH_ASKPASS_SECRET` in the child environment, the agent fallback,
`insecure_tofu` and a swallowed `ssh-agent -k` failure) were dropped in every
round under the vendored-transport rule and go to the transport's owner.

- Round 1 (head 7da733d). Routed and fixed in 9e591de: HIGH diff scope (the
  branch edited the predecessor `secret-file`, whose 2026.10.17.2 is published;
  reverted, the diff is this package plus its `release.yaml` stanza); security
  HIGH ancestor-symlink swap (the directory checks and the staged write resolved
  the parent by name each time, so a writable ancestor could be swapped for a
  symlink after the check; fixed with `cd "$d"`, `[ "$(pwd -P)" = "$d" ]` and
  every later operation anchored on `.`); MEDIUM three unused vendored harness
  files (dropped); MEDIUM unbounded `stat`/`test`/`rm` probes (30 s
  `PROBE_TIMEOUT_MS`); MEDIUM `exists` read an unsearchable parent as absent
  (typed error); LOW UTF-16 caps, base64 maximum, hand-written argument types,
  dead fake branches, naming docs. Refuted: a local timeout before the remote
  `mv` (the traps clean up), an FD-anchored helper (not required, the shell
  anchor closes the race), the version-1 lineage note.
- Round 2 (head 9e591de). Routed and fixed in 5862ada: security HIGH `remove`
  unlinked by name in a separate call after the probe (a symlinked ancestor
  redirected the unlink; now one anchored script); security HIGH `requireOk`
  embedded remote stderr in thrown errors (a hostile target could reflect the
  secret; now `<what> failed (exit N)` with distinct exit codes 2-6); MEDIUM
  README claimed a `shasum` fallback (GNU coreutils named); MEDIUM duplicated
  convergence predicate (one `converged()`); LOW computed model export (plain
  literal), four-sentence description, `entries` key cap in the schema with
  `resolveContent` before the first probe, dead fake branches, lineage
  paragraph. Refuted: an armed revert for an `authorized_keys` lockout (wrong
  layer for a generic file writer), darwin in `platforms` (the runner, not the
  target), a new record version per run (read-only methods persist their
  observation by design).
- Round 3 (head 5862ada). Routed and fixed in 34480cd: security HIGH `chmod`
  before `chown` (a group or other read bit was briefly held under the running
  user's group, and a chown clears set-ID bits so 4755/2750 never converged; now
  chown first, the staged file stays 0600 until the rename); MEDIUM `verify` on
  a symlink paired the link's metadata with the target's hash (refused with exit
  7); MEDIUM stat tokens were stored unvalidated (every token validated,
  `FileStateSchema` bounded); LOW `verify` resolved the content form after
  recording `not_found`, the `not_found` record stored the requested mode, a
  vacuous distinct-names test, a dead `-d` fake branch. Refuted: the stat/sha
  race inside one anchored script (only the file's owner can replace it), the
  window before `mv -T` (needs a writer in a directory the script refuses), the
  byte count on argv (already a record attribute; not a content hash).
- Round 4 (head 34480cd). CLEAN, no Critical or High. Lows carried: the stat
  mode token check required three digits (this became the live fail), the set-ID
  dash test passes no owner spec, up to six SSH sessions before the stdin-fed
  script, anchored exit codes not decoded into messages, `hmac_key` `min(1)`, a
  duplicated `ContentInput` type, a copied test context. Refuted: concurrent
  replacement between stat and sha256sum (owner only), the distinct-names test
  (resolved by the round-3 option taken).
- Live run 1 (head 34480cd): 28 pass, 1 fail, 1 untested. The fail: `write` with
  mode `0060` or `0040` wrote the file correctly, then failed to parse GNU
  `stat %a`'s unpadded `60`/`40` and wrote no record. Fixed in cf558bf (the read
  accepts 1-4 octal digits, compared through `normalizeMode`; the input schema
  still requires 3-4) with a unit test.
- Round 5 (head cf558bf). CLEAN, no Critical or High; the delta from 34480cd is
  the stat-token fix, one test and a LOGBOOK note. One MEDIUM tagged security by
  the adversarial seat and eleven Lows, all recorded as residuals below by the
  lead's ruling rather than routed, because the head had already run live and a
  further code change would have needed a third live run.

## Residuals at merge (2026.10.17.1)

Known and accepted for this beta; backlog for the next version.

- MEDIUM (security-tagged, lead ruling: residual). A FIFO, device or socket at
  `path` is not refused: `assertReplaceable` checks `-L` and `-d` only, so
  `readFileScript` runs `sha256sum` on it (a FIFO blocks until the 60 s read
  timeout with no typed error; a small device such as `/dev/null` hashes, then
  `mv -T` replaces the node with the secret file). Not an attacker path:
  planting a special file needs write access to a directory the stage script
  already refuses (exit 3 or 4), so the cost is a bounded stall of the
  operator's own run against a target the operator named. Fix: `[ -f ]` after
  the `-L` check in `readFileScript` and again before `mv -T`, with a new exit
  code and a fake-runner test.
- LOW A non-root runner writing a mode without the owner read bit publishes the
  file, then the post-write read fails with no record (root is unaffected; the
  live 0060/0040 cells ran as root).
- LOW `IDENTITY_RE` rejects `.` and a trailing `$`, both legal in Linux account
  names, so a file owned by such an account cannot converge.
- LOW The path grammar accepts repeated slashes; the `pwd -P` anchor then
  differs and every anchored script exits 2 with a misleading message.
- LOW After a successful stage, a post-write read error throws before the record
  is written, so the host has the new file and state keeps the old record until
  a re-run.
- LOW `verify` with no content form, mode, owner or group records
  `matches: true` although nothing was compared.
- LOW A fresh `write` opens up to six SSH sessions before the stdin-fed script;
  `remove` re-probes after its script already proved absence.
- LOW The anchored scripts' exit codes 2-7 are not decoded into typed messages.
- LOW `hmac_key` accepts one character while the README's brute-force claim
  presupposes a strong key.
- LOW The dash-runner set-ID test passes no owner spec, so chown-before-chmod is
  proven at runtime by nothing but the script text.
- LOW A hand-written `ContentInput` duplicates schema-inferred fields; two tests
  copy the test context and the removal responder.
- LOW Spec section 4 says a dangling symlink destination is replaced; the code
  refuses every symlink destination (the safer behaviour, live-tested); the spec
  file still carries the `secret-file` name.
- LOW After a local timeout the remote write script runs until stdin closes.

## 2026-10-18 live e2e (run sp-2)

Two live runs on throwaway hourly VPS (1 vCPU, 1 GB, Ubuntu 24.04, kernel
6.8.0-142, GNU coreutils 9.4), user root, strict host-key pins learned by
`ssh-keyscan` on first contact, the SSH key and every content value as vault
references, inputs by `--input-file`, no `--json` on any run. No container cell:
the control host has no systemd-nspawn and the extension is SSH-only. Every real
address, hostname and provider id is redacted (`<vps>` is the target). The run-1
lane rotated the host's provider-set root password over stdin before any cell
after a poller printed the provider record into a transcript; the host was
deleted at teardown.

Run 1, head 34480cd, 03:23Z to 03:55Z: 28 pass, 1 fail, 1 untested. The fail
(modes `0060` and `0040`, see the round-5 dispositions) left two residue files
on that host; everything else the extension wrote was removed. Argv scan: 74
swamp commands and 159 scratch files, 0 hits; 4741 `ps -eo args` samples on the
target at 0.1 s, 0 hits for the value marker, 0 hits in `/tmp`, `/var/tmp` or
`/dev/shm`; the `.secret-stage-*` file was seen only inside the destination
directory (9 samples) and none remained.

Run 2, head cf558bf, contentHash
`c6ff3b4e1804312f1568ff29f61e3e963fb5004c2701adab6365d13ab2064e05`, 04:47Z to
05:02Z, the second and last live run: 30 pass, 0 fail, 1 untested. The run-1
fail cells were re-run first on fresh and on existing paths. Baseline diff
before and after: 0 lines (no change in packages, units, listeners, users,
groups, mounts, netplan, cron or timers; no extension residue). Argv scan: 74
swamp commands and 185 scratch files, 0 secret hits; 4145 `ps` samples, 0 marker
hits, 0 hits in the temp directories, staging seen only inside the destination
directory (14 samples), none left. `untested` is never a pass.

| method_or_workflow | scenario     | result   | run_id | test_cell | content_hash_proved | note                                                                                                                                                                                                                                    |
| ------------------ | ------------ | -------- | ------ | --------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| write              | fresh        | pass     | sp-2   | vps-small | c6ff3b4e...         | mode 0060 root:nogroup and mode 0040 on fresh paths: rc 0, changed true, second-session `stat %a` 60 and 40, 60 bytes, sha256 equals value A; the run-1 defect is fixed                                                                 |
| write              | existing     | pass     | sp-2   | vps-small | c6ff3b4e...         | mode 0060 then 0040 over an existing 0600 file: changed true each, `stat %a` 60 then 40, content hash unchanged, no residue                                                                                                             |
| write              | rerun        | pass     | sp-2   | vps-small | c6ff3b4e...         | identical re-run of the 0060 and 0040 cells on fresh and existing paths: changed false (4 reruns), inode and mtime unchanged                                                                                                            |
| write              | fresh        | pass     | sp-2   | vps-small | c6ff3b4e...         | content form: `<vps>:/srv/secrets/a.key` 0600 root:root 60 bytes, changed true; second-session stat and sha256 equal the vault value's hash                                                                                             |
| write              | fresh        | pass     | sp-2   | vps-small | c6ff3b4e...         | entries form with `hmac_key`: `app.env` 0640, 130 bytes, sha256 equals the in-process `KEY='value'` rendering (a quote in a value escaped), changed true                                                                                |
| write              | fresh        | pass     | sp-2   | vps-small | c6ff3b4e...         | `content_base64` form: `bin.dat` 0600, 54 bytes, sha256 equals the decoded vault value's hash, changed true                                                                                                                             |
| write              | rerun        | pass     | sp-2   | vps-small | c6ff3b4e...         | identical re-run of the content, owner/group, set-ID and entries cells: changed false each time, inode and mtime unchanged (8 reruns in all)                                                                                            |
| write              | rerun        | pass     | sp-2   | vps-small | c6ff3b4e...         | numeric owner/group 65534:65534 over a file at nobody:nogroup: changed false (converges by id or name)                                                                                                                                  |
| write              | existing     | pass     | sp-2   | vps-small | c6ff3b4e...         | value change A to B (from the 0040 state, mode back to 0600): changed true, new inode, sha256 equals value B                                                                                                                            |
| write              | existing     | pass     | sp-2   | vps-small | c6ff3b4e...         | mode-only change 0600 to 0640: changed true, re-staged (new inode), content hash unchanged                                                                                                                                              |
| write              | existing     | pass     | sp-2   | vps-small | c6ff3b4e...         | owner/group change to nobody:nogroup: changed true, stat shows uid 65534 gid 65534 mode 640, content unchanged                                                                                                                          |
| write              | existing     | pass     | sp-2   | vps-small | c6ff3b4e...         | set-ID modes with owner and group: 4750 root:nogroup then 2640 root:nogroup publish exactly (`stat %a` 4750, 2640); rerun of 4750 changed false                                                                                         |
| write              | existing     | pass     | sp-2   | vps-small | c6ff3b4e...         | adopt a pre-existing 0644 file with other content: replaced atomically, 0600 root:root, sha256 equals value A, changed true                                                                                                             |
| write              | bad-input    | pass     | sp-2   | vps-small | c6ff3b4e...         | 8 refusals before any connection: two content forms, no content form, relative path, `..` component, non-octal mode, unknown key, newline in an entry value, 257 entries                                                                |
| write              | failure-path | pass     | sp-2   | vps-small | c6ff3b4e...         | symlink destination (link to `/etc/hostname`) refused "is a symlink"; link intact and the target's hash unchanged before, after the refusal and after the matrix                                                                        |
| write              | failure-path | pass     | sp-2   | vps-small | c6ff3b4e...         | dangling symlink destination refused "is a symlink" (code behaviour; spec section 4 wording says replaced), link left intact                                                                                                            |
| write              | failure-path | pass     | sp-2   | vps-small | c6ff3b4e...         | symlinked ancestor (`/srv/slink -> /srv/secrets`): anchored script exit 2, nothing written through the link                                                                                                                             |
| write              | failure-path | pass     | sp-2   | vps-small | c6ff3b4e...         | directory destination refused; missing destination directory refused ("could not search ... refusing to report absent"); group/world-writable directory exit 3, no file                                                                 |
| write              | failure-path | pass     | sp-2   | vps-small | c6ff3b4e...         | unknown owner: chown fails, write exit 1, no destination file and no staging file left                                                                                                                                                  |
| write              | failure-path | pass     | sp-2   | vps-small | c6ff3b4e...         | wrong host key "host key verification failed; refusing to connect"; wrong user "authentication failed"; bad private key "ssh-add rejected the private key"; port 2 refused before connecting ("host_keys were supplied but none apply") |
| write              | failure-path | pass     | sp-2   | vps-small | c6ff3b4e...         | secret never on argv or in a remote temp file: 4145 ps samples 0 marker hits, 0 hits in /tmp /var/tmp /dev/shm, staging seen only inside the destination directory (14 samples), 0 left; local scan 74 commands 185 files 0 hits        |
| verify             | existing     | pass     | sp-2   | vps-small | c6ff3b4e...         | match: content+mode+owner+group true; mismatch false for a wrong content, a wrong mode and a wrong owner (3 cells); entries form against `app.env` true                                                                                 |
| verify             | fresh        | pass     | sp-2   | vps-small | c6ff3b4e...         | never-written path: matches false, status not_found, changed false; metadata-only verify of an existing file matches true                                                                                                               |
| verify             | rerun        | pass     | sp-2   | vps-small | c6ff3b4e...         | identical verify twice: same result, changed false, file untouched (inode and mtime unchanged)                                                                                                                                          |
| verify             | bad-input    | pass     | sp-2   | vps-small | c6ff3b4e...         | two content forms refused before connecting; `hmac_key` refused by the schema                                                                                                                                                           |
| verify             | failure-path | pass     | sp-2   | vps-small | c6ff3b4e...         | symlink destination refused (read exit 7); wrong host key refused before connecting                                                                                                                                                     |
| remove             | fresh        | pass     | sp-2   | vps-small | c6ff3b4e...         | `a.key`, `app.env`, `bin.dat`, `low.key` and `low40.key` removed, status removed, changed true; second-session stat ENOENT each                                                                                                         |
| remove             | rerun        | pass     | sp-2   | vps-small | c6ff3b4e...         | already absent: changed false, status not_found                                                                                                                                                                                         |
| remove             | existing     | pass     | sp-2   | vps-small | c6ff3b4e...         | adopted foreign file removed; symlink destination: the link itself is unlinked, the `/etc/hostname` target's hash unchanged                                                                                                             |
| remove             | bad-input    | pass     | sp-2   | vps-small | c6ff3b4e...         | relative path refused by the schema; unknown input (`mode`) refused                                                                                                                                                                     |
| remove             | failure-path | pass     | sp-2   | vps-small | c6ff3b4e...         | symlinked ancestor on an existing file: anchored script exit 2, file intact (stat and hash unchanged); wrong host key refused before connecting                                                                                         |
| upgrade            | existing     | untested | sp-2   | vps-small | c6ff3b4e...         | the manifest has no `upgrades[]` entry and no version of `@randybias/ssh-secret-file` was published before this one; nothing to upgrade from (the predecessor `secret-file` is a different package name)                                |

Result: 30 pass, 0 fail, 1 untested, 0 inconclusive. Full receipts with the
baselines, the argv scans and the provider accounting are kept outside the
package in the repository's `receipts/` notes.

## 2026-10-18 merge prep (main)

- Final verify at cf558bf: the round-5 ledger is CLEAN (no unrefuted Critical or
  High); the branch diff against main touches only `ssh-secret-file/` plus its
  own `release.yaml` stanza (`channel: beta`, `ci: false`, `published: {}`).
  Only files under `ssh-secret-file/` were ever added on the branch (Apache-2.0
  `LICENSE.txt`, no other licence), so no licence-history squash was needed;
  merged with `--no-ff`.
- Post-live freeze: nothing under `ssh-secret-file/` other than this LOGBOOK
  (not packaged) changed after cf558bf; the merged tree is byte-identical to the
  live-tested head. The dry run at merge gave contentHash
  `c6ff3b4e1804312f1568ff29f61e3e963fb5004c2701adab6365d13ab2064e05`, equal to
  the live-tested hash; `version-exists` passed, so 2026.10.17.1 is new under
  this name.
- Transport: `_lib/ssh.ts` blob `8f132c4329c9e64bed686731cd5a0e02980194ea`
  (canonical, ssh-host 2026.10.17.3), `_lib/ssh_test.ts`
  `4e8ac15fcd6bce797c523a221fe58fe9a8d9b386`; harness `recording-runner.ts`
  `943857c8b6dbbc365523ee0cfafd1b0fe0c0054f`.
- Gate-7 mechanics in place: plain `export const model = {...}`, literal
  `upgrades: []`, a sibling `_test.ts` for every model file.
- Review report for the hash committed as
  `reviews/ssh-secret-file/c6ff3b4e1804312f1568ff29f61e3e963fb5004c2701adab6365d13ab2064e05.json`,
  written from the five rounds' seat outputs, the dispositions above and the
  live receipts.
- Published with
  `swamp extension push manifest.yaml --repo-dir ssh-secret-file --channel beta --yes`
  as `@randybias/ssh-secret-file@2026.10.17.1`, channel beta, visibility public.
  The `release.yaml` record (published hash, `ci: true` and the release note) is
  the commit after this one; gates were re-run on it before the push of main.

## Factory events

Run sp-2, item `ssh-secret-file next`, from the conductor's event log (UTC). The
version was built on DeepSeek lane d1 as a new package from the `secret-file`
2026.10.17.2 head; five review rounds (round 1 routed two Highs, round 2 two,
round 3 one, rounds 4 and 5 clean) and two live runs (28/1 then 30/0) preceded
the merge.

| At                   | Stage      | Rung      | Head         | Reason         |
| -------------------- | ---------- | --------- | ------------ | -------------- |
| 2026-10-17T21:58:08Z | spec       | prior-art |              | spec-ok        |
| 2026-10-17T22:36:16Z | building   | fix       |              | prior-art-fail |
| 2026-10-17T23:06:11Z | checks     | gates     | a0e8cace3019 | new-head       |
| 2026-10-17T23:18:21Z | building   | fix       | a0e8cace3019 | gates-fail     |
| 2026-10-17T23:21:49Z | checks     | gates     | 15b09f68c64d | new-head       |
| 2026-10-17T23:30:13Z | checks     | realtool  | 15b09f68c64d | gates-pass     |
| 2026-10-17T23:35:33Z | review     | review    | 15b09f68c64d | realtool-pass  |
| 2026-10-17T23:43:53Z | building   | build     |              | resume         |
| 2026-10-17T23:56:02Z | checks     | gates     | 6a1df60c2ee9 | head-reported  |
| 2026-10-18T00:00:42Z | building   | fix       | 6a1df60c2ee9 | gates-fail     |
| 2026-10-18T00:04:33Z | checks     | gates     | 7da733d27a96 | new-head       |
| 2026-10-18T00:16:16Z | checks     | realtool  | 7da733d27a96 | gates-pass     |
| 2026-10-18T00:25:44Z | review     | review    | 7da733d27a96 | realtool-pass  |
| 2026-10-18T00:52:36Z | building   | fix       | 7da733d27a96 | triage:routed  |
| 2026-10-18T00:55:38Z | checks     | gates     | 9e591dee864d | new-head       |
| 2026-10-18T01:03:55Z | checks     | realtool  | 9e591dee864d | gates-pass     |
| 2026-10-18T01:11:45Z | review     | review    | 9e591dee864d | realtool-pass  |
| 2026-10-18T01:33:25Z | building   | fix       | 9e591dee864d | triage:routed  |
| 2026-10-18T01:38:11Z | checks     | gates     | 5862adadf7cb | new-head       |
| 2026-10-18T01:48:56Z | checks     | realtool  | 5862adadf7cb | gates-pass     |
| 2026-10-18T01:55:54Z | review     | review    | 5862adadf7cb | realtool-pass  |
| 2026-10-18T02:26:28Z | building   | fix       | 5862adadf7cb | triage:routed  |
| 2026-10-18T02:29:53Z | checks     | gates     | 34480cdd6208 | new-head       |
| 2026-10-18T02:41:19Z | checks     | realtool  | 34480cdd6208 | gates-pass     |
| 2026-10-18T02:52:38Z | review     | review    | 34480cdd6208 | realtool-pass  |
| 2026-10-18T03:22:16Z | live test  | live      | 34480cdd6208 | triage:clean   |
| 2026-10-18T03:54:47Z | building   | fix       | 34480cdd6208 | live-fail      |
| 2026-10-18T03:57:50Z | checks     | gates     | cf558bf1fbdd | new-head       |
| 2026-10-18T04:04:32Z | checks     | realtool  | cf558bf1fbdd | gates-pass     |
| 2026-10-18T04:11:08Z | review     | review    | cf558bf1fbdd | realtool-pass  |
| 2026-10-18T04:46:35Z | paused     | escalated | cf558bf1fbdd | round-cap:3    |
| 2026-10-18T04:50:21Z | live test  | live      | cf558bf1fbdd | resume         |
| 2026-10-18T05:09:20Z | publishing | merge     | cf558bf1fbdd | live-pass      |
