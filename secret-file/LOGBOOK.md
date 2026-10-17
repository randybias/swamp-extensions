# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

## Naming and visibility

Answers to the five naming questions (naming and visibility convention, §3):

visibility: public

audience: general

1. Private or public? Public: published to swamp-club with public visibility,
   source in this repo.
2. Individual or general? General: any operator who needs a secret file on a
   host over SSH; no environment, host or deployment is baked in.
3. Does the name clearly describe and disambiguate while staying short? Not
   fully: it names no system, and the run sp-20261017 naming audit judged
   "rename". A rename to `ssh-secret-file` is proposed and pending Randy, so
   2026.10.17.2 ships as `secret-file` for now.
4. Private purpose check: not applicable (public).
5. Would a stranger guess roughly right and wrong about nothing? Partly: a
   stranger could guess a swamp vault backend that reads secrets from a file,
   which is wrong. It writes a secret file onto a remote host over SSH, which
   the proposed `ssh-secret-file` would make plain.

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
