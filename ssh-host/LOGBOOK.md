# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

## Adopt-versus-build evaluation (spec item 2, first task)

Two candidates were assessed from the registry before writing code:

- `@keeb/ssh` (`2026.07.18.1`) is published as a **skill**, not a model:
  `swamp extension info` lists `contentTypes: ["skills"]` and an empty
  `contentMetadata.models`. It cannot be a dependency of `wireguard-mesh`,
  `server-host` or `k0s-cluster`, because those need to call an `exec`/`upload`
  method.
- `@swamp/ssh` (`2026.10.16.1`) is a real model, but its shape contradicts the
  contract three consumers need. It fixes the fleet in `globalArguments.hosts[]`
  and selects members by name/tag/CEL, whereas the consumers must hand a target
  to every method and keep `globalArguments` empty. Its published description
  documents key and `sshpass` auth but no required strict-versus-insecure
  host-key input, and it manages long-lived ControlMaster state that a one-shot
  transport does not need.

Decision: **outcome 2, the shared helper pattern**, plus a thin generic model.
`extensions/models/_lib/ssh.ts` is self-contained (imports nothing from the
extension) so it can be copied byte-identical into the consuming lanes' `_lib/`.

## Notes

- 2026-10-17: initial release. `_lib/ssh.ts` is the critical-path helper: `exec`
  posix-quotes an argv vector, `upload` streams bytes over stdin and renames a
  temp file, `wait_connection` is `ssh-keyscan`-based and read-only. A private
  key goes into a short-lived `ssh-agent` over stdin; a password goes through a
  temp askpass helper and an environment variable. Neither can appear in argv.
  `runRemote` returns a remote non-zero exit as data but maps OpenSSH's own exit
  255 to a typed `SshError` (host key, auth, or unreachable).
- 2026-10-17: the model is a factory (`createModel(deps)`), with the production
  export `createModel()` and `denoDeps`. Tests pass a fake runner, clock and
  sleep, so no process is spawned and no socket is opened.
- 2026-10-17: `host_key_policy` has no default and is required; `strict`
  requires pinned `host_keys` and `denoDeps` disables the operator's ssh config
  (`-F /dev/null`, `IdentityFile=none`). Stored data is keyed by host:
  `exec-<host>`, `upload-<host>`, `connection-<host>`.
- 2026-10-17: `4117d67` offline-green (`scripts/gates.sh --offline ssh-host`,
  gates 0-6 pass, 7-8 skipped offline). Live e2e matrix and adversarial review
  are run by the lead; record every finding and fix here.
- 2026-10-17: gitleaks' `generic-api-key` rule flagged the synthetic base64 host
  keys and a placeholder password as secrets. The fixtures now use low-entropy
  valid base64 blobs (`QUFBQUFB`, `QkJCQkJC`, `Q0NDQ0ND`) whose fingerprints are
  recomputed in the tests; no suppression comments were needed.

## Review ledger: conformance + adversarial (round 1)

Verified at `4117d67` by the lead; fixes below are in the offline-green commit
for this round.

- HIGH-1 (injection surface): `runRemote(remoteCommand: string)` was exported,
  so a consumer could hand it an unquoted shell string. `runRemote` is now
  internal. The public surface is `exec(argv)`, `quoteArgv(argv)` and
  `buildRemoteCommand(stages, operators)`; operators come from a fixed allowlist
  and every word is `posixQuote`d. A test asserts `runRemote` is not exported.
- HIGH-2 (insecure_tofu was not TOFU): accept-new with a deleted per-invocation
  known_hosts trusted a fresh key every run. Now `insecure_tofu` records the
  first keys seen into the `connection-<host>-<port>-<user>` resource and pins
  exactly those on later runs; a changed key is refused. `checkHostKeys`
  verifies whenever pins are supplied, under either policy, and the helper's
  bare accept-new path is only reachable on a genuine first use.
- MEDIUM-3 (upload directory paths): `assertRemotePath` (and the `upload`
  schema) now reject a trailing `/`, a `.` or `..` component, and require a
  concrete final filename.
- MEDIUM-4 (upload not idempotent): `upload` reads the destination's SHA-256
  first and, on a match, skips the write and writes no new resource version;
  `UploadResult.changed` reports which happened.
- MEDIUM-5 (resource key ignored port): instance names are now
  `<verb>-<host>-<port>-<user>`, so two ports or users cannot overwrite each
  other.
- MEDIUM-6 (exec output): persisted `stdout` and `stderr` are marked sensitive;
  the method description and README say argv must never carry a secret.
- MEDIUM-7 (README `--json`): dropped `--json` from the run examples.
- LOW: `upload` is prefixed `DESTRUCTIVE.` and `exec` names its destructive
  potential; the model has a `description`; `parseHostKeys` discriminates bare
  lines by field count (accepting `sk-`/FIDO algorithms); `USER_RE` accepts
  uppercase and dotted names; `keysForHost` accepts `[host]:22` on port 22; the
  `isSensitive` test throws if zod's wrapper shape changes.
- Not fixed by design: the LOWs from the two OCR seats that timed out were not
  available at the time of this round; fold any that arrive into the next one.

## Review ledger: round 3 (codex astra + terra on ab51a14)

- MEDIUM-1 (ambiguous key): `host-port-user` concatenation could collide
  (`a-22-x-3-y`). Instance names now use length-prefixed labeled components:
  `h<len>-<host>-p<port>-u<len>-<user>`, so target identity is unambiguous.
- MEDIUM-2 (non-transactional pin): a first-use `insecure_tofu` scan persisted
  the pin before the operation ran. `resolveTarget` now learns the keys and pins
  the operation only; `commitPin` writes the `connection` resource after the
  transport returns without throwing, so a failed auth or key change leaves no
  durable trust. Test added.
- MEDIUM-3 (convergence skipped mode): `upload`'s probe now returns sha256 and
  mode; identical bytes under a different mode get a chmod only, and identical
  bytes and mode are the no-op case.
- MEDIUM-4 (directory destination): the probe reports `DIRECTORY` and `upload`
  throws; the write script also refuses a directory immediately before `mv`, so
  a directory can never be treated as the file.
- LOW-5: the mode is rendered with `posixQuote` in the chmod-only path and the
  write script.
- LOW-6: `exec` is prefixed `DESTRUCTIVE.` with a three-sentence description;
  the README explains that reachability/rollback protection belongs in the
  owning extension.
- LOW-7 (dead code): `buildRemoteCommand` is now used by a public
  `execPipeline(stages, operators)` entry, so the pipeline builder is live.
- REFUTED, deliberately not done: terra's mandatory armed-revert on `exec` and
  `upload`. This is a generic transport primitive; a forced rollback on every
  exec breaks normal use. Reachability protection lives in the higher-level
  extensions, and `DESTRUCTIVE.` plus the README note is the right treatment.

## Review ledger: round 4 (codex astra + terra on 78cc26a)

- HIGH-1 (exec result leaked secrets): `exec` no longer returns raw stdout or
  stderr. The default result is `{ exit_code, stdout_sha256, stderr_sha256 }`;
  captured output is persisted in the sensitive-marked `execution` resource and
  only included in the result when the new `return_output` input is set. README
  warns never to combine `return_output` with captured `--json`.
- HIGH-2 (upload final-target race): the write script now uses `mv -T`
  (rename(2) no-target-directory semantics) on Linux, a directory guard with
  plain `mv` elsewhere, and verifies the destination is a regular file whose
  SHA-256 matches before reporting success.
- MEDIUM-3 (argv NUL): `quoteArgv` and the `exec` schema both reject a NUL byte
  with a typed error before any spawn.
- LOW-4: README and the `upload` description now say convergence is bytes AND
  mode, matching the chmod-only branch.
- LOW-5: the upload idempotence test keeps remote state (sha + mode) and asserts
  the second run writes nothing and returns `changed: false`.
- REFUTED, kept: terra's armed-revert-on-exec; see the round-3 disposition.

## Review ledger: round 5 (codex astra + terra on af55e6f)

- HIGH-1 (exec result output not sensitive): fix (a) is unavailable — swamp has
  no method-result schema to mark sensitive; only resource/data output schemas
  support `.meta({ sensitive: true })`, and `result` is not even part of the
  documented `UserMethodResult`. Fix (b) applied: raw stdout/stderr are never
  returned in the result. The result is
  `{ exit_code, stdout_sha256,
  stderr_sha256 }`; `return_output: true`
  additionally stores the raw output in the sensitive-marked `execution`
  resource and adds `output_resource` to the result. Default runs store only
  hashes, so no secret is persisted either.
- HIGH-2 (macOS mv fallback raced the dir check): the non-Linux fallback is
  gone. `upload` fails closed on a non-Linux target with a typed
  `SshConfigError` (`mv -T` is the only no-target-directory rename); the write
  also verifies the destination's SHA-256 after the rename.
- LOW (wait schema carried credentials): `wait_connection` now takes a scan-only
  target shape with no `private_key` or `password`; a test asserts they are
  absent.

## Review ledger: round 6 (codex astra + terra on 1b78c7d)

- HIGH-1 (mode-only chmod followed symlinks): the chmod-in-place branch is gone.
  The probe tests `-L` first and refuses a symlink, and a mode-only difference
  now goes through the temp-file `mv -T` replacement path. The write script also
  refuses a symlink or directory immediately before and after the rename. Tests
  cover the symlink refusal and that a mode-only change never runs `chmod` on
  the destination path.
- HIGH-2 (unbounded capture): every method takes `max_output_bytes` (default 10
  MiB, max 100 MiB). `denoRunner` streams each stream and throws a typed
  `SshError` at the cap (killing the child); `runRemote` re-checks the returned
  strings with a non-allocating UTF-8 length so an injected runner is bounded
  too. Tests cover the typed overflow error.

## Review ledger: round 7 (k0s review of the vendored helper)

- HIGH-1 (unrecognized exit 255 became data): `transportFailure` now maps every
  ssh exit 255 to a typed `SshError`; OpenSSH reserves 255 for its own failures,
  so a remote command that exits 255 is reported as a transport error. The test
  expects the error, and the README and `exec` description say so.
- HIGH-2 (non-applicable pins fell back to accept-new): a supplied `host_keys`
  set that matches nothing for the host/port now throws `SshConfigError` in both
  `runRemote` and `waitConnection`; only a run with no `host_keys` at all may
  take the first-use accept-new path. Tests cover the refusal in both paths.
  This is the canonical `_lib/ssh.ts` sha for k0s/zfs/libvirt to resync.

## Review ledger: round-6 verification triage (pin keyed by host+port)

- HIGH (TOFU pin keyed by user): the pin record was keyed by host+port+user, so
  a second user on an already-pinned host:port looked like a first use and
  accepted any key. The pin is now keyed by host+port only
  (`connection-h<len>-<host>-p<port>`), matching `known_hosts` semantics and the
  spec's "state is keyed by host"; every user on that host:port is verified
  strictly against the shared pin. Per-user execution evidence keeps the user in
  its key (`exec-…-u<len>-<user>`, `upload-…`). A test pins as one user and
  proves a second user gets strict verification with no scan and no pin rewrite.

## Live finding (cells X5b, X7b) — supplied pin silently replaced by record

- HIGH: under `insecure_tofu` with a recorded pin, `pinnedTarget` overwrote the
  caller's supplied `host_keys` with the record, so a wrong pin or a pin for
  another host connected successfully instead of refusing. Now a supplied set
  must apply to this host/port and match the record exactly; a mismatch or an
  inapplicable set throws `SshConfigError`. Only when no `host_keys` are
  supplied is the record used. Tests mirror X5b (wrong pin + record) and X7b
  (other-host pin + record), and a matching pin proceeds strictly. Live was the
  only thing that caught this; unit tests now cover it. The `_lib/ssh.ts`
  vendored helper is unchanged by this fix.

## Live end-to-end, 2026-10-17 (run sp-20261017)

Folded from the swamp-e2e receipts. The target VPS address is redacted as
`<vps1>`; 192.0.2.1 is the RFC 5737 unreachable probe. Receipt hashes were taken
over the unredacted console output.

Source: lane/d1 head 70b698f (ssh_host.ts sha256 5ff46ece…, _lib/ssh.ts sha256
23074b45…), installed locally into swamp-e2e. Every cell below was run on
70b698f. The earlier 5a0ede5 matrix (11/11 pass) is kept in ssh-host-5a0ede5.md.
Target: shared VPS, user root, key from vault, strict pins from ssh-keyscan. Run
through the model's real entry point (swamp model method run), never --json.
Receipt hash = first 16 hex of sha256 of the run's console output with
timestamps stripped.

| Cell                                              | Result | Detail                                                                                                                                                                                                                                                       | Time (UTC)           | Receipt          |
| ------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------- | ---------------- |
| 1 exec success                                    | PASS   | exit 0, stdout_sha256 == local sha256(hello-e2e)                                                                                                                                                                                                             | 2026-10-17T12:07:53Z | d2007a5a291a62dc |
| 2 exec non-zero                                   | PASS   | exit_code 7 returned as data, run succeeded, no throw                                                                                                                                                                                                        | 2026-10-17T12:07:58Z | 9c849bc9b84bbb8a |
| 3 upload                                          | PASS   | upload sha256 == local; changed=true                                                                                                                                                                                                                         | 2026-10-17T12:08:13Z | 00c4b014c96de4d2 |
| 3b upload read-back                               | PASS   | remote sha256sum + mode 600 read back via exec == local                                                                                                                                                                                                      | 2026-10-17T12:08:19Z | 2d015d8c28352367 |
| 10 idempotent re-run                              | PASS   | console: already current, no write; upload resource version unchanged (before=[v1] after=[v1])                                                                                                                                                               | 2026-10-17T12:08:27Z | d4c35e47d58b2bd7 |
| 4 wait_connection                                 | PASS   | reachable=true                                                                                                                                                                                                                                               | 2026-10-17T12:08:33Z | 1f871f41bf635ad3 |
| 5 strict host-key match                           | PASS   | connects under strict with pinned keys; id -un == root                                                                                                                                                                                                       | 2026-10-17T12:08:38Z | 31e2623c5d57bd8a |
| 6 strict mismatch                                 | PASS   | wrong pin refused: Error: host key verification failed for <vps1>:22; refusing to connect                                                                                                                                                                    | 2026-10-17T12:08:40Z | 213c8fd95ca340e7 |
| 7 unreachable host                                | PASS   | Error: host 192.0.2.1:22 did not answer SSH with acceptable host keys within 5s                                                                                                                                                                              | 2026-10-17T12:08:47Z | 0c472ca9f35a6dc5 |
| 8 auth failure                                    | PASS   | Error: authentication failed for root@<vps1>:22                                                                                                                                                                                                              | 2026-10-17T12:08:50Z | f1e1910b99415e2b |
| 9 injection literal                               | PASS   | ['echo','a;id'] -> stdout == 'a;id\n' (one argv word)                                                                                                                                                                                                        | 2026-10-17T12:08:55Z | 9dae74df1afeff43 |
| 9b injection: $(), backtick, newline, quote-break | PASS   | none created /tmp/swamp-e2e-pwn (test -e exit 1)                                                                                                                                                                                                             | 2026-10-17T12:09:13Z | e2444ab28855a741 |
| X1 over-cap output                                | PASS   | Error: ssh stdout exceeded the 100-byte capture limit                                                                                                                                                                                                        | 2026-10-17T12:09:16Z | 390b4d3f67f21df3 |
| X2 upload onto symlink                            | PASS   | refused; symlink and target intact: Error: upload destination root@<vps1>:/tmp/swamp-e2e-link is a symlink; refusing to follow it                                                                                                                            | 2026-10-17T12:09:27Z | 268a3b5fe36ef418 |
| X3 upload onto directory                          | PASS   | Error: upload destination root@<vps1>:/tmp is a directory                                                                                                                                                                                                    | 2026-10-17T12:09:30Z | 85f7b59ea0eb40ee |
| X4 upload unwritable path                         | PASS   | typed error, no partial file: Error: upload to root@<vps1>:/nonexistent-dir/f failed (exit 1)                                                                                                                                                                | 2026-10-17T12:09:39Z | ff47b381413a31f7 |
| X5 pin for a different host (strict)              | PASS   | refused: Error: host_keys were supplied but none apply to <vps1>:22                                                                                                                                                                                          | 2026-10-17T12:09:41Z | da1b064e4d8fe756 |
| X5b pin for a different host (insecure_tofu)      | FAIL   | insecure_tofu with a supplied pin for another host connected and ran (exit 0); expected refusal. Cause (ssh_host.ts pinnedTarget): with a recorded key the caller host_keys are overwritten by the recorded set, so the supplied pin is ignored, not checked | 2026-10-17T12:09:44Z | 7d70f8d211604375 |
| X6 remote exit 255                                | PASS   | typed transport error, never a remote exit code: Error: ssh transport failed for <vps1>:22 (exit 255)                                                                                                                                                        | 2026-10-17T12:09:47Z | 89a77fc2a2855662 |
| X7a insecure_tofu first contact                   | PASS   | connects, records first key                                                                                                                                                                                                                                  | 2026-10-17T12:09:52Z | a15d6110a24f4987 |
| X7b tofu second run, wrong pin                    | FAIL   | insecure_tofu second run with a deliberately wrong host_keys connected and ran (exit 0); expected refusal. Same cause: recorded keys replace the supplied pin silently                                                                                       | 2026-10-17T12:09:55Z | 15c0a6544d3a638a |
| X7c tofu third run, recorded pin                  | PASS   | still connects with the recorded key                                                                                                                                                                                                                         | 2026-10-17T12:10:00Z | a15d6110a24f4987 |
| X8 wait_connection wrong pin                      | PASS   | Error: host key mismatch for ssh-ed25519                                                                                                                                                                                                                     | 2026-10-17T12:10:03Z | ac911585eb51f320 |

### Summary

21 of 23 cells pass on 70b698f; 2 fail (X5b, X7b), both the same behaviour:
under `insecure_tofu` with a recorded key, a caller-supplied `host_keys` is
silently replaced by the recorded set and never compared, so a wrong or
other-host pin is not refused. `strict` refuses both (6, X5, X8). Not testable
live without rotating the shared VPS's host keys: a recorded key that then
changes. Cleanup: /tmp/swamp-e2e-* test files removed from the VPS; no secret
found in .swamp, receipts or models (grep for private-key armor).

### Re-run on lane/d1 6773984 (ssh_host.ts sha256 599da438…, _lib/ssh.ts 23074b45… unchanged)

| Cell                                     | Result | Detail                                                                           | Time (UTC)           | Receipt          |
| ---------------------------------------- | ------ | -------------------------------------------------------------------------------- | -------------------- | ---------------- |
| X7b tofu + recorded key, wrong pin       | PASS   | [6773984] Error: host key mismatch for ssh-rsa                                   | 2026-10-17T12:14:08Z | fbfb17fbd5dbcdd9 |
| X5b tofu + recorded key, other-host pin  | PASS   | [6773984] Error: host_keys were supplied but none apply to <vps1>:22             | 2026-10-17T12:14:09Z | da1b064e4d8fe756 |
| X9 tofu + recorded key, MATCHING pin     | PASS   | [6773984] connects, exit 0                                                       | 2026-10-17T12:14:17Z | 0b1162b302b33230 |
| X7c tofu, recorded pin, no supplied keys | PASS   | [6773984] still connects                                                         | 2026-10-17T12:14:22Z | a15d6110a24f4987 |
| 6 strict wrong pin (regression)          | PASS   | [6773984] Error: host key verification failed for <vps1>:22; refusing to connect | 2026-10-17T12:14:24Z | 213c8fd95ca340e7 |
| 9 injection literal (regression)         | PASS   | [6773984]                                                                        | 2026-10-17T12:14:29Z | 78df4e4c72511d45 |

Result on 6773984: X5b and X7b now refuse (X7b: "host key mismatch", X5b:
"host_keys were supplied but none apply"); a matching pin with a recorded key
still connects (X9, X7c). Regression cells 6 and 9 pass. With the 70b698f
results for the other 21 cells (transport code in _lib/ssh.ts unchanged between
the two heads, sha256 23074b45…): 23/23.

## Review ledger: final verify (codex astra + terra on 6773984) and merge prep

- No unrefuted Critical/High. terra's HIGH (two concurrent first-use
  `insecure_tofu` calls race on the pin write) is downgraded to MEDIUM under the
  run rulings: it needs distributed locking for a single-orchestrator op, and
  first use is trust-on-first-use by definition.
- Known residuals for the next version: MEDIUM argv has no allowlist grammar
  beyond NUL (quoting is the defence for a generic exec); MEDIUM `ssh-keyscan`
  output is not capped; MEDIUM a Linux target with no `sha256sum`/`shasum` fails
  only after the rename; MEDIUM SHA-256 of low-entropy output or content can be
  guessed; LOW `exec`/`upload` descriptions misstate `return_output` and the
  mode-only path; LOW duplicated known_hosts setup and test fakes.
- Merge prep `9e94c5a`: plain
  `export const model = { ...createModel(), type,
  version } satisfies SshHostModel`,
  because the dry run flagged `uncatalogued-model`. Lanes vendoring this model
  should resync it.

- 2026-10-17: 2026.10.17.2 security fix in the vendored `_lib/ssh.ts`. The
  upload's post-rename verification used to send the content's expected SHA-256
  to the remote script, so it appeared on the local `ssh` argv and the remote
  command line and a process listing could brute-force a low-entropy secret. The
  write script now prints the destination's own SHA-256 and mode after the
  rename and the check runs locally in TypeScript; the probe already worked that
  way. `mv -T`, symlink and directory refusal, and mode convergence are
  unchanged. A test asserts no 64-hex content-derived string appears in any
  spawned argv or script text. Every vendor resyncs to this blob.

## 2026-10-17: 2026.10.17.2 live e2e status and delta review

Delta: only the upload's post-rename verification in `_lib/ssh.ts` changed (blob
fe0139f0…; the remote prints the destination's SHA-256 and mode and the
comparison runs locally). exec, execPipeline, wait_connection, the transport
(`runRemote`), host-key handling and the upload probe are byte-identical to
2026.10.17.1, which is on stable with 23/23 live cells.

| Cell                                                                      | 2026.10.17.2 status                                   |
| ------------------------------------------------------------------------- | ----------------------------------------------------- |
| 3 upload                                                                  | pending re-run on 2026.10.17.2                        |
| 3b upload read-back                                                       | pending re-run on 2026.10.17.2                        |
| 10 idempotent re-run (upload)                                             | pending re-run on 2026.10.17.2                        |
| X2 upload onto symlink                                                    | pending re-run on 2026.10.17.2                        |
| X3 upload onto directory                                                  | pending re-run on 2026.10.17.2                        |
| X4 upload unwritable path                                                 | pending re-run on 2026.10.17.2                        |
| 1, 2, 4, 5, 6, 7, 8, 9, 9b, X1, X5, X5b, X6, X7a, X7b, X7c, X8 (17 cells) | carried from 2026.10.17.1 (PASS); code path unchanged |

The six upload cells must pass on 2026.10.17.2 before it is promoted to stable;
beta allows the pending state.

Delta review (codex astra + terra over e3c0057 against merge-base 63987af; a
first run against origin/main produced a two-dot diff that showed main's newer
commits as deletions and was discarded):

- No unrefuted Critical/High. Triage 4h confirmed: no content-derived 64-hex
  string on any spawned argv or in script text for upload (probe and write),
  exec or execPipeline; `mv -T`, symlink/directory refusal and mode convergence
  unchanged; manifest and model version literals both 2026.10.17.2.
- terra HIGH (upload returns the content SHA-256 in its result and resource):
  refuted as a regression. Behaviour is unchanged from 2026.10.17.1, where it
  was dispositioned as the MEDIUM residual "SHA-256 of low-entropy output or
  content can be guessed"; hashes in place of raw content is the design the run
  rulings require. Carried as that MEDIUM.
- New MEDIUM residual (terra): the post-rename check takes the first stdout
  token, so a target whose forced-command wrapper prints to stdout fails upload
  with "did not converge" after the rename. It fails closed (never a false
  success) and the probe already parsed stdout the same way. Fix: a delimited
  verification record.
- LOW (astra): the exact-hash assertion in the new no-hash-on-argv test is
  subsumed by the 64-hex assertion.

- 2026-10-17: 2026.10.17.2 upload cells re-run live on a throwaway VPS with
  strict pins — 6/6 pass (upload + read-back sha/mode; identical re-upload is a
  no-op with inode, mtime and data version unchanged; mode-only change through
  the temp-file path; symlink, directory and unwritable destinations refused,
  nothing left behind). Security property of this release verified live: while a
  random secret was uploaded three times, process listings sampled on the
  control host (4,502 samples) and the target (1,798 samples, plus execsnoop)
  never showed the secret, its SHA-256 or its base64. Every live cell of the
  matrix now passes on 2026.10.17.2, so it was promoted from beta to stable.

## 2026.10.17.3 — additive exec options

- Extended `exec()` with an optional `{ stdin?, timeoutMs?, maxOutputBytes? }`
  object. No-options calls take the exact pre-extension code path, so the ssh
  argv and the stdout/stderr/exit code are unchanged; a test pins the full ssh
  argv (masking only the transport-internal random known_hosts path).
- `stdin` is streamed to ssh's stdin and never placed on argv. `timeoutMs` kills
  the local ssh (the remote command keeps running; bound it with the remote
  `timeout`) and raises `SshError` with `kind: "timeout"`; a timeout never
  returns partial output. `maxOutputBytes` must be an integer 1..the target's
  `max_output_bytes` and caps stdout only (round 2 below); exceeding it sets
  `truncated: true`, stops reading and kills ssh instead of draining an endless
  writer. `ExecResult` gained `truncated` (the exit code is not meaningful when
  set) and `duration_ms`. Exit 255 is still a transport error unless the result
  was truncated, and no content hash or secret ever reaches argv.
- Real ssh round trip against a throwaway `ubuntu:24.04` sshd (openssh-server,
  pinned host key, key over ssh-agent): `exec` with stdin containing a NUL piped
  to `sha256sum` matched locally; a 64 KiB stdin payload matched; a 128-byte cap
  on `seq 1 100000` returned 128 bytes with `truncated: true` and exit 0;
  `sleep 30` with `timeoutMs: 1500` raised `SshError` kind `timeout`.
- This becomes the new canonical transport; vendors re-vendor it one by one.

### Review round 2 dispositions (3cda9da)

- HIGH: stderr is never truncated. `RunOptions.stderrMaxOutputBytes` bounds it
  at the target's `max_output_bytes` and over that throws, so ssh's own
  diagnostics ("Host key verification failed", "Permission denied", "Connection
  closed") are captured whole and still classify a transport failure; only a
  stdout-cap kill sets `killedForCap`, which is what exempts exit 255. This also
  fixes the `insecure_tofu` first-use case where the "Permanently added" warning
  filled a small cap and killed ssh before the command ran. Verified live: a
  wrong pin with cap 64 and a bad credential with cap 16 throw, and a tofu first
  use with cap 64 runs the command with the 85-byte warning intact.
- MEDIUM: `readCappedStream` rethrows a real read error; only the abort-sourced
  cancel breaks quietly.
- MEDIUM: `upgrades` is a literal array on the exported `model` object (no
  longer inside `createModel()`), so the registry check sees it (dry run free of
  the version-bump warning).
- MEDIUM: stdin is read in the same `Promise.all` as the readers, so a real
  stdin failure is handled immediately rather than becoming an unhandled
  rejection; the race's abort listener is removed in a `finally`.
- LOW: `MAX_EXEC_TIMEOUT_MS`/`assertExecOptions` moved above `exec`'s doc; the
  readers are one `Promise.all` and the redundant `work.catch` is gone.

### Review round 3 (5cc589d) — clean

- conformance-astra, adversarial-terra and tightness-astra rc=0, plus the
  advisory GLM seat (no findings). 0 Critical/High; verdict CLEAN.
- Residual MEDIUM (terra): `maxOutputBytes` caps stdout only. Remote stderr
  cannot be told apart from ssh's own diagnostics, so it stays bounded by the
  target's `max_output_bytes` and throws over it. This is the round-2 design.
  The `ExecOptions` doc and the README now say so.
- LOW (astra): the long-stderr test now uses a 100-byte stdout cap below the
  500-byte stderr. It asserts that the runner gets a separate stderr cap.
- LOW (astra): the stale shared-`UPGRADES` wording in round 2 is corrected.
- tightness-astra: COULD-BE-TIGHTER, about 5 lines. The unused `calls` bindings
  are gone and the stderr loop is shared, both at merge prep.

### Container sshd round trip, 2026-10-17 (5cc589d)

The test target was a throwaway `ubuntu:24.04` openssh-server on 127.0.0.1. It
used a pinned host key and a key over ssh-agent, and was driven through the
vendored `exec()`:

| Cell                                                         | Result                                                         |
| ------------------------------------------------------------ | -------------------------------------------------------------- |
| wrong pin, cap 16/64/4096                                    | throws host key verification failed (3/3)                      |
| bad credential, cap 16/64/4096                               | throws authentication failed (3/3)                             |
| connection killed, cap 16/64/4096, with and without truncate | throws transport failed, exit 255 (6/6)                        |
| `insecure_tofu` first use, cap 64                            | exit 0, command ran, 85-byte "Permanently added" warning whole |
| `yes`, cap 128 / cap 16 + timeoutMs 3000                     | truncated, killed in 336 / 374 ms                              |
| 20 MB stderr flood, no options                               | throws at 10485760 bytes, as before                            |
| 4 KB stderr, target max 1000, cap 64                         | throws at the 1000-byte stderr limit                           |
| 500 B stderr, target max 1000, cap 16                        | exit 0, stderr whole (500 B)                                   |
| stdin with NUL / 4 MiB / 64 MiB                              | remote sha256 matches (3/3)                                    |
| 4 MiB stdin + 8 MB stderr                                    | match, stderr whole, not truncated                             |
| timeout during a 64 MiB / 4 MiB (+ cap) stdin write          | throws `SshError` kind `timeout` at about 2 s (2/2)            |
| no-options echo; remote exit 255                             | same result shape; 255 throws as transport                     |

- Every failure cell throws: pin, credential and kill at each cap (9/9), plus
  kill with truncate (3/3).
- A no-options call spawns ssh with an argv that is byte-identical to the
  fe0139f0 transport (scripted comparison of the old and new `_lib/ssh.ts`).
- On a timeout, only the local ssh is killed. The remote command keeps running
  (as documented); bound it with the remote `timeout` inside a surviving shell.
- `_lib/ssh.ts` stays one file of 1250 lines. Vendors copy it byte for byte and
  check it by blob hash, so it is not split.
