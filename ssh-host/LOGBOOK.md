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
