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
- 2026-10-17: offline gates 0-6 pass. Live e2e matrix and adversarial review are
  run by the lead; record every finding and fix here.
