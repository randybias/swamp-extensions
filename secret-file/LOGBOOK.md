# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

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
