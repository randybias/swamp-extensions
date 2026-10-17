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
