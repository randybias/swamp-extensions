# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

## Registry evaluation (before building)

Searched the registry for Syncthing or generic file-sync peering:

- No `syncthing` package exists at all.
- `@wendy/rsync` is an rsync src→dst model, not Syncthing and not a peering
  primitive.
- `@mgreten/github-file-track` and `@sntxrr/scaleway-file-storage` are
  unrelated.

Decision: build a thin generic model, vendoring the canonical `_lib/ssh.ts` from
`ssh-host` (blob `cb61c4adfbedee0a6c9914deae52d3864d5a1afb`) for the remote
transport.

## Notes

- 2026-10-17: initial release. Access is either `local` (injectable fetch to the
  loopback API) or `ssh` (curl on the host). The API key is sent only in the
  `X-API-Key` header: locally in memory, remotely inside a `curl --config` file
  uploaded over stdin to a mode-0600 temp file and removed afterwards. The key
  never appears on an argv, in a URL, in a log or in stored state.
- Loopback policy: plain HTTP only on `localhost`/`127.0.0.0/8`/`::1`; any other
  origin must be HTTPS.
- State is keyed by `sha256(node, api_url)` (32 hex chars), with device and
  folder records appended by a length-prefixed id — not fnv.
- `ensure_*` re-read after the PUT and refuse when the config did not converge;
  `remove_*` re-read and refuse when the config is still present, so a partial
  API effect is never recorded as success.
- Live testing runs later on two throwaway VPS: ensure a device and folder on
  node A, verify idempotence, then remove, with the second node used to confirm
  the declaration from the other side.
