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

## Review round 1

- HIGH: `FOLDER_ID_RE` accepted `.` and `..`, which dot-segment resolution turns
  into `/rest/config`, so a `..` folder id could replace the whole node config.
  The grammar now requires a leading alphanumeric, rejecting both.
- HIGH: `insecure_tofu` was offered without persisting the first-seen key. It is
  dropped; the SSH transport is strict-only and `host_keys` is required.
- HIGH: `ensure_folder` could never converge because Syncthing adds the node's
  own device to every folder. `folderMatches` now ignores the node's `myID` on
  both sides and stored state keeps the observed read-back (`folderSpecOf`).
  Fixtures model the normalized read-back.
- HIGH: the remote key file could leak or collide. It now has a random name
  under a 0700 `~/.cache/syncthing-peer/` directory, is uploaded inside the try,
  and curl plus its trap cleanup run in one remote shell; stale configs are
  swept before each upload.
- MEDIUM: the local fetch uses `redirect: "manual"` and refuses a 3xx.
- MEDIUM: an existing device or folder is updated with `PATCH`; `PUT` creates.
- MEDIUM: `sync` rethrows a configuration, host-key or auth (401/403) failure
  and records `unreachable` only for a connect or timeout failure.
- MEDIUM: device addresses must be exactly `dynamic` or a tcp/quic/relay
  host:port URL; names and labels reject control characters.
- LOW: removed the dead `errorText`/`checkResult`/`isNotFound` helpers and the
  unused `Reply`; `get` and `sync` share one `observe` path.

## Review round 2

- HIGH: the remote key-file directory is now verified, not assumed. The prepare
  shell runs under `umask 077`, refuses a symlinked or foreign-owned directory,
  forces mode 700 and checks it with `stat`, chains the stale sweep, and prints
  the directory only on success; a non-zero prepare exit aborts before any
  upload (tested).
- MEDIUM: remote `curl` runs with `-q` first, so `~/.curlrc` cannot make it
  follow redirects or skip TLS checks; the config pins `proto = "=http,https"`,
  and a 3xx response is refused on the remote path too.
- MEDIUM: `sync` now treats only a connect or timeout failure (SshError "could
  not connect"/"ssh transport failed", curl exit 6/7/28, or a fetch `TypeError`)
  as `unreachable`; an HTTP 500, a refused redirect, a TLS failure and
  everything else are rethrown (500 and curl-exit-60 tested).
- MEDIUM: `isDeviceAddress` parses the host and port structurally, rejecting
  userinfo, query, an extra colon and a port outside 1-65535.
- LOW: test fixture uses `https://evil.test`; `remove_folder` records the
  observed device list without the node's own `myID`, matching `ensure_folder`.

## Final polish

- MEDIUM: `isUnreachable` no longer treats every `TypeError` as unreachable; it
  classifies only a connection-refused, DNS or timeout failure by message/cause,
  and rethrows a code error.
- MEDIUM: requests are bounded. `timeout_s` (default 30) drives
  `AbortSignal.timeout` on the local fetch and `--max-time`/`--connect-timeout`
  in the remote curl config.
- MEDIUM: a DELETE that returns 404 is treated as already gone and absence is
  still confirmed.
- MEDIUM: the API URL is normalized (lowercased host, no trailing slash) before
  keying state, so `.../` and `...` share one record.
- LOW: curl and prepare stderr pass into errors as the last line, capped at 200
  characters; labels are checked against a printable-ASCII allowlist.
