# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

## Naming and visibility

Answers to the five naming questions (naming and visibility convention, §3):

visibility: public audience: general

1. Private or public? Public: published to swamp-club with public visibility,
   source in this repo.
2. Individual or general? General: any operator running Syncthing nodes; no
   environment, host or deployment is baked in.
3. Does the name clearly describe and disambiguate while staying short? Yes:
   `syncthing-peer` is the product plus the resource it manages, a peer device
   and the folder shared with it, in two segments. Judged "keep" in the run
   sp-20261017 naming audit.
4. Private purpose check: not applicable (public).
5. Would a stranger guess roughly right and wrong about nothing? Yes: it peers
   Syncthing nodes. It does not install Syncthing or manage its global options,
   and the name does not suggest that it does.

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

## 2026-10-17 live e2e

Run sp-20261017 on 3f038b4, swamp 20261013.025835.0. Two throwaway VPS nodes,
`<vps3>` (A) and `<vps4>` (B), Ubuntu archive `syncthing 1.27.2~ds4` run as a
dedicated system user under the packaged `syncthing@` unit, GUI/API on loopback
:8384 only. Transport `access=ssh`, `host_key_policy=strict` with pinned keys.
Each node's API key went from its config.xml over ssh stdout straight into the
vault through stdin; `api_key` and `private_key` were vault references only and
no run used `--json`.

| Cell                                        | Result      | Detail                                                                                                                                             |
| ------------------------------------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 get/sync both nodes                       | PASS        | `reachable true`, `present`, my_id and counts; node record holds the normalized api_url                                                            |
| 2 ensure_device A->B, B->A, repeat          | PASS        | first runs `changed true`, peer name and `tcp://<peer>:22000` address on each side; repeats `changed false`                                        |
| 3 ensure_folder both + real sync            | PASS        | first runs `changed true`, repeats `changed false`; a 64 KiB random file written on A appeared on B with identical size and sha256 after 11 s      |
| 4 label change is a PATCH                   | PASS        | out-of-model fields (rescanIntervalS, order, fsWatcherDelayS) and both device ids survived the label change; repeat `changed false`                |
| 5 remove_folder / remove_device, repeat     | PASS        | each `changed true`, `removed`, absent on the host API; second round all `changed false`, `not_found`, rc 0                                        |
| 6 folder id `..` refused before any request | PASS        | rc 1 with the folder_id grammar error; sshd on A saw no connection in the window                                                                   |
| 7 wrong API key                             | PASS (note) | get/sync: `system status returned 403`, typed `SyncthingError`, rc 1, no record written (not recorded as unreachable); ensure_device: 403 likewise |
| 8 Syncthing stopped on B                    | PASS        | sync `timeout_s: 5`: `reachable false`, `unreachable` (curl exit 7); a listener that never answers gave curl exit 28 within the timeout; restarted |
| 9 host-key mismatch                         | PASS        | B's pins for A's address: `host key verification failed`, rc 1, sync rethrows; sshd logged only preauth closes                                     |
| 10 argv scan + no leftovers                 | PASS        | ps sampled every 50 ms on control, A and B during cells 2-5: 0 hits for keys, substrings or their sha256 (positive control hit); cache dirs empty  |
| 11 workflows                                | N/A         | the extension ships no workflows                                                                                                                   |

Result 10/10 applicable cells PASS, 0 FAIL, 0 BLOCKED. Both nodes were purged
(package, unit, user, cache) and the vault emptied afterwards.

- 2026-10-17 (merge-prep, main): review CLEAN at 9f46ceb (rounds 7ecc8c8,
  863cdf3, 9f46ceb); the 3f038b4 polish (timeouts, `isUnreachable`, DELETE 404,
  URL normalization, label allowlist) was self-reviewed at merge-prep with no
  Critical/High. Residuals:
  - LOW (fixed at merge-prep, message only): a 401/403 now reads
    `... returned 403 (the API key was rejected)` instead of a bare status (live
    cell 7 note); unit test asserts the wording.
  - LOW (open): remote curl stderr is passed into errors as its last line,
    capped at 200 characters; earlier lines are dropped.
  - LOW (open): no `docs/specs/` spec exists for this extension.

## 2026.10.17.2 — re-vendor transport, stream the key on stdin

- Re-vendored `_lib/ssh.ts` and `_lib/ssh_test.ts` byte-identical from
  `@randybias/ssh-host` 2026.10.17.3 (blob
  `8f132c4329c9e64bed686731cd5a0e02980194ea`), which adds optional
  `exec(argv, { stdin, timeoutMs, maxOutputBytes })`.
- Dropped the remote temp-file workaround: the curl config (which carries the
  `X-API-Key` header) is now streamed to `curl -q --config -` on stdin, so no
  secret byte reaches remote disk. The 0700 `~/.cache/syncthing-peer/`
  directory, the random `*.curlrc` upload, the stale sweep and the trap-based
  cleanup are all gone. A dropped session cannot strand the key because there is
  no file to strand.
- The remote command text changed from
  `sh -c 'trap ...; curl -q --config "$1"' sh <path>` to `curl -q --config -`,
  which is the whole point: the config is stdin, not a path. Every non-secret
  behaviour (URL/key/body config, redirect refusal, GET/PUT/PATCH, timeout,
  status parsing) is unchanged. A recording-runner test asserts the config is on
  stdin, the key is on no argv, and no
  `mktemp`/`curlrc`/`umask`/cache-dir/`rm -f` command is ever issued.
- Remote steps carry `timeoutMs` = curl's `max-time` plus 5 s, so curl is the
  one that stops first and the local ssh does not kill a request early.
- Inputs and the REST contract are unchanged, so the `upgrades[]` entry is a
  no-op.

## 2026-10-17 live e2e (2026.10.17.2)

Run sp-20261017 on 2ef94b9, swamp 20261013.025835.0, model typeVersion
2026.10.17.2. Two throwaway VPS nodes, `<vps5>` (A) and `<vps6>` (B), Ubuntu
archive `syncthing 1.27.2~ds4` as a dedicated system user under the packaged
`syncthing@` unit, API on loopback :8384 only. Transport `access=ssh`,
`host_key_policy=strict` with pinned keys. API keys went from config.xml over
ssh stdout into the vault on stdin; `api_key` and `private_key` were vault
references only and no run used `--json`.

| Cell                                        | Result | Detail                                                                                                                                                     |
| ------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 get/sync both nodes                       | PASS   | rc 0, `reachable true`, `present`, device and folder counts                                                                                                |
| 2 ensure_device A->B, B->A, repeat          | PASS   | first runs `changed true`, peer name and `tcp://<peer>:22000` on each side; repeats `changed false`                                                        |
| 3 ensure_folder both + real sync            | PASS   | first runs `changed true`, repeats `changed false`; a 64 KiB random file written on A appeared on B with identical size and sha256 after 15 s              |
| 4 label change is a PATCH                   | PASS   | out-of-model fields (rescanIntervalS, order, fsWatcherDelayS) and both device ids survived the label change; repeat `changed false`                        |
| 5 remove_folder / remove_device, repeat     | PASS   | each `changed true`, `removed`; second round all `changed false`, `not_found`, rc 0                                                                        |
| 6 folder id `..` refused before any request | PASS   | rc 1 with the folder_id grammar error; sshd on B saw no connection in the window (positive control after)                                                  |
| 7 wrong API key                             | PASS   | `system status returned 403 (the API key was rejected)`, rc 1, no record written; the earlier wording note is resolved                                     |
| 8 Syncthing stopped on B                    | PASS   | sync `timeout_s: 5`: `unreachable` (curl exit 7); a listener that never answers gave curl exit 28 within the timeout; restarted, `reachable true`          |
| 9 host-key mismatch                         | PASS   | B's pins for A's address: `host key verification failed`, rc 1                                                                                             |
| 10 argv scan                                | PASS   | ps every 50 ms on control, A and B: 0 hits for keys, substrings or their sha256 (positive control hit); the only remote command was `curl -q --config -`   |
| 11 no remote file written (new)             | PASS   | no cache dir, `*.curlrc` or upload temp file appeared on either host during or after the run; a content scan of every new file found no API key            |
| 12 hostile folder label (new)               | PASS   | a label with quotes, backslashes and a `url = http://example.invalid` line was stored verbatim (byte-equal read-back); all 6 requests went to the loopback |

Result 12/12 PASS, 0 FAIL, 0 BLOCKED. Both nodes were purged (package, unit,
user) and the vault emptied afterwards.

- 2026-10-17 (merge-prep, main): review CLEAN at 2ef94b9, including a
  hostile-label curl-config test against real curl. Residuals:
  - LOW (open): after a local timeout the remote curl keeps running until its
    own `max-time` stops it; it is bounded by curl, not killed by the model.
  - LOW (open): remote curl stderr is passed into errors as its last line,
    capped at 200 characters; earlier lines are dropped.
  - LOW (open): no `docs/specs/` spec exists for this extension.
