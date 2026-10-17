# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17: initial model (`@randybias/apt-cache`, 2026.10.17.1), clean-room
  build from the approved spec `docs/specs/apt-cache.md` only. Layout mirrors
  the sibling extensions: a model entry point plus `_lib/` helpers, a sibling
  `_test.ts` for every `.ts`, and golden fixtures under `_lib/testdata/`.

## Design decisions

- **Transport seam.** All remote work goes through the vendored, byte-identical
  `_lib/ssh.ts` (blob `fe0139f08c42e3fdae0061b9688fb5c534174957`), whose
  functions take an injectable `CommandRunner`. The model's `AptCacheDeps`
  extends `SshDeps`, so unit tests call model methods with a fake runner and
  never open a socket. No transport logic is hand-rolled here.
- **globalArguments empty.** Every method takes the SSH target and its operands
  per call, and state is keyed by the canonical `{user}@{host}:{port}`, so one
  definition serves a fleet and `host:22` never shares a record with
  `host:2222`.
- **Mutating methods are `kind: "action"`.** `install_server`, `apply_server`,
  `remove_server`, `configure_client` and `unconfigure_client` are actions; a
  method named `delete` would tombstone the whole model.
- **Read-only methods persist an observation.** `render_server`, `get`, `sync`,
  `stats` and `client_get` write a resource, because swamp does not show or
  store a method's `result`. `render_server` is the only one with no target and
  writes a render report.
- **Host-key policy.** `strict` only, with a required non-empty `host_keys`.
  There is no `insecure_tofu`, because the model does not persist first-seen
  keys (RULINGS 4g).
- **Secrets are vault references.** `ssh_key_ref` and `admin_auth_ref` are
  marked `.meta({ sensitive: true })`. The key reaches a short-lived `ssh-agent`
  over stdin and the admin credential is uploaded to `security.conf` over stdin
  (mode 0600, owned by `apt-cacher-ng`). Neither ever appears in argv, logs or
  stored state.
- **In-method preconditions.** Every action re-checks its own preconditions,
  because a workflow gate can be bypassed (swamp lab 3583). `apply_server`
  verifies the service is active and listening after restart; `configure_client`
  reads back `apt-config dump` and rolls back when the managed proxy is not the
  one in force.

## Decisions for Randy's review

The spec allows the simplest safe option when it is silent; these are the
choices made, each with the reason.

1. **Managed filenames sort last (`zzzz-` prefix).** Apt-Cacher NG reads every
   `*.conf` in `/etc/apt-cacher-ng/`, and the Debian package generates
   `zz_debconf.conf` whose `PassThroughPattern` can be `.*`. The managed
   fragment is `zzzz-apt-cache.conf` and each backend is
   `zzzz-apt-cache-backend-<key>`, so they load after both and the last
   assignment wins. A `zzz_override.conf` example in the package sorts before
   `zzzz-`.
2. **`PassThroughPattern` is always rendered explicitly**, even for `direct` and
   `https_backends`, pinning the upstream default
   (`^(bugs\.debian\.org|changelogs\.ubuntu\.com):443$`). Rendering it only for
   `passthrough` would leave a broader value from an earlier run in force. A
   passthrough allowlist is anchored and escaped, so `.*` cannot be expressed.
3. **Backends are rendered from the distro key, and the scheme follows the
   policy.** For `direct` and `passthrough` the backend URL must be `http`; for
   `https_backends` it must be `https`. Credentials, a query string, a fragment
   and an explicit port are refused.
4. **`install_server` adopts an already-installed package.** It answers the
   debconf tunnel prompt `false` before installing and reads back the version
   either way, so a re-run is a no-op and the recorded state is accurate.
5. **`remove_server` needs `confirm_host` and a separate `purge_cache_ack`.**
   `confirm_host` must equal the SSH host, so a mistyped host cannot purge the
   wrong server; the cache directory is deleted only with the ack, matching the
   spec's "the cache is data, not configuration" note.
6. **Report-page window is matched by its row label.** `stats` reads the
   rendered `acng-report.html` and finds the row whose label contains the
   requested window (`today`, `7 days`). It fails closed on a page with no
   matching row, so an upstream template change is a typed error, not a silent
   zero.
7. **Client fallback is a tiny static script.** `fallback_direct` writes
   `/usr/local/lib/apt-cache/proxy-detect` and points
   `Acquire::http::Proxy-Auto-Detect` at it; the script probes the proxy with a
   two-second `/dev/tcp` timeout and prints the proxy URL or `DIRECT`. Nothing
   from the input is interpolated unquoted.
8. **Client policy is checked against recorded servers.** `configure_client`
   looks up a recorded server whose `host` or `listen` covers the proxy host and
   refuses a client policy that disagrees, so a client cannot be pointed at a
   server that cannot serve its HTTPS mode.
9. **`stats` reads the request log.** The log directory is the package default
   (`/var/log/apt-cacher-ng`); the model does not set `LogDir`. See the round-1
   fix below for why the report page is not used.
10. **`ci:false` and no `published` entry.** This is the first commit of the
    version; it has not been pushed, so the release stanza records only
    `channel: beta` and `ci: false`.

## Round 1 review fixes (2026-10-17)

Every item from the round-1 review is fixed and covered by a test. The two
behavioural regressions that motivated the review were reproduced live first.

- **Remap syntax (HIGH).** apt-cacher-ng reads
  `Remap-<key>: <url-pattern> ;
  <target>`; the pre-fix line put the backend
  file in the pattern slot, so a `/ubuntu-ports` request never reached a mirror.
  Live against apt-cacher-ng 3.7.4 (`acng-d5` image): the pre-fix fragment
  returns 503 for `/ubuntu-ports/dists/noble/Release`; the fixed
  `Remap-<key>: /<key> ;
  file:<backend>` returns 200 with a real proxied body.
  Golden updated.
- **Cache deleted without ack (HIGH).** `apt-get purge` runs the package's
  `postrm`, which `rm -rf`s `/var/cache/apt-cacher-ng`. `remove_server` now runs
  `apt-get remove` unless `purge_cache_ack` is set, honours a `cache_dir`
  argument, and deletes the cache only with the ack, only when it is a real
  directory (a symlink is refused). Exit codes are checked; state is written
  last.
- **Proxy URL grammar (HIGH).** `new URL` accepts host characters such as
  `$ ( ) { } , ; & \`
  "`; a`http://x$({touch,pwned})y:3142`proxy rendered an
  auto-detect script that ran the command as root.`parseProxyUrl`now checks
  the raw string against`http://<ipv4|[ipv6]|dns-1123
  fqdn>:<port>`before any
  URL parsing, the address is passed to`bash -c` as an
  argv word rather than interpolated, and both payloads are regression tests.
- **Fallback dir and rollback (HIGH).** `configure_client` now creates the
  auto-detect directory (`0755`), uploads the script before the snippet, and
  rolls both back on any failure.
- **Client credential leak (HIGH).** `client_get` stores only
  `Acquire::(http|https)::Proxy*` keys with userinfo stripped, never the whole
  apt config.
- **`stats` on a real page (HIGH).** The report page's log-analysis table is
  empty until an operator clicks `Count Data`, so parsing it never worked live.
  `stats` now reads `apt-cacher.log` directly and derives the report's totals
  (`reqMax = max(I, O)`, `dataMax = max(byteIn, byteOut)`), matching upstream
  `GetStats`, and fails closed on an unrecognised log. The fixture is a real log
  sample.
- **Listen verify (MEDIUM).** `apply_server` requires the exact parsed
  `address:port` pair from `ss -ltn`; the port-only fallback is gone.
- **Wildcard normalisation (MEDIUM).** IPv6 spellings (`::0`, `0:0:0:0:0:0:0:0`,
  `[::]`) are normalised, so `listen_any_ack` is required.
- **Resource names and render record (MEDIUM).** Records are named from the
  target `{user, host, port}`, not the host alone; `render_server` writes its
  own `render` spec and never clobbers the `server` record.
- **Policy check (MEDIUM).** The `queryData` predicate is scoped to
  `modelType == "@randybias/apt-cache" && specName == "server"`; a missing or
  failing query API now refuses unless `policy_check_ack=true`.
- **Full client verify (MEDIUM).** `configure_client` verifies every managed key
  (`Acquire::http::Proxy`, `Acquire::https::Proxy`, each bypass and
  `Proxy-Auto-Detect`) from `apt-config dump`, not just the HTTP proxy.
- **Tests (MEDIUM).** Added a plain-object `context.vaultService` test, a real
  `apt-config` check of the rendered snippet, real-tool log-sample tests, and
  the injection payloads.
- **Backend URL grammar (LOW).** `isBackendUrl` is a raw-string allowlist, so a
  trailing `#`, `;` or an explicit `:80` is refused.

## Round 2 review fixes (2026-10-17)

- **`https_backends` did not fetch over TLS (HIGH).** A path-only
  `Remap-<k>:
  /<k>` only matches path-style requests; the proxy-style requests
  apt sends (`GET http://ports.ubuntu.com/ubuntu-ports/...`) missed it and went
  upstream on port 80. Measured in the `acng-d5` image with `--network none` and
  host override listeners:
  - `Remap-ubuntu-ports: /ubuntu-ports` → proxy-style hit port 80.
  - `... : /ubuntu-ports ports.ubuntu.com/ubuntu-ports` → hit port 443.
  - `debian-security` with an own remap → still hit port 80 for both styles: the
    built-in `Remap-secdeb` owns those prefixes with inline http backends, and
    neither a second `Remap-` (it appends) nor the inline backend can be
    overridden.
  - Overwriting `/etc/apt-cacher-ng/backends_debian` with the https URL →
    `Remap-debrep` (which reads that file) fetched over 443 for both styles.
    Design: manage the built-in backend files for `debian` and `ubuntu`, render
    an own remap (path + client host/path prefix) for `ubuntu-ports`, and refuse
    `debian-security` (its configured mirror would be silently ignored). A
    guarded docker test asserts 443 and never 80 for both styles and both
    supported keys.
- **`client_get` still persisted credentials (HIGH).** Redaction now handles any
  `<scheme>://` (socks5h included), strips up to the LAST `@` before the first
  `/`, and is tested with `socks5h://`, a double `@`, and an upper-case scheme.
- **`cache_dir` could delete a system directory (HIGH).** `assertCacheDir` now
  rejects `.`/`..` components, `//`, shallow paths and the system top-level
  roots (`etc`, `usr`, `home`, ...), and `remove_server` requires the path to
  match the live fragment's `CacheDir` or the recorded server `cache_dir`.
- **`fallback_direct` tolerated a mismatch (MEDIUM).** A key mismatch and a
  failed `apt-get update` are now always failures, with the prior state
  restored.
- **Rollback deleted a working snippet (MEDIUM).** `configure_client` snapshots
  both managed files and restores them on failure, instead of always deleting.
- **Unknown typed log rows defeated fail-closed (MEDIUM).** Only `I`, `O`, `E`
  and the documented misc rows `M` and `X` count as recognised; `1|Z|100` now
  trips the fail-closed check.
- **`stats` under-counted after rotation (MEDIUM).** It reads the current log
  and the rotated `.1` and `.N.gz` files (logrotate: `size 10M`, `rotate 7`,
  `delaycompress`), gzip-decompressing as needed.
- **A prior plain remove blocked a later purge (MEDIUM).** `remove_server`
  treats `deinstall ok config-files` as present so a later call with
  `purge_cache_ack` purges the package and deletes the cache.

## Quality pass and round-2 follow-ups (2026-10-17)

**Split by concern.** `apt_cache.ts` fell from 1624 to a 158-line registry; the
code now lives in `_lib/schemas.ts` (argument and state shapes),
`_lib/remote.ts` (dependency seam, naming, host read/write, parsers),
`_lib/server_methods.ts`, `_lib/client_methods.ts`, and the pure `_lib/apt.ts`.
Every file is under 800 lines and every function under 80. Test doubles moved to
`_lib/test_support.ts`, shared by the model tests and the new
`_lib/remote_test.ts`.

**One quoting helper.** The private `shQuote` in `apt.ts` was replaced by the
vendored transport's `posixQuote`; every remote shell string now uses it.

**Managed backend files are backed up and restored.** `apply_server` now writes
every managed file through `writeManagedFile`, which saves a pre-existing file
to `<path>.apt-cache.bak` once and records the SHA-256 of the bytes written in
the server resource's `managed_files`. `remove_server` calls
`removeOrRestoreManaged`: it restores the backup or deletes the file only when
the current digest still equals the recorded one, and otherwise leaves the file
untouched (an admin edit) and warns. So overwriting the package's
`backends_debian`/`backends_ubuntu` is reversible, and a file the model did not
write is never deleted.

**README.** The routing section now states that `security.ubuntu.com` is not a
`Remap-uburep` prefix, so under `https_backends` a proxy-style request for it
still goes upstream on plain HTTP (:80) and is not cached.

**Cache guard.** `assertCacheDir` also refuses the whole paths `/var/lib`,
`/var/log` and `/var/cache` as the configured server path, in addition to the
system top-level roots.

**Log rotations.** `renderLogReadScript` reads the current log, `.1`, and the
compressed `.2.gz`… set (so a stray `.1.gz` beside `.1` is never double counted)
and exits non-zero on a corrupt gzip, so `stats` fails closed instead of
silently undercounting. Covered by a test that writes real and gzipped
rotations.

**Client restore.** `restoreClient` checks the exit status of its `rm`, like its
uploads.

## Round-2 delta review fixes (2026-10-17)

- **A second apply backed up the model's own output (HIGH).** `writeManagedFile`
  now skips the backup when the file is absent, when its digest equals the
  content about to be written, or when it equals the prior digest recorded for
  that path (`priorSha`). Only a pre-existing file the model did not write is
  saved to `<path>.apt-cache.bak`. `remove_server` then deletes the model's own
  files and restores the originals; the double-apply case is covered by a test
  built on the new in-memory `boxFake`.
- **Ownership records were lost (HIGH).** `install_server` carries the prior
  `managed_files` map forward instead of dropping it, and `apply_server` reads
  the prior map, passes each path's previous digest to `writeManagedFile`, and
  guarded-removes/restores any path this apply no longer writes (a dropped
  backend key, or dropped `admin_auth_ref`). So `remove_server` no longer keeps
  an old fragment or admin credential forever.
- **`unconfigure_client` ignored `rm` (HIGH).** Both `rm` calls are checked and
  the snippet's absence is verified before state is written.
- **Recorded paths had no allowlist (MEDIUM).** `removeManagedFiles` only ever
  touches the fixed managed set (`FRAGMENT_PATH`, `SECURITY_CONF_PATH`, and the
  `listManagedConfNames()` files); a tampered record cannot name an arbitrary
  remote path.
- **`remoteSha` conflated absence with failure (MEDIUM).** A failed `sha256sum`
  on a file that exists now throws; only a confirmed-absent (`test -e` rc 1)
  path returns null. This stops a failed probe from overwriting a backup or
  reporting a still-present file as removed.
- **Test file over 800 lines (MEDIUM).** `apt_cache_test.ts` was split into
  `_lib/server_methods_test.ts` and `_lib/client_methods_test.ts`, sharing
  `_lib/model_test_support.ts` (fixtures plus a context that makes writes
  readable) and `_lib/test_support.ts` (which gained the stateful `boxFake`).
- **Corrupt rotation error (LOW).** `stats` maps the log reader's exit 4 to a
  distinct `log_corrupt` code.

## Fixtures

- All addresses are RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`) or the IPv6
  documentation prefix `2001:db8::/32`; names are `example.com` or `.test`; the
  key and password are placeholder strings.
- `_lib/testdata/apt-cacher.log.txt` is the real log shape (`<time>|I|<bytes>`
  and `<time>|O|<bytes>`, with optional `|client|path` fields, plus a `misc`
  row) with synthetic values. The server and client goldens are produced by the
  renderers and the Remap shape is checked against real apt-cacher-ng.

## Live end-to-end status

- Offline gates plus targeted real-tool checks, no full end-to-end run yet, so
  this version is `beta` and `ci: false`. Beyond the unit tests: the fragment
  served a real `/ubuntu-ports` request through apt-cacher-ng 3.7.4 (200 vs the
  pre-fix 503), `apt-config` accepted the snippet and reported every key, the
  auto-detect script ran under `sh -eu` and printed the proxy URL or `DIRECT`,
  and the log parser read a real request log. Planned live run on one
  Debian/Ubuntu host: install and adopt, apply with each policy, verify with
  `get`/`sync`/`stats`, point a second host at it and check a real package
  fetch, then `remove_server` with and without `purge_cache_ack`.

## Round 5 (delta d256e1a review)

- HIGH: dropping admin_auth_ref (or a backend key) restored/removed the file but
  never restarted apt-cacher-ng, so the daemon kept enforcing the old
  credential. A dropped path that changed on disk now triggers the restart, and
  the apply verifies the live daemon: an unauthenticated read-only admin request
  (`/acng-report.html?doCount=Count+Data`, measured against apt-cacher-ng 3.7.4:
  401 with AdminAuth loaded, 200 without; the report page itself is not gated)
  must be refused after setting admin_auth_ref and must not be refused after
  dropping it and deleting the file. A restored admin file is not asserted on.
- MEDIUM: one `managedPaths()` allowlist feeds both the dropped-path cleanup and
  remove; a recorded path outside it is ignored.
- MEDIUM: `writeManagedFile` backs up a pre-existing file even when its bytes
  equal the new ones (remove gives it back instead of deleting it).
- MEDIUM: one `write()` helper replaces three repeated writeManagedFile calls.
- Tests: restart after dropping only admin_auth_ref or a backend key, a daemon
  that never reloads fails the apply, tampered record paths, remoteSha failure
  paths, unconfigure_client with a failing rm, log_corrupt code; the ownership
  tests moved to `server_ownership_test.ts`; test_support dedupes agent replies,
  upload bytes and response normalisation.

## Round 6 (live: fresh Cherry Ubuntu 24.04)

- HIGH: install failed with "Unable to locate package" on the stock image (no
  package lists). `install_server` runs a bounded `apt-get update` first (300 s,
  30 s per fetch); its error is surfaced.
- HIGH: the package starts apt-cacher-ng on 0.0.0.0 and [::] straight after
  install, an open proxy on the public address until apply_server. The
  loopback-only bootstrap fragment (`BindAddress: 127.0.0.1`, sorted after
  acng.conf) is written BEFORE the package is installed and recorded as the
  model's own, so apply_server replaces it and remove deletes it. After install
  `ss` must show no wildcard listener on 3142, else the daemon is stopped and
  the install fails with `open_listener`. Checked in a fresh ubuntu:24.04 with
  stale lists, running the model's argv: the listeners ever seen during install
  and first start were 127.0.0.1:3142 only; the same flow without the fragment
  showed 0.0.0.0:3142 and [::]:3142. (A policy-rc.d deny was not used: it would
  leave an enabled service that starts open on the next boot.)
- LOW: unconfigure_client removes the script directory when empty.
