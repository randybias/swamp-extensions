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
9. **`stats` reads the report over loopback** (`http://127.0.0.1:<port>`) using
   the port from the recorded server state, so it never depends on the public
   listen address.
10. **`ci:false` and no `published` entry.** This is the first commit of the
    version; it has not been pushed, so the release stanza records only
    `channel: beta` and `ci: false`.

## Fixtures

- All addresses are RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`) or the IPv6
  documentation prefix `2001:db8::/32`; names are `example.com` or `.test`; the
  key and password are placeholder strings.
- Report-page fixture `_lib/testdata/report-page.txt` reproduces the real
  template's log-analysis table shape with synthetic counts. The server and
  client goldens are produced by the renderers themselves.

## Live end-to-end status

- Offline gates only so far; no live pass yet, so this version is `beta` and
  `ci: false`. Planned live run on one Debian/Ubuntu host: install and adopt,
  apply with each policy, verify with `get`/`sync`/`stats`, point a second host
  at it and check a real package fetch, then `remove_server` with and without
  `purge_cache_ack`.
