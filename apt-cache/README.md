# @randybias/apt-cache

[Swamp](https://github.com/swamp-club/swamp) extension for running a caching apt
proxy ([Apt-Cacher NG](https://www.unix-ag.uni-kl.de/~bloch/acng/)) on one Linux
host over SSH and pointing apt clients at it. It installs and configures the
server, renders one managed configuration fragment plus per-distribution mirror
backend files, writes a managed apt snippet on each client, reports cache
hit/miss and byte statistics, and removes what it created.

One model type serves both the server and its clients: the SSH target and every
operand arrive per call, so a single definition can drive a fleet and never
shares one host's state with another.

## Models

### `@randybias/apt-cache`

State is keyed by the canonical `{user, host, port}` target. Server records are
written by `install_server` and `apply_server`; client records by
`configure_client`; every read-only method writes an observation resource,
because swamp does not persist a method's `result`.

| Method               | Kind      | Description                                                                                                 |
| -------------------- | --------- | ----------------------------------------------------------------------------------------------------------- |
| `install_server`     | action    | Install apt-cacher-ng non-interactively, or adopt it when already installed, and read its version           |
| `render_server`      | read-only | Render the managed fragment and backend files for the given inputs without touching a host                  |
| `apply_server`       | action    | Write the fragment, backends and optional admin auth, restart, and verify the service and its listen socket |
| `remove_server`      | action    | **DESTRUCTIVE.** Stop, disable and purge apt-cacher-ng and remove the managed files; cache only with an ack |
| `get`                | read-only | Read service state, listen sockets, config digest, cache size and filesystem free space                     |
| `sync`               | read-only | Re-render and compare with the live fragment; flag an edited file or a widened `PassThroughPattern`         |
| `stats`              | read-only | Read the request log for hit/miss counts and bytes over a window, plus cache size and free space            |
| `configure_client`   | action    | Write the managed apt snippet (and optional auto-detect script) on a client and verify it                   |
| `client_get`         | read-only | Report the effective `Acquire::*::Proxy` values, whether the managed snippet is in force, and conflicts     |
| `unconfigure_client` | action    | Remove the managed snippet and auto-detect script and verify apt no longer uses the managed proxy           |

## The HTTPS policy is required and has no default

Apt clients fetch `Release` and package metadata over plain HTTP but list
`https://` mirror URLs on newer releases. There is no single safe default, so
every server and client method requires `https_policy`:

- `direct` — clients fetch HTTPS directly and the proxy serves only HTTP. The
  server's `PassThroughPattern` is pinned to the upstream default
  (`bugs.debian.org`, `changelogs.ubuntu.com`); backends must be plain `http`.
- `passthrough` — the proxy tunnels named hosts over HTTPS. `passthrough_hosts`
  is required and must be a non-empty list of DNS names; each is matched
  anchored and escaped, so a `.*` pattern is impossible. Backends are plain
  `http`.
- `https_backends` — the proxy fetches HTTPS mirrors itself. Backends must be
  `https` URLs.

`PassThroughPattern` is always rendered explicitly, even for `direct` and
`https_backends`, so a broader value left in place by an earlier run or package
default cannot remain in force.

### How the mirrors are routed

Apt sends **proxy-style** requests when it uses the proxy
(`GET
http://ports.ubuntu.com/ubuntu-ports/...`), and path-style requests only
when a client requests the cache by path. The routing follows the package's own
remaps, because a second `Remap-` for a key only appends to that repo:

- `debian` and `ubuntu` are served by the package's built-in `Remap-debrep` and
  `Remap-uburep`. The model writes their backend files
  (`/etc/apt-cacher-ng/backends_debian`, `backends_ubuntu`) so both proxy-style
  and path-style requests use the configured mirrors (over TLS under
  `https_backends`).
- `ubuntu-ports` has no built-in remap, so the model renders
  `Remap-ubuntu-ports: /ubuntu-ports ports.ubuntu.com/ubuntu-ports ; file:...`
  with both the path and the client host+path prefix.
- `security.ubuntu.com` (the Ubuntu security pocket) is not one of the
  `Remap-uburep` prefixes, so it cannot be remapped. Under `https_backends` a
  proxy-style request for it still goes upstream on plain HTTP (:80) and is not
  cached; use `passthrough` with it in `passthrough_hosts` if it must be
  tunnelled.
- `debian-security` is **refused**: the package's built-in `Remap-secdeb`
  already owns every `debian-security` prefix with inline `http` backends, and a
  managed mirror would be silently ignored. Configure it in the package's own
  `acng.conf` instead.

`ss -ltn` verification requires the exact parsed `address:port` pair, and the
managed fragment uses a `zzzz-` prefix so it loads after `acng.conf`.

## Dependencies

Server host:

- Linux with `systemd` and `apt` (Debian or Ubuntu), reachable over SSH by a
  user that can install packages (typically `root`).
- `apt-cacher-ng`, installed by `install_server`; `curl`, `ss`, `du`, `df`,
  `sha256sum`, `mktemp` and `stat`.
- An SSH private key, resolved from a vault reference inside the method and
  delivered to a short-lived `ssh-agent` over stdin; it never appears on a
  command line.

Client host:

- `apt-config` and `apt-get`. The conflicting-proxy check reads
  `/etc/apt/apt.conf.d/*`.

## Install

```bash
swamp extension pull @randybias/apt-cache
```

## Example

Keep the inputs in a file so the private key stays a vault reference and never
reaches the command line.

```yaml
# server.yaml — keep this file out of version control
ssh:
  host: 192.0.2.10
  user: root
  port: 22
  host_key_policy: strict
  host_keys:
    - 192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
  ssh_key_ref:
    vault: default
    key: APT_CACHE_SSH
  connect_timeout_s: 15
listen: [192.0.2.10]
https_policy: direct
backends:
  debian: [http://deb.debian.org/debian/]
  ubuntu: [http://archive.ubuntu.com/ubuntu/]
```

```bash
# Install and configure the server, then stop a client from using it.
swamp behavior run @randybias/apt-cache install_server apt-server --input-file server.yaml
swamp behavior run @randybias/apt-cache apply_server apt-server --input-file server.yaml

# Point a client at the proxy.
swamp behavior run @randybias/apt-cache configure_client apt-client \
  --input-file client.yaml

# Remove it again; pass purge_cache_ack only to delete the cache directory too.
swamp behavior run @randybias/apt-cache remove_server apt-server \
  --input-file server.yaml
```

`client_get` and `get` are safe to run at any time and write an observation you
can query; `sync` reports drift between the recorded render and the live
fragment.

## Security

- `host_key_policy` is `strict` only and `host_keys` is required. There is no
  trust-on-first-use: the model never learns or persists a key from a live
  connection, so it cannot silently pin the wrong host.
- The private key and the admin credential are vault references marked
  sensitive. The key goes to an `ssh-agent` over stdin; the admin credential is
  uploaded to `security.conf` over stdin and `chmod 0600`, owned by
  `apt-cacher-ng`.
- Every value that reaches a remote command is a validated literal: addresses,
  port, mirror URLs, distro keys, cache directory and paths are checked against
  strict grammars, and every argv element is shell-quoted before it is sent. A
  wildcard `listen` binds an open proxy, so it is refused unless
  `listen_any_ack=true`; passthrough hosts and backend URLs must be plain DNS
  names and credential-free URLs.
- Each method enforces its own preconditions in-method, because a workflow gate
  can be bypassed. `apply_server` verifies the service is active and listening
  after restart; `configure_client` reads back `apt-config dump` and rolls the
  snippet back when the managed proxy is not the one in force, and refuses to
  overwrite a conflicting proxy file without `override_existing_ack`.

## Behaviour notes

- `stats` reads `/var/log/apt-cacher-ng/apt-cacher.log` plus its rotated `.1`
  and `.N.gz` files (logrotate rotates at 10 MB, keeping 7), and derives the
  same hit/miss and byte totals the maintenance page shows, without invoking its
  `Count Data` action (which is off by default, so the page's log-analysis table
  is usually empty). It fails closed if too many rows are unrecognisable.
- `remove_server` uses `apt-get remove` unless `purge_cache_ack` is set: the
  package's `purge` deletes the cache directory, `remove` does not. A package
  left in `deinstall ok config-files` by an earlier remove is still purged. The
  cache is deleted only with the ack, only when it is a real directory (a
  symlink is refused), only when its path matches the server's recorded or live
  `CacheDir`, and never for a system top-level directory. The package's
  `backends_debian` and `backends_ubuntu` are backed up before the first
  overwrite and restored on removal; a managed file whose bytes no longer match
  what the model wrote (an admin edit) is left in place.
- A failed `configure_client` restores the prior managed files instead of
  deleting them, and a key mismatch or a failed `apt-get update` is always a
  failure, even with `fallback_direct`.
- The managed fragment emits `Remap-` lines only for keys with no built-in
  remap, in the `Remap-<key>: <prefix> ; file:<backend>` form (URL pattern
  first, mirror file after the `;`).

## Live testing

Offline gates plus targeted real-tool checks so far; no full end-to-end run
against a managed host yet. The rendered server fragment, client snippet and
request-log parser were validated against real tools:

- apt-cacher-ng 3.7.4: for `https_backends`, both proxy-style
  (`GET http://ports.ubuntu.com/ubuntu-ports/...`) and path-style requests are
  fetched over TLS (port 443), for `ubuntu-ports` (its own remap) and for
  `debian` (the managed built-in backend file). The test that asserts this lives
  in `apt_cache_test.ts` and runs when the `acng-d5:latest` image is present.
- apt-cacher-ng 3.7.4: the fragment with
  `Remap-ubuntu-ports: /ubuntu-ports ports.ubuntu.com/ubuntu-ports ; file:...`
  serves a real `/ubuntu-ports/dists/.../Release` request (200); the pre-fix
  order (`file:... /ubuntu-ports`) returns 503.
- `apt-config` accepts the rendered snippet and reports every managed key.
- The rendered auto-detect script runs under `sh -eu` and prints the proxy URL
  or `DIRECT` as intended.
- The log parser reads a real apt-cacher request log.

This is recorded in `LOGBOOK.md`, and the extension stays on the beta channel
until a full live run passes.
