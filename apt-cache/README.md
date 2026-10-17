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
| `stats`              | read-only | Read the report page over loopback for hit/miss counts and bytes over a window, plus cache size             |
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
default cannot remain in force. The managed fragment and backend files use a
`zzzz-` prefix, so they sort after the packaged `acng.conf` and the Debian
`zz_debconf.conf` and win.

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

## Live testing

Offline gates only so far. The model's unit and integration tests run against a
fake transport with real tool output shapes; no server or client has been
touched live yet. This is recorded in `LOGBOOK.md`, and the extension stays on
the beta channel until a live run passes.
