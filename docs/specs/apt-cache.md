# Spec: P2 — `@randybias/apt-cache`

Status: DRAFT — awaiting Randy's approval (P2, written from public docs only; no prior implementation consulted)
RFC 2119 keywords.
Sources: Apt-Cacher NG user manual (server quick start, client setup,
"SSL/TLS" and "BindAddress" how-tos), squid-deb-proxy package documentation,
`apt.conf(5)` and `apt-transport-http(1)` from Debian/Ubuntu, this repo's
CONVENTIONS and specs. Net-new; nothing outside public docs and this repo was
read.

## 1. Purpose

Run a caching apt proxy on one host and point other hosts' apt at it, over SSH:

- **Server:** install and configure Apt-Cacher NG (listen address, port,
  upstream backends, HTTPS policy, expiry), and report health and statistics.
- **Clients:** write one apt configuration snippet
  (`Acquire::http::Proxy …`) on each client, with an explicit, required HTTPS
  policy and an optional fall-back-to-direct mode, and verify apt still works.

The HTTPS policy is the one decision that changes security posture, so it is a
**required input with no default**, like `host_key_policy`.

### Choice of proxy (decided)

Apt-Cacher NG over squid-deb-proxy: it understands apt repositories (index vs
package files, mirror deduplication via backend remapping, HTTPS backends),
refuses non-repository file types, and needs no general-purpose proxy
configuration. squid-deb-proxy (a Squid profile with a mirror-domain allowlist
and Avahi discovery) is not supported; its domain-allowlist idea is kept as
`passthrough_hosts` (§5).

## 2. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host` byte-identical
(source commit + sha256 in the LOGBOOK). `host_key_policy` required; key as
`ssh_key_ref` via `context.vaultService`, stdin only. Server and client methods
each take their own SSH target.

## 3. HTTPS policy (the explicit decision)

Apt-Cacher NG cannot transparently cache an `https://` source: TLS is end to
end. Its manual lists four approaches; this model exposes three as
`https_policy` and never edits clients' `sources.list`:

| `https_policy` | Client snippet | Server | Effect |
|---|---|---|---|
| `direct` | `Acquire::https::Proxy "DIRECT";` | no tunnelling (`PassThroughPattern` unset) | HTTPS sources bypass the cache entirely. Safest; no caching of HTTPS repos. |
| `passthrough` | `Acquire::https::Proxy "http://<cache>:<port>";` | `PassThroughPattern` built from `passthrough_hosts[]`, anchored, port 443 only | HTTPS tunnelled through the proxy for listed hosts only; nothing cached; one egress point. |
| `https_backends` | `direct` for HTTPS + HTTP sources proxied | upstream backends declared with `https://` URLs | Clients keep `http://` sources for remapped distributions; the cache fetches upstream over TLS and caches. Integrity still rests on apt's signed Release files; LAN hop is plain HTTP. |

Hard rules: `PassThroughPattern: .*` (or any unanchored or port-wildcard
pattern) is **never** rendered — it makes the cache an open TCP tunnel to any
host and port. The fourth manual approach (`HTTPS///` URLs in client sources)
is out of scope because it rewrites sources (open question 2).

## 4. Model contract

- **Type** `@randybias/apt-cache`. CalVer == manifest version.
- **`globalArguments` empty.**
- **State keyed by** canonical `{host, port, user}`: one cache server per
  host; one client snippet per client host.
- **Factory with overridable deps** (transport runner, clock,
  `resolveSecret`). Unit tests render `acng.conf` fragments, client snippets and
  parse recorded reports/logs only.
- Resources: `server` (rendered sha256, listen, port, https_policy,
  applied_at), `client` (snippet sha256, proxy URL, https_policy, verified_at),
  `observation` (last `get`/`sync`/`stats`). Lifetime and GC declared; stats
  observations short-lived (e.g. 7d, keep 20).
- **RULINGS convention:** `get`, `sync`, `stats` and `client_get` are
  READ-ONLY toward the host but **persist their observation** as a resource,
  only after every probe succeeds.

### Methods (every mutating one `kind:"action"`; none is named `delete`)

| Method | Kind | Description |
|---|---|---|
| `install_server` | action | Idempotent. Preseed debconf (tunnel prompt answered **no**), install `apt-cacher-ng` non-interactively. Returns `{host, version}`. |
| `render_server` | — | READ-ONLY. Return the managed config fragment and backend files with sha256. Deterministic. |
| `apply_server` | action | Idempotent. Write the managed fragment, restart if changed, verify the listen socket and a fetch through the proxy. Returns `{host, changed, listen[], port, https_policy}`. |
| `remove_server` | action | DESTRUCTIVE. Stop, disable and purge the package config; the cache directory is deleted only with `purge_cache_ack`. Second call is a no-op. |
| `get` | — | READ-ONLY. Service state, listen sockets, config sha vs recorded, cache directory size and free space on its filesystem. Persists `observation`. |
| `sync` | — | READ-ONLY. Reconcile recorded state; report drift (fragment edited, passthrough widened out of band). Persists `observation`. |
| `stats` | — | READ-ONLY. Hit/miss counts and bytes served from cache vs fetched upstream over a window, from the transfer log and report page read on the server's loopback. Persists `observation`. |
| `configure_client` | action | Idempotent. Write the apt snippet on a client, verify with `apt-config dump` and (optional) `apt-get update`. Returns `{client, changed, proxy_url, https_policy, verified}`. |
| `client_get` | — | READ-ONLY. Effective `Acquire::*::Proxy` values on a client and whether the managed snippet is the one in force. Persists `observation`. |
| `unconfigure_client` | action | Remove the managed snippet (and auto-detect script); verify apt reverts to direct. Second call is a no-op. |

## 5. Inputs and grammars

- `ssh` block as in the other host models (server and each client).
- Server:
  - `listen[]` — 1–4 IP addresses (`BindAddress`). `0.0.0.0` / `::` refused
    unless `listen_any_ack: true` (§10).
  - `port` — 1024–65535, default 3142.
  - `https_policy` — REQUIRED, `direct | passthrough | https_backends`, no
    default.
  - `passthrough_hosts[]` — REQUIRED and non-empty iff `passthrough`; ≤ 32
    hostnames (RFC 1123, lowercased, no wildcards, no IP literals). Rendered as
    one anchored regex `^(host1|host2)(:443)?$` with every dot escaped; the
    escaping is unit-tested.
  - `backends{}` — map of distribution key (`debian`, `ubuntu`,
    `ubuntu-ports`, `debian-security`) → 1–4 mirror base URLs (`http://` or,
    under `https_backends`, `https://`; host + path grammar, no query,
    fragment, credentials or whitespace).
  - `expire_days` — 1–90 (`ExThreshold`), default 4. `cache_dir` — absolute
    path, default `/var/cache/apt-cacher-ng`.
  - `admin_auth_ref` — optional sensitive vault ref `user:password` for the
    report page's maintenance actions (§9).
- Client:
  - `proxy_url` — `http://<ipv4|[ipv6]|fqdn>:<port>`; never `https://`, never
    userinfo.
  - `https_policy` — REQUIRED, must equal the server's; `configure_client`
    refuses a mismatch when a server record exists for the URL's host.
  - `bypass_hosts[]` — hostnames that go `DIRECT`
    (`Acquire::http::Proxy::<host> "DIRECT";`).
  - `fallback_direct` — bool, default `false`. When true, render an
    `Acquire::http::Proxy-Auto-Detect` script that prints the proxy URL if a TCP
    connect to it succeeds within 2 s, else `DIRECT`. The script is static
    text with the validated URL embedded, mode 0755 root.
  - `verify_update` — bool, default `true`: run `apt-get update` and require
    exit 0.
- Strict `z.object`, no `.passthrough()`. Grammars re-enforced host-side.

### Outputs

As in the table. `stats` returns `{window, requests, hits, misses,
bytes_from_cache, bytes_upstream, hit_ratio, cache_bytes, fs_free_bytes}`. No
secret in any output; the snippet holds no credentials.

## 6. Rendering and idempotency

- The server owns **one** fragment: a file under `/etc/apt-cacher-ng/`
  (Apt-Cacher NG reads every `*.conf` in its config directory) plus the
  backend files it names. The package's `acng.conf` is not edited. (Proven by
  a live cell before relying on it; fallback is owning `acng.conf` with a
  takeover ack.)
- The client owns **one** snippet: `/etc/apt/apt.conf.d/90apt-cache-proxy`
  (and `/usr/local/lib/apt-cache/proxy-detect` when `fallback_direct`). Other
  proxy settings already present elsewhere in `apt.conf.d` are reported by
  `client_get` as conflicts; `configure_client` refuses when another file sets
  `Acquire::http::Proxy` unless `override_existing_ack`.
- Same inputs → byte-identical files → no write, no restart. Atomic
  temp + rename on every write.

## 7. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| Missing `https_policy`; `passthrough` without hosts | Rejected by schema. |
| Wildcard / regex metacharacters in a passthrough host | Rejected; never rendered. |
| Wildcard listen without ack | Refused. |
| Backend URL with credentials/query | Rejected. |
| Client policy ≠ server policy | Refused. |
| Another file already sets the proxy | Refused without ack; named in the error. |
| Proxy unreachable at `configure_client` | Verify fails; snippet rolled back unless `fallback_direct`. |
| Proxy down later, `fallback_direct: true` | apt works directly. |
| HTTPS host not in allowlist under `passthrough` | Tunnel refused by the cache (live cell). |
| Non-repository URL through the proxy | Refused by the cache (403). |
| Re-apply identical | No write, no restart. |
| `remove_server` / `unconfigure_client` twice | Second is a no-op. |
| Injection in any host, URL, path | Rejected by grammar; literal in files and argv. |

## 8. Tests (offline, increasing risk)

1. Schema/secret/license; grammars, the required no-default policy.
2. Pure mapping: golden server fragments per policy; anchored passthrough
   regex (dots escaped, `.*` impossible); backend files; golden client snippets
   per policy with and without bypass/fallback; detect-script text;
   stats parser on recorded, sanitized log and report fixtures.
3. Failure + adversarial: §7 rows; injection (quotes and `;` inside apt.conf
   values, newline, `$(...)`, regex metacharacters) on every input; detect
   script run under `sh` with a stub connect.
4. Packaging.

Fixtures synthetic: RFC 5737 addresses, `example.com` mirrors.

## 9. Credential policy (repo-wide policy)

SSH keys as in every host model. `admin_auth_ref` is sensitive, uploaded over
stdin to `/etc/apt-cacher-ng/security.conf` (mode 0600, owner the service
user), never in the returned render, argv, outputs or resources. `stats` reads
the report page over the server's loopback without credentials and never
triggers maintenance actions. Clients carry no credentials; authenticated
repositories (any URL with userinfo or an `auth.conf.d` entry) must be in
`bypass_hosts`.

## 10. Live e2e matrix (maintainer-run; two throwaway VPS tagged `swamp-e2e=<run-id>`)

Server VPS + client VPS on Ubuntu 24.04, plus a Debian 13 client. Port 3142 is
reachable **only from the client VPS** (provider firewall, or `server-host`
`apply_firewall`), so the test never runs an open proxy on the internet.

| Cell | Expected |
|---|---|
| install_server / again | no debconf prompt; tunnelling off; no-op second |
| apply_server (`direct`) / idempotent | listening on the given address; no restart second time |
| configure_client + `apt-get update` | update succeeds; cache log shows the client |
| second client install of a package | `stats` shows hits > 0 |
| `passthrough` allowlist | listed HTTPS repo works through proxy; unlisted host refused |
| `https_backends` | remapped mirror fetched over TLS upstream and cached |
| `fallback_direct` | stop the cache → client apt still updates |
| conflict refusal | pre-existing proxy file → refused without ack |
| get / sync / stats / client_get | reflect live state; observations persisted |
| unconfigure_client / again | apt direct again; no-op |
| remove_server / again | service gone; cache kept unless ack; no-op |
| injection literal | metacharacters land literally |

Receipts into `apt-cache/LOGBOOK.md`; no `stable` with any `untested`/`skip`.

## 11. Known traps

- **The package asks (debconf) whether to allow HTTP tunnels;** answering yes
  sets a match-all passthrough. Preseed to no before install; `sync` flags any
  `PassThroughPattern` not rendered by the model.
- **An open proxy on a public address** is abused within hours. Wildcard listen
  needs an ack; README points to a firewall.
- **Single point of failure:** every client's apt fails when the cache is down,
  including security updates and unattended-upgrades. `fallback_direct` exists
  for this; the auto-detect script runs as root on every apt invocation, so it
  is static, tiny and validated.
- **HTTPS cannot be cached transparently;** pointing `https://` sources at the
  cache fails certificate checks. Hence §3.
- **No hard cache size limit:** expiry removes unreferenced files only; `get`
  reports free space; put the cache on a filesystem that can fill safely.
- **Ubuntu 24.04 deb822 sources** (`ubuntu.sources`) use `http://` mirrors by
  default, so `direct` still caches the main archive.
- The transfer log format is not formally specified; the parser is built from
  a recorded live sample and fails closed (typed error, nothing persisted) on
  unrecognised lines above a small threshold.

## 12. Open questions for Randy

1. **Default posture for HTTPS:** keep `https_policy` required with no default
   (spec), or default to `direct`?
2. Support the manual's preferred `HTTPS///` source-rewrite mode (caches HTTPS
   repos, but the model would edit clients' sources)?
3. Should `configure_client` take a list of clients in one call, or one client
   per call (spec) driven by a workflow?
4. Fold the port-3142 firewall rule into this model, or leave it to
   `server-host`?
