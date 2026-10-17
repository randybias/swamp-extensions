# Spec: P2 — `@randybias/artifact-server`

Status: DRAFT — awaiting Randy's approval (P2, written from public docs only; no prior implementation consulted)
RFC 2119 keywords.
Sources: nginx docs (nginx.org/en/docs: `ngx_http_core_module`,
`ngx_http_auth_basic_module`, `ngx_http_ssl_module`, `nginx -t`), Caddy docs
(caddyserver.com/docs, automatic HTTPS) for the server choice, GNU coreutils
`sha256sum` format; this repo's CONVENTIONS.md and `@randybias/ssh-host`.

## 1. Purpose

Serve a directory of pinned artifacts (OS images, kernels/initrds, binaries,
small seed bundles) from a host over HTTP(S), so provisioning flows (Redfish
virtual media, libvirt, `curl` in a late-command) fetch bytes by **content
hash**, not by a mutable name. The server is static: no upload over HTTP, no
CGI, no directory listing. All mutation goes over SSH through the canonical
transport. Consumers verify against `SHA256SUMS`; the server is a cache, not a
source of trust.

## 2. Build decision: nginx (made in this draft; Randy may overturn)

nginx, from the distro archive. Reasons, from the public docs:

- **TLS policy must be explicit.** Caddy's defining feature is automatic HTTPS
  (it obtains/serves certificates unless told otherwise); every Caddyfile would
  have to switch that off or pin it. nginx serves TLS only when a `listen ...
  ssl` + `ssl_certificate` is written, which matches "explicit or nothing".
- **Pre-flight check.** `nginx -t -c <file>` validates a config before reload,
  the same check-then-apply shape `server-host` uses with `nft -c`.
- **Basic auth** reads a crypt(3)-format file (`auth_basic_user_file`); the hash
  can come from vault unchanged, so re-runs are byte-identical (§8).
- Archive package, no third-party repo or ACME client on the host.

Caddy remains a plausible later backend; the on-disk layout (§4.2) is the
interface, so swapping the daemon MUST NOT change any URL.

## 3. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host`, byte-identical.
Every remote action is `exec(argv)` or `upload()` (temp file in the destination
directory, `mv -T`, converges on bytes+mode, never puts a content digest on the
remote command line). Strict host-key policy required; key over stdin/agent.

`upload()` holds the payload in memory and streams it on stdin, so it is for
bounded payloads. Large images use `fetch` (host-side download, §4.1).

## 4. Model contract

- **Type** `@randybias/artifact-server`. CalVer == manifest version.
  `globalArguments` empty; every method takes `ssh` + `root` per call. State
  keyed by canonical `{host,port,user}` + `root`, never the definition name.
- Factory with injectable transport + clock; unit tests render nginx config,
  assemble argv and parse remote output only.

### 4.1 Methods (every mutating one `kind:"action"`)

| Method | Kind | Description |
|---|---|---|
| `render_config` | — | READ-ONLY. Return the nginx site config for the inputs; deterministic. No secret in the text (paths to secret files only). |
| `install` | action | Idempotent. Install nginx, create the layout, write site config + htpasswd + TLS files, `nginx -t`, then reload. Same config sha = no reload. Returns `{config_sha256, url_base, changed}`. |
| `upload` | action | Idempotent. Push bytes (≤ `max_upload_bytes`) to `sha256/<hex>/<filename>`; refuses if the computed hash ≠ caller's `sha256` when given. Optionally sets `ref`. Regenerates `SHA256SUMS`. Returns `{sha256, path, url, changed}`. |
| `fetch` | action | Idempotent. Host downloads an `https://` upstream into a hidden temp file; remote prints its SHA-256, this side compares to the **required** pinned `sha256`; only then rename into place (else temp removed). Optionally sets `ref`. Returns as `upload`. |
| `publish_bundle` | action | Idempotent. Write a set of small named files under `bundles/<tree-hash>/` (tree hash = SHA-256 of the bundle's sorted `SHA256SUMS` lines). For seed directories that need fixed filenames (`user-data`, `meta-data`). Returns `{tree_sha256, url}` (URL ends in `/`). |
| `ref` / `unref` | action | Point a named ref at a blob or bundle hash / remove it. `unref` of an absent ref is a clean no-op. Refs are what make an object "referenced". |
| `list` | — | READ-ONLY. Refs, blobs, bundles with sizes and mtimes, from the host. |
| `verify` | — | READ-ONLY. Rehash every object on the host; report `ok`, `corrupt` (hash ≠ path), `missing`/`extra` vs `SHA256SUMS`. Never repairs. |
| `get` / `sync` | — | READ-ONLY. Observe nginx state (active, config sha, listen/TLS mode) + layout summary; persist that observation as the `server` resource. |
| `plan_prune` | — | READ-ONLY. List objects not reachable from any ref and not in `keep[]`, with total bytes and a `plan_sha256` over the sorted list. |
| `prune` | action | DESTRUCTIVE. Delete exactly the objects of a plan; requires `plan_sha256` and refuses if the recomputed plan differs (something changed since planning). Regenerates `SHA256SUMS`. |
| `uninstall` | action | DESTRUCTIVE. Remove the site config and reload; with `remove_data:true` also remove `root`. Clean no-op when absent. Does not purge the nginx package. |

### 4.2 On-disk layout (the interface other extensions write to)

```
<root>/
├── SHA256SUMS                 served; `sha256sum -c` format, sorted, regenerated atomically
├── sha256/<hex>/<filename>    served; immutable; Cache-Control: immutable
├── bundles/<tree-hex>/<name>  served; immutable
├── refs/<ref-name>            NOT served; one line: `blob <hex>` or `bundle <hex>`
└── .lock                      NOT served; flock(1) target for SHA256SUMS regeneration
```

URLs are `<url_base>/sha256/<hex>/<filename>` and `<url_base>/bundles/<hex>/`.
The layout is versioned (`<root>/.layout-version`); a change ships with an
`upgrades[]` migration and is a breaking change for consumers such as
`@randybias/ubuntu-autoinstall`.

### 4.3 Inputs (selected) and grammars

- `ssh` — transport block (strict `host_key_policy` + pinned `host_keys`; key a
  sensitive **vault reference**).
- `root` — absolute path, `^/[A-Za-z0-9._/-]{1,255}$`, no `..` segment, not `/`,
  default `/srv/artifacts`.
- `listen` — `{address, port}`; address IPv4/IPv6 literal or `*`; port 1–65535.
- `server_name` — hostname grammar (RFC 1123 labels) or IP literal.
- `tls` — **required**, discriminated union, no default:
  - `{mode:"none", plaintext_ack:true}` — HTTP only; the ack is mandatory.
  - `{mode:"provided", cert_pem, key_pem}` — `key_pem` sensitive vault ref;
    `cert_pem` parsed (PEM, not expired, key matches) before upload.
- `basic_auth` — optional `{realm, users:[{name, hash}]}`; `name`
  `^[a-z_][a-z0-9_-]{0,31}$`; `hash` sensitive vault ref matching
  `^\$(6|5|y|2[aby])\$[./A-Za-z0-9$]{8,}$`. Over `tls.mode:"none"` additionally
  requires `basic_auth_plaintext_ack:true`.
- `sha256` — `^[0-9a-f]{64}$`. `filename` — `^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`
  and not `SHA256SUMS`. `ref` — `^[a-z0-9][a-z0-9._-]{0,63}$`.
- `fetch.url` — `https://` only, no userinfo, no whitespace/`;`/quote; ≤ 2048.
- `upload.content` — bytes from a vault value, data reference or stdin;
  `max_upload_bytes` default 64 MiB, hard cap 512 MiB.
- `keep[]` — hashes, bounded 0–10 000. Strict `z.object`, no `.passthrough()`.

### 4.4 Outputs

Typed objects as above. `get`/`sync` persist the observation as the `server`
resource (lifetime infinite, GC 10 versions); `upload`/`fetch`/`publish_bundle`
write an `artifact` resource per hash (GC 5); `plan_prune` writes a `prune_plan`
resource (lifetime 1d). No resource contains a TLS key, auth hash or
bundle file content.

## 5. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| `install` twice, same inputs | no write, no reload, `changed:false` |
| `nginx -t` fails on rendered config | typed error; previous config still active, never reloaded |
| `upload`/`fetch` hash mismatch | typed error; temp removed; nothing renamed; no ref change |
| `fetch` upstream 404/timeout/non-https redirect | typed error; no partial object (curl `--proto =https --proto-redir =https`) |
| same blob uploaded twice | `changed:false`, one object |
| concurrent mutations | `SHA256SUMS` regeneration serialized by `flock`; file is always complete |
| `prune` with stale `plan_sha256` | refuse; nothing deleted |
| `prune` of a referenced object | impossible by construction (plan excludes refs); tested |
| `uninstall` / `unref` absent | clean no-op |
| filename/ref/root/url injection | rejected by grammar; argv-quoted |
| path traversal (`..`, absolute filename, symlink at target) | rejected; transport refuses symlink destinations |
| plaintext without ack; basic auth over HTTP without ack | rejected before any remote call |
| SSH transport failure | typed error (vendored exit-255 handling); no state written |

## 6. Tests (offline, increasing risk)

1. Schema/secret/license: sensitive marking on key + hashes; tls has no default.
2. Pure mapping: golden nginx configs for (none, provided) × (auth, no auth);
   assert dotfiles and `refs/` denied, `autoindex off`, `disable_symlinks on`;
   `SHA256SUMS` rendering (sorted, two spaces, relative paths); tree-hash
   stability under input reordering; prune-plan determinism.
3. Failure + adversarial: §5 rows; injection on every remote-bound input; no
   secret or digest on remote argv.
4. Packaging.

Fixtures synthetic: RFC 5737 addresses, `example.com`, placeholder hashes.

## 7. Live e2e matrix (maintainer-run)

Target: throwaway Ubuntu 24.04 VPS tagged `swamp-e2e=<run-id>`; the
bare-metal box for the cross-extension cell.

| Cell | Expected |
|---|---|
| install (tls none + ack) / re-run | 200 on `SHA256SUMS`; second run `changed:false` |
| install (tls provided, basic auth) | 401 without creds, 200 with; cert served matches |
| upload small blob + `curl` + `sha256sum -c` | hashes match |
| fetch Ubuntu live-server ISO (pinned upstream sha) | object present once; Range request returns 206 |
| fetch with wrong pin | typed error; no object, no temp left |
| publish_bundle | URL ends `/`; files served at fixed names |
| verify after manual corruption of one object | `corrupt` reported; nothing changed |
| plan_prune / prune / prune again | only unreferenced removed; second is no-op |
| dotfile / `refs/` request | 403/404 |
| get/sync | reflect real nginx + layout |
| uninstall (+`remove_data`) / again | gone; no-op |
| autoinstall seed consumer (bare-metal box) | `@randybias/ubuntu-autoinstall` boot fetches bundle from this server |

Receipts into `artifact-server/LOGBOOK.md`. No `stable` while any cell `untested`.

## 8. Credential policy

Repo-wide credential policy applies: SSH key, TLS private key and basic-auth hashes
are sensitive inputs, shown only as `${{ vault.get(...) }}`, delivered via
stdin/upload, never argv, never in `--json` captures (lab 3555). The vault holds
the **crypt hash**, not the password, so the model never sees a plaintext and
renders byte-identical htpasswd files (a model-generated salt would make every
run a change). Clients get the password from their own vault entry. The TLS key
lands `0600 root`, htpasswd `0640 root:www-data` (nginx workers read it per
request).

## 9. Known traps

- **In-flight temp files live in the served tree** (the transport writes
  `.ssh-host-upload.*` beside the destination): the config MUST deny dotfiles.
- **Ubuntu's `sites-enabled/default` also listens on :80.** `install` takes an
  explicit `disable_default_site` input; a port clash fails `nginx -t`/bind,
  never silently serves the wrong root.
- `upload()` sets mode, not owner; ownership is set by a follow-up `chown -h`
  (no symlink follow) and is part of the convergence check.
- An installer or firmware HTTP client usually cannot trust a private CA:
  plaintext on an isolated provisioning network with hash pinning is the
  realistic mode, which is why `none` exists but needs an ack.
- Basic-auth credentials embedded in a URL (`http://u:p@...`) end up in kernel
  command lines and BMC logs; consumers SHOULD NOT do that (see autoinstall spec).
- `sha256sum -c` paths are relative to `<root>`; consumers must `cd` there.

## 10. Open questions for Randy

1. **Large-artifact ingest:** is host-side `fetch` from a pinned upstream URL
   acceptable as the path for multi-GB images, or must every byte originate on
   the control host (which needs a streaming, file-backed transport upload —
   a change to the canonical `ssh.ts`)?
2. nginx over Caddy (§2) — confirm.
3. Should refs be served (e.g. `/refs/<name>` as a stable redirect), or stay
   private as drafted?
