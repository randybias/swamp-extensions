# artifact-server — build log

Clean-room build from the approved spec. Only the spec, this repository, public
upstream documentation, and the swamp skill files informed it. No host name, IP,
account id or private value appears anywhere; fixtures use documentation
addresses and `.test` names only.

## Status

- Version `2026.10.17.1`, channel `beta`, `ci: false`, no `published` entry.
- Model `artifact_server.ts`; helper modules under `extensions/models/_lib/`.
- Tests: layout, nginx rendering, TLS validation, observation parsing, remote
  file helpers and the full model over an in-memory SSH target.

## Prior art

Three nearby packages exist. None delivers a content-addressed, SSH-only
artifact origin, so this extension is not a duplicate of any of them.

### `@taylor/nexus` 2026.10.14.1

Runs a Nexus repository manager in a container and configures raw repositories.

- **What it gives you:** a long-lived repository daemon, its own HTTP API and
  admin surface, and raw hosted repos keyed by _path_.
- **Gap:** raw repos are mutable and path-addressed: the same URL can serve
  different bytes over time, so a consumer cannot pin a build to the exact bytes
  it validated. It also adds a second daemon and API that must be managed,
  patched and authenticated.
- **What ours adds:** immutable, SHA-256-addressed blobs served as plain files
  (`sha256/<hash>/<name>`), with `SHA256SUMS` and `verify` to prove the bytes;
  no repository daemon or new API is introduced — management is SSH-only and the
  served tree is a static directory any web server can host.

### `@keeb/nginx`

Covers nginx **stream proxying** only (TCP/UDP `stream {}` proxying).

- **Gap:** it configures a forwarder, not an origin. It has no notion of stored
  objects, manifests, immutability or fetch verification.
- **What ours adds:** the HTTP(S) origin itself: an nginx `server` block that
  serves a pinned artifact tree read-only, plus upload/fetch/bundle/ref and a
  prune plan. The two are complementary; ours does not do stream proxying.

### nginx-proxy-manager packages

Drive the Nginx Proxy Manager API (hosts, certificates, access lists) against a
running NPM instance.

- **Gap:** NPM is a reverse-proxy control plane with a mutable database and a
  web API; it has no content-addressed store and no host-side verification. A
  package that drives its API still depends on that daemon being up and that API
  being reachable and authenticated.
- **What ours adds:** no control-plane API to depend on. The extension manages a
  static tree over SSH, stores bytes by content hash, verifies a download before
  it is adopted (`fetch` keeps a hidden temp file until the host-side SHA-256
  matches the pin), and publishes named bundles and refs so a versioned set of
  files is addressable and protected from prune.

**Net:** the unique combination here is SHA-256-addressed immutable blobs, a
verified fetch, named bundles/refs, and SSH-only management that starts no new
daemon or API — none of the three pieces gives that.

## Decisions for Randy's review

1. **Daemon** — nginx, as the spec recommends: explicit TLS, a `nginx -t`
   pre-flight, `crypt(3)` basic-auth files and a distro archive. The on-disk
   layout is the contract, so a later swap cannot change a URL.
2. **Host keys** — `host_key_policy` is the literal `strict` and `host_keys` is
   required. Trust-on-first-use is not offered, because no key store is
   persisted between calls. This is the house rule for this build.
3. **URL base for object methods** — `upload`, `fetch` and `publish_bundle`
   return a URL. They read the `url_base` recorded by `render_config` or
   `install`; when neither has run, they fall back to `http://<host>`. The spec
   does not fix how an object method learns the public scheme/port, and reading
   the recorded config avoids a second source of truth.
4. **Secret delivery** — a private key is loaded into a short-lived ssh-agent
   over stdin; a password goes through an askpass helper in the environment;
   basic-auth hashes and the TLS key are sensitive method inputs written to
   root-only files. No secret is placed on a command line, in state, or in a
   log.
5. **Config rollback** — `install` snapshots the site file, the enabled link,
   the default site, the TLS files and the htpasswd before changing anything. If
   `nginx -t` fails it restores every one of them, removes a first-install
   enabled link so no dangling symlink can break a host-wide `nginx -t`, and
   re-runs `nginx -t` before throwing. It never reloads a broken config.
6. **Served-root policy** — `root` requires at least two segments and may not be
   a bare system directory. `install` refuses a populated root with no regular
   `.layout-version` sentinel, and `uninstall` removes a root only when it is a
   real directory holding that sentinel.
7. **`SHA256SUMS` semantics** — a line records the content address in the path
   (`sha256/<hex>/<name>`), not a re-read of the bytes; dotfiles are skipped. It
   is rebuilt under `flock` and renamed into place. `verify` re-hashes the bytes
   and reports a mismatch against either the path hash or the recorded value.
8. **Object path grammar** — paths read from the host must match
   `sha256/<64-hex>/<name>` or `bundles/<64-hex>`. `prune` refuses to remove
   through a symlinked `sha256/`, `bundles/` or hash directory, and the shell
   refuses any path that fails the grammar.
9. **Bundles** — duplicate file names are refused, and files are staged in a
   hidden dot-directory and renamed into place, so the tree hash always matches
   what is served.
10. **`fetch` transport** — `https` only, no userinfo or shell metacharacters,
    `-L` with at most five redirects, a `curl --max-filesize` and a
    post-download size check. A present object with the pinned hash is not
    downloaded again.
11. **Nginx realm and locations** — the basic-auth realm is restricted to
    `[A-Za-z0-9 ._-]`; the `sha256/` and `bundles/` locations no longer use `^~`
    and nest a dotfile `deny` so in-flight temp files are never served.
12. **Read-only methods persist** — `render_config`, `list`, `verify`, `get`,
    `sync` and `plan_prune` each persist their observation as a resource.
13. **In-method preconditions** — every destructive method re-checks its own
    safety preconditions at run time, so a workflow resume with overridden
    inputs cannot bypass a workflow gate.
14. **Plain model literal** — `model` is a plain object literal (not a computed
    spread) so tooling can catalogue it; `createModel(deps)` remains a thin
    compatibility wrapper that sets the transport for tests.

## Quality pass

After the review rounds, one deliberate simplification pass:

- The model is split by concern: `artifact_server.ts` is the plain object
  literal; `_lib/schema.ts` and `_lib/types.ts` hold the grammars and types;
  `_lib/methods_lifecycle.ts`, `_lib/methods_objects.ts` and
  `_lib/methods_admin.ts` hold the method bodies; and `_lib/target.ts`,
  `_lib/render.ts`, `_lib/install.ts`, `_lib/fetch.ts`, `_lib/verify.ts`,
  `_lib/snapshots.ts`, `_lib/artifacts.ts` and `_lib/runtime.ts` hold the
  helpers. Every file is under 800 lines.
- One grammar per format: the object-file-name grammar lives once in
  `layout.ts`; `schema.ts`, `observe.ts` and `ops.ts` import it. `posixQuote` is
  the only remote-shell quoter. `normalizeMode` has one implementation.
- `install` is split into snapshot, install, layout, site, credentials, rollback
  and verify-and-reload steps, each a small function.
- `parseLayout`, `parseVerifyOutput`, `parseSha256Sums` and `parseOpenSslDate`
  are the single parsers for their formats.
- Tests share one `modelFor(host)` setup helper, and the shell builders are run
  through a real `sh`.

## Round-2 fixes

- `install` writes credentials before it enables the site, and wraps every step
  after the snapshots in one rollback: any throw — a failed credential write, a
  failed remove, `nginx -t`, a lost connection — restores the host and re-tests
  the restored config.
- After a passing `nginx -t` the reload always runs, so a retry after a prior
  reload failure picks up the config even when nothing changed this run.
- `snapFile` refuses to proceed when a probe sees a file but the read fails, so
  a rollback can never replace a real file with an empty one.
- The `SHA256SUMS` and verify scripts iterate with shell globs instead of
  `find | while read`, and validate each path against the layout ERE, so a
  newline-named directory cannot inject a line. One `hashCmd` helper is the
  single SHA-256 command.
- `plan_prune` and `prune` share one `computePlan`; `get` fails when no site is
  installed while `sync` succeeds; `renderFor` takes its inputs as one object;
  `InstallArgs` extends `RenderConfigArgs`.
- Tests share one `test_support.ts` helper and are split by concern.

## Round-3 polish

- The `SHA256SUMS` and verify loops now reject a newline in a **file** name too
  (a shell `case` test, not a per-line `grep`), and skip a symlinked hash
  directory, so neither can inject a forged index line or hash outside the root.
- `verify` exports `LC_ALL=C` so a bundle's file order — and therefore its tree
  hash — is code-point order regardless of the caller's locale.
- Install persists the config resource and logs only after a successful reload,
  so a later throw cannot restore the files while nginx keeps the new config.
- `snapLink` refuses a failed read and rollback checks every `rm`/`ln` exit
  code, reporting any rollback failure in the error.
- `hashCmd` callers validate a 64-hex result; comments that restated code were
  removed; the install description matches the always-reload behaviour.

## Live fixes (post-deploy)

- Install no longer exposes the package default site: `policy-rc.d` (and a
  best-effort systemd mask) block the service start during the package install,
  the managed config is written after, and a post-start `ss` check fails the
  install if nginx left a wildcard listener on a port we did not configure.
- Inline `upload` is capped at 128 MiB (schema and run time); larger artifacts
  must use the host-side pinned `fetch`, which never puts the bytes on the
  control host.
- `uninstall` restores the package default site that `install` removed, using
  the snapshot recorded in the `config` resource.
- `prune` removes an emptied hash directory and refuses a symlinked hash
  directory with a clear error instead of silently skipping it.
- A rolled-back install removes the served root when the model created it.

## Open spec questions resolved by the simplest safe option

- **Listen port vs URL** — see decision 3.
- **How `verify` checks a bundle** — it recomputes the tree hash on the host by
  hashing the exact rendered `<sha256>  <name>` lines, matching the control-host
  implementation byte for byte.
- **Default served root** — `/srv/artifacts`, overridable per call and validated
  as an absolute path that is neither `/` nor contains `.`/`..` segments.
