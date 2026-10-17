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

## Open spec questions resolved by the simplest safe option

- **Listen port vs URL** — see decision 3.
- **How `verify` checks a bundle** — it recomputes the tree hash on the host by
  hashing the exact rendered `<sha256>  <name>` lines, matching the control-host
  implementation byte for byte.
- **Default served root** — `/srv/artifacts`, overridable per call and validated
  as an absolute path that is neither `/` nor contains `.`/`..` segments.
