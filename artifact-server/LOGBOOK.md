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
5. **Config rollback** — `install` reads the previous site file before writing
   the new one. If `nginx -t` fails, it restores the previous file and throws
   without reloading, so the running config is never replaced by a broken one.
6. **Prune safety** — `plan_prune` persists a plan whose hash covers the sorted
   object paths; `prune` recomputes the plan with the same `keep` list and
   refuses when the hash differs, so a change since planning deletes nothing.
7. **`fetch` transport** — restricted to `https` with no userinfo and no shell
   metacharacters in the URL. The download lands in a hidden temp file and is
   moved into place only after the host-reported hash matches the pin.
8. **Read-only methods persist** — `render_config`, `list`, `verify`, `get`,
   `sync` and `plan_prune` each persist their observation as a resource.
9. **In-method preconditions** — every destructive method re-checks its own
   safety preconditions at run time, so a workflow resume with overridden inputs
   cannot bypass a workflow gate.

## Open spec questions resolved by the simplest safe option

- **Listen port vs URL** — see decision 3.
- **How `verify` checks a bundle** — it recomputes the tree hash on the host by
  hashing the exact rendered `<sha256>  <name>` lines, matching the control-host
  implementation byte for byte.
- **Default served root** — `/srv/artifacts`, overridable per call and validated
  as an absolute path that is neither `/` nor contains `.`/`..` segments.
