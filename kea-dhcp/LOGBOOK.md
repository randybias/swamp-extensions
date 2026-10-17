# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

## Clean-room provenance

Built from the approved spec `docs/specs/kea-dhcp.md` (sha256
`1bd3383b8fb51d619cf563da767fb5b15706a052fc570a2f0fb55aca497eb84d`), public ISC
Kea documentation and house conventions only. No prior or ex-employer
implementation was read. The canonical transport is vendored byte-identical from
`ssh-host` on `origin/main`: `extensions/models/_lib/ssh.ts`, git blob
`fe0139f08c42e3fdae0061b9688fb5c534174957`.

## Decisions for Randy's review

The approved spec leaves open questions in §14. Where it states a decision it is
followed; where it does not, the simplest safe option was taken:

1. **Armed revert (open question 1).** Implemented as the spec body decided:
   validate, snapshot, arm a host-side timer, write, `config-set`, verify; the
   change is not permanent until `commit`. `commit` refuses after expiry, after
   a fired revert, on hash drift and when a canary is unreachable.
2. **Lease query (open question 2).** Default is the memfile CSV parser; the
   `lease_cmds` hook is opt-in with `lease_api` plus an explicit
   `lease_cmds_path`. The hook is only rendered when the loader asks for it and
   names the library; this extension does not guess an architecture-specific
   path.
3. **Distro Kea only (open question 3).** Targets the distribution package
   (`kea-dhcp4-server`, Ubuntu 24.04 / Debian), not ISC's 3.0 packages.
4. **DHCPv6 and DDNS (open question 4).** Out of scope; DHCPv4 only.
5. **Host-key policy.** The spec allows explicit `insecure_tofu`. House ruling
   4g permits TOFU only when the first-seen key is persisted and pinned later;
   this model does not persist it, so the transport is **strict-only with
   required `host_keys`**. This is the safe reading of the spec and the house
   rule.
6. **Apply idempotency.** "Identical live hash" is read as the live config
   file's SHA-256 equalling the rendered JSON's, with the service active; that
   is a no-op that arms nothing.
7. **`remove`.** Implemented as stop, disable and restore the package's original
   config (captured once by `install`), idempotent. The spec asks for the same
   armed-revert protocol on `remove`; that wrapper is a known residual for the
   live pass rather than a second full arm/commit cycle here.
8. **Factory export.** The spec asks for a factory with overridable deps; the
   registry requires a plain `export const model`. The plain literal is used,
   and `setDeps` overrides the seams for tests.

## Notes

- 2026-10-17: initial release. Pure modules: `_lib/grammar.ts` (IPv4, CIDR, MAC,
  interface, FQDN, pools, options, target key), `_lib/render.ts` (deterministic
  render and the ordered apply plan), `_lib/lease.ts` (memfile CSV collapse and
  lease_cmds JSON). The model is strict zod throughout, marks `ssh_key_ref`
  sensitive and resolves it through `context.vaultService`.
- Tests: grammar/render/lease unit tests, a model test that drives the real
  plain-object context shape (including `vaultService`), the arm-before-write
  ordering, the no-op and refusal paths, and a `kea-dhcp4 -t` check on a
  rendered golden when the tool is installed.
- Live testing is the lead's slot on a throwaway VPS with an isolated veth
  segment; Kea must never serve the provider-facing NIC.
