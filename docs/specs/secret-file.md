# Spec: `@randybias/secret-file`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone placing a vault-held secret as a file on a remote Linux host.

Q3: No. no system is named; it writes a secret file onto a remote host over SSH. Naming audit verdict: rename to `ssh-secret-file`, pending Randy's confirmation; until confirmed the published name stays `secret-file`.

Q4: Not applicable (public and general).

Q5: No. A stranger could read `secret-file` as a swamp vault backend that reads secrets from a file, which is the opposite of what it does. The proposed name fixes that.

Status: written after the first published versions, from the README and LOGBOOK; it describes
the behaviour as shipped. RFC 2119 keywords. Not clean-room (written from this repo's README, LOGBOOK and public docs).

## 1. Purpose

Write one secret file onto one Linux host over SSH from values held in a vault, atomically and
idempotently, so that the value never appears on a command line, in a log, in swamp state or in
`--json` output, and the published file is never briefly wrong.

## 2. Model contract

One generic model type `@randybias/secret-file`. The definition holds nothing instance-specific:
every method takes its own target, and state is keyed by
`sha256("<host>\u0000<port>\u0000<user>\u0000<path>")` as `secret-<32 hex>`.

| Method | Kind | Behaviour |
|---|---|---|
| `write` | action, DESTRUCTIVE | Write the file over stdin, atomically; converge by content, mode, owner and group; identical re-run is a no-op (`changed: false`). |
| `verify` | READ-ONLY | Stat the file; compare mode, owner and group when given and the SHA-256 of the content when a content form is given; store match flags and metadata only. |
| `remove` | action, DESTRUCTIVE | Remove the file; an already-absent file is a clean no-op. |

## 3. Inputs

- Target: `host`, `port` (default 22), `user`; `host_key_policy` (only `strict` is offered) and a
  non-empty `host_keys` list; `private_key` (vault reference; loaded into a short-lived
  `ssh-agent` over stdin).
- File: absolute `path`, octal `mode`, optional `owner` and `group` (name or numeric id).
- Content, exactly one form: `content` (bytes) or `entries` (an object rendered as POSIX-shell
  `KEY='value'` lines, single quotes escaped; at most 256 keys and 1 MiB rendered). It is safe to
  source with `sh`, and is not a systemd `EnvironmentFile`.
- Optional `hmac_key`: when given, a keyed HMAC-SHA256 of the content is stored as `content_hmac`.
  No plain hash and no content is ever stored.
- Strict schemas; unknown keys refused; `content`, `entries`, `private_key` and `hmac_key` are
  sensitive and MUST be passed as vault references.

## 4. Invariants

- The value travels only over stdin: never argv, never a remote temp file outside the destination
  directory, never logs or state.
- `write` stages the bytes in the destination directory, applies owner and group to the staged
  file, then renames over the destination.
- Existence is `test -e || test -L`, so a dangling symlink counts as present and is replaced.
- A `stat` failure after the file is known to exist is an error, not absence.
- `verify` refuses more than one content form.

## 5. Failure modes

Typed transport errors from the vendored `_lib/ssh.ts` (connect, auth, host-key mismatch,
timeout); a missing destination directory; a target without GNU `stat` or a SHA-256 tool;
`chown` failure when `owner` or `group` is set. Every failure leaves the previous file intact.

## 6. Test obligations

Unit: `entries` rendering and quoting, the state key, schema refusals, the stdin script. Contract
tests against an injectable transport. Adversarial: symlink destination, dangling symlink,
oversize `entries`, a value containing quotes and newlines, no secret in any log or result.

## 7. Live matrix

Eight cells on a throwaway host: write new; identical re-write (no-op); content change; mode
change; owner and group change; `verify` match and mismatch; `remove`; `remove` when absent.

## Next version scope: next

Next `secret-file` version (public, beta).

- This spec is written first; the first versions shipped without one.
- Medium: the destination checks and the rename are separate operations, so a
  symlink planted in between is replaced. Fix: check-then-rename under a
  directory the attacker cannot write (the `O_NOFOLLOW` equivalent in `sh`:
  verify the parent, then rename within it) and refuse otherwise.
- Lows: a symlinked parent directory is not detected; after a local timeout the
  remote write runs until stdin closes.
- Live: the 8 cells in section 7 plus the symlink race attempt.
- Lands under `ssh-secret-file` instead if the rename is confirmed first.

## Next version scope: ssh-secret-file (new package, pending rename)

New package `ssh-secret-file` (public, general), pending rename.

- Blocked on Randy confirming the rename `secret-file` -> `ssh-secret-file`.
- New package from the `secret-file` head above (the version above lands here
  instead of under the old name if the rename is confirmed before it starts):
  manifest, model type, README, LOGBOOK with the five naming answers and the
  literal declarations, `release.yaml` stanza.
- Full live matrix under the new name.
- Deprecate the public `secret-file` versions afterwards (never delete).
