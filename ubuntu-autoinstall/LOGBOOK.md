# `@randybias/ubuntu-autoinstall` LOGBOOK

Maintainer notes. Not packaged with the extension.

## Scope

Clean-room P2 build from the approved spec. One model type renders and validates
an Ubuntu Server autoinstall NoCloud seed and publishes it for the installer;
`render`, `validate` and `cmdline` are pure. Inputs were the approved spec, this
repo, public KubeVirt/Ubuntu/cloud-init/curtin docs, and the public source of
`@evrardjp/cloud-init-nocloud` (checked per the spec's first task).

## First task: `@evrardjp/cloud-init-nocloud` (spec §2)

Checked the registry package (`swamp extension info`) and the public source at
`github.com/evrardjp/swamp-extensions`.

1. **Caller-supplied bytes verbatim?** Yes. `generate` takes `userData` as a
   string and writes it into the ISO's `user-data` file unchanged; it does not
   parse or re-serialize it. So an `autoinstall:` cloud-config passes through.
2. **Where it writes / host-key policy?** Local only: it builds ISO bytes in
   memory and optionally writes them to a host filesystem path with Deno FS.
   There is no SSH, no remote host and no host-key policy.
3. **HTTP or CIDATA only?** CIDATA media only.

Outcome (spec §2): the `CIDATA` path is a **workflow** that wires this model's
`render` output into `cloud-init-nocloud.generate`; this model ships no ISO
builder and no `build_seed` action. The HTTP path (`publish_http`) is ours.

## Decisions for Randy

1. **`@evrardjp/cloud-init-nocloud` reused** for the CIDATA path (it fits, per
   §2); no `build_seed` action.
2. **LUKS refused.** Spec §10 Q3 (is a LUKS passphrase in served user-data
   acceptable, or CIDATA-only?) is unresolved, and autoinstall takes the
   passphrase in plaintext. Following the lead's instruction, `luks_password` is
   accepted by the schema (marked sensitive) but the pipeline **refuses** it
   with a validation finding, for both `render`/`publish_http` (it would be
   served) and `validate`. Re-enable once Q3 is answered, likely limited to the
   CIDATA path.
3. **`instance-id` derivation.** The spec says `iid-<tree12>`; the meta-data
   carries the id and is itself part of the tree hash, so a literal tree-hash id
   is circular. The id is `iid-<sha256(user-data)[0:12]>` instead: derived from
   the content that matters, still a new instance when the seed changes.
4. **`manifest_base_url`-style coupling.** `publish_http` writes
   artifact-server's documented layout (`bundles/<tree>/`, `refs/`,
   `SHA256SUMS`) directly over SSH, as the spec drafted; it reads
   `<root>/.layout-version` and refuses a mismatch, but an absent marker is
   allowed so a fresh root works.
5. **Schemas pinned.** `autoinstall-schema.json` from `canonical/subiquity` tag
   `24.04.5` and cloud-init's `schema-cloud-config-v1.json` from
   `cloud-init 26.1` (Ubuntu 24.04 archive) are vendored under `_lib/schemas/`
   and compiled with `ajv` / `ajv-draft-04` / `ajv-formats`. Unknown
   `autoinstall` keys are rejected separately because the subiquity schema sets
   `additionalProperties: true`.
6. **Late commands.** The spec allows a shell string with `shell:true` plus
   `late_commands_shell_ack`; it is rendered as the argv `["sh","-c", cmd]`
   (prefixed with `curtin in-target --` when asked), so the rendered document
   only ever contains argv lists and nothing is interpolated into a string.
7. **Storage `match`.** The spec wrote `size:"largest"|"smallest"|ssd`; `size`
   is the enum and `ssd` is a separate boolean selector.

## Container validation

`cloud-init schema --config-file` in `ubuntu:24.04` (cloud-init 26.1) accepts a
rendered seed (run with `AUTOINSTALL_CONTAINER=1`; it is ignored otherwise). The
subiquity schema validation runs offline in the unit tests via `ajv`.

## Live testing

Not run: booting the installer needs a nested-KVM target. Every live cell in the
spec's matrix is **blocked**, so the version is published to `beta`
(`release.yaml`, `ci: false`).

## Test count

103 tests (0 failed, 2 ignored: the gated container and subiquity cross-check
tests, both run green manually).

## Vendor note

The vendored cloud-init `schema-cloud-config-v1.json` is upstream except one
string: an internal-range IPv6 example was replaced with the documentation
address `2001:db8::1` so the repo's leak scan passes. It is a description
example and does not affect validation.

## Round 1 review fixes

- **Strict-only SSH.** `insecure_tofu` is dropped: nothing persisted a
  first-seen key, so it was a silent MITM window. `host_key_policy` is
  `literal("strict")` and `host_keys` is required (min 1).
- **No secret in a result.** `render` no longer returns the seed bytes; they
  live in a `seed_files` resource whose three fields are
  `.meta({sensitive: true})`. The result carries hashes and the command line
  only.
- **`unpublish` derives the tree from the ref.** A supplied `tree_sha256` that
  differs from the ref is refused; with no ref, a bundle is deleted only when
  its `meta-data` records the same hostname. The A/B cross-delete is tested.
- **Meta-data and numbers.** `meta-data` is emitted by the same quoting emitter
  (no string joining), so a hostname `on` stays a string; non-safe-integer
  numbers are rejected by policy and quoted by the emitter as a fallback.
- **`validate` headers.** The document must start with exactly `#cloud-config`
  and a `## template: jinja` header is refused.
- **Seed URL grammar.** An allowlist (RFC 3986 unreserved plus `/ : . - _ ~ %`)
  replaces the denylist, so `$`, quotes, backslash, backtick and braces are
  refused; a command-line seed URL must end in `/`.
- **Boundary checks.** `authorized_keys` entries are parsed (type allowlist, RSA
  3072+); argv late-command elements must be printable; `network` is a bounded
  netplan subset; `validate`'s `user_data` is sensitive.
- **Publish/observe.** `publish_http` checks every bundle file and the ref, and
  counts ref convergence as a change; `get`/`sync` report `mismatch` separately
  from `not_found`; `sync` validates too.

## License ruling (Randy, safe default pending final word)

Subiquity's `autoinstall-schema.json` is AGPL-3.0 and no longer ships here.
`autoinstall/` validation is our own structural code written from the public
reference; a dev-only test (`AUTOINSTALL_SUBIQUITY=1`) fetches the upstream
schema into a temp dir and cross-checks the renders. The cloud-init schema
(Apache-2.0 / GPL-3.0) stays, with its source and license recorded in
`LICENSE.txt` and the README. The container test now also runs
`netplan generate` on the rendered network.

## Round 2 review fixes

- **HIGH:** `password` is now a plaintext-secret key (a crypt hash under it is
  still allowed, so `identity.password` is fine); `first_boot_user_data` is
  marked sensitive.
- `unpublish` is idempotent when a `tree_sha256` is passed: an absent bundle is
  `not_found`, and only a bundle that exists with a different hostname is a
  conflict.
- Remote reads distinguish absent from unreadable: existence is probed with
  `test -e`, and any other non-zero exit is a transport error. A bundle whose
  files exist but are wrong is `mismatch`, not `not_found`.
- The structural validator accepts list-form `snaps`, compares enums without
  `String()`, and requires a crypt hash on `identity.password`.
- The render goldens are byte goldens per profile x network and run the full
  validation pipeline; the RAID10+LVM fixture was fixed (one grub disk).
- The container test asserts `netplan generate` exit 0 and that netplan is
  installed.
- The secret walk runs once and user-data findings are pointed at
  `/autoinstall/user-data/...`.
- `renderValidated` renders once; the `persist` wrapper is gone.
- LOW: `SIZE_OPT_RE` removed; the static bond lives in `testkit.ts`; `unpublish`
  removes the ref before the bundle.

## Prior art

Registry search (2026-10-17) for `autoinstall`, `subiquity`, `pxe`, `preseed`
and `netboot` returns no autoinstall/installer package; the only related
packages are cloud-init seed helpers.

- **`@evrardjp/cloud-init-nocloud`** (2026.06.29.1) — **reused**. Its `generate`
  method takes `userData`/`metaData` as strings and writes them into a `CIDATA`
  seed ISO unchanged (no parsing or re-serialization), and it is local-only
  (Deno FS, no SSH, no host-key policy, no HTTP). It accepts autoinstall
  user-data verbatim, so the CIDATA path is a workflow wiring this model's
  `render` output into it; this model ships no ISO builder. Its
  `@evrardjp/arch-cloud-init` sibling prepares Arch images and is unrelated.
- No published package renders or validates a subiquity autoinstall document,
  publishes a NoCloud seed over HTTP, or emits the kernel/GRUB command line, so
  the rest of this model is built here.

## Polish before live (round 3)

- `isCryptHash` now accepts only real crypt(3) formats with a salt and a hash
  part of the right length: `$1$`, `$2a/2b/2y$`, `$5$`, `$6$` (with optional
  `rounds=`), and `$y$` yescrypt. `$6$hunter2222` (one field) is refused, and
  yescrypt with three fields is accepted. Tests cover each plus the near-miss.
- Remote existence uses `stat` and its stderr, so an unreadable parent is a
  transport failure rather than an absent file; `publish_test.ts` covers absent,
  permission-denied and present-but-wrong.
- `first_boot_user_data` is bounded to 64 KiB.
- The user-data goldens are built from shared blocks (identity, ssh, version,
  network, per-profile storage) instead of eight full copies.

## Live fixes on bm1 (fc6e664)

- **Duplicate data instance name.** `render` wrote the `render` and `seed_files`
  resources under the SAME instance name, which swamp rejects within one method
  run even across resource specs. Each kind now gets a distinct name
  (`<key>-render`, `<key>-files`), with a test that every name written in a run
  is unique.
- **Bundling the ajv peer.** `ajv-draft-04` peer-depends on `ajv`, and a plain
  swamp repo could not bundle the extension ("Could not resolve ajv/dist/core")
  until the extension's deno.json/deno.lock were beside it. `schemas.ts` now
  imports `npm:ajv@8.17.1` explicitly (pinned), so the peer is always in the
  module graph. Proven by copying the packaged extension into a fresh swamp repo
  without deno.json/deno.lock: `swamp extension quality` bundles and `render`
  runs (the seed files land in the repo vault).
