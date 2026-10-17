# LOGBOOK — @randybias/libvirt

Item 9 of run sp-20261017. Lane d4, branch `lane/d4`. Clean-room: built only
from the spec (`swamp/docs/specs/libvirt.md`), this repository, public upstream
libvirt/virsh documentation, and the swamp skill files.

## Scope

`@randybias/libvirt` manages libvirt/KVM over SSH. Decision (from the item 9
evaluation) was **build fresh** on the generic `virsh` surface, not to depend on
a candidate extension:

- `@bad-at-naming/libvirt` covers define/undefine networks (incl. `default`),
  `vol-clone`, and power, but its SSH path uses
  `StrictHostKeyChecking=accept-new` TOFU with no host-key policy input.
  Unacceptable, so we model its surface and bring our own reviewed transport.
- `@evrardjp/libvirt-vm-pool` is unusable here: no networks, no libvirt volumes,
  local/URI-only, and Arch-cloud specific.

What is new here, and neither candidate has: a turnkey golden-volume → domain
clone workflow, serial console access, and a required strict pinned host-key
policy.

## Landing

- Vendored transport `extensions/models/_lib/ssh.ts`, byte-identical from the D1
  lane HEAD (`70b698f`, git hash-object
  `cb61c4adfbedee0a6c9914deae52d3864d5a1afb`), with `ssh_test.ts`
  (`2246ed69eb526ce929012128c930568e2b9c7fff`). Resynced from the earlier
  `1b78c7d` copy; the resync brings: every ssh exit 255 is a typed `SshError`
  (never remote data), a supplied `host_keys` set that applies to no host/port
  refuses instead of falling back to accept-new, a `max_output_bytes` capture
  cap, and upload refusing symlink/dir destinations (`mv -T`). Not edited here;
  all `virsh` goes through `exec`/`execPipeline`. Adaptations: the model exposes
  `max_output_bytes` (bounded, 10 MiB default); a transport 255 raises
  `SshError` with no state written, while a virsh non-zero exit raises a typed
  `LibvirtError` with no state written, and a timed-out console still returns
  the text captured so far.
- New helpers under `extensions/models/_lib/`:
  - `validate.ts` — `LibvirtConfigError`, name/URI/IP/MAC grammars and
    allowlists (`NAME_RE`, `URI_RE`, `URI_SCHEMES`, `NETWORK_MODES`,
    `DISK_FORMATS`).
  - `xml.ts` — deterministic network and domain XML rendering,
    `networkProjection` for a stable `net-dumpxml` comparison, and the `virsh`
    output parsers.
  - `virsh.ts` — `virsh` argv builder (`virsh -c <uri> …`), `virshTry`,
    benign-error matching, allowlisted temp XML path, upload/remove, and the
    forced bounded `console` argv.
- Model `extensions/models/libvirt.ts` — one generic model, empty globals,
  injectable transport/clock/token. Methods: `define_network`,
  `undefine_network`, `clone_volume`, `define_domain`, `power`, `console`,
  `undefine_domain`, `get`, `sync`.

## Design decisions

- **Generic type.** No host name, IP, account or private value appears in the
  definition; the SSH target, URI and operands are per-call arguments. State is
  keyed by the canonical `{host, port, user}` plus the resource name.
- **`kind: action`** on every mutating method so a call cannot tombstone a whole
  shared definition; `console`, `get` and `sync` are queries.
  `undefine_network`, `undefine_domain`, and `power` with `action: destroy` are
  DESTRUCTIVE.
- **Host-key policy is required, never defaulted.** `strict` uses only pinned
  `host_keys`; `insecure_tofu` is an explicit opt-in. This is the reason the
  model was built fresh.
- **Strict schemas, no passthrough.** Every CEL-exposed object is a
  `z.strictObject`; unknown keys are rejected. `private_key` carries
  `.meta({ sensitive: true })`, and so does the `console_capture.text`.
- **Idempotency.** `define_network` compares a stable projection of
  `net-dumpxml` with the rendered XML and no-ops when equal (replace only with
  `replace=true`, or when raw `xml` makes comparison impossible). `clone_volume`
  never clones over an existing target. `undefine_*` treat an absent object as a
  no-op. `power` no-ops when already in the target state.
- **Injection safety.** Names and URIs are grammar-checked, operands travel as
  separate argv words, remote XML lands in an allowlisted temp path and is
  removed in a `finally`.
- **Serial console.** Rendered domains carry `<serial type='pty'>` +
  `<console type='pty'>`; `console` runs
  `virsh console <name> --force
  --timeout <s>` so it can never block past the
  timeout.

## Gates

`scripts/gates.sh --offline libvirt` gates 0–6 are expected green. Offline means
gates 7 (dry run) and 8 (adversarial review) are SKIP; live `virsh` cells need a
KVM-capable target and are marked blocked.

Unit tests (68 across `libvirt_test.ts` and the `_lib/*_test.ts` files) assemble
the exact `virsh` argv and parse `virsh` output with a fake transport; they
never touch a real hypervisor.
