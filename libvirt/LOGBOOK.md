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
  `<console type='pty'>`; `virsh console` has no `--timeout` and needs a pty, so
  `console` runs
  `timeout -s KILL <s> script -qec 'virsh ... console <name>
  --force'` with a
  local deadline backstop, and returns only `bytes`/`sha256` (the text stays in
  the sensitive `console_capture` resource).

## Gates

`scripts/gates.sh --offline libvirt` gates 0–6 are expected green. Offline means
gates 7 (dry run) and 8 (adversarial review) are SKIP; live `virsh` cells need a
KVM-capable target and are marked blocked.

Unit tests (77 across `libvirt_test.ts` and the `_lib/*_test.ts` files) assemble
the exact `virsh` argv and parse `virsh` output with a fake transport; they
never touch a real hypervisor.

## Round 1 review fixes (head 95dec2e)

Ledger: `reviews/libvirt/...` (lead). Every Critical/High/Medium item addressed;
no release.yaml edit and no server-host in the branch (the lead owns
release.yaml).

- **BLOCKER** — rebased `lane/d4` onto `origin/main` so the diff is `libvirt/`
  only: the server-host commits and the release.yaml edit are gone.
- **HIGH** — `arch` was a free string injected into `<type arch='...'>`: it is
  now a `z.enum` allowlist (`x86_64|aarch64|i686|ppc64le|s390x`) and
  `renderDomainXml` asserts it (`assertArch`).
- **HIGH** — `escapeXmlAttribute` left `'` unescaped while `dns_domain` is
  written into a single-quoted attribute: `'` is now escaped to `&apos;`, and
  `dns_domain` must match a DNS-name grammar (`assertDnsName`, `DNS_NAME_RE`).
- **HIGH** — `define_network` destroyed and redefined a differing network even
  with `replace=false`. Now only `replace=true` does; otherwise the network is
  left untouched and the result reports `drift: true` (with a warning log). The
  old test that asserted the bug was rewritten and a no-replace drift test
  added.
- **HIGH** — `console` returned the raw capture text in `result.text`, and swamp
  has no sensitive result schema (RULINGS 4). The result now returns only
  `target`, `domain`, `bytes` and `sha256`; the text stays in the sensitive
  `console_capture` resource.
- **HIGH** — `virsh console` has no `--timeout` and needs a controlling TTY.
  `consoleArgv` now wraps it as
  `timeout -s KILL <s> script -qec '<virsh ...
  console>' /dev/null` (stdin is
  the closed ssh channel), and the method adds a local `withDeadline` backstop.
  The argv test now checks the real option names and the absence of `--timeout`.
- **MEDIUM** — `net-info`/`dominfo`/`vol-info` treated every non-zero exit as
  absent. They now use `isNotFound`, so only explicit not-found errors mean
  absence and a broken URI/permission/libvirtd records a typed error instead.
- **MEDIUM** — raw network `xml` was not checked against `name`. `<name>` is
  parsed from the XML and must equal `name` before any undefine/define.
- **MEDIUM** — `URI_RE` accepted `+ssh`/`+tls`/`+unix`, userinfo and query
  params. It is now local schemes only (`qemu|test|xen|lxc|vbox|bhyve:///`),
  which also rejects userinfo and query params; documented in the README.
- **MEDIUM** — `devname` had only a length check; it now matches `NAME_RE`.
- **MEDIUM** — method descriptions: `define_network`, `define_domain` and
  `power` now start with the exact `DESTRUCTIVE.` prefix, and `define_domain`
  was trimmed to three sentences.

## Round-1 residuals (triage)

- `dns_domain` is a direct child of `<network>`
  (`<domain name='...'
  localOnly='yes'/>`), not a child of `<dhcp>`; confirmed
  against the public libvirt formatnetwork docs. `<bootp/>` was only a
  placeholder and is gone, and `domain` is now part of `networkProjection` so a
  changed DNS domain is detected as drift.
- XML comments are stripped before `firstTagText`/`firstTagAttr`, so a
  commented-out `<name>` cannot satisfy the raw-XML name check or a projection
  read.
- The README documents that `console` passes `--force`, taking the console over
  from any operator already attached.

## Live-run fixes (Ubuntu 24.04, 37/41 cells)

Applied to lane/d5-libvirt on top of 0733670. Drafted directly, not via
`codex exec`: codex was blocked by a missing `codex-code-mode-host` binary in
this environment.

- **A. Domains could not start on stock Ubuntu.** `renderDomainXml` now emits
  `<disk type='file'>` with the path resolved by `virsh vol-path`, instead of
  `<disk type='volume'>`; virt-aa-helper grants a file AppArmor access but not a
  volume reference, so qemu got Permission denied.
- **B. `shutdown` never powered the guest off.** The XML now carries
  `<features><acpi/><apic/></features>` (qemu previously ran with acpi=off), and
  `power shutdown` polls until the domain is off, up to `shutdown_timeout_s`,
  and raises a typed error instead of returning success if it never stops.
- **C. Console capture was discarded on the hard timeout.** `consoleArgv` now
  runs `timeout -s KILL … script -qec '<virsh console>'` inside an outer `sh -c`
  that survives the killed child and exits 0 on 137/124, so a timed-out capture
  returns the bytes read so far instead of an ssh exit 255. Tests prove a
  running-domain capture stores text in the sensitive resource and returns only
  bytes+sha256.
- **D. Console on a shut-off domain stored virsh's error as the capture.**
  `console` refuses a non-running domain with a typed error and refuses any
  non-zero console exit; `bytes` is now the real UTF-8 byte count.
- **E. Network start failure dropped the cause and left a half-defined
  network.** The typed error now includes the sanitized virsh text, and a
  network this call created is `net-undefine`d. The default bridge is now
  `vb-<8 hex>` (`defaultBridgeName`), inside the 15-char IFNAMSIZ limit, for any
  network name.
- **Seed/extra disks.** `define_domain` takes `extra_disks` (path, device, bus,
  format, target, readonly); a CD-ROM defaults to read-only, so a cloud-init
  NoCloud seed ISO can be attached. `undefine_domain remove_volumes` detaches
  read-only media before `--remove-all-storage` unless `remove_attached_media`
  is set, so a seed the extension did not create is kept.
- Minor: `clone_volume` records the qemu format parsed from `vol-dumpxml`, not
  `vol-info`'s `Type: file`.
- `ssh.ts` is unchanged (blob cb61c4ad). `release.yaml` gains the required
  `libvirt` beta stanza so the offline gates can run.
