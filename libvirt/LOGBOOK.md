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

## Delta-live review round 2 (bcd2871 vs 0733670)

- **HIGH console was still broken live.** `consoleArgv` pasted the already
  quoted `inner` command raw into the `sh -c` text, so `script -qec` saw many
  arguments and failed with "unexpected number of arguments". The whole bounded
  command is now built by `quoteArgv([...])` (so `inner` is quoted as one word),
  and the wrapper maps exit `0|124|137` to 0 and anything else to its code. Two
  tests execute the rendered argv locally against a stub `virsh`: one times out
  and asserts exit 0 with the partial output, one exits 1 and asserts non-zero.
- **HIGH `undefine_domain remove_volumes` could delete an extra disk.** It only
  detached cdroms, so a `device=disk` extra (e.g. another domain's root image)
  was removed by `--remove-all-storage`. It now detaches every disk except the
  primary boot disk (`vda`) before undefining, unless `remove_attached_media`.
- **MEDIUM a normal console exit 0 was mapped to 1.** The `case` statement now
  treats 0, 124 and 137 as success.
- **MEDIUM** the remote `domblklist` target is validated with `assertName`
  before `detach-disk`.
- **MEDIUM** explicit `extra_disks` targets are reserved, duplicates are
  rejected, and implicit targets skip used letters.
- **MEDIUM** `DomainDiskSpec.format` is typed to `DISK_FORMATS` and asserted at
  render time.
- **MEDIUM** the shutdown poll sleeps `min(interval, remaining)`, never past the
  deadline.
- **LOW** `clone_volume` accepts a host-derived format only if it matches
  `/^[a-z0-9]{1,16}$/`, else records `unknown`.
- **LOW** the network start error strips control characters.
- `deno.json` test task gains `--allow-run` for the executed console tests.
- `_lib/ssh.ts` resynced to the canonical blob `fe0139f0` (ssh-host
  2026.10.17.2): upload no longer sends the content sha256 on the remote command
  line; the libvirt fake now returns the written hash and mode.

## Delta-live-2 review round 3 (52f8449)

- HIGH `insecure_tofu` was offered but learned keys were never persisted, so
  every later call would trust whatever key the host presented. Per RULINGS 4g
  the model is now `strict`-only with a required non-empty `host_keys` list;
  `insecure_tofu` is no longer accepted and the README examples pin keys.
- MEDIUM `undefine_domain remove_volumes` kept "vda" by target, which is wrong
  for a foreign domain whose root is `sda` (root leaks) and could delete a
  foreign `vda` data image. `define_domain` now records the resolved boot volume
  path as `root_disk` on `domain_state`, and `undefine_domain` keeps only the
  disk whose source equals it, detaching every other disk before
  `--remove-all-storage`. A domain with no recorded root, or none matching,
  refuses `remove_volumes`. Tests: root at `sda`, no record, no match.
- MEDIUM explicit `extra_disks` targets were reserved only as they were reached,
  so an implicit disk listed first could take a later explicit `vdb`. Explicit
  targets are now reserved up front (duplicates rejected) before any implicit
  allocation; a test covers both orderings.
- LOW a genuine 137 (e.g. OOM-killed virsh) is no longer indistinguishable from
  the timeout kill: the console wrapper records elapsed seconds with `date` and
  only maps 137 to success when the bound was actually reached.
- 106 tests; gates 0-6 PASS offline; ssh.ts blob fe0139f0 unchanged.

## Escalation fix (Claude, lane/fx-libvirt from 889af57)

- HIGH `power` rewrote `domain_state` without `root_disk`, so the README flow
  define -> power shutdown -> undefine remove_volumes always refused. Every
  `domain_state` writer for a present domain now merges the previous record
  (fresh fields win; nothing carried when the uuid differs). `get`/`sync` write
  only `host_state`; `undefine_domain` writes `present: false` and deliberately
  drops `root_disk`, because the domain is gone and a stale root could match a
  later same-named domain. Test: the full golden-image flow in one context with
  a data disk and a seed, only `vda` left attached for `--remove-all-storage`.
- HIGH `remove_attached_media=true` skipped every detach, so a data disk was
  deleted. It now still requires the recorded root, keeps the root plus
  read-only media (cdrom, floppy, or `<readonly/>` in `dumpxml --inactive`), and
  detaches every other disk. Refusal text no longer points at it. Test: a data
  disk, a read-only shared image, a cdrom and a floppy; only the data disk is
  detached. `domblklist` now reads `--inactive` (the persistent config that
  `undefine --remove-all-storage` acts on).
- MEDIUM `define_domain` on an existing domain without replace recorded an
  unchecked root. The root is recorded only when `domblklist --inactive` shows
  it attached; otherwise the earlier record is carried (no-op) or nothing is
  recorded (redefined).
- MEDIUM refusal checks in `undefine_domain` ran after destroying a running
  domain; record and domblklist checks now run first. Test: running domain, no
  record / no match, no `destroy` sent.
- MEDIUM console 137 with `timeout_s=1` had a 0-second budget. The budget is now
  `timeout_s` (whole-second floor difference is provably >= the real elapsed
  floor), `timeout_s` has a 5 s floor, and `consoleArgv` refuses a bound < 1.
  Test: an early `kill -9` exits non-zero.
- MEDIUM (TRIAGE 4e2) `xml_test.ts` runs `virt-xml-validate` on four network and
  two domain renders when it is on PATH, and is reported ignored with the reason
  otherwise. Verified locally against libvirt 11.3 schemas (extracted
  libvirt-common + libvirt-clients 9.0 script); all renders validate.
  `virsh define --validate` is not used: it needs a connection whose driver
  accepts `type='kvm'`.

## Escalation residuals (after CLEAN review of 28ccf18)

- `undefine_domain` destroys whenever the state is not off (`isOffState`), so
  `in shutdown` and `dying` domains are destroyed before undefine. Test.
- `undefine_domain remove_volumes` refuses, before any destroy/detach/undefine,
  when the record's uuid is missing or differs from `dominfo`. Test (other uuid
  and no uuid).
- README documents exactly which disks are deleted vs kept per
  `remove_attached_media`, including that a pool-managed CD-ROM is detached and
  kept when it is false.

## 2026-10-17 live e2e

Folded from the run receipts (`sp-20261017`); real addresses, hostnames and ids
are redacted (`<bm1>` is the target). Every head was installed from
`git archive` (tests excluded) into a separate repo. Target `<bm1>`: bare metal,
Ubuntu 24.04, libvirt 10.0, `/dev/kvm` present, a dir pool `e2e-pool` holding
the noble cloud image (`golden-noble.qcow2`, sha256 checked against SHA256SUMS),
a 1 GiB data disk and a NoCloud seed ISO. `private_key` as a vault reference,
`host_key_policy` strict with the pinned keys, no `--json` capture.

Earlier run on lane/d4 0733670 (superseded): 37 of 41 cells passed, including
networks (define, re-run no-op, differing config warns, undefine and again),
clone_volume (clone, re-run no-op, missing golden refused), define_domain
(define, re-run no-op, missing volume refused), power start/destroy/no-ops,
get/sync, virsh non-zero errors, undefine_domain (kept and removed volumes,
again a no-op), injection refusals (domain and network name, URI, target
volume), transport refusals (wrong pin, wrong pin on a destructive call, pin for
another host only, wrong private key) and a cloud-init NoCloud seed boot. Four
failed: start on a stock host (AppArmor, volume-type disk), power shutdown (no
ACPI in the render), console on a running domain (top-level `timeout -s KILL`
mapped to ssh exit 255) and console capture. Those, plus define_network dropping
the start error and the 15-char bridge-name limit, were fixed in the live-run,
round-2/3 and escalation fixes above.

### Final matrix on 08e8052

| Cell                                                                           | Result | Detail                                                                                                   |
| ------------------------------------------------------------------------------ | ------ | -------------------------------------------------------------------------------------------------------- |
| define_network e2e-nat                                                         | PASS   | defined and listed                                                                                       |
| clone_volume golden -> e2e-node1                                               | PASS   | clone present once                                                                                       |
| [earlier fail] define_domain + start on a stock Ubuntu host (no AppArmor rule) | PASS   | running                                                                                                  |
| [earlier fail] console on a running domain (timeout_s 20)                      | PASS   | returned in 24 s; capture stored in the sensitive resource as bytes + sha256 only                        |
| console bound: timeout_s 5                                                     | PASS   | returned in 9 s (5 s bound plus ssh/virsh overhead)                                                      |
| [earlier fail] power shutdown on a running guest                               | PASS   | shut off after 10 s                                                                                      |
| power shutdown again (already off)                                             | PASS   | no-op                                                                                                    |
| [earlier fail] console on a shut-off domain                                    | PASS   | typed error "it is not running"; no capture stored                                                       |
| golden flow 1: define_domain with a data disk (vdb) and seed ISO (sda), start  | PASS   | running with vda (clone), vdb (data), sda (seed)                                                         |
| golden flow 2: power shutdown                                                  | PASS   | shut off                                                                                                 |
| golden flow 3: undefine_domain remove_volumes=true                             | PASS   | only the root volume deleted; data disk, seed ISO, golden image and the other clone survive; domain gone |
| undefine_domain again                                                          | PASS   | clean no-op                                                                                              |
| undefine_domain on a running domain (remove_volumes=false)                     | PASS   | destroyed and undefined; volume kept; no qemu process left                                               |
| get (pool e2e-pool)                                                            | PASS   | networks, domains and volumes listed                                                                     |
| sync                                                                           | PASS   | no error                                                                                                 |

15 pass, 0 fail.

### Residuals (accepted for beta)

- `virsh define --validate` is not used (it needs a connection whose driver
  accepts `type='kvm'`); renders are checked with `virt-xml-validate` in tests
  when it is on PATH, and reported ignored otherwise.
- MEDIUM (terra): `undefine_domain remove_volumes=true` destroys a running guest
  before the `detach-disk --config` calls; a detach failure then leaves the
  guest off and its persistent definition partly detached (the method throws;
  nothing is deleted).
- MEDIUM (astra, raised as High and downgraded at merge prep): `define_domain`
  on an existing domain records `volume` as the root whenever it is attached,
  even as a data disk; a later `remove_volumes=true` would then delete that
  volume and keep the real boot disk. It requires the operator to name another
  disk of an existing domain as its root volume.
- MEDIUM (astra): the stateful test fake does not drop attachments on
  `detach-disk`; the golden flow is covered live (cell golden flow 3).

## Prior art

Registry search on stable and beta (`swamp extension search`, whole-word
matches in the package name or description) for `libvirt`.

- `@bad-at-naming/libvirt` (stable): very broad libvirt/virsh management
  (about forty VM methods including snapshots and the guest agent; network
  define, undefine, start, autostart and DHCP leases; pools, volumes and
  `volClone`; host facts) over SSH or a local URI, with adversarial,
  idempotency and coverage suites. Host keys are hard-coded to
  `StrictHostKeyChecking=accept-new`, so there is no strict or pinned mode;
  no turnkey golden-volume or zvol clone per node and no serial-console
  capture. OVERLAP, justified on narrow grounds: this extension's spec
  modelled its command shapes on theirs and built only because of the
  host-key policy plus zvol clone and console capture. If upstream accepted a
  strict known_hosts option, most of this extension would be redundant; that
  is the overlap most worth upstreaming.
- `@evrardjp/libvirt-vm-pool` (stable): a desired-state reconciler for a
  local VM pool that publishes connection facts; local only, no remote host
  and no network or volume management. OVERLAP (minor), justified.
- `@rjeschmi/vm` (stable): VM provisioning for libvirt/QEMU and OpenStack
  through an ssh-virsh provider, bundled with k3s, Helm and cloud-init
  utilities; weaker host-key handling and no clone-from-golden flow. OVERLAP
  (minor), justified.
- `@rjeschmi/kolla-openstack` (stable): provisions one Ubuntu VM on libvirt
  as a step of a Kolla-Ansible OpenStack deployment; libvirt is incidental.
  NONE (adjacent).
- `@mccormick/truenas` (stable): read-only VM inventory on TrueNAS SCALE
  through its JSON-RPC API; not libvirt management. NONE.

Verdict: OVERLAP, justified on narrow grounds (strict pinned host keys, zvol
clone, serial console). Worth filing upstream: an opt-in strict pinned
known_hosts mode, a zvol-backed clone and serial-console capture for
`@bad-at-naming/libvirt`.
