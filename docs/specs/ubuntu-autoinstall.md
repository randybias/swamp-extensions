# Spec: P2 — `@randybias/ubuntu-autoinstall`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone provisioning Ubuntu hosts unattended.

Q3: Yes. `ubuntu-autoinstall` names the product (Ubuntu) and Ubuntu's own feature name (autoinstall); short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `ubuntu-autoinstall` as an Ubuntu autoinstall seed builder and publisher, which is what it does, and guesses wrong about nothing.

Status: approved (see `docs/CLEANROOM.md`); written from public docs only, no prior implementation consulted. The next-version scope is at the end.
RFC 2119 keywords.
Sources: Ubuntu installer (subiquity) docs at
canonical-subiquity.readthedocs-hosted.com (autoinstall reference, autoinstall
JSON schema, providing autoinstall, cloud-init and autoinstall interaction,
zero-touch confirmation); cloud-init docs (NoCloud datasource, cloud-config
schema); curtin storage-config docs; this repo's CONVENTIONS.md,
`@randybias/ssh-host`, and the `@randybias/artifact-server` draft.

## 1. Purpose

Render Ubuntu Server autoinstall configuration from typed inputs — identity,
storage (guided LVM/direct, or explicit curtin actions incl. RAID + LVM),
network (netplan), SSH authorized keys, packages, late-commands — validate it,
and make it reachable by the installer: as an HTTP NoCloud seed directory on
`@randybias/artifact-server`, or as the inputs to a `CIDATA` seed image. The
password is a crypt hash from vault, never plaintext. **Booting** the installer
(Redfish virtual media, libvirt direct kernel boot) is out of scope; this model
emits the boot interface (§4.5) and other models wire it.

## 2. First task: evaluate `@evrardjp/cloud-init-nocloud`, then decide

It is already adopted for NoCloud seeds. Before building, establish from
`swamp model type describe` and its public README:

1. Does it accept **caller-supplied user-data/meta-data bytes** verbatim, or
   only its own cloud-config inputs? Autoinstall user-data is a cloud-config
   whose payload sits under `autoinstall:`, which a generic cloud-config
   renderer may reject, reorder or re-serialize.
2. Where does it write the seed (local file, remote host path), and with what
   host-key/credential policy?
3. Does it serve over HTTP, or only build `CIDATA` media?

Outcome: if (1) holds, the `CIDATA` path is a **workflow** wiring this model's
`render` output into it, and this model ships no ISO builder. If not, report to
the maintainer; a `build_seed` action (`xorriso`/`cloud-localds` on a host via the
canonical transport) is the fallback. The HTTP path (§4.1 `publish_http`) is
ours either way.

## 3. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host`, byte-identical,
used only by `publish_http` / `unpublish` / `get`. `render`, `validate` and
`cmdline` are pure and touch no host.

## 4. Model contract

- **Type** `@randybias/ubuntu-autoinstall`. CalVer == manifest version.
  `globalArguments` empty. State keyed by `hostname` (identity) + seed tree
  hash, never the definition name. Factory with injectable transport + clock.

### 4.1 Methods (every mutating one `kind:"action"`)

| Method | Kind | Description |
|---|---|---|
| `render` | — | READ-ONLY. Build `user-data`, `meta-data`, `vendor-data` from inputs and validate them (§4.4). Deterministic. Returns `{tree_sha256, files:[{name,sha256,bytes}], cmdline}`; file bytes are a sensitive field. |
| `validate` | — | READ-ONLY. Validate a supplied user-data document (e.g. hand-written) with the same pipeline; returns findings, never rewrites. |
| `cmdline` | — | READ-ONLY. Emit the kernel-argument string for a seed URL in both forms (§4.5). |
| `publish_http` | action | Idempotent. Render + validate, then write the files into an artifact-server root as `bundles/<tree-hash>/` using its documented layout (+ `SHA256SUMS`), and set ref `autoinstall-<hostname>`. Same tree = no-op. Returns `{seed_url, tree_sha256, cmdline, changed}`. |
| `unpublish` | action | DESTRUCTIVE. Remove the bundle and ref (the seed carries a password hash; remove it once the host is installed). Clean no-op when absent. |
| `get` / `sync` | — | READ-ONLY. Check the published bundle on the server (presence, per-file SHA-256 vs render); persist the observation as the `seed` resource. |

`build_seed` (action) exists only if §2 rules the adopted extension out.

### 4.2 Inputs (selected) and grammars

- `identity` — `hostname` RFC 1123 label (≤ 63, lowercase); `username`
  `^[a-z_][a-z0-9_-]{0,31}$`; `realname` printable ≤ 64, no control chars;
  `password_hash` **sensitive vault ref** matching
  `^\$(6|5|y|gy|2[aby])\$[./A-Za-z0-9$]{8,}$` — a plaintext is rejected by
  shape, never hashed by us.
- `ssh` — `install_server` (bool), `authorized_keys[]` (1–32 OpenSSH public key
  lines, parsed: type ∈ ed25519/ecdsa/rsa ≥ 3072, base64 blob, comment
  printable), `allow_pw` (default false; true requires `allow_pw_ack`).
- `storage` — discriminated union:
  - `{layout:"lvm"|"direct", match:{serial|path|model|size:"largest"|"smallest"|ssd},
    sizing_policy:"scaled"|"all", luks_password?}` (`luks_password` sensitive
    vault ref; LUKS passphrase, which autoinstall takes in plaintext — §9).
  - `{config:[...]}` — curtin storage actions as a typed union: `disk`
    (`ptable: gpt`, `match` or `serial`/`path`, `wipe`, `grub_device`),
    `partition` (size bytes/`-1`, `flag: boot|bios_grub|...`), `raid`
    (`raidlevel` 0/1/5/6/10, `devices[]`, `spare_devices[]`), `lvm_volgroup`,
    `lvm_partition`, `format` (ext4/xfs/vfat/swap), `mount`. Every `id`
    `^[a-z][a-z0-9-]{0,31}$`; every reference must resolve to an earlier id
    (graph check, no cycles, no dangling).
  - `{preset:"raid1-lvm", disks:[2 serials|paths], vg_name, lvs:[{name,size,fs,mount}]}`
    — a convenience that expands to `config` (ESP on each disk, md1 across the
    data partitions, VG on md1).
- `network` — netplan v2 object (ethernets/bonds/vlans; `match.macaddress`,
  addresses CIDR, routes, nameservers); validated structurally, RFC 5737 in
  fixtures. Absent ⇒ installer default (DHCP).
- `packages[]` — `^[a-z0-9][a-z0-9+.-]{0,127}(=[A-Za-z0-9.+~:-]{1,64})?$`, ≤ 256.
- `late_commands[]` — **argv lists only** (each element printable, ≤ 4096
  bytes), run by the installer without a shell; `curtin in-target --` is
  prepended when `in_target:true`. A shell string needs `shell:true` per item
  plus `late_commands_shell_ack`; no other input is ever interpolated into it.
- `first_boot_user_data` — optional cloud-config object placed under
  `autoinstall.user-data`, validated against the cloud-config schema.
- `shutdown` (`reboot`|`poweroff`), `updates` (`security`|`all`),
  `source_id` (optional, `^[a-z0-9.-]{1,64}$`), `locale`, `keyboard`, `timezone`.
- `server` (for `publish_http`) — `ssh` block + artifact-server `root` +
  `url_base` (`http(s)://` host[:port][/path], no userinfo, no `;`/space).
- Strict `z.object` throughout, no `.passthrough()`, arrays bounded.

### 4.3 Rendering (structured, never string concatenation)

Build a plain object tree, then serialize with one YAML emitter configured to
**quote every string**, emit no anchors/aliases/tags, sort keys, and fix the
document header to exactly `#cloud-config\n`. No template engine, no string
joining of YAML fragments. `meta-data` carries `instance-id: iid-<tree12>`
(derived from content, so changed user-data is a new instance) and
`local-hostname`. `vendor-data` is an empty cloud-config.

### 4.4 Validation pipeline (the parser-differential guard)

The installer parses with a YAML 1.1 loader; our emitter is a different
implementation. The classic differentials — `on/off/yes/no` → bool,
`0644` → octal, `22:22` → base-60, `1e3`, `null`/`~`, duplicate keys, a
leading `#cloud-config` being stripped — would silently change meaning. So:

1. Re-parse the rendered bytes with a **YAML 1.1-semantics** loader that
   rejects duplicate keys, anchors and tags; deep-compare to the object tree.
   Any difference is a hard error.
2. Validate `autoinstall:` against the subiquity autoinstall JSON schema,
   **vendored and pinned** to the release under test (generated by subiquity's
   `make schema`, stored with its source version).
3. Validate the top level and `autoinstall.user-data` against the cloud-init
   cloud-config schema (vendored, pinned). Reject autoinstall keys outside
   `autoinstall:` (the installer errors on these too).
4. Our own semantic checks: storage graph (§4.2), exactly one `/` mount, an
   ESP or `bios_grub` per boot disk, `version: 1`.
5. Live cells additionally run `cloud-init schema -c user-data` on the target.

### 4.5 Boot interface (consumed by redfish / libvirt models)

```
autoinstall ds=nocloud-net;s=<seed_url>
```

- `<seed_url>` MUST end in `/` (NoCloud requirement) and point at the bundle
  directory holding `user-data` and `meta-data`.
- `autoinstall` skips the installer's "Continue with autoinstall?" prompt;
  without it the boot is not zero-touch.
- Two renderings are returned: `kernel_args` (for direct kernel boot, e.g. a
  libvirt `<cmdline>` or a Redfish boot override, no escaping) and
  `grub_args` (`ds=nocloud-net\;s=<url>`, because an unescaped `;` ends a GRUB
  statement). For the `CIDATA` path: `autoinstall` only (cloud-init finds the
  labeled volume itself).

### 4.6 Outputs

`render` writes a `render` resource (tree hash, per-file hashes, cmdline;
lifetime 30d, GC 10); file bytes are sensitive and never written to data.
`get`/`sync` persist the `seed` observation (lifetime infinite, GC 10). No
output contains a password hash, LUKS passphrase or SSH private key.

## 5. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| plaintext in `password_hash` | rejected by shape; value never echoed in the error |
| YAML differential (e.g. hostname `on`, mode `0644`) | rendered quoted; round-trip equal; a forced unquoted emit fails step 1 |
| schema violation (unknown key, bad layout) | typed findings with JSON pointer; nothing published |
| storage graph dangling ref / cycle / two `/` | rejected before render |
| `publish_http` same inputs | no write, `changed:false` |
| `unpublish` absent | clean no-op |
| seed URL without trailing `/`, with userinfo or `;` | rejected |
| injection in any string (`$(..)`, `;`, newline, `---`, `: `) | inert data in quoted YAML; argv-quoted on the host |
| shell late-command without ack | rejected |
| artifact-server layout version mismatch | typed error; nothing written |
| SSH transport failure | typed error; no state written |

## 6. Tests (offline, increasing risk)

1. Schema/secret/license: hash and LUKS fields sensitive; plaintext rejected.
2. Pure mapping: golden user-data for (lvm guided, direct, raid1-lvm preset,
   explicit curtin RAID10+LVM) × (DHCP, static bond); render determinism under
   input reordering; tree-hash stability; both cmdline forms.
3. Failure + adversarial: §5 rows; a YAML 1.1 trap corpus (Norway problem,
   octals, sexagesimals, duplicate keys, `<<` merge) through the round-trip.
4. Packaging (vendored schemas listed, licenses noted).

Fixtures synthetic: RFC 5737 addresses, `example.com`, placeholder serials,
MACs, keys and hashes.

## 7. Live e2e matrix (maintainer-run — bare-metal box, nested KVM)

Target: a libvirt VM on the bare-metal box boots the Ubuntu 24.04 live-server
ISO (fetched into artifact-server by pinned hash) with the seed; disks are
throwaway qcow2/zvols. Boot wiring via `@randybias/libvirt` direct kernel boot
(`casper/vmlinuz`, `casper/initrd` from the ISO, ISO attached as cdrom).

| Cell | Expected |
|---|---|
| render + validate (all golden profiles) | pass; `cloud-init schema` clean on host |
| publish_http / re-run | bundle served; second run no-op |
| HTTP seed, guided LVM, one disk | unattended install completes, VM reboots, SSH with the pinned key works, password login off |
| HTTP seed, raid1-lvm preset, two disks | `/proc/mdstat` shows md1 clean; VG/LVs as specified; boots with either disk removed |
| static network (bond) | netplan on target matches input |
| packages + late-commands (argv) | packages installed; late-command marker file in `/target` |
| `CIDATA` seed via adopted extension (§2) | same install result as HTTP |
| missing `autoinstall` arg | installer stops at confirmation (documents the interface) |
| bad seed URL (404) | installer falls back to interactive; recorded, no false pass |
| get/sync | reflect the bundle on the server |
| unpublish / again | bundle + ref gone; no-op |

Receipts into `ubuntu-autoinstall/LOGBOOK.md`. No `stable` while any cell `untested`.

## 8. Credential policy

Repo-wide credential policy applies. The vault holds the **crypt hash** (SHA-512
`$6$` or yescrypt `$y$`, generated off-box, e.g. `mkpasswd`), so no plaintext
ever enters the model; examples show `${{ vault.get(...) }}` only. The rendered
user-data still contains that hash and SSH public keys: it is a sensitive
document, served only for the install window and removed by `unpublish`. The
LUKS passphrase (if used) is plaintext by autoinstall's design; it is
sensitive, and its use requires `tls.mode:"provided"` on the server or the
`CIDATA` path.

## 9. Known traps

- The NoCloud seed is fetched **unauthenticated** by the installer; putting
  basic-auth credentials in the URL leaks them into the kernel command line and
  BMC/console logs. Isolated provisioning network + short publish window.
- `identity` users are created at install; users in `autoinstall.user-data`
  are created at first boot, by cloud-init on the target.
- `allow-pw` defaults to true only when no authorized keys are given — we
  always render it explicitly.
- Any non-zero exit in `early-`/`late-commands` aborts the install.
- `source_id` values are ISO-specific (`casper/install-sources.yaml`); a wrong
  one fails late.
- UEFI on RAID1: the ESP cannot live on the md array for the firmware; render
  one ESP per disk and mark each disk `grub_device`.
- cloud-init docs now show `ds=nocloud;s=`; the installer docs and long
  practice use `nocloud-net`. Live cells pin which works on the tested release.
- Unknown autoinstall keys are warnings in version 1 but slated to become
  fatal; our schema rejects them now.

## 10. Open questions for Randy

1. **Interplay with `@evrardjp/cloud-init-nocloud` (§2):** depend on it for the
   `CIDATA` path via a workflow, or own a `build_seed` action so the two seed
   paths share one renderer and one validation pipeline?
2. `publish_http` writes artifact-server's layout directly (layout as a
   versioned contract) rather than handing sensitive bytes through a workflow
   to `artifact-server.publish_bundle` — acceptable coupling?
3. Is a LUKS passphrase in served user-data acceptable at all, or is LUKS
   limited to the `CIDATA` path?

## Next version scope: next

Next `ubuntu-autoinstall` version (public, beta).

- Re-vendor the canonical transport (`8f132c4329c9e64bed686731cd5a0e02980194ea`).
- Medium: `unpublish` without a ref treats a bundle with no `meta-data` as
  absent and leaves stray files.
- Live: the CIDATA path end to end (hand the files to the NoCloud CIDATA
  builder, boot a KVM guest from the ISO plus CIDATA, SSH-verify), plus the
  `publish_http` path as regression. The guest may be created with the
  `libvirt` extension if its define path supports it, else `virt-install` with
  the reason noted.
