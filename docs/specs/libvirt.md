# Spec: `@randybias/libvirt`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone managing libvirt/KVM networks, volumes and domains on a host over SSH.

Q3: Yes. `libvirt` names the product (libvirt), which covers networks, volumes and domains; short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `libvirt` as a libvirt/KVM manager, which is what it does, and guesses wrong about nothing.

Status: implemented and published (beta); the next-version scope is at the end.
Not clean-room (net-new). RFC 2119 keywords.

## 1. Purpose

Manage libvirt/KVM on a host over SSH: virtual networks (define/undefine,
including removing the `default` network), storage volumes (including cloning a
**golden zvol/volume** per node), domains (define from a cloned volume, power,
console), over `virsh` + a libvirt URI. Twin substrate's VM layer.

## 2. Build decision (made)

BUILD `@randybias/libvirt` fresh. Model the virsh surface after the public
`@bad-at-naming/libvirt` (network define/undefine, `vol-clone`, power) — learn
its command shapes, do NOT depend on it: its SSH path is accept-new TOFU with no
host-key policy, which we must not inherit. Add what neither candidate has: a
turnkey golden-volume → domain clone, console/serial access, and strict pinned
host-key handling. `@evrardjp/libvirt-vm-pool` is unusable here (no networks, no
libvirt volumes, local-only).

## 3. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host`,
byte-identical — do not hand-roll a transport. All `virsh` runs go through
`exec(argv)`/`execPipeline`. Strict host-key policy required.

## 4. Model contract

- **Type** `@randybias/libvirt`. CalVer == manifest version. `globalArguments`
  empty; methods take the SSH target + libvirt URI + operands per call. State
  keyed by canonical `{host,port,user}` + resource name. Factory with injectable
  transport + clock; unit tests assemble argv and parse `virsh` XML/output only.

### Methods (every mutating one `kind:"action"`)

| Method | Kind | Description |
|---|---|---|
| `define_network` | action | Define (and optionally start/autostart) a network from inputs; idempotent by name+config. |
| `undefine_network` | action | DESTRUCTIVE. Stop + undefine a network (use to remove `default`); `undefine`-again is a clean no-op. |
| `clone_volume` | action | Clone a golden volume/zvol in a pool to a new volume (`virsh vol-clone`); idempotent by target name; supports zfs-backed pools. |
| `define_domain` | action | Define a domain from a cloned volume + rendered XML; idempotent by name. Does not auto-start unless asked. |
| `power` | action | start / shutdown / destroy(force) / reboot / suspend / resume; idempotent toward the desired state. `destroy` is DESTRUCTIVE. |
| `console` | — | READ-ONLY. Attach/read the serial console (bounded capture with a timeout); never blocks forever. Returns captured text (mark sensitive if it can carry boot secrets). |
| `get` / `sync` | — | READ-ONLY. Report network/volume/domain state from `virsh dumpxml`/`list`/`vol-info`. |
| `undefine_domain` | action | DESTRUCTIVE. Destroy if running, then undefine; optionally remove its volumes (explicit flag). Clean no-op when absent. |

### Inputs (selected)

- `ssh` — transport block (strict `host_key_policy` + pinned `host_keys`, key via
  stdin/agent, sensitive; a **vault reference**, never a literal — see §7).
- `uri` — libvirt connect URI (e.g. `qemu:///system`), validated.
- network: `name`, plus either raw `xml` or structured inputs (bridge, mode,
  dhcp range as RFC-5737 in fixtures); reject shell metacharacters.
- volume: `pool`, `source_volume` (golden), `target_volume`, `format`.
- domain: `name`, `volume`, vcpus, memory, plus rendered XML; names validated by
  a strict grammar.
- Strict `z.object`, no `.passthrough()`; arrays bounded.

### Outputs

Typed state (names, states, UUIDs). No private key or console secret in `get`
output; console capture marked sensitive.

## 5. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| undefine absent network/domain | clean no-op |
| define idempotent | existing same-config = no-op |
| clone_volume to existing target | no-op (or typed conflict), never a silent second clone |
| power toward current state | no-op |
| console timeout | returns captured-so-far, never hangs |
| injection in any name/pool/uri | rejected by grammar; argv-quoted |
| SSH transport failure | typed error (vendored exit-255 handling); no state written |
| virsh non-zero exit | typed error; no success state written |

## 6. Live e2e matrix (needs a KVM-capable host)

Target: a bare-metal host with nested-virt or a VPS that supports KVM (blocked
until provisioned; mark cells `blocked`, not skip). Build + offline-gate fully.

| Cell | Expected |
|---|---|
| define_network / undefine default | custom net up; default removed |
| clone_volume (golden→node) | clone present once |
| define_domain from clone | domain defined |
| power start/shutdown/destroy | state transitions; idempotent |
| console | serial text captured, bounded |
| get/sync | reflect real libvirt state |
| undefine_domain (+volumes) | gone; no-op again |
| transport failure | typed error, no state |

Receipts into `libvirt/LOGBOOK.md`.

## 7. Credential policy (applies repo-wide)

The SSH private key is a **sensitive** input delivered to the remote only via
stdin/agent (never remote argv), and every example/README shows it ONLY as a
vault reference (`${{ vault.get(...) }}`), never a literal, and never with
`--json`. The swamp CLI echoing a *literal* sensitive arg under `--json` is a
known platform limitation (lab 3555), out of our scope; we do not redesign the
model to take opaque handles swamp does not provide. Note this in LOGBOOK.

## Next version scope: next

Next `libvirt` version (public, beta).

- Re-vendor the canonical transport (`8f132c4329c9e64bed686731cd5a0e02980194ea`).
- Residual Mediums: `remove_volumes` destroys a running guest before detaching,
  so a detach failure leaves it off and partly detached (detach first, destroy
  last, or refuse while running); `define_domain` on an existing domain can
  record a data disk as the root that a later `remove_volumes` deletes (verify
  the boot device from the domain XML); the stateful test fake does not drop
  attachments on detach.
- Use `virsh define --validate` in the realtool gate.
- Live on bare metal, in the same batch as `zfs`.
