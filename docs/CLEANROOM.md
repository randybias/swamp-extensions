# Clean-room protocol

Some extensions in this repo re-implement behaviour that Randy first built
during prior employment. That earlier code is not ours to reuse, so these
extensions are written clean-room. A **spec side** studies the old code and
writes a behaviour-only spec. A separate **implementation side**, which never
sees the old code, builds from that spec and public documentation.

## Roles

| Role | Who | May read | Produces |
|---|---|---|---|
| Spec side | The "swamp-publisher" Claude Code session and the spec-extraction subagents it spawns | Old source (a temporary local clone), the spec | Behaviour spec in `docs/specs/` |
| Reviewer | Randy | Anything | Approval of the spec |
| Implementation side | Fresh subagents or sessions started *after* the spec is approved | The approved spec, this repo, public Ceph/cephadm/Linux docs, swamp skills and docs | Code, tests, README |

## Rules

### What the spec may and may not contain

1. The spec describes **behaviour**:
   - methods and their arguments (the functional interface);
   - inputs and their validation, expressed as an accepted language, not copied
     patterns;
   - outputs;
   - idempotency;
   - invariants;
   - failure modes;
   - test obligations;
   - the public commands invoked.
2. The spec contains **no code** from the old source: no pseudo-code that
   mirrors its structure, no internal identifiers, no copied comments, error
   strings or description prose, and no private names, addresses or narrative.

### What the implementation side may not do

3. Implementers must never read, clone, fetch or search the old repositories.
   That covers `randybias/swamp-ceph-cluster` and any other repo or backup of
   ex-employer code.
4. Implementers must not be given any summary of the old code other than the
   approved spec.

### Order of events

5. The spec side deletes its local clone after the spec is approved, before any
   implementation work starts.
6. Every implementer prompt carries a clean-room preamble (rules 3–4) and is
   recorded in the log below.

## Provenance log

| Date (UTC) | Event | Detail |
|---|---|---|
| 2026-10-14 | Old source cloned for spec extraction | `randybias/swamp-ceph-cluster` at `4f6c72b`, into a session scratchpad (not in this repo) |
| 2026-10-14 | Spec extraction | 8 spec-side subagents wrote behaviour notes (scratchpad only, not committed) under shared extraction rules |
| 2026-10-14 | Spec written | `docs/specs/cephadm/00-overview.md` … `08-workflows.md` (9 files) |
| 2026-10-17 | Spec approved by Randy | sha256 of each file in `docs/specs/cephadm/SHA256SUMS` |
| 2026-10-17 | Local clone deleted | scratchpad clone removed before any implementation work |
| 2026-10-17 | Implementation started | Fresh implementer lanes started after the spec was approved and the clone deleted; every implementer prompt carried the clean-room preamble (rules 3–4) |
| 2026-10-17 | Implementer lane d6 | Groups 01–07 (transport, host prep, cluster lifecycle, pools/fs/CSI, verify, maintenance and teardown, RGW admin plane) and the handoff notes; clean-room preamble |
| 2026-10-17 | Implementer lane d1 | Group 08 workflow catalog (22 workflows); clean-room preamble |
| 2026-10-17 | Implementer lane d4 | RGW S3 plane (bucket inventory, inspect, ensure, policy, versioning); clean-room preamble |
| 2026-10-17 | Implementer lane b2 | Disk-wipe guard, the shared protected-device module (`_lib/protected_devices.ts`) and integration of all lanes (`lane/cephadm-int`); clean-room preamble |
| 2026-10-17 | Merged to main | `@randybias/cephadm` 2026.10.17.1 (beta), from `lane/cephadm-int` at `95517dc` |
| 2026-10-17 | P2 specs approved by Randy | Seven P2 specs (see "Approved specs" below), approval relayed via the swamp-publisher session; written from public docs only, so no old-source clone exists to delete |

## Approved specs

The approved text of each spec is pinned by its sha256. An "editorial scrub"
hash, where present, is a later commit that removed internal run jargon with
purely editorial changes: no method, input, output, invariant or failure mode
changed. Implementers build from the current file; if it no longer matches
either hash, the spec needs re-approval before implementation continues.

### P2 specs, approved 2026-10-17

Approved by Randy on 2026-10-17, relayed via the swamp-publisher session. The
specs were written from public documentation only; no prior implementation
was consulted.

| Spec | Approved sha256 | Editorial scrub sha256 (behaviour unchanged) |
|---|---|---|
| `docs/specs/kubevirt.md` | `07c1cdb1743178123fc3776b3d72d99b9e5052f5a6f65843dbb08a6c75663982` | — |
| `docs/specs/k0s-multinode.md` | `6534cd73d873394725e06f72ca6d2efa65b8d7ce17f853d6aed24aba446d340d` | — |
| `docs/specs/kea-dhcp.md` | `1bd3383b8fb51d619cf563da767fb5b15706a052fc570a2f0fb55aca497eb84d` | — |
| `docs/specs/knot-dns.md` | `4063e65244c7279dd2dc17a579e1b62f35b74ea438786192e211c53a7fdbb1e6` | — |
| `docs/specs/apt-cache.md` | `7c72f48649fc3b22b1abe69373a9ed5b65009a6f01a5e642599d49df27cd03e2` | — |
| `docs/specs/artifact-server.md` | `fe7243f97cfd95a0a7a878e5777abfc01b53a318cad2f38953a10216ef735e4c` | — |
| `docs/specs/ubuntu-autoinstall.md` | `aa444f483129ad43688cdc8e7f28948fd152aaa74c50edd82e2a18e088469a36` | — |

Implementation-side rules for these specs:

- Implementation starts only after this approval; implementers are fresh
  subagents or sessions.
- Rules 3–4 apply: implementers read only the approved spec, this repo, public
  upstream documentation and swamp skills and docs; never any prior or
  ex-employer implementation, and no summary of one.
- Every implementer prompt carries the clean-room preamble (rules 3–4) and is
  recorded in the provenance log above.
- A behaviour change to an approved spec (methods, inputs, outputs,
  idempotency, invariants, failure modes, test obligations) needs a fresh
  approval and a new hash here before it is implemented.
