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
