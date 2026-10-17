# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17 (lane/d2-knot-dns, base origin/main): built `@randybias/knot-dns`
  from the approved clean-room spec only. Transport `_lib/ssh.ts` and its
  `_lib/ssh_test.ts` are vendored byte-identical from `@randybias/ssh-host`
  (blob `fe0139f08c42e3fdae0061b9688fb5c534174957`); implementers never read the
  old source.
- Design: managed zones are whole-file declarations rendered deterministically
  and loaded with Knot's `zonefile-sync: -1`,
  `zonefile-load:
  difference-no-serial`, `journal-content: all`,
  `serial-policy: unixtime`. Knot computes the diff on `zone-reload` and
  re-signs only what changed; the file on disk is the zone and its sha256 is the
  idempotency/drift identity. `apply_zone` validates the staged zone
  (`kzonecheck`) and the merged config (`knotc -c <staged> conf-check`) before
  swapping, and restores the backup on a reload or verify failure. No `knotc`
  transaction is used, because an open transaction blocks signing.
- Credentials: the SSH key and every TSIG secret are vault references resolved
  in-model through `context.vaultService` (a plain `{get, put}` object) and
  delivered to the host over stdin; no secret is rendered into the zone file or
  the zone config fragment returned by `render_zone`, and none is stored.
- Offline tests: schema/grammar/semantic rules, golden zone files for all record
  types, wildcard, delegation with DS and glue and a reverse zone,
  canonical-order stability, TXT escaping, golden zone config fragment and
  resolver YAML, served-vs-declared diff, and `sh -n` syntax validation of every
  host script. 72 tests.

## Decisions for Randy's review

Spec open questions are answered with the spec's own recommendation where it
states one; the rest take the simplest safe option or a documented deviation.

1. **Whole-zone ownership (spec §12 Q1).** Taken as specified: managed zones own
   all their records and refuse DDNS; no journal-as-source design.
2. **`zone:` across include files (spec §12 Q2).** The spec's open question is
   avoided rather than guessed: each zone gets its **own** fragment
   (`/etc/knot/knot.conf.d/50-managed-<apex>.conf`) with a complete `zone:`
   section, so no `zone:` section must continue across files and removing one
   zone never touches another. The include glob still pulls them all in. This
   deviates from the spec's single `50-managed-zones.conf`; the live
   include-split cell still proves the fragments load. If a shared file is
   required, `remove_zone` would need to re-render the remaining zones.
3. **Knot Resolver 5 vs 6 (spec §12 Q3).** Knot Resolver 6 only, from the
   distro/vendor package; no 5.x Lua rendering.
4. **Secondaries/transfers in v1 (spec §12 Q4).** Included as configuration:
   `notify_secondaries`, `allow_transfer` and `tsig_keys` render into the zone
   fragment, but the model is primary-focused and does not verify a secondary.
5. **SSH policy.** `host_key_policy` is `strict` only, with required
   `host_keys`; no `insecure_tofu`, per the lead's house rule (TOFU would
   require persisting first-seen keys).
6. **SOA serial.** The rendered SOA serial is a fixed placeholder `1`; Knot owns
   the live serial (`serial-policy: unixtime`, `difference-no-serial`), so the
   file stays byte-stable.
7. **Default TTL.** A record that omits `ttl` takes `soa.minimum`, and every
   record in one RRset must agree on TTL.
8. **TXT.** Strings are restricted to printable ASCII and rendered quoted and
   escaped; arbitrary bytes are refused rather than risk a zone-file injection.
9. **Resolver config path.** `/etc/knot-resolver/config.yaml` (with a staged
   sibling), and the resolver's own service unit `knot-resolver`.

## Known gaps for the live run

- The Knot tools (`kzonecheck`, `knotc`, `kresctl`, `kdig`) are not installed in
  the build environment, so unit tests cannot run them; renders are checked by
  golden files and the host scripts by `sh -n` only. The live matrix MUST
  validate every render with the real tools (`kzonecheck`, `knotc conf-check`,
  `kresctl validate`) before this is more than beta.
- The Knot Resolver 6 `config.yaml` schema is rendered from the public docs;
  `kresctl validate` on the live host is the authority.
- The vendor repository line for Knot Resolver 6 in `install` is distro
  dependent and must be confirmed live.

## Live matrix (lead's slot; all blocked — no throwaway host yet)

- install / again: blocked
- include-split proof: blocked
- apply_zone create / idempotent / record add-change-remove: blocked
- kzonecheck rejection: blocked
- DNSSEC on / ksk_submitted / DNSSEC off with ack: blocked
- apply_resolver / internal zone via resolver / cache size: blocked
- get / sync: blocked
- remove_zone / again; remove_resolver: blocked
- injection literal: blocked

## Review round 1 (HEAD 8ae8a5a) dispositions

Validated by the lead in a container against real knot 3.3.4 / 3.6.1 and
knot-resolver6 6.5.0.

- HIGH zone-file injection: every domain-valued field (`CNAME`/`NS`/`PTR` data,
  `MX` exchange, `SRV` target, `ns[]`, `soa.primary_ns`/`contact`) now enforces
  the `FqdnSchema` grammar, so a newline, `$INCLUDE` or `;` payload is refused
  by the schema. Tests cover all three.
- HIGH conf-check: the fragment now renders top-level `policy:`/`remote:`/
  `acl:` sections with apex-derived ids and references them from the `zone:`
  entry; inline blocks and `disable-any` are gone; `ksk-lifetime`/`zsk-lifetime`
  are rendered. (`parent_ds_check` has no Knot policy key, so it stays
  accepted-but-unrendered.)
- HIGH kresctl: `cache: size-max`, forward options under `options:`, and `view:`
  `subnets`/`answer`. Real `kresctl validate` is still the authority (not
  installed here).
- HIGH zone-read: `parseZoneRead` reads the real `owner ttl TYPE rdata` form
  (optional `[apex.]` prefix, optional `IN`), and IPv6 is compressed on both
  sides, so an `AAAA` declaration matches the served form.
- HIGH rollback: the apply script keeps the backup until the served-record
  verify passes; on a mismatch the model restores it. `knotc -b` blocks on
  reload. The resolver script tests the query before discarding its backup.
- HIGH ownership/TSIG: managed files are `chown root:knot`; the TSIG fragment is
  per-zone now (`10-managed-tsig-<apex>.conf`), staged and swapped under flock,
  and included in backup/restore, so applying one zone no longer clobbers
  another's keys. (Deviation: the spec says one key file.)
- HIGH dnssec-off: `apply_zone` refuses a recorded signed zone turned `off`
  without `dnssec_unsign_ack`; the delete-algorithm path is not implemented in
  v1, so `remove_zone` (with ack) is the supported way to retire signing.
- HIGH remove_resolver: requires a recorded applied resolver or `remove_ack`,
  fails if the service cannot be stopped, and restores the package
  `config.yaml`.
- MEDIUM names: resources are suffixed (`zone`/`render`/`ds`/`resolver`/
  `observation`), so `get_ds` no longer overwrites zone state and `render_zone`
  no longer overwrites applied state.
- MEDIUM listen: wildcard needs `listen_any_ack`, the auth and resolver listen
  sets must be disjoint, a port-53 precheck refuses a foreign listener, and the
  authoritative listen is rendered as a host-global fragment.
- MEDIUM service owners: a leading underscore is allowed on any owner label
  (`_sip._tcp`, `_443._tcp.www`, `_dmarc`).
- MEDIUM get/sync: they now diff served vs the recorded declaration
  (added/removed), report DNSSEC key states, and only persist after both probes
  succeed.
- `purge_keys_ack` now runs `knotc zone-purge` for the journal; KASP key
  deletion is left to `keymgr` and is a residual.

## Review round 2 (HEAD 15b7978) dispositions

- HIGH CHGRP bug: the ownership loop now uses `"$x"` and fails the script
  (`CHOWN_FAILED`) when it cannot set ownership; the generated apply and restore
  scripts run clean under dash `set -eu` (verified in ubuntu:24.04 with stub
  tools), which would have caught the old `$1` unbound-variable abort.
- HIGH listen: the authoritative listen is now host-global and staged as
  `server:\n  listen: [...]` (a top-level `listen:` and a dash block are both
  rejected); it is conf-checked, backed up, swapped and restored under the same
  `flock`, and the model renders the union of the recorded zones' listens.
  Verified with real `knotc conf-check` on knot 3.3.4 and 3.6.1.
- HIGH kzonecheck: dropped `-d on`; a signed zone's input file is checked
  unsigned and Knot signs after load. Verified rc=0 on 3.3.4 and 3.6.1.
- HIGH ACL key: `key: [k1, k2]` for several keys and `key:` omitted when there
  are none; verified conf-check clean.
- HIGH resolver: `cache.size-max: 256M`, per-server `address`/`transport: tls`/
  `hostname`, `network.listen` (`interface` + `port`) and `views`
  `answer:
  refused`, all from `kresctl schema`. Verified `kresctl validate`
  6.5.0 reports "Basic validation was successful".
- HIGH TSIG change detection: the staged TSIG fragment is uploaded every time
  (empty when there are no keys) and takes part in the change comparison and the
  install/remove decision, so a rotation or a removal is applied and a stale
  staged file cannot be installed later.
- HIGH rollback: the restore exit status is checked and a failed rollback raises
  `rollback_failed` with the backup path; the restore script fails if its reload
  fails.
- HIGH port-53 precheck: only the requested listen address/port pairs are
  checked (with wildcard coverage) and a Knot listener is allowed, so a
  co-hosted systemd-resolved stub or kresd on a disjoint address is fine.
- MEDIUM: one `remote:` per secondary with `notify: [ids]`; `remove_zone` runs
  under `flock` and backs up/restores the TSIG fragment; `ListenSchema` parses
  addresses and ports; `notify_secondaries`/`allow_transfer` now require address
  grammar; the listen overlap check normalizes addresses; declared tuples are
  stored as JSON; the config id includes a digest; `observe` fails the probe
  instead of persisting when a read fails.

## Real-tool receipts

Renders were checked against the containers the lead named:

- `knotc -c knot.conf conf-check`: **valid** on `knot-check:local2` (3.6.1) and
  `knot-distro:local` (3.3.4), for the signed and unsigned fragments with
  `server.listen`, `key`, `policy`, `remote`, `acl` and `zone` sections.
- `kzonecheck -o example.com. example.com.zone`: **rc=0** on both.
- `kresctl validate config.yaml`: **"Basic validation was successful"** on
  `knot-check:local2` (6.5.0).
- `applyZoneScript` under `sh -eu` (dash) in `ubuntu:24.04` with stub
  `knotc`/`kzonecheck`/`chown`/`chgrp`: **rc=0**, `backup=` and `changed=yes`
  printed, so no unbound-variable abort.
