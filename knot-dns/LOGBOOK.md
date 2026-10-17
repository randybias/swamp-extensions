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

## 2026.10.17.2 (lane/b3-knot, from d2 9bd91e8): r3 review round

Each fix was reproduced first in the Knot 3.6.1 + Resolver 6.5 and Knot 3.3.4
containers, and is covered by `_lib/host_test.ts`, which runs the real host
scripts under dash `sh -eu` against real knotd, kdig, ss and kresd (skipped when
docker or the image is absent; set `KNOT_BOX_IMAGE`, default `knot-check:b3`:
the `local2` image plus `iproute2 psmisc procps`).

- Listen changes: Knot ignores `server.listen` on reload ("changes of listen
  require restart"), and the stock Ubuntu config has no listen, so a reload
  bound nothing while apply reported success. A changed listen fragment now
  restarts knotd under the lock after `conf-check`, then every host listen is
  queried with kdig for the zone's SOA (rcode `NOERROR`); any failure restores
  the previous files and restarts again. Wildcard listens are queried on
  loopback.
- `ss -lntupH` (was `-h`, which is help): a socket is the host's own only when
  its line carries `users:(("knotd"`. An unprivileged probe cannot see owners
  and so fails closed.
- Probes: `kdig +retry=0 -p <port>` (`+tries` is not a kdig option), rcode
  checked because kdig exits 0 on SERVFAIL/REFUSED; `knot-dnsutils` is
  installed; the resolver test queries its own listen port and a forwarded
  subtree. Apply fails with `KDIG_MISSING` rather than skipping the check.
- Forward `dnssec` is always rendered. Knot Resolver 6 validates by default, so
  an omitted `false` turned private or locally signed forwards into SERVFAIL.
- Reload: `zone-reload` is no longer `-b`; the script polls `zone-status` until
  `load: pending` clears (a blocking reload can wait on NOTIFY retries to an
  unreachable secondary).
- Listen union: each applied zone stores its own `requested_listen`; the host
  fragment is the union of the other zones' requests plus this one's, so it can
  shrink, and `remove_zone` recomputes it. An unreadable store fails the call
  instead of falling back. State written by 2026.10.17.1 has no
  `requested_listen`, so its listens are ignored until that zone is re-applied.
- Rollback: an ownership failure restores before exiting; when the rollback
  reload itself fails the backup is kept and the error says
  `RESTORE_RELOAD_FAILED backup=<dir>` (this marker was previously shadowed by
  `RELOAD_FAILED`). Observe captures each probe's output before filtering so a
  failing `knotc`/`sha256sum` is `PROBE_FAILED`, not an empty serial.
- Staging: files are uploaded under per-run names and consumed by the locked
  script, so concurrent applies cannot swap each other's files.
- Not changed: the resolver test query is refused when the resolver listens on a
  non-loopback address and `allow_query_from` excludes that address; apply then
  rolls back with `TEST_QUERY_FAILED`. Add the address to `allow_query_from`.
- Structure: `knot_dns.ts` split into `_lib/schemas.ts`, `_lib/errors.ts` and
  `_lib/listen.ts`; shell fragments (`shq`, lock wrapper, restart, wait, query)
  live once in `_lib/fragments.ts`. `_lib/ssh.ts` stays at its vendored size so
  it remains byte-identical to ssh-host.

## Round 4 (live: fresh Ubuntu 24.04, 11/13)

- HIGH install: `knot-dnssecutils` (kzonecheck) is installed; exit 127 is a
  `tool_missing` error, not "kzonecheck rejected the zone". The resolver path
  adds the CZ.NIC repository for real (pinned key fingerprint, apt priority 100
  so Knot DNS stays 3.3.4 while knot-resolver6 6.5.0 comes from CZ.NIC; checked
  in a fresh ubuntu:24.04 under dash), verifies kresctl/kresd and the major
  versions, and leaves the resolver service stopped (its package config would
  fight knotd for 127.0.0.1:53). The key fingerprint is unverified against a
  second public source.
- HIGH apply_resolver self-test: the name is the caller's `test_name`, else a
  name the upstream serves (see README), so a parent forward to an authoritative
  that serves only children no longer rolls back.
- MEDIUM: `allow_transfer` takes the CIDR grammar, `notify_secondaries`
  `ADDR[@port]`; a failed apply_resolver removes its staged file (EXIT trap in
  the script, best-effort remove if the script was never reached); `outcome`
  records persist install/apply/remove results.
- Quality: install and the resolver methods moved out of knot_dns.ts
  (`install.ts`, `resolver_methods.ts`, shared `runtime.ts`).

## Prior art (re-checked at merge, 2026-10-17)

`swamp extension search` for knot, dns, bind and resolver, on stable and beta:
no package manages Knot DNS or Knot Resolver, and none is a zone-file
authoritative server over SSH. Adjacent only, each driving another product
through its API: @jamesakeech/technitium and @thomas/technitium (Technitium DNS
Server), @shrug/freeipa/dns (FreeIPA's integrated DNS), @magistr/pihole and
@lint/adguard (filtering resolvers), @lint/dns-policy, @svendowideit/mdns, and
the cloud DNS packages (@swamp/cloudflare/dns and secondary-dns, @swamp/gcp/dns,
@swamp/aws/route53). None renders and validates a Knot zone or a Knot Resolver 6
config, so there is nothing to file upstream.

## Decisions for Randy (merge summary)

1. **Per-zone fragments.** Each zone has its own
   `knot.conf.d/50-managed-<apex>.conf` instead of the spec's single shared
   file, so removing one zone never touches another (decision 2 above).
2. **Knot Resolver 6 only.** No 5.x Lua rendering (decision 3 above).
3. **DDNS refused.** Managed zones are whole-file declarations that own all
   their records (decision 1 above).
4. **Secondaries as configuration.** `notify_secondaries`, `allow_transfer` and
   `tsig_keys` render into the fragment; no secondary is verified (decision 4
   above).
5. **The CZ.NIC repository, pinned.** Ubuntu 24.04 ships Knot Resolver 5.7, so
   `install resolver: true` adds the CZ.NIC Labs repository. Its signing key is
   refused unless the primary fingerprint is
   `9C71D59CD4CE8BD2966A7A3EAB6A303124019B64` (read from pkg.labs.nic.cz/gpg and
   confirmed independently on keys.openpgp.org and pkg.labs.nic.cz/doc). The
   repository is pinned at apt priority 100, so Knot DNS stays at the archive
   version and only knot-resolver6 and its own libraries come from CZ.NIC
   (confirmed live: knot stayed 3.3.4).

## Merge prep (2026-10-17)

- Merged `lane/b2-knot` at 37fa21e. The history holds d2's `lane/d2-knot-dns`
  (review rounds 1-3), b3's `lane/b3-knot` escalation (c7f35ea, reviewed CLEAN
  with real knotd/kresd in `host_test.ts`) and b2's live fixes (37fa21e). Gate 5
  scans that history: no secret-like literal.
- Never published before, so the version is 2026.10.17.1 (the branch carried
  .3). The earlier version numbers in this logbook were lane-internal, so the
  "state written by 2026.10.17.1" migration note above concerns no released
  data.
- Self-review of c7f35ea..37fa21e against the runtime-shape,
  parser-differential, render-vs-live, remote-command, TOFU and argv-hash
  checks: no Critical/High. The vault is read as a plain `{get, put}` object
  (tested through a plain-object context), resolver configs are validated by
  `kresctl` on the host, host keys are strict only, and no content hash reaches
  an argv.
- Quality pass: the version, the fingerprint comments (now independently
  confirmed), and `systemctl reset-failed knot-resolver` after install disables
  the unit, so a package start that failed on a port knotd holds no longer
  leaves the unit reading `failed`.
- 112 offline tests, 0 failed.

## Live e2e (2026-10-17)

Target `<vps1>` (fresh Ubuntu 24.04.5), root over SSH with strict pinned host
keys and a vault `ssh_key_ref`; a throwaway TSIG secret was generated straight
into the vault and never printed. Loopback only: knotd on 127.0.0.1 and
127.0.0.2, the resolver on 127.0.0.3; data under `a.example.test` and
`b.example.test` with RFC 5737 addresses. A `tcpdump` guard for outbound DNS on
both NICs recorded 0 packets on the final run. The host was returned to its
baseline afterwards (dpkg, users, apt sources, keyrings, `:53` listeners).

First run on c7f35ea: 11/13 (install lacked `kzonecheck`; the resolver path got
Knot Resolver 5 and its self-test asked a name the upstream refuses). Final run
on 37fa21e from a clean baseline, with nothing installed by hand:

| Cell                                                                    | Result |
| ----------------------------------------------------------------------- | ------ |
| 1 install (knot, knot-dnsutils, knot-dnssecutils 3.3.4; outcome record) | PASS   |
| 2 render_zone + apply_zone A (unsigned, 127.0.0.1)                      | PASS   |
| 3 apply_zone B signed (127.0.0.2; listen union, restart)                | PASS   |
| 4 re-apply A: `changed: false`, no reload or restart                    | PASS   |
| 5 get_ds B (matches `keymgr ds`)                                        | PASS   |
| 6 TSIG transfer: AXFR with key 6 RRs, without key NOTAUTH               | PASS   |
| 7 unsign B: refused without the ack, then signing off                   | PASS   |
| 8 install resolver + apply_resolver forwarding example.test.            | PASS   |
| 9 injection (owner, allow_transfer, notify, NS, TXT) refused, no change | PASS   |
| 10 remove_zone B twice (second a no-op)                                 | PASS   |
| 11 remove_resolver (package config restored, disabled)                  | PASS   |
| 12 get / sync (no drift; outcome records listed)                        | PASS   |
| 13 argv scan: 0 hits for the TSIG secret or its sha256                  | PASS   |

Result: 13/13. Cell 8 confirmed the pinned key fingerprint on the host, knot
held at 3.3.4 with knot-resolver6 6.5.0 from CZ.NIC, and a self-test name of
`a.example.test.` chosen from the served zones.

## Residuals (beta)

- `remove_zone` does not purge the zone's KASP keys; use `keymgr` if they must
  go.
- `parent_ds_check` is accepted but not rendered into the Knot config.
- `install resolver: true` installs `ca-certificates curl gnupg`, which upgraded
  curl and libcurl as a dependency side effect live (`--no-upgrade` would avoid
  it).
- The resolver unit read `failed` after install live (the package's start could
  not bind 127.0.0.1:53 held by knotd). The quality pass adds
  `systemctl reset-failed`; not re-run live.
- The resolver self-test queries the first listen address; when
  `allow_query_from` excludes that address the query is refused and the apply
  rolls back (documented in the README: add the address to `allow_query_from`).
- Unsigning drops DNSKEY and RRSIG immediately (no delete-algorithm path).
