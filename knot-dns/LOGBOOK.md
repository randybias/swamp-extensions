# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17 (lane/d2-knot-dns, base origin/main): built `@randybias/knot-dns`
  from the approved clean-room spec only. Transport `_lib/ssh.ts` and its
  `_lib/ssh_test.ts` are vendored byte-identical from `@randybias/ssh-host`;
  re-vendored for 2026.10.17.2 (ssh-host 2026.10.17.3) to blobs `ssh.ts`
  `8f132c4329c9e64bed686731cd5a0e02980194ea` and `ssh_test.ts`
  `4e8ac15fcd6bce797c523a221fe58fe9a8d9b386`; implementers never read the old
  source.

## Vendored

| File                                 | Blob (git hash-object)                     | Source                             |
| ------------------------------------ | ------------------------------------------ | ---------------------------------- |
| `extensions/models/_lib/ssh.ts`      | `8f132c4329c9e64bed686731cd5a0e02980194ea` | `@randybias/ssh-host` 2026.10.17.3 |
| `extensions/models/_lib/ssh_test.ts` | `4e8ac15fcd6bce797c523a221fe58fe9a8d9b386` | `@randybias/ssh-host` 2026.10.17.3 |

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
the provider DNS packages: @swamp/cloudflare/dns and
@swamp/cloudflare/secondary-dns, @swamp/vercel/dns, @swamp/gcp/dns,
@swamp/aws/route53 and @sntxrr/scaleway-dns (zone and record management over a
provider API), and @webframp/aws/dns-observation (read-only Route53 zone and
record observation with orphan detection). None renders and validates a Knot
zone or a Knot Resolver 6 config; every one needs a provider API, account token
or registrar credential, and none edits an on-host zone file over SSH, so there
is nothing to file upstream.

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
  leaves the unit reading `failed`. The zone record schemas are now
  `z.strictObject` (they were `z.object`, which silently dropped a misspelt key
  such as `TTL`, despite a comment calling them strict).
- 113 offline tests, 0 failed.

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

## 2026.10.17.2 (lane/d2-knot-dns): next build

Re-vendored the canonical transport and closed the three Lows the backlog named.
Live testing is for the reset-failed fix and the strict schemas merged in
2026.10.17.1, plus these changes.

- **Transport.** `_lib/ssh.ts` and `_lib/ssh_test.ts` are byte-identical to
  `@randybias/ssh-host` 2026.10.17.3 (blobs `ssh.ts` `8f132c43...`,
  `ssh_test.ts` `4e8ac15f...`); the SSH key reaches `ssh-agent` over stdin and
  uploads stream over stdin, so no secret byte touches an argv or a remote temp
  file. No knot code needed a change: the transport's public shape is unchanged.
- **`remove_zone` KASP purge.** The old `purge_keys_ack` ran `knotc zone-purge`
  without `-f` _after_ the zone had been removed, so Knot answered "force option
  required" and "no such zone found" and the `|| true` swallowed both. With the
  ack the script now runs `knotc -f zone-purge` while the zone is still
  configured (data, journal, timers, KASP), then removes the zone, then runs
  `keymgr <zone> delete` for every key the signer regenerated, and retries the
  key purge on a `present=no` re-run. Without the ack neither runs, so the
  journal and keys survive a remove. Covered by a new real-container
  `host_test.ts` cell (`remove: purge_keys_ack removes the zone's KASP keys`)
  that signs a zone, removes it, and asserts `keymgr -l` no longer lists it.
- **`parent_ds_check` dropped.** It had no Knot policy key (review round 1), so
  the schema dropped it; a caller that still passes it is refused rather than
  silently ignored.
- **Resolver self-test.** `apply_resolver` now tests the first listen address
  `allow_query_from` permits (`pickTestListen`); the default access list is
  loopback plus each listen address as a host route, matching the spec's
  "loopback + the listen subnets" without opening a wider network. An explicit
  list that excludes every listen address is refused before any host work with
  `invalid_input`, instead of swapping a config that fails its own test and
  rolls back.
- **README.** Secondaries are documented as configuration only.
- **Harness capture (deliberate).** The tests exercise the rendered host scripts
  against real `knotd`/`kzonecheck`/`kresctl`/`kdig` in a container and validate
  every script with `sh -n`; they do not vendor `_lib/bogworks/` and so write no
  `BOGWORKS_CAPTURE_SCRIPTS`. The `dash-runner` and `bashisms` gates report that
  as a MEDIUM (they pass). The capture harness is a larger refactor than this
  item's transport re-vendor, so it is left for a follow-up.

## Residuals (beta)

- `install resolver: true` installs `ca-certificates curl gnupg`, which upgraded
  curl and libcurl as a dependency side effect live (`--no-upgrade` would avoid
  it).
- The resolver unit read `failed` after install live (the package's start could
  not bind 127.0.0.1:53 held by knotd). The quality pass adds
  `systemctl reset-failed`; this version's live run covers that path.
- Unsigning drops DNSKEY and RRSIG immediately (no delete-algorithm path).
- `purge_keys_ack` removes the active KASP keys with `keymgr`; deleted keys can
  remain in keymgr's "trash bin" until `keymgr <zone> trash-discard` (kept as a
  rollover safety net, not a live secret).

## Review round 1 (HEAD 8bf261f) dispositions

- HIGH unmanaged KASP purge: `remove_zone` passed `purge_keys_ack` straight to
  the script, whose `present=no` branch purged any apex's keys with `keymgr`, so
  an apex this model never managed could lose its active keys while the call
  reported `removed=no`. The method now permits the ack only when the stored
  zone record exists and is not `rendered` (applied or removed), and refuses
  otherwise with `invalid_input` before any host work; the `present=no` retry
  still works for a zone this model applied. New unit test covers both the
  missing-record and render-only cases.
- MEDIUM swallowed `keymgr list` failure: the list is captured and its status
  checked (`ids=$(keymgr ...) || return 1`), so a missing or locked KASP DB, an
  absent `keymgr` or a permission error fails the action (`PURGE_KEYS_FAILED`,
  exit 16) instead of reporting `removed=yes` with the keys still on disk;
  `keymgr delete` reads `/dev/null` rather than the list pipe, and the
  after-backup retry removes the backup directory before it exits. Covered by a
  new container cell with a failing `keymgr` stub.
- MEDIUM irreversible purge ordering documented: `knotc -f zone-purge` runs
  while the zone is configured, so a later reload failure rolls the files back
  but not the keys; the rollback now prints `RELOAD_FAILED_KEYS_PURGED` (typed
  `reload_failed`, keys gone) and the README says to re-run `remove_zone` to
  finish the removal.
- LOW key-id grammar: a key id read back from `keymgr` is checked against
  `[0-9a-fA-F]` before it reaches `keymgr delete`.
- LOW description length: the `remove_zone` description is three sentences.
- LOW test hygiene: the purge container cell interpolates `APEX` rather than a
  hardcoded zone; `cidrContains` drops its `/0` mask special case.

## Live round 1 (HEAD 3b87cf4, sp-2 vps-small) dispositions

The live matrix was 44 pass / 4 fail / 1 untested / 2 inconclusive. All four
fails are fixed here.

- FAIL `apply_zone` port-53 precheck: `ss` prints the resolved stub as
  `127.0.0.53%lo:53`; the awk comparison kept the `%lo` scope, so the precheck
  missed it and knotd restarted into a failed bind before rolling back. The
  address scope is stripped before the comparison, and `PORT_BUSY` now names the
  holding process. Container cell fakes a scoped `ss` line.
- FAIL `apply_resolver` overlap: a resolver listen held by knotd was not refused
  as an overlap (`apply_zone` refuses the mirror case). `apply_resolver` now
  runs the same `assertListenAcceptable` against the applied zones' requested
  listens, before any host work.
- FAIL `apply_resolver` wildcard: `listen_any_ack` was never enforced on the
  resolver; the same precheck refuses a wildcard without the ack before dialling
  (the old path connected first and only failed at the bind).
- FAIL `apply_resolver` busy port: there was no port precheck at all. It now
  runs `portCheckScript` with the resolver's own process allowed (`kresd`,
  `knot-resolver`) and knotd not, so a foreign holder is a typed `port_busy`
  before the config is staged.
- FAIL `ksk_submitted` rerun: the second call surfaced `knotc`'s
  `(no key ready
  for submission)` as exit 1. That is the already-done state,
  so the script now exits 0 with `submitted=already`; a real error still
  propagates.
- Observation: `ZONE_ABSENT` now maps to `invalid_input`.
- Observation: `install` no longer rewrites `knot.conf`'s mtime on a no-op run
  (`[ -e ] || : >` replaces `touch`).
- Left as noted: `render_resolver` persists no render (two inconclusive rows,
  LOW in `receipts-exist`; the bad-input pass covers the method);
  `remove_resolver`'s second call stays a refusal; knot-resolver6's
  `supervisor.service` is an install artifact; `sync` lists a served-but-
  undeclared record under `removed`.

## Review round 2 (HEAD 3b87cf4) dispositions

Triage round 2 (run sp-2) on the round-1 fix commit was review-clean: no
Critical or High. Seats conformance, adversarial and tightness all returned rc=0
(tightness TIGHT, 3 lines); 138 offline tests. The lane neither fixed nor
recorded the one Medium and four Lows, so they are dispositioned here at merge.

- MEDIUM host-only record key (kept, backlog for the next version). Every
  `zone`, `resolver`, `observation` and `ds` record is keyed by `ssh.host` plus
  apex, where the spec keys state by `{host, port, user}`. Two targets reached
  through one hostname on different ports or users share one record set, so an
  apply on the second overwrites the first's record and the purge gate's
  `managed` is true for a zone applied only on the other target. Downgraded from
  the adversarial seat's High: unchanged since 2026.10.17.1, the operator names
  the target and passes every ack explicitly, and no credential or privilege
  boundary is crossed. Confirmed live in both runs (`render_zone` existing: user
  `other` on port 2222 wrote v3 of the port-22 record). Fix: persist `port` and
  `user` on apply and refuse a mismatching target with `invalid_input`, keeping
  the names so existing records upgrade.
- LOW `CHOWN_FAILED` after the purge (kept). After `knotc -f zone-purge` only
  the reload rollback prints `RELOAD_FAILED_KEYS_PURGED`; an `own_all` failure
  in the same window rolls the files back under a plain `CHOWN_FAILED` although
  the KASP keys are gone. The README documents the purge as irreversible on any
  failed remove; the path is rare.
- LOW redundant `[ -n "$ids" ] || return 0` in `purge_keys` (kept, cosmetic).
- LOW resource-name uniqueness test compares names it recomputes, not the names
  the fake context captured (kept, test gap; the `apply_zone` test shares it).
- LOW LOGBOOK blob prose (fixed here): the transport paragraphs now name both
  blobs, `ssh.ts` 8f132c43... and `ssh_test.ts` 4e8ac15f....

Refuted in round 2: the `ssh.ts` seat findings (timeout returns before the child
settles, a stdin secret echoed by `cat`, a local kill leaving the remote
mutation running, an orphaned `Promise.race` rejection, `killedForCap`) are
dropped under ruling R6, the file being byte-identical to the canonical
transport and knot-dns passing no `timeoutMs` or output cap; the `Promise.race`
item went to the lead for `ssh-host`. Advisory "IPv4-embedded IPv6 reaches
`BigInt(NaN)`": `isIpv6` admits only `[0-9a-fA-F:]`. Advisory "trashed keys make
the acked re-run fail": the container cell asserts `keymgr list` is empty after
the acked remove. Advisory "`return 1` in the pipeline subshell is not
portable": the shell is dash under `set -eu`, where the pipeline's status is the
function's. Advisory CIDR message: `CidrSchema` accepts a bare address as /32 or
/128.

## Review round 3 (HEAD 67e2169) dispositions

Round 3 reviewed the live-round-1 fix commit. Seats conformance, adversarial and
tightness all rc=0; 144 offline tests and 13 container cells passed in the
triage worktree; tightness COULD-BE-TIGHTER (24 lines), not BLOATED, so no
simplification pass was required. All four live fails were verified fixed at
HEAD (see "Live round 1" above). No Critical or High: review-clean, and the head
went to its second live run unchanged.

- MEDIUM host-only record key: carried from round 2, see above.
- LOW `allow_query_from` ordering (kept). The purely local `pickTestListen`
  check (an access list that permits no listen address) now runs after
  `sshTarget` and the `assertPortsFree` probe, so `apply_resolver` dials and
  probes before refusing. Still refused before anything is swapped, and the
  probe is read-only; live run 2 recorded the connect timeout on an unroutable
  target where run 1 refused in 1.7 s. Fix: move the check before the render and
  the vault read, and assert `host.commands.length === 0`.
- LOW `CHOWN_FAILED` after the purge (kept, carried).
- LOW redundant `ids` check (kept, carried).
- LOW `PORT_BUSY` formatting (kept, cosmetic). The message prints the address
  twice and, when both the udp and tcp sockets match, a second unlabeled line;
  the method keeps only the first line. Seen live as
  `PORT_BUSY 127.0.0.53:53 ... owner=systemd-resolve`.
- LOW string-level tests (kept, test gap). The offline port-check test passes
  `127.0.0.53:53`, not the `ADDR@port` grammar the script parses, and the
  `ksk_submitted` already-done branch is asserted as a substring; the executed
  coverage is the container cell for the scope strip and owner, plus the
  triage's dash run of both `ksk_submitted` branches. Next version: use
  `127.0.0.53@53` and add a dash-executed test with a stub `knotc`.
- LOW tightness (kept): `ipv4ToInt` is single-use (about 5 lines), the three
  `apply_resolver` refusal tests repeat their setup (about 15), and the
  `keys_purged` shell state is fixed at render time (about 4).
- LOW uniqueness test (kept, carried).
- LOW LOGBOOK blob prose: fixed here.

Refuted in round 3: advisory HIGH "`return 1` inside the `printf | while`
subshell never fails `purge_keys`", by execution under dash and bash-as-sh (the
function returns 1 for both the `keymgr delete` failure and the grammar guard).
Adversarial MEDIUM "`pickTestListen` returns the wildcard literal": by design,
the apply script's `query_ok` rewrites `0.0.0.0` to `127.0.0.1` and `::` to
`::1` before `kdig`, as `resolver_test.ts` asserts. The `ssh.ts` timeout and
`killedForCap` items are dropped under R6 as in round 2. Advisory IPv4-embedded
IPv6: as in round 2. Advisory "idempotency detected by an English substring":
`knotc` has no message catalogue, the text is libknot's fixed error string, and
`knotc`'s exit 1 cannot tell this case from a real failure.

## Live round 2 (HEAD 67e2169, sp-2 vps-small)

Run sp-2 on 67e2169, contentHash
`114326131b4aef84406adeeb9b865d15d04d165d998785c0dae44a8ba952600a`,
2026-10-18T03:27Z to 03:49Z, the second and last live run of this version; the
four run-1 fails were re-run first. Result is `pass`, `fail`, `untested` or
`inconclusive`; only `pass` counts. Real addresses, hostnames and provider ids
are redacted: `<vps>` is the target, a throwaway hourly VPS (1 vCPU, 1 GB,
Ubuntu 24.04.5, kernel 6.8.0-142, knot 3.3.4 from the archive, knot-resolver6
6.5.0 from CZ.NIC pinned at priority 100). No container cell: the control host
is aarch64 with docker only, and every method drives apt, systemd and
knotd/kresd over SSH, so the lifecycle ran on the VPS with every listen on
loopback (knotd 127.0.0.1 and 127.0.0.2, kresd 127.0.0.3); 491 host listener
samples at 1/s showed no non-loopback :53 or :853 at any time. Fresh scratch
repo with the head's `extensions/models` copied in unchanged (tar sha256
identical on both sides); model `dns`, typeVersion 2026.10.17.2; the SSH key a
vault reference, the TSIG secret generated straight into the vault; host key
pinned by keyscan on first contact, policy strict; every run through a logging
wrapper with `--input-file`, `--json` only on one host-less `render_resolver`
run carrying vault references only. Baseline before and after (144-line diff):
only the documented install residue remains (the knot, knot-dnsutils,
knot-dnssecutils and knot-resolver6 packages with their dependencies, the knot
and knot-resolver users, `/etc/knot` with an empty `knot.conf.d`, the
`/var/lib/knot` LMDBs with two trashed `.pem` files from keymgr's trash bin, the
package `config.yaml`, kresd's own cache, the CZ.NIC list, preferences and
keyring, curl/libcurl 10.15 to 10.16, and `/root/.gnupg` from the documented
`gpg --show-keys` fingerprint check); listeners identical to the baseline. Argv
scan: 1,455 unique local `ps` argv lines (118,990 raw samples at 2 s) and 94
unique host `ps` lines scanned in memory against the run SSH key, the provider
token and the swamp token: 0 secret hits. The throwaway server was deleted at
the end (HTTP 204) and the provider's project listing showed no server of this
lane afterwards. `content_hash_proved` is the first 12 characters of the hash
above.

| method_or_workflow | scenario     | result       | run_id | test_cell | content_hash_proved | note                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------ | ------------ | ------------ | ------ | --------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| render_zone        | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | no host contact (unroutable 192.0.2.1 target, 33 ms): record knot_32040b0a… status rendered, sha 4495d22c…, 8 records (same sha as run 1, deterministic render)                                                                                                                                                                                                                                                                                                                                                                                                   |
| render_zone        | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | same inputs: same sha 4495d22c…, record v2 with identical content                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| render_zone        | existing     | pass         | sp-2   | vps-small | 114326131b4a        | the known Medium (recorded, not failed): same host with user `other` and port 2222 and a 3-record declaration wrote v3 of the same record knot_32040b0a… (sha 2087a7e4…, record_count 3); records are still keyed by host and apex only                                                                                                                                                                                                                                                                                                                           |
| render_zone        | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | owner `evil\n$INCLUDE /etc/shadow`: invalid owner label; DNSKEY record: signer-owned types refused; apex CNAME refused; dnssec.parent_ds_check refused by the strict schema; all without host contact (1.7-1.8 s wall, CLI start-up)                                                                                                                                                                                                                                                                                                                              |
| render_resolver    | fresh        | inconclusive | sp-2   | vps-small | 114326131b4a        | succeeded in 24 ms without host contact, but the rendered config.yaml and sha are only in the return value: the CLI, --json (dataArtifacts [], "succeeded with no data output") and the output metadata do not show them and nothing is persisted; the applied render is validated on the host in apply_resolver fresh                                                                                                                                                                                                                                            |
| render_resolver    | rerun        | inconclusive | sp-2   | vps-small | 114326131b4a        | succeeded again; no observable output to compare (same gap as run 1)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| render_resolver    | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | authoritative upstream with transport tls refused at validation; observation unchanged from run 1: an allow_query_from excluding every listen still renders fine and is refused only by apply_resolver                                                                                                                                                                                                                                                                                                                                                            |
| install            | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | host_key_policy insecure_tofu refused at validation (`expected "strict"`), nothing dialled                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| get                | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | missing ssh.host_keys refused at validation (`expected array, received undefined`), nothing dialled                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| remove_zone        | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | purge_keys_ack on an apex this model never applied and on a render-only apex: both refused before host work (`purge_keys_ack only applies to a zone this model applied on this host`); invalid apex refused at validation                                                                                                                                                                                                                                                                                                                                         |
| ksk_submitted      | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | invalid apex refused at validation, nothing dialled                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| get_ds             | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | invalid apex refused at validation, nothing dialled                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| apply_zone         | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | NS with a newline, TXT with a newline, allow_transfer `127.0.0.1"\n action: update`, notify_secondaries `; reboot`, a misspelt `TTL` key and a 0.0.0.0 listen without listen_any_ack: each refused by field before host work (the wildcard refusal was reproduced with the vault key deliberately absent, so it precedes even the key read)                                                                                                                                                                                                                       |
| apply_resolver     | failure-path | pass         | sp-2   | vps-small | 114326131b4a        | run-1 High re-run: listen 0.0.0.0 without listen_any_ack is now refused in 1.7 s (`a wildcard listen address needs listen_any_ack`) before the vault key is read or the host dialled (reproduced with the vault key absent; unroutable target), no kresd restart possible                                                                                                                                                                                                                                                                                         |
| apply_resolver     | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | allow_query_from permitting no listen address is still refused, but at this head only AFTER the port precheck has dialled the host (unroutable target: `could not connect` after the 15 s timeout, 16.9 s); run 1 refused it before host work: ordering regression, pure-input check now behind `assertPortsFree` (resolver_methods.ts: sshTarget/assertPortsFree precede pickTestListen); no host mutation                                                                                                                                                       |
| remove_resolver    | bad-input    | pass         | sp-2   | vps-small | 114326131b4a        | no recorded resolver and no remove_ack: refused before dialling (`this model did not apply a resolver on this host; pass remove_ack to proceed`, 2.2 s, unroutable target)                                                                                                                                                                                                                                                                                                                                                                                        |
| install            | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | Ubuntu 24.04.5 target: knot, knot-dnsutils, knot-dnssecutils 3.3.4 from the archive in 57.4 s; knotc/kdig/kzonecheck/keymgr present, `include: /etc/knot/knot.conf.d/*.conf` once in knot.conf (sha b5479f32…), knot active (MainPID 2176); outcome knot_version 3.3.4; read back over a second SSH session; no :53 listener added (knotd binds only when a zone sets a listen)                                                                                                                                                                                   |
| install            | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | 3.8 s; package set, include count (1), MainPID 2176 and knot.conf mtime (1792294587) and sha identical: the run-1 `touch` mtime observation is fixed at this head; journal shows no restart                                                                                                                                                                                                                                                                                                                                                                       |
| install            | existing     | pass         | sp-2   | vps-small | 114326131b4a        | resolver true over the existing install (1m2s): knot stays 3.3.4 (apt candidate 3.3.4, knotd MainPID 7488 unchanged) while knot-resolver6 6.5.0 and libknot16/libdnssec10/libzscanner5 3.5.8 come from CZ.NIC (`Pin: origin pkg.labs.nic.cz` 100, cznic-labs-pkg.gpg keyring, list file); knot-resolver inactive, disabled, not failed; outcome kresd_version 6.5.0; documented side effect curl/libcurl 10.15 to 10.16                                                                                                                                           |
| apply_zone         | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | a.example.test on 127.0.0.1: zone file root:knot 0640 under /var/lib/knot/zones, fragments 40-managed-listen.conf (`listen: ["127.0.0.1"]`) and 50-managed-a.example.test.conf; `knotc zone-status` role master serial 1; kdig www A 192.0.2.10, AAAA 2001:db8::10, alias CNAME www; knotd (MainPID 3477) listens on 127.0.0.1:53 only, resolved's 127.0.0.53/54 untouched; 16.2 s                                                                                                                                                                                |
| apply_zone         | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | b.example.test signed (ecdsap256sha256) on 127.0.0.2: listen fragment became ["127.0.0.1", "127.0.0.2"], knotd restarted (3477 to 5895), both addresses answer both zones; B answers carry RRSIG and 2 DNSKEY (256/257 alg 13), A none; keymgr lists ZSK 31323 active and KSK 19731 ready; served serial 1792294674; outcome dnssec true                                                                                                                                                                                                                          |
| apply_zone         | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | identical A: every mtime under /etc/knot and the zone file, served serial 1 and MainPID 3477 unchanged; journal shows only zone-status/zone-read control commands, no zone-reload or restart; same record sha 4495d22c…                                                                                                                                                                                                                                                                                                                                           |
| apply_zone         | existing     | pass         | sp-2   | vps-small | 114326131b4a        | record add/change/remove on A: www 192.0.2.10 to .11, alias removed (NXDOMAIN), ftp 192.0.2.21 added, serial 1 to 1792294654 via `zone-reload … loaded`, MainPID 3477 unchanged (no restart); injection literal: TXT `x" ; $INCLUDE /etc/shadow` stored escaped and served literally                                                                                                                                                                                                                                                                              |
| apply_zone         | existing     | pass         | sp-2   | vps-small | 114326131b4a        | DNSSEC turned on for the applied A: RRSIG served, 2 DNSKEY, 2 new KASP keys, `dnssec-signing: on` plus a managed policy in the fragment (serial 1792294803); then off with dnssec_unsign_ack: `dnssec-signing: off`, 0 RRSIG, 0 DNSKEY, www still NOERROR 192.0.2.11, the 2 keys kept (documented: no delete-algorithm path)                                                                                                                                                                                                                                      |
| apply_zone         | existing     | pass         | sp-2   | vps-small | 114326131b4a        | drift adopted: after a hand-appended `drift A 192.0.2.99` and a manual `knotc zone-reload` (answered 192.0.2.99; see sync existing), re-applying the declaration removed it (NXDOMAIN, 0 occurrences in the zone file), serial 1792294999                                                                                                                                                                                                                                                                                                                         |
| apply_zone         | failure-path | pass         | sp-2   | vps-small | 114326131b4a        | signed A turned off without the ack: refused (`turning signing off needs dnssec_unsign_ack`) in 1.7 s; every file mtime under /etc/knot and /var/lib/knot and MainPID 7488 identical before and after                                                                                                                                                                                                                                                                                                                                                             |
| apply_zone         | failure-path | pass         | sp-2   | vps-small | 114326131b4a        | run-1 High re-run: listen 127.0.0.53 (systemd-resolved's stub, `127.0.0.53%lo:53` in ss) is now refused at the precheck in 3.2 s with `PORT_BUSY 127.0.0.53:53 … owner=systemd-resolve`; MainPID 5895, the listen fragment, the fragment list and the served answers unchanged, no restart in the journal. Control: 127.0.0.54 refused the same way (owner named) in 3.3 s. Observation: the message prints the address twice                                                                                                                                     |
| apply_zone         | failure-path | pass         | sp-2   | vps-small | 114326131b4a        | listen overlap with the applied resolver (zone C on 127.0.0.3): refused before any host work (`the authoritative and resolver listen sets overlap at 127.0.0.3`, 1.7 s); knotd 7488 and kresd 11675 MainPIDs and the fragment list unchanged                                                                                                                                                                                                                                                                                                                      |
| apply_zone         | failure-path | untested     | sp-2   | vps-small | 114326131b4a        | kzonecheck rejection with broken glue forced past schema: still not reachable from the CLI at this head; every malformed input is refused by the schema before host work (bad-input row), and the matrix forbids editing the model to bypass it                                                                                                                                                                                                                                                                                                                   |
| remove_zone        | failure-path | pass         | sp-2   | vps-small | 114326131b4a        | signed B without dnssec_unsign_ack: refused (`recorded as signed; pass dnssec_unsign_ack`) in 1.7 s, the three fragments and the served answer (www.b 192.0.2.10) unchanged                                                                                                                                                                                                                                                                                                                                                                                       |
| remove_zone        | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | B with dnssec_unsign_ack and purge_keys_ack: journal `zone-purge … zone purged`, fragment and zone file gone, `keymgr -l` lists no B key (the two .pem files on disk are the documented keymgr trash-bin residual), listen shrank to ["127.0.0.1"], knotd restarted (5895 to 7488), 127.0.0.2:53 released, B REFUSED on 127.0.0.1 while A answers 192.0.2.11; outcome removed true; 4.8 s                                                                                                                                                                         |
| remove_zone        | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | same call again: outcome removed false; every file under /etc/knot and /var/lib/knot (mtime and size) and MainPID 7488 identical, except the mtime of keymgr's LMDB lock (the present=no key-list read)                                                                                                                                                                                                                                                                                                                                                           |
| remove_zone        | existing     | pass         | sp-2   | vps-small | 114326131b4a        | A (unsigned, keys kept) without purge: zone file, fragment and the listen fragment gone, 127.0.0.1:53 released, knot stays active, A's keys survive in `keymgr -l` (1 line); the follow-up remove with purge_keys_ack returned removed false and left `keymgr -l` empty (the present=no retry purge path)                                                                                                                                                                                                                                                         |
| get_ds             | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | B: 2 DS (keytag 19731, alg 13, digest types 2 and 4) persisted as knot_7627c82d…, byte-identical to `keymgr b.example.test. ds` on the host                                                                                                                                                                                                                                                                                                                                                                                                                       |
| get_ds             | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | same 2 DS, record v2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| get_ds             | existing     | pass         | sp-2   | vps-small | 114326131b4a        | unsigned A: ds [] persisted (knot_efbef535…), no error                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ksk_submitted      | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | B: KSK 19731 advanced ready to active (`keymgr list` gained active=1792294692), zone re-signed, served serial 1792294674 to 1792294692                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ksk_submitted      | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | run-1 High re-run: the second and a third call both succeed in 1.5 s; knotd logs `(no key ready for submission)` and the method treats it as the already-done state; keymgr list, served serial 1792294692 and MainPID 5895 unchanged                                                                                                                                                                                                                                                                                                                             |
| ksk_submitted      | failure-path | pass         | sp-2   | vps-small | 114326131b4a        | absent zone c.example.test: refused with the typed message `the zone is not present on the host` (the run-1 untyped exit 3 is fixed); no host change                                                                                                                                                                                                                                                                                                                                                                                                              |
| apply_resolver     | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | 127.0.0.3 forwarding example.test. to 127.0.0.1 (authoritative, dnssec false), cache 64 MB: kresd 6.5.0 active and enabled on 127.0.0.3:53 (UDP and TCP) only, self-test name a.example.test. chosen from the served zones; through 127.0.0.3: www.a 192.0.2.11 and ftp.a 192.0.2.21; config.yaml size-max 64M, `kresctl validate` ok, sha bb8910d1…; config.yaml.package kept beside it; 13.0 s. Observation: kresd also holds an unconnected UDP socket `*:<ephemeral>` for its upstream queries while running (not a :53 listener, gone after remove_resolver) |
| apply_resolver     | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | the requested unchanged-listen re-apply: kresd's own 127.0.0.3:53 socket passed the new port precheck by its `ss -p` process name; outcome changed false; config.yaml mtime 1792294904, size 375, sha bb8910d1… and kresd MainPID 11675 identical; still answers www.a; 8.5 s                                                                                                                                                                                                                                                                                     |
| apply_resolver     | existing     | pass         | sp-2   | vps-small | 114326131b4a        | cache_size_mb 64 to 128: changed true, size-max 128M on the host (sha 88fb30d3…), kresd worker restarted (11700 to 12543, manager MainPID 11675 stable) and still answers www.a; no .staged leftover                                                                                                                                                                                                                                                                                                                                                              |
| apply_resolver     | failure-path | pass         | sp-2   | vps-small | 114326131b4a        | run-1 High re-run: resolver listen 127.0.0.1 (held by the applied zone A) is now refused before any host work (`the authoritative and resolver listen sets overlap at 127.0.0.1`, 1.7 s); config.yaml sha 88fb30d3…, kresd 11675 and knotd 7488 MainPIDs unchanged, no restart in the journal. The live-host wildcard variant was not repeated (my input generator omitted the file after the server was up); the host-less wildcard row above covers the same code path, which runs before sshTarget                                                             |
| remove_resolver    | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | config.yaml sha back to the package's 4e8f6b4e…, config.yaml.package consumed, unit inactive and disabled, no kresd socket (only resolved's 127.0.0.53/54 remain); outcome removed true; 3.1 s                                                                                                                                                                                                                                                                                                                                                                    |
| remove_resolver    | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | second call changed nothing but is refused (`this model did not apply a resolver on this host; pass remove_ack`) rather than a silent no-op like remove_zone; config sha, unit state and listeners identical                                                                                                                                                                                                                                                                                                                                                      |
| get                | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | observation knot_04ac8f60… v1 persisted: 1 zone (a.example.test.), drift false, resolver_active active; 4.4 s                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| get                | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | v2 of the same observation, same size (541 B) and content fields                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| get                | failure-path | pass         | sp-2   | vps-small | 114326131b4a        | wrong pinned host key: `host key verification failed for <vps>:22; refusing to connect` in 2.2 s; unreachable RFC 5737 target: `could not connect` after the 3 s timeout (host-less run)                                                                                                                                                                                                                                                                                                                                                                          |
| sync               | fresh        | pass         | sp-2   | vps-small | 114326131b4a        | drift false, resolver_active active, observation v3 persisted                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| sync               | rerun        | pass         | sp-2   | vps-small | 114326131b4a        | observation v4, same size and content                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| sync               | existing     | pass         | sp-2   | vps-small | 114326131b4a        | after `drift A 192.0.2.99` appended to the live zone file by hand plus `knotc zone-reload` (kdig answered it): observation v5 reports drift true (v4 false); the re-apply then removed it (apply_zone existing)                                                                                                                                                                                                                                                                                                                                                   |

Result: pass 48, fail 0, untested 1, inconclusive 2. The untested cell
(`kzonecheck` rejection with broken glue forced past the schema) is unreachable
from the CLI: every malformed input is refused by the schema before host work,
and the matrix forbids editing the model to bypass it. The two inconclusive rows
are `render_resolver` fresh and rerun: the method succeeds without host contact
but returns its render instead of persisting it, and the CLI shows no method
result, so there is nothing to compare; the applied render is validated on the
host in `apply_resolver` fresh and the bad-input row covers the method. Both
keep this version on `beta`.

Observations for the maintainer (no cell failed on them): `apply_resolver`'s
`allow_query_from` check now runs after the port precheck's SSH connection
(ordering regression from run 1, input-only, no host mutation); `PORT_BUSY` and
the listen-overlap messages print the address twice; `install resolver: true`
leaves `/root/.gnupg` and an enabled `supervisor.service`, neither named in the
README; kresd holds a wildcard-bound ephemeral UDP socket for its upstream
queries while running (not a :53 listener, gone after `remove_resolver`);
`remove_resolver`'s second call is a refusal where `remove_zone`'s is a no-op;
the host-only record key remains the known Medium.

## Residuals at 2026.10.17.2 (beta)

The complete list at publish; it supersedes "Residuals (beta)" above. None
blocks `beta`; all are backlog for the next version.

- MEDIUM records are keyed by `ssh.host` plus apex, not `{host, port, user}`
  (spec section 4); see review round 2.
- MEDIUM the `dash-runner` and `bashisms` gates capture no scripts: the rendered
  scripts run against real `knotd`, `kzonecheck`, `kresctl` and `kdig` in a
  container plus `sh -n`, not through the recording harness (both gates pass).
- LOW the `allow_query_from` self-test check runs after the port probe.
- LOW `CHOWN_FAILED` after a purge hides that the KASP keys are gone.
- LOW `PORT_BUSY` prints the address twice.
- LOW `render_resolver` returns its render without persisting a record, so the
  CLI cannot show it.
- LOW `remove_resolver`'s second call is refused unless `remove_ack` is set;
  `remove_zone`'s second call is a no-op.
- LOW `install resolver: true` leaves `/root/.gnupg` (gpg's homedir from the
  fingerprint check) and an enabled `supervisor.service` (knot-resolver6's
  dependency), and can upgrade curl and libcurl as a dependency side effect.
- LOW `purge_keys_ack` leaves keymgr trash-bin entries until
  `keymgr <zone> trash-discard`.
- LOW unsigning drops DNSKEY and RRSIG immediately (no delete-algorithm path).
- LOW `sync` lists a served-but-undeclared record under `removed`.
- LOW test gaps: the port-check and `ksk_submitted` already-done tests assert
  strings only; the uniqueness test compares recomputed names.
- No promotion to `stable`: one `untested` cell and two `inconclusive` rows.

## Prior art (re-checked at merge, 2026-10-18)

`swamp extension search` for knot, knot resolver, dns, bind and resolver on
stable and beta: unchanged since 2026-10-17. The only Knot package on either
channel is this one (`@randybias/knot-dns` 2026.10.17.1, beta); every other
match drives another product or a provider API (Technitium, FreeIPA, Pi-hole,
AdGuard, Route 53 and its resolver endpoints, Cloudflare, GCP, Vercel, Scaleway,
Porkbun, GoDaddy, mDNS, a DNS policy compiler). Nothing to file upstream.

## Merge prep (2026-10-18)

- Merged `lane/d2-knot-dns` at 67e2169 into main with `--no-ff` (70e46a7); the
  `knot-dns/` tree on main is byte-identical to the live-tested head, and the
  branch diff touches only `knot-dns/` plus one notes line in the knot-dns
  `release.yaml` stanza (`channel: beta`, `ci: true` unchanged). No file was
  added on the branch, so no licence-history squash was needed.
- Post-live freeze: nothing under `knot-dns/` other than this LOGBOOK (not
  packaged) changed after 67e2169. The dry run at merge gave contentHash
  `114326131b4aef84406adeeb9b865d15d04d165d998785c0dae44a8ba952600a`, equal to
  the live-tested hash; `version-exists` passed, so 2026.10.17.2 is new.
- Transport: `_lib/ssh.ts` blob `8f132c4329c9e64bed686731cd5a0e02980194ea`
  (canonical, ssh-host 2026.10.17.3), `_lib/ssh_test.ts`
  `4e8ac15fcd6bce797c523a221fe58fe9a8d9b386`.
- Gate-7 mechanics already in place: plain `export const model = {...}`, literal
  `upgrades[]` with one identity entry to 2026.10.17.2, a sibling `_test.ts` for
  every model file.
- Review report for the hash committed as
  `reviews/knot-dns/114326131b4aef84406adeeb9b865d15d04d165d998785c0dae44a8ba952600a.json`,
  written from the round-2 and round-3 seat outputs, the dispositions above and
  the live receipts.

## Factory events

Run sp-2, item `knot-dns next`, from the conductor's event log (UTC). The
version was built on DeepSeek lane d2; three review rounds (round 1 routed one
High, rounds 2 and 3 clean) and two live runs (44/4 then 48/0) preceded the
merge.

| At                   | Stage      | Rung      | Head         | Reason                                                                                                                  |
| -------------------- | ---------- | --------- | ------------ | ----------------------------------------------------------------------------------------------------------------------- |
| 2026-10-17T21:58:08Z | spec       | prior-art |              | spec-ok                                                                                                                 |
| 2026-10-17T22:36:16Z | building   | fix       |              | prior-art-fail                                                                                                          |
| 2026-10-17T23:06:11Z | checks     | gates     | 0c973fab8cda | new-head                                                                                                                |
| 2026-10-17T23:18:21Z | checks     | realtool  | 0c973fab8cda | gates-pass                                                                                                              |
| 2026-10-17T23:25:17Z | review     | review    | 0c973fab8cda | realtool-pass                                                                                                           |
| 2026-10-17T23:43:50Z | building   | build     |              | resume                                                                                                                  |
| 2026-10-18T00:04:33Z | checks     | gates     | 8bf261fc7a62 | head-reported                                                                                                           |
| 2026-10-18T00:16:16Z | checks     | realtool  | 8bf261fc7a62 | gates-pass                                                                                                              |
| 2026-10-18T00:25:44Z | review     | review    | 8bf261fc7a62 | realtool-pass                                                                                                           |
| 2026-10-18T00:52:36Z | building   | fix       | 8bf261fc7a62 | triage:routed                                                                                                           |
| 2026-10-18T01:02:27Z | checks     | gates     | 3b87cf45f74d | new-head                                                                                                                |
| 2026-10-18T01:11:17Z | checks     | realtool  | 3b87cf45f74d | gates-pass                                                                                                              |
| 2026-10-18T01:21:45Z | review     | review    | 3b87cf45f74d | realtool-pass                                                                                                           |
| 2026-10-18T01:47:30Z | live test  | live      | 3b87cf45f74d | triage:clean                                                                                                            |
| 2026-10-18T02:19:47Z | building   | fix       | 3b87cf45f74d | live-fail                                                                                                               |
| 2026-10-18T02:32:54Z | checks     | gates     | 67e21693047c | new-head                                                                                                                |
| 2026-10-18T02:47:56Z | checks     | realtool  | 67e21693047c | gates-pass                                                                                                              |
| 2026-10-18T02:55:38Z | review     | review    | 67e21693047c | realtool-pass                                                                                                           |
| 2026-10-18T03:25:16Z | live test  | live      | 67e21693047c | triage:clean                                                                                                            |
| 2026-10-18T03:54:47Z | paused     | parked    | 67e21693047c | park:lead: inconclusive rows are a cli visibility gap, not a defect; conductor rule being adjusted; resume:live follows |
| 2026-10-18T03:57:50Z | live test  | live      | 67e21693047c | resume                                                                                                                  |
| 2026-10-18T04:00:50Z | publishing | merge     | 67e21693047c | live-pass                                                                                                               |
