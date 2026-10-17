# Spec: P2 — `@randybias/knot-dns`

Status: DRAFT — awaiting Randy's approval (P2, written from public docs only; no prior implementation consulted)
RFC 2119 keywords.
Sources: Knot DNS documentation (knot-dns.cz: configuration, reference,
operation, `knotc`/`kzonecheck`/`keymgr` man pages), Knot Resolver 6
documentation (knot-resolver.readthedocs.io / knot-resolver.cz),
Debian/Ubuntu package documentation, this repo's CONVENTIONS and specs.
Net-new; nothing outside public docs and this repo was read.

## 1. Purpose

Over SSH, manage on a Linux host:

- **Authoritative DNS with Knot DNS:** declare zones and converge their records
  to a declared set, optionally **DNSSEC-signed** by Knot's automatic signer;
- **Recursive DNS with Knot Resolver:** listen addresses, cache size and
  per-subtree forwarding (including forwarding internal zones to the local
  authoritative server).

Every candidate is validated by the vendor tools (`knotc conf-check`,
`kzonecheck`, `kresctl validate`) before it reaches the live service.
Convergence is idempotent: the same declaration produces no change. Generic:
zones, records, addresses and upstreams are inputs.

## 2. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host` byte-identical
(source commit + sha256 in the LOGBOOK). `host_key_policy` required; key as
`ssh_key_ref` via `context.vaultService`, stdin only.

## 3. Zone mechanism (decided): managed zone files, not knotc transactions

Each managed zone is a **whole zone file rendered by the model**, loaded by
Knot with the operation guide's "automatic serial" setup:

```
zonefile-sync: -1                  # Knot never writes back into our file
zonefile-load: difference-no-serial
journal-content: all
serial-policy: unixtime            # input; increment|unixtime|dateserial
```

Knot computes the difference between the file and its journal on
`knotc zone-reload`, increments the serial itself and re-signs only what
changed. Reasons over `knotc zone-begin/zone-set/zone-commit`:

- **Declarative:** the whole candidate zone exists before apply, so
  `kzonecheck` validates the final state, not a diff.
- **Reboot- and reinstall-consistent:** the file on disk is the zone.
- **No held lock:** an open transaction blocks every zone-modifying event
  including DNSSEC signing; a transport drop mid-transaction leaves the zone
  locked until someone aborts.
- **Our file is never mutated by Knot** (`zonefile-sync: -1`), so its sha256
  is a stable identity for idempotency and drift detection.

Consequence: **a managed zone is owned whole** — records not declared are
removed. Dynamic updates (RFC 2136) to managed zones are refused by ACL
(open question 1).

Zone declarations live in one model-owned file,
`/etc/knot/knot.conf.d/50-managed-zones.conf`, pulled in by a single
`include:` line the model adds once to `/etc/knot/knot.conf` (glob over
`knot.conf.d/*.conf`). Whether a `zone:` section may continue across included
files is not stated in the public reference; it MUST be proven by a live cell
before relying on it, else fall back to the model owning the whole
`knot.conf` with an explicit `takeover_config_ack` (open question 2).

## 4. Model contract

- **Type** `@randybias/knot-dns`. CalVer == manifest version.
- **`globalArguments` empty.** SSH target + zone/resolver inputs per call.
- **State keyed by** canonical `{host, port, user}` + zone apex (lowercased,
  trailing dot) for zones, `{host, port, user}` for the resolver.
- **Factory with overridable deps** (transport runner, clock, `resolveSecret`).
  Unit tests render zone files, config fragments and argv only.
- Resources: `zone` (apex, rendered sha256, record count, dnssec, served
  serial, applied_at), `resolver` (rendered sha256, applied_at), `observation`
  (last `get`/`sync`), `ds` (last `get_ds`). Lifetime and GC declared for each.
- **RULINGS convention:** `get`, `sync` and `get_ds` are READ-ONLY toward the
  host but **persist their observation** as a resource, written only after
  every probe succeeds.

### Methods (every mutating one `kind:"action"`; none is named `delete`)

| Method | Kind | Description |
|---|---|---|
| `install` | action | Idempotent. Install `knot` (and, when `resolver: true`, Knot Resolver 6 from the vendor repository) and the `include:` line. Returns `{host, knot_version, kresd_version?}`. |
| `render_zone` | — | READ-ONLY. Return the canonical zone file, its sha256 and the zone config fragment. Deterministic. Touches no host. |
| `apply_zone` | action | Idempotent. Stage, `kzonecheck`, `knotc conf-check`, swap, `knotc reload`/`zone-reload`, verify served records. Returns `{zone, changed, added[], removed[], serial, dnssec}`. |
| `remove_zone` | action | DESTRUCTIVE. Stop serving the zone, remove its file and config entry; journal and KASP keys are purged only with `purge_keys_ack`. Refuses a signed zone unless `dnssec_unsign_ack`. Second call is a no-op. |
| `get_ds` | — | READ-ONLY. Return the DS/CDS for the zone's current KSK(s) (`keymgr <zone> ds`) for submission to the parent. Persists `ds`. |
| `ksk_submitted` | action | Confirm to Knot that the DS is at the parent (`knotc zone-ksk-submitted`). Idempotent. |
| `render_resolver` | — | READ-ONLY. Return the Knot Resolver `config.yaml` and its sha256. |
| `apply_resolver` | action | Idempotent. Stage, `kresctl validate`, swap, reload, verify a test query. Returns `{host, changed, listen[], forwards[]}`. |
| `remove_resolver` | action | DESTRUCTIVE. Stop and disable the resolver, restore the package config. No-op when absent. |
| `get` | — | READ-ONLY. Per managed zone: served SOA serial, record digest vs declared, DNSSEC key states (`knotc zone-status`, `keymgr list`); resolver service and listen sockets. Persists `observation`. |
| `sync` | — | READ-ONLY. Reconcile recorded state with the host; report drift (file sha changed, served set ≠ declared, unmanaged zone shadowing a managed one). Never rewrites. Persists `observation`. |

## 5. Inputs and grammars

- `ssh` block as in the other host models.
- `zone` — apex FQDN: labels `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` (plus
  leading `_` labels allowed for service owners only), ≤ 253 octets,
  lowercased, trailing dot normalised. IDN must be supplied as A-labels.
- `soa` — `{primary_ns, contact (RNAME form), refresh, retry, expire,
  minimum}`, bounded integers; serial is Knot's (§3).
- `ns[]` — 1–8 FQDNs. In-zone NS targets need matching A/AAAA records (glue
  check by `kzonecheck`).
- `records[]` (≤ 5000) — `{name, type, ttl?, data}`. `name` is `@`, a relative
  name, or an FQDN inside the zone; wildcard `*` only as the leftmost label.
  `ttl` 1–604800. `type` from a closed allowlist with typed `data`:
  `A` (IPv4), `AAAA` (IPv6), `CNAME` (FQDN), `MX` `{preference, exchange}`,
  `TXT` (list of strings, each ≤ 255 octets, rendered quoted and escaped),
  `SRV` `{priority, weight, port, target}`, `CAA` `{flags, tag ∈
  issue|issuewild|iodef, value}`, `NS` (delegation below apex), `DS` (for
  delegations), `PTR` (in reverse zones), `SSHFP`, `TLSA` (hex fields
  validated). `DNSKEY`, `RRSIG`, `NSEC*`, `CDS`, `CDNSKEY`, `SOA` are refused —
  the signer owns them.
  - Semantic rules: no CNAME at the apex, no other data at a CNAME owner,
    duplicate `(name,type,data)` collapses, RRset TTLs must agree.
- `dnssec` — `off` (default) or `{policy: {algorithm ∈ ecdsap256sha256
  (default) | ecdsap384sha384 | ed25519, nsec3: bool, ksk_lifetime?,
  zsk_lifetime?}, parent_ds_check: [ipv4|ipv6]?}`.
- `listen[]` (authoritative) — `ADDR[@port]`; wildcards `0.0.0.0`/`::` refused
  unless `listen_any_ack`. Must be disjoint from the resolver's listen set.
- `notify_secondaries[]` / `allow_transfer[]` — IP + optional TSIG key ref.
- `tsig_keys[]` — `{name, algorithm ∈ hmac-sha256|hmac-sha512, secret_ref}`;
  secret sensitive (§10).
- Resolver: `resolver_listen[]` (`ADDR[@port]`, wildcard refused unless ack),
  `cache_size_mb` 16–65536, `forwards[]` (≤ 64) `{subtree, servers[],
  transport ∈ udp|tls, tls_hostname?, authoritative: bool, dnssec: bool}`;
  `authoritative: true` rejects TLS and ports per upstream docs.
  `allow_query_from[]` CIDRs (default: loopback + the listen subnets).
- Strict `z.object`, no `.passthrough()`. Grammars re-enforced host-side.

### Outputs

Typed as in the table. `added[]`/`removed[]` are `(name, type, data)` tuples
from the served-vs-declared diff. No TSIG secret, private key or KASP content in
any output.

## 6. Apply pipeline and idempotency

`apply_zone`, per zone, one host script under `flock`:

1. Render canonically (records sorted by owner in canonical DNS order, then
   type, then data; fixed TTL and quoting). Compare its sha256 with the live
   managed file; equal **and** served digest equal → no-op, no reload.
2. Stage file and config fragment beside the live ones; `kzonecheck -o <apex>
   <staged>` (with `-d on` for a signed zone where supported) and
   `knotc -c <staged knot.conf> conf-check`. Any failure stops; nothing swapped.
3. Back up the live pair, swap atomically, `knotc reload` (config) then
   `knotc zone-reload <apex>`; poll `knotc zone-status` until loaded.
4. Verify: `knotc zone-read <apex>` filtered to declared types equals the
   declared set; SOA served over the listen address with `kdig`.
5. On reload error or verify mismatch: restore the backup, reload, report
   failure (synchronous rollback — no armed timer; DNS changes do not cut the
   SSH path).

Resolver: render `config.yaml`, `kresctl validate <staged>`, swap, reload via
the service manager, `kdig @<listen>` a forwarded and a recursive name;
rollback as above on failure.

## 7. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| Bad apex / owner / type / rdata / TTL | Rejected by schema. |
| CNAME conflicts, apex CNAME, signer-owned type | Rejected by schema. |
| `kzonecheck` / `conf-check` / `kresctl validate` fails | Nothing swapped; error carries the tool's message (sanitized). |
| Reload fails or served set ≠ declared | Backup restored; typed error. |
| Re-apply identical | No-op: no reload, serial unchanged. |
| Record removed from declaration | Removed from served zone; serial bumped by Knot. |
| Enable DNSSEC | Zone signed; `get_ds` returns DS. |
| Disable DNSSEC without ack | Refused. With ack: the documented delete-algorithm path (publish CDS/CDNSKEY delete, wait for parent DS removal and TTL) before keys go. |
| Listen overlap auth/resolver, wildcard without ack | Refused. |
| Port 53 busy (e.g. a stub resolver) | Refused at pre-check with the owning process named. |
| remove_zone twice | Second is a no-op. |
| Injection in any name, rdata, address | Rejected by grammar; literal in file and argv. |

## 8. Tests (offline, increasing risk)

1. Schema/secret/license; every grammar and semantic rule above.
2. Pure mapping: golden zone files (plain; all record types; wildcard;
   delegation with DS and glue; reverse zone), canonical-order stability under
   shuffled input, TXT escaping, golden config fragment and resolver YAML,
   served-vs-declared diff on recorded `zone-read` output.
3. Failure + adversarial: §7 rows; injection (newline, `;`, `$ORIGIN`/`$INCLUDE`
   smuggled in TXT or names, quotes, backslash) on every input; host scripts
   under `sh` with stub `knotc`, `kzonecheck`, `kresctl`, `kdig`, `flock`.
4. Packaging.

Fixtures synthetic: `example.com`/`.test`, RFC 5737 and `2001:db8::/32`.

## 9. Live e2e matrix (maintainer-run; throwaway VPS tagged `swamp-e2e=<run-id>`)

Ubuntu 24.04 + Debian 13. Authoritative listens on the VPS address, resolver on
loopback (or the reverse) so they never share a socket. No public delegation is
needed: queries go straight to the VPS with `kdig @addr`.

| Cell | Expected |
|---|---|
| install / again | packages + include present; no-op second time |
| include-split proof | a `zone:` in `knot.conf.d/` loads alongside the package's own config (§3) |
| apply_zone create | zone served, records match |
| apply_zone idempotent | no reload, same serial |
| record add / change / remove | diff exact; serial increases |
| kzonecheck rejection | broken glue (forced past schema) → nothing swapped |
| DNSSEC on | DNSKEY/RRSIG served; `kdig +dnssec` validates against `get_ds` |
| ksk_submitted | key state advances |
| DNSSEC off with ack | delete-algorithm path, zone ends unsigned and not bogus |
| apply_resolver | forwarded and recursive names resolve; cache size set |
| resolver forwards internal zone to local auth | internal name resolves via resolver |
| get / sync | live state and drift reported; observation persisted |
| remove_zone / again; remove_resolver | gone; no-op |
| injection literal | metacharacters land literally |

Receipts into `knot-dns/LOGBOOK.md`; no `stable` with any `untested`/`skip`.

## 10. Credential policy (repo-wide policy)

SSH key as in every host model (stdin only, vault reference, never `--json`).
**TSIG secrets** are sensitive vault references, written host-side to a
dedicated key file (`0640 root:knot`) via stdin upload, `include:`d by the
config — never in the rendered config text returned by `render_zone`, never in
argv, outputs or persisted resources. `knotc conf-read` output is never
captured. DNSSEC private keys stay in Knot's KASP directory; the model reads
only public DS/DNSKEY data.

## 11. Known traps

- **`zonefile-sync` default is 0**: Knot rewrites the zone file, including
  signatures, breaking file-sha idempotency. Always `-1` for managed zones.
- **`difference-no-serial` is unsuitable when something else edits the zone**
  (dynamic updates, a second tool). Managed zones refuse DDNS.
- **An open `zone-begin` transaction blocks DNSSEC signing.** Never use one.
- **Disabling signing with a DS at the parent makes the zone bogus.** Only the
  documented delete-algorithm path is safe.
- **Manually added DNSKEYs are removed by the signer.** DNSKEY is refused input.
- **systemd-resolved** binds `127.0.0.53:53` (and `127.0.0.54`) on Ubuntu;
  `0.0.0.0:53` collides. Explicit listen addresses only.
- **Knot Resolver 5 vs 6:** Ubuntu 24.04 ships 5.x (Lua `kresd.conf`, no
  offline validator); 6.x uses YAML + `kresctl validate`. This spec targets 6.x
  from the vendor repository (open question 3).
- **KASP permissions**: the KASP directory must stay owned by the Knot user;
  never touch it except via `keymgr`.

## 12. Open questions for Randy

1. **Whole-zone ownership:** managed zones refuse dynamic updates — fine, or
   must a zone accept DDNS (e.g. from Kea) for some names, which forces a
   journal-as-source design with `knotc` transactions instead?
2. If `zone:` cannot be split across include files, may the model take over
   the whole `knot.conf`?
3. Knot Resolver 6 from the vendor repo only, or also render 5.x Lua for distro
   packages?
4. Secondaries/zone transfer (TSIG, NOTIFY) in v1, or primary-only first?
