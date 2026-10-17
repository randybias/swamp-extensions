# @randybias/knot-dns

[Swamp](https://github.com/swamp-club/swamp) extension for authoritative
[Knot DNS](https://www.knot-dns.cz) zones and a
[Knot Resolver 6](https://www.knot-resolver.cz) recursive resolver, managed over
SSH. Built against the Knot DNS 3 configuration and zone-file syntax and the
Knot Resolver 6 `config.yaml` schema.

## Models

### `@randybias/knot-dns`

One host, addressed by method arguments (the `ssh` target and the declaration),
so a single definition serves any host. Zone files and config fragments are
rendered deterministically and validated by `kzonecheck`, `knotc conf-check` and
`kresctl validate` before anything is swapped. Secret references arrive as vault
names and are resolved in-model; the SSH key and every TSIG secret reach the
host over stdin, never on an argv, in a log or in stored state.

| Method            | Description                                                                      |
| ----------------- | -------------------------------------------------------------------------------- |
| `install`         | Install Knot and the include line; idempotent                                    |
| `render_zone`     | Render the canonical zone file, fragment and sha256 without a host (read-only)   |
| `apply_zone`      | Validate, atomically swap, reload and verify one whole zone                      |
| `remove_zone`     | Remove one managed zone; signed zones need an explicit ack (destructive)         |
| `get_ds`          | Read the DS records for a signed zone (read-only)                                |
| `ksk_submitted`   | Tell Knot the KSK DS is at the parent (destructive)                              |
| `render_resolver` | Render the resolver `config.yaml` and sha256 without a host (read-only)          |
| `apply_resolver`  | Validate, swap and reload the resolver, then verify a query                      |
| `remove_resolver` | Stop and disable the resolver (destructive)                                      |
| `get`             | Observe each managed zone and the resolver; persists the observation (read-only) |
| `sync`            | Report drift between the recorded render and the host (read-only)                |

A managed zone is owned whole: records not declared are removed, and dynamic
updates (RFC 2136) are refused by ACL. `apply_zone` prunes, so it is
destructive.

## Dependencies

A Debian or Ubuntu host reachable over SSH, with `apt-get` and `systemctl`.
`install` installs `knot`, `knot-dnsutils` and `knot-dnssecutils` (which ships
`kzonecheck`) from the distribution archive and fails unless `knotc`, `kdig`,
`kzonecheck` and `keymgr` exist and Knot is the 3.x line. With `resolver: true`
it also adds the CZ.NIC Labs package repository (the Ubuntu 24.04 archive has
Knot Resolver 5, which has no `kresctl`): the signing key is refused unless its
fingerprint is the pinned `9C71D59C D4CE8BD2 966A7A3E AB6A3031 24019B64`, the
repository is pinned at apt priority 100 so Knot DNS stays at the archive
version while `knot-resolver6` (and its own library versions) come from CZ.NIC,
and `kresctl`/`kresd` must be 6.x afterwards. The fingerprint was read from
https://pkg.labs.nic.cz/gpg and confirmed against keys.openpgp.org and
https://pkg.labs.nic.cz/doc. The resolver service is left stopped and disabled
until `apply_resolver` writes its configuration. The SSH key and any TSIG secret
are read from a swamp vault.

## Install

```sh
swamp extension pull @randybias/knot-dns
```

## Example

One definition serves every host and zone.

```sh
swamp model create @randybias/knot-dns dns

swamp model method run dns install \
  --input 'ssh:json={"host":"ns1.example.test","user":"root","host_key_policy":"strict","host_keys":["ns1.example.test ssh-ed25519 AAAAPLACEHOLDER"],"ssh_key_ref":{"vault":"ops","key":"ssh"}}'

swamp model method run dns apply_zone \
  --input 'ssh:json={"host":"ns1.example.test","user":"root","host_key_policy":"strict","host_keys":["ns1.example.test ssh-ed25519 AAAAPLACEHOLDER"],"ssh_key_ref":{"vault":"ops","key":"ssh"}}' \
  --input zone=example.test \
  --input 'soa:json={"primary_ns":"ns1.example.test.","contact":"hostmaster.example.test.","refresh":7200,"retry":3600,"expire":1209600,"minimum":3600}' \
  --input 'ns:json=["ns1.example.test."]' \
  --input 'records:json=[{"name":"www","type":"A","data":"192.0.2.10"}]' \
  --input 'dnssec:json={"algorithm":"ecdsap256sha256","nsec3":false}'
```

Pass the SSH key and any TSIG secret only as vault references.

## How it works

`apply_zone` renders the whole zone file locally (absolute owner names, no
`$ORIGIN`), uploads it beside the live file, and runs a single `flock`ed host
script that validates the zone and the merged config, backs up the live pair,
swaps, reloads, and verifies the served records. Any failure restores the
backup. Knot never writes into the model's file (`zonefile-sync: -1`,
`zonefile-load: difference-no-serial`, `serial-policy: unixtime`), so the file's
sha256 is a stable identity for idempotency and drift detection. The SOA serial
in the rendered file is a placeholder; Knot owns the live serial.

Every zone and resolver input is grammar- and semantics-checked (apex, owner,
rdata per type, TTLs, CNAME rules, signer-owned types, listen overlap,
wildcards). The SSH transport is the canonical `_lib/ssh.ts` from
`@randybias/ssh-host`, vendored byte-identical; `host_key_policy` is `strict`
with required pinned `host_keys`.

Changing the authoritative listen addresses restarts knotd (Knot ignores listen
changes on reload) and the apply then queries every listen address with `kdig`
(`install` adds `knot-dnsutils`). Forwards always render an explicit `dnssec`
setting, because Knot Resolver 6 validates by default.

`apply_resolver` proves the new configuration with an SOA query on the
resolver's own listen address. An authoritative upstream answers REFUSED (the
resolver reports SERVFAIL) for names outside the zones it serves, so the name is
the caller's `resolver.test_name`, else the forwarded subtree when this host
serves it, else a zone this host serves below the subtree, else the subtree.
Every action also persists an `outcome` record (`changed`, `removed`, versions)
because the CLI shows resources, not a method's result.

## License

Apache-2.0
