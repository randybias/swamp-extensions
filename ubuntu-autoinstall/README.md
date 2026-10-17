# @randybias/ubuntu-autoinstall

[Swamp](https://github.com/swamp-club/swamp) extension for Ubuntu Server
autoinstall seeds. It renders `user-data`, `meta-data` and `vendor-data` from
typed inputs, validates them, and publishes them for the installer.

## Models

### `@randybias/ubuntu-autoinstall`

One autoinstall target per cluster-less definition, addressed by method
arguments, so a single definition serves any host and any seed server.

| Method         | Description                                                                   |
| -------------- | ----------------------------------------------------------------------------- |
| `render`       | Build and validate the seed; returns hashes, cmdline and the file contents    |
| `validate`     | Validate a supplied user-data document against the same pipeline (read-only)  |
| `cmdline`      | Emit the kernel and GRUB command lines for a seed URL (read-only)             |
| `publish_http` | Write the seed into an artifact-server bundle and set a ref                   |
| `unpublish`    | Remove the bundle and the ref; an absent seed is a clean no-op                |
| `get`          | Check the published bundle's presence and hashes (read-only)                  |
| `sync`         | Refresh stored state; an absent bundle is recorded as `not_found` (read-only) |

The password is a crypt hash (`$6$` or `$y$`) supplied only as a vault
reference; a plaintext is refused by shape. Storage is a guided `lvm`/`direct`
layout, explicit curtin actions (disk, partition, raid, lvm, format, mount), or
a `raid1-lvm` preset that expands to one ESP per disk, an md1 array and LVs on
an LVM volume group. A LUKS passphrase is refused: autoinstall takes it in
plaintext and the seed is served unauthenticated. `late_commands` are argv
lists; a shell command needs `shell_ack` and is still rendered as `sh -c`.

## Dependencies

`@evrardjp/cloud-init-nocloud` for the `CIDATA` path (it accepts the rendered
`user-data` bytes verbatim). `ssh` on the control host for `publish_http`,
`unpublish`, `get` and `sync`.

## Install

```sh
swamp extension pull @randybias/ubuntu-autoinstall
```

## Example

One definition serves every host. The kubeconfig-style server block and the
password hash are vault references.

```sh
swamp model create @randybias/ubuntu-autoinstall server
for host in web-1 web-2; do
  swamp model method run server publish_http \
    --input identity:json="{\"hostname\":\"$host\",\"username\":\"installer\",\"password_hash\":\"${{ vault.get(\"lab\", \"installer-hash\") }}\"}" \
    --input 'ssh:json={"install_server":true,"authorized_keys":["<openssh pubkey>"]}' \
    --input 'storage:json={"layout":"lvm"}' \
    --input 'server:json={"ssh":{"host":"192.0.2.10","host_key_policy":"strict","host_keys":["<ssh-keyscan line>"]},"root":"/srv/artifacts","url_base":"https://seed.example.com"}'
done
```

## How it works

The seed files are assembled as one object tree and emitted by a single YAML
emitter configured to quote every string and key, with no anchors, aliases or
tags; the rendered bytes are re-parsed with a **YAML 1.1** loader that refuses
duplicate keys, merges, anchors and tags, then deep-compared to the tree, so a
hostname `on`, a mode `0644` or a time `22:22` cannot silently change meaning.
`autoinstall:` is validated by our own structural checks written from the public
reference (unknown keys rejected, key types checked) plus the storage graph
(every reference resolves to an earlier action, no cycles), exactly one `/`
mount, a boot partition per grub disk, `version: 1`, no non-integer numbers and
no plaintext secrets. The document and `autoinstall.user-data` are also
validated against cloud-init's vendored `26.1` cloud-config schema
(Apache-2.0/GPL-3.0); subiquity's own autoinstall schema is **not** bundled (it
is AGPL-3.0) but a dev-only test fetches it into a temp dir and cross-checks the
renders (`AUTOINSTALL_SUBIQUITY=1`). The container test runs
`cloud-init schema --config-file` and `netplan generate` in `ubuntu:24.04` on a
rendered seed, skipped unless `AUTOINSTALL_CONTAINER=1`. `publish_http` writes
`bundles/<tree-hash>/` with fixed file names plus `SHA256SUMS` and sets
`refs/autoinstall-<hostname>`, all over the canonical SSH transport with the
bytes on stdin; an identical bundle and ref is a no-op. The tree hash is the
SHA-256 of the sorted sums lines. This version is published to `beta`: it has
not been booted against a live installer.

## License

Apache-2.0
