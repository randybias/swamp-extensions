# @randybias/secret-file

[Swamp](https://github.com/swamp-club/swamp) extension that writes a secret file
onto one host over SSH from values held in a vault. Built against the OpenSSH
client shipped with Ubuntu 24.04 and macOS.

## Models

### `@randybias/secret-file`

One generic secret file. The definition holds nothing instance-specific: every
method takes its own target, and state is keyed by host, port, user and path.

| Method   | Description                                                                       |
| -------- | --------------------------------------------------------------------------------- |
| `write`  | DESTRUCTIVE. Write the file atomically over stdin; idempotent by content and mode |
| `verify` | READ-ONLY. Stat the file and compare metadata and content without storing a hash  |
| `remove` | DESTRUCTIVE. Remove the file; an already-absent file is a clean no-op             |

## Dependencies

- OpenSSH client tools on the runner: `ssh`, `ssh-agent`, `ssh-add`. The target
  must be Linux for the atomic rename.
- GNU `stat` and `sha256sum` (or `shasum -a 256`) on the target. `chown` runs
  only when `owner` or `group` is set.

## Install

```bash
swamp extension pull @randybias/secret-file
```

## Example

Create one definition and write it per host. The value comes from a vault and
travels only over stdin:

```bash
swamp model create @randybias/secret-file secret-file
```

```bash
swamp model method run secret-file write \
  --input host=192.0.2.10 --input port=22 --input user=root \
  --input host_key_policy=strict \
  --input 'host_keys:json=["192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"]' \
  --input 'private_key=${{ vault.get("default", "SSH_PRIVATE_KEY") }}' \
  --input path=/etc/wireguard/wg0.key --input mode=0600 \
  --input owner=root --input group=root \
  --input 'content=${{ vault.get("default", "WG0_KEY") }}'
```

Render several values as a dotenv file:

```bash
swamp model method run secret-file write \
  --input host=192.0.2.10 --input user=root \
  --input host_key_policy=strict \
  --input 'host_keys:json=["192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"]' \
  --input 'private_key=${{ vault.get("default", "SSH_PRIVATE_KEY") }}' \
  --input path=/etc/example/secret.env \
  --input 'entries:json={"API_URL":"${{ vault.get("default", "API_URL") }}","API_TOKEN":"${{ vault.get("default", "API_TOKEN") }}"}' \
  --input 'hmac_key=${{ vault.get("default", "STATE_HMAC_KEY") }}'
```

Read a result from stored data with
`data.latest("secret-file", "secret-<32 hex>").attributes.changed`, where the
suffix is `sha256("<host>\u0000<port>\u0000<user>\u0000<path>")`. Pass
`content`, `entries`, `private_key` and `hmac_key` as vault references only: the
swamp CLI prints literal sensitive arguments under `--json`.

## How it works

- The value is written over stdin: it is never a command-line argument, never
  logged, and never written to swamp state.
- `write` is atomic: the bytes are staged in the destination directory, the
  requested owner and group are applied to the staged file, and it is then
  renamed over the destination, so the published file is never briefly wrong and
  the value still travels only over stdin. It converges by content, mode, owner
  and group, so an identical re-run is a no-op. Numeric ids and names both
  compare against the live file (owner id or name, and group id or name).
- `entries` is rendered as POSIX-shell `KEY='value'` lines; a single quote in a
  value is escaped. It is safe to source with `sh`/`bash` but is not a systemd
  `EnvironmentFile`. At most 256 entries and 1 MiB rendered.
- A `content_hmac` is stored only when `hmac_key` is given; it is a keyed
  HMAC-SHA256, so the state cannot be used to brute-force low-entropy values. No
  content and no plain hash is ever stored.
- `verify` compares the remote file's SHA-256 with the local value's when a
  content form is given, and compares mode, owner and group when given; it
  stores match flags and metadata only.
- `host_key_policy` is required and only `strict` is offered: the host is
  verified against the pinned, required `host_keys` on every run, so no key is
  ever accepted unseen. The private key is loaded into a short-lived `ssh-agent`
  over stdin.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
