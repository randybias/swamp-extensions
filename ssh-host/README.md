# @randybias/ssh-host

[Swamp](https://github.com/swamp-club/swamp) extension for running a command,
pushing a file and waiting for host keys on a remote host over SSH. Built
against the OpenSSH client shipped with Ubuntu 24.04 and macOS.

## Models

### `@randybias/ssh-host`

One generic SSH transport. The definition holds no host and no credential; every
method takes its target as arguments.

| Method            | Description                                                                      |
| ----------------- | -------------------------------------------------------------------------------- |
| `exec`            | Run one argv vector over SSH and return stdout, stderr and exit code             |
| `upload`          | Write bytes to an absolute path over stdin, atomically, and return their SHA-256 |
| `wait_connection` | Poll until the host answers SSH with acceptable host keys, read-only             |

## Install

```bash
swamp extension pull @randybias/ssh-host
```

## Dependencies

- OpenSSH client tools on the runner: `ssh`, `ssh-agent`, `ssh-add` and
  `ssh-keyscan`.
- A POSIX runner host (macOS or Linux); `ssh-agent -s` output is parsed.

## Example

Create one definition, then run it for any host. Target values arrive as method
arguments, so a single definition serves a whole fleet.

```bash
swamp model create @randybias/ssh-host ssh-transport --json
```

```bash
for host in web-1.example.com web-2.example.com; do
  swamp model method run ssh-transport exec \
    --input host=$host --input user=root \
    --input host_key_policy=strict \
    --input 'host_keys:json=["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyPlaceholder"]' \
    --input 'argv:json=["uname","-r"]' \
    --input 'private_key=${{ vault.get("default", "SSH_PRIVATE_KEY") }}' --json
done
```

Push a rendered file atomically, then wait for the host to come back:

```bash
swamp model method run ssh-transport upload \
  --input host=web-1.example.com --input user=root \
  --input host_key_policy=insecure_tofu \
  --input path=/etc/wireguard/wg0.conf --input mode=0600 \
  --input 'content=${{ vault.get("default", "WG0_CONF") }}' \
  --input 'private_key=${{ vault.get("default", "SSH_PRIVATE_KEY") }}' --json

swamp model method run ssh-transport wait_connection \
  --input host=web-1.example.com --input user=root \
  --input host_key_policy=strict \
  --input 'host_keys:json=["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyPlaceholder"]' --json
```

Read a result from stored data:

```bash
swamp data query 'model("ssh-transport") && name == "exec-web-1.example.com"' \
  --select content
```

Pass `private_key` and `password` as vault references, never as literals: the
swamp CLI echoes method arguments, sensitive ones included, in `--json` output
([swamp-club lab 3555](https://swamp-club.com/lab/3555)).

## How it works

- `host_key_policy` is required. `strict` verifies the host against the pinned
  `host_keys` lines (the only accepted set) and refuses a mismatch without
  trusting a new key; `insecure_tofu` explicitly trusts the first key seen. Each
  line is `ssh-keyscan` format: either bare `type key`, or with a host field
  that names this target (port 22 as `host`, otherwise `[host]:port`). There is
  no silent default.
- `exec` takes a command and its arguments as an array. Each element is quoted
  as one literal word before it is sent, so `;`, `$()`, backticks and newlines
  inside an element can never become a second command. A non-zero remote exit
  code is returned as data; an unreachable host, rejected credential or host-key
  mismatch is an error that names the host.
- `upload` writes a temporary file in the destination directory from stdin,
  applies `mode`, then renames it over the destination, so the destination is
  never half-written and an unwritable path leaves no partial file. It returns
  the path, byte count and SHA-256.
- Credentials never touch the command line. A private key is loaded into a
  short-lived `ssh-agent` over stdin; a password goes through a temporary
  askpass helper and an environment variable. Neither appears in a spawned argv.
- Stored data is keyed by host: `exec-<host>`, `upload-<host>` and
  `connection-<host>`. The definition name is never part of the key.
- On Ubuntu 24.04, `sshd` is socket-activated: a cloud-init that changes the SSH
  port must restart `ssh.socket`, or the new port never accepts a connection.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
