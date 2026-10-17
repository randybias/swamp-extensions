# @randybias/ssh-host

[Swamp](https://github.com/swamp-club/swamp) extension for running a command,
pushing a file and waiting for host keys on a remote host over SSH. Built
against the OpenSSH client shipped with Ubuntu 24.04 and macOS.

## Models

### `@randybias/ssh-host`

One generic SSH transport. The definition holds no host and no credential; every
method takes its target as arguments.

| Method            | Description                                                                                     |
| ----------------- | ----------------------------------------------------------------------------------------------- |
| `exec`            | Run one argv vector over SSH; return the exit code and output hashes, never raw output          |
| `upload`          | DESTRUCTIVE. Write bytes to a file over stdin, atomically; unchanged bytes and mode are a no-op |
| `wait_connection` | READ-ONLY. Poll until the host answers SSH with acceptable host keys, read-only                 |

## Install

```bash
swamp extension pull @randybias/ssh-host
```

## Dependencies

- OpenSSH client tools on the runner: `ssh`, `ssh-agent`, `ssh-add` and
  `ssh-keyscan`. `upload` needs a Linux target with `mv -T` (a
  no-target-directory rename) and uses `sha256sum` or `shasum -a 256` for its
  convergence check; a non-Linux target is refused.
- A POSIX runner host (macOS or Linux); `ssh-agent -s` output is parsed.

## Example

Create one definition, then run it for any host. Target values arrive as method
arguments, so a single definition serves a whole fleet.

```bash
swamp model create @randybias/ssh-host ssh-transport
```

```bash
for host in web-1.example.com web-2.example.com; do
  swamp model method run ssh-transport exec \
    --input host=$host --input user=root \
    --input host_key_policy=strict \
    --input 'host_keys:json=["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyPlaceholder"]' \
    --input 'argv:json=["uname","-r"]' \
    --input 'private_key=${{ vault.get("default", "SSH_PRIVATE_KEY") }}'
done
```

Push a rendered file atomically, then wait for the host to come back:

```bash
swamp model method run ssh-transport upload \
  --input host=web-1.example.com --input user=root \
  --input host_key_policy=insecure_tofu \
  --input path=/etc/wireguard/wg0.conf --input mode=0600 \
  --input 'content=${{ vault.get("default", "WG0_CONF") }}' \
  --input 'private_key=${{ vault.get("default", "SSH_PRIVATE_KEY") }}'

swamp model method run ssh-transport wait_connection \
  --input host=web-1.example.com --input user=root \
  --input host_key_policy=strict \
  --input 'host_keys:json=["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyPlaceholder"]'
```

Read a result from stored data:

```bash
swamp data query 'model("ssh-transport") && name == "exec-h17-web-1.example.com-p22-u4-root"' \
  --select content
```

Pass `private_key` and `password` as vault references, never as literals: the
swamp CLI echoes method arguments, sensitive ones included, in `--json` output
([swamp-club lab 3555](https://swamp-club.com/lab/3555)). Never put a secret in
`argv` either; it is delivered to the remote host.

## How it works

- `host_key_policy` is required, with no silent default. `strict` verifies the
  host against the pinned `host_keys` lines (the only accepted set) and refuses
  a mismatch without trusting a new key. `insecure_tofu` records the first keys
  it sees, keyed by host and port as `known_hosts` is, and pins exactly those on
  every later run and for every user on that host:port; a changed key is
  refused. Each line is `ssh-keyscan` format, either bare `type key` or with a
  host field naming this target (port 22 as `host`, otherwise `[host]:port`); a
  supplied set that matches no host/port, or that disagrees with an
  already-recorded pin, is refused, never silently downgraded or substituted.
- `exec` takes a command and its arguments as an array. Each element is quoted
  as one literal word before it is sent, so `;`, `$()`, backticks and newlines
  inside an element can never become a second command. `argv` can still run a
  destructive command on the host, and `exec` cannot roll back what it changed;
  reachability protection (locking down a host, reverting a config) belongs in
  the extension that owns that workflow. A non-zero remote exit code is returned
  as data, except exit 255, which ssh reserves for its own failures and which is
  always reported as a transport error. An unreachable host, rejected credential
  or host-key mismatch is an error that names the host. The result carries only
  `exit_code` and the `stdout_sha256`/`stderr_sha256` hashes, never the raw
  bytes. Set `return_output` to store the captured output in the
  sensitive-marked `execution` resource; the result then also names that
  resource, and a model read resolves its vault reference. Captured output is
  capped by `max_output_bytes` (default 10 MiB); exceeding it is a typed error
  rather than unbounded memory use.
- `upload` writes a temporary file in the destination directory from stdin,
  applies `mode`, then renames it over the destination, so the destination is
  never half-written and an unwritable path or a destination that is a directory
  or a symlink is an error. It converges on bytes and mode: identical bytes and
  mode mean no write, no rename and no new resource version, while a mode-only
  difference is replaced through the same temp-file path (never a chmod that
  could follow a symlink). It returns the path, byte count, SHA-256 and whether
  anything changed.
- Credentials never touch the command line. A private key is loaded into a
  short-lived `ssh-agent` over stdin; a password goes through a temporary
  askpass helper and an environment variable. Neither appears in a spawned argv.
- Stored data uses length-prefixed, labeled keys so a target's identity can
  never be confused with another's. The host-key pin is one record per host and
  port (`connection-h17-web-1.example.com-p22`), shared by every user; execution
  evidence is per user (`exec-h17-web-1.example.com-p22-u4-root` and likewise
  `upload-…`). The definition name is never part of the key.
- On Ubuntu 24.04, `sshd` is socket-activated: a cloud-init that changes the SSH
  port must restart `ssh.socket`, or the new port never accepts a connection.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
