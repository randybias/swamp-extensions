# @randybias/cherry-servers

[Swamp](https://github.com/swamp-club/swamp) extension for the
[Cherry Servers](https://www.cherryservers.com) API: bare-metal and VPS servers,
projects, SSH keys and live plan stock. Built against the Cherry Servers v1 REST
API. Exercised live so far: the read-only `list` calls; `projects create`,
`ssh-keys create`, and on a VPS order `servers create`, `wait_ready` and an
idempotent `create` re-run that adopted the server. `delete` is covered by unit
tests only and has not yet been run against a real server.

## Models

### `@randybias/cherry-servers/servers`

One server, described by its global arguments (project, hostname, plan, region,
image, billing cycle, SSH keys, optional user data).

| Method       | Description                                                               |
| ------------ | ------------------------------------------------------------------------- |
| `create`     | Order the server, or adopt one with the same hostname in the project      |
| `get`        | Fetch a server by ID (read-only)                                          |
| `sync`       | Refresh stored state; records `not_found` when gone (read-only)           |
| `list`       | Store every server in the project (read-only)                             |
| `wait_ready` | Wait for an SSH banner, acceptable host keys and an optional marker       |
| `delete`     | Delete the recorded server after hostname and project checks; confirm 404 |

### `@randybias/cherry-servers/projects`

| Method   | Description                                                        |
| -------- | ------------------------------------------------------------------ |
| `create` | Create the project, or adopt one with the same name in the team    |
| `get`    | Fetch a project by ID (read-only)                                  |
| `sync`   | Refresh stored state; records `not_found` when gone (read-only)    |
| `list`   | Store every project in the team (read-only)                        |
| `delete` | Delete the recorded, empty project after a name check; confirm 404 |

### `@randybias/cherry-servers/ssh-keys`

| Method   | Description                                                      |
| -------- | ---------------------------------------------------------------- |
| `create` | Upload the key, or adopt one with the same key material          |
| `sync`   | Refresh stored state; records `not_found` when gone (read-only)  |
| `list`   | Store every key on the account, without key material (read-only) |
| `delete` | Delete the recorded key after a label check; confirm 404         |

### `@randybias/cherry-servers/plans`

| Method | Description                                                                                                                         |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `list` | Plans with prices per billing unit and stock per region, filtered by type, region, RAM and hourly price, cheapest first (read-only) |

## Workflows

- `cherry-servers-create-server`: create, then `wait_ready`. Takes the generic
  server model's name plus the server's inputs: hostname, project, plan, region,
  image, cycle, SSH keys, and optionally `os_partition_size`, `spot_market` and
  `tags`. For cloud-init and a marker check, name a vault and the keys in it
  (`secrets_vault`, `user_data_key`, `ssh_private_key_key`) and set
  `marker_path`; workflow inputs are stored in plain text, so the values
  themselves never pass through them.
- `cherry-servers-delete-server`: `sync`, then `delete` of the recorded server
  for a hostname.

## Install

```bash
swamp extension pull @randybias/cherry-servers
```

## Dependencies

- A Cherry Servers API token.
- `wait_ready` runs the OpenSSH client tools: `ssh-keyscan` and `ssh-keygen`,
  plus `ssh-agent`, `ssh-add` and `ssh` when `marker_path` is set. It parses
  `ssh-agent -s` output, so it needs a POSIX host (macOS or Linux).

## Example

Create one generic definition per resource kind, not one per server. Each server
is a set of inputs; stored data is keyed by hostname.

```bash
swamp model create @randybias/cherry-servers/servers cherry-server --json
```

Then give the definition an `inputs` schema and read the global arguments from
it:

```yaml
type: "@randybias/cherry-servers/servers"
name: cherry-server
inputs:
  properties:
    project_id: { type: integer }
    hostname: { type: string }
    plan: { type: string }
    region: { type: string }
    cycle: { type: string, enum: ["hourly", "monthly", "annually"] }
    image: { type: string, default: null }
    ssh_keys: { type: array, items: { type: integer }, default: null }
    os_partition_size: { type: integer, default: null }
    spot_market: { type: boolean, default: null }
    user_data: { type: string, default: null }
    tags: { type: object, default: null }
  required: ["hostname"]
globalArguments:
  project_id: ${{ inputs.project_id }}
  hostname: ${{ inputs.hostname }}
  plan: ${{ inputs.plan }}
  region: ${{ inputs.region }}
  cycle: ${{ inputs.cycle }}
  image: ${{ inputs.image }}
  ssh_keys: ${{ inputs.ssh_keys }}
  os_partition_size: ${{ inputs.os_partition_size }}
  spot_market: ${{ inputs.spot_market }}
  user_data: ${{ inputs.user_data }}
  tags: ${{ inputs.tags }}
  token: ${{ vault.get("default", "CHERRY_TOKEN") }}
```

Two servers from the same definition:

```bash
for host in web-1 web-2; do
  swamp model method run cherry-server create --input hostname=$host \
    --input project_id=123456 --input plan=example-plan \
    --input region=example-region --input image=ubuntu_24_04_64bit \
    --input cycle=hourly --input 'ssh_keys:json=[1001]' --json
done
swamp model method run cherry-server wait_ready --input hostname=web-1 \
  --input host_key_policy=accept-new --json
```

Read a server's state with
`data.latest("cherry-server", "web-1").attributes.public_ipv4`. Give every
optional input a `default: null`, as above: swamp fails a method that reads a
global argument whose input was not given, and the model treats null as not set.
`get`, `sync`, `wait_ready` and `delete` then need just `hostname`, and `list`
needs `project_id` as well.

Marker checks need the private key. Keep it in a vault and pass a reference,
which swamp resolves at run time and never prints:

```bash
swamp model method run cherry-server wait_ready --input hostname=web-1 \
  --input host_key_policy=accept-new \
  --input marker_path=/var/lib/cloud/instance/boot-finished \
  --input 'ssh_private_key=${{ vault.get("default", "WEB_1_SSH_KEY") }}' --json
```

User data works the same way: give `user_data` as a vault reference. The create
workflow takes the vault and key names (`secrets_vault`, `user_data_key`,
`ssh_private_key_key`), never the values. Don't pass either as a literal value,
with `--input` or with `--stdin`: the swamp CLI currently prints method
arguments, including ones marked sensitive and ones read from stdin
([swamp-club lab 3555](https://swamp-club.com/lab/3555)).

On bare metal, port 22 first answers from Cherry's provisioning environment,
which has its own host keys and does not accept yours. Set `marker_path` (for
example `/var/lib/cloud/instance/boot-finished`) so readiness means the
installed system; without one, `wait_ready` also waits for the API to stop
reporting the server as deploying, which can take several minutes longer.

## How it works

- The API token is sent only in the `Authorization` header. It comes from the
  `token` global argument (wire it to a vault) or `CHERRY_AUTH_TOKEN`.
- Every API request times out after 30 seconds. Reads and deletes are retried on
  a timeout or a transient gateway error (502 to 504, Cloudflare's 520 to 524);
  orders never are. A timed-out order may still have been placed; run `create`
  again and it adopts the server by hostname.
- Stored server state is an allowlist. Provider responses also contain root and
  BMC passwords; those are never written to swamp data. User data is never
  stored either, only its SHA-256.
- `create` never places a second order for a hostname that already exists in the
  project. The guard is per model: two different models ordering the same
  hostname at the same moment can both place an order. A recorded server id is
  adopted only while its hostname and project still match.
- `create` for an SSH key adopts an existing key with the same material even
  under another label; `delete` then refuses, because it never deletes a key
  whose live label differs from this model's. Delete such a key under its own
  label.
- `delete` acts only on the server this model recorded. With no record it
  refuses, an `id` other than the recorded one is refused, and so is a live
  server whose hostname or project differs from the record. Project `delete`
  also refuses a project that still holds servers.
- `cycle` has no default. Monthly and annual cycles are charged upfront from the
  account balance.
- `wait_ready` judges readiness from the server, because the API can report a
  server as active minutes after SSH answers, or before setup has finished.
  Marker checks load the private key into a temporary `ssh-agent` over stdin and
  ignore the operator's `~/.ssh/config` and default keys. Invalid input or a
  rejected key fails at once instead of retrying until the timeout.
- Host keys: `strict` checks against `known_hosts` entries for the server's
  address and port, as OpenSSH does: every key of a pinned type must match, key
  types with no entry are ignored, and at least one key must match; `accept-new`
  records the keys on first success and enforces them on later runs; `insecure`
  records without enforcing.
- Data names: server state is stored under the hostname, readiness evidence
  under `<hostname>-readiness`, e.g.
  `data.latest("cherry-server", "web-1").attributes.public_ipv4`.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
