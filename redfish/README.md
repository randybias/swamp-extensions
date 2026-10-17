# @randybias/redfish

[Swamp](https://github.com/swamp-club/swamp) extension for the DMTF Redfish
out-of-band management API. Built against the Redfish `ComputerSystem` schema
and `SessionService`.

## Models

### `@randybias/redfish`

One ComputerSystem, addressed by method arguments (BMC endpoint, system id and
vault-wired credentials), so a single definition serves any BMC. Credentials
travel only in a Redfish session token or an `Authorization` header; the TLS
policy is an explicit input with no default.

| Method     | Description                                                       |
| ---------- | ----------------------------------------------------------------- |
| `get`      | Read power state, boot override and health (read-only)            |
| `sync`     | Refresh stored state; records `not_found` when gone (read-only)   |
| `power`    | Power on, power off or restart, then wait for the resulting state |
| `set_boot` | Set a one-time or continuous boot override and confirm it         |

`set_boot` is destructive: a continuous override can boot the host into an
installer on every restart.

## Dependencies

HTTPS reachability to the BMC and a Redfish `ComputerSystem` resource. No
third-party runtime package beyond the exact-pinned `zod`.

## Install

```sh
swamp extension pull @randybias/redfish
```

## Example

One definition serves every BMC and system; the arguments pick the endpoint,
system and credentials.

```sh
swamp model create @randybias/redfish bmc

for sys in 437XR1138R2 1; do
  swamp model method run bmc get \
    --input endpoint=https://bmc.example.com \
    --input system_id=$sys \
    --input 'username=${{ vault.get("bmc", "username") }}' \
    --input 'password=${{ vault.get("bmc", "password") }}' \
    --input tls_verify=strict
done
```

Power and boot actions:

```sh
swamp model method run bmc power \
  --input endpoint=https://bmc.example.com --input system_id=437XR1138R2 \
  --input 'username=${{ vault.get("bmc", "username") }}' \
  --input 'password=${{ vault.get("bmc", "password") }}' \
  --input tls_verify=strict --input action=GracefulRestart
swamp model method run bmc set_boot \
  --input endpoint=https://bmc.example.com --input system_id=437XR1138R2 \
  --input 'username=${{ vault.get("bmc", "username") }}' \
  --input 'password=${{ vault.get("bmc", "password") }}' \
  --input tls_verify=strict --input target=Pxe --input enabled=Once
```

Pass `username` and `password` only as vault references; never as literal
`--input` values.

## How it works

`get` and `sync` read `PowerState`, the boot override and `Status`, and store an
allowlist of metadata; no credential is ever written to state or output. By
default a Redfish SessionService session is opened and deleted in a `finally`,
falling back to Basic auth when the BMC has no SessionService; `auth_mode`
forces one or the other. Over `insecure_skip_verify` no credential is sent at
all — session or Basic — unless `allow_insecure_credentials` is set; the
recommended path for a self-signed BMC is to put its certificate in `ca_pem` and
keep `strict` verification. `power` validates the requested `ResetType` against
the system's advertised allowables (only values this model knows are echoed
back), is a no-op when the system is already in the target state, follows a
returned Redfish task monitor, and accepts a restart once the system is back at
the desired state. Only an explicit `TaskState` of `Completed` with an `OK` (or
absent) `TaskStatus` is a confirmed task; a `404`/`204`/empty task read is
unconfirmed and falls through to the power-state poll, and every action other
than a restart must read back the desired state. A restart with no observed
transition is accepted with a warning at the timeout; `Nmi` is fire-and-forget.
`set_boot` patches the override, sending `If-Match` when the BMC provides an
ETag, and reads it back to confirm.

The endpoint must be an https origin: no path, query, fragment or embedded
credentials, and every `@odata.id` is resolved back onto that origin. The TLS
policy is required — `strict` (system trust, plus an optional additional CA via
`ca_pem`, which is not an exclusive pin) or the explicit `insecure_skip_verify`
for the self-signed certificates BMCs commonly ship. Every request carries a
timeout (clamped to the `power` deadline, and also applied to the body read and
the session logout), response bodies are read with a hard byte cap, and every
failure is a typed message that never echoes a response body, URL or credential.

## License

Apache-2.0
