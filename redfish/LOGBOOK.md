# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17 (lane/d2-redfish, base origin/main): built `@randybias/redfish`
  after an evaluation found no existing extension covers generic Redfish. The
  registry (stable and beta) has nothing for redfish/sushy/bmc/ipmi/idrac; the
  nearest neighbours are IP-KVM vendor APIs (GL.iNet, NanoKVM), libvirt and
  provider cloud power APIs, none of which speak Redfish.
- Design: one model per ComputerSystem; the endpoint, system id and credentials
  are method arguments. Credentials are vault-wired sensitive inputs sent only
  in an `X-Auth-Token` or `Authorization` header; a SessionService session is
  opened and deleted in a `finally`, with Basic fallback when the BMC has no
  SessionService. The TLS policy is a required input (`strict`, optionally with
  a pinned `ca_pem`, or explicit `insecure_skip_verify`) because BMCs commonly
  use self-signed certificates. The endpoint is an https origin only, and
  `@odata.id` links are kept on that origin. Response bodies are capped at 1 MiB
  and errors are typed and fixed, never echoing a body or credential.
- State is keyed by `{origin}/{system_id}`; `power` and `set_boot` are actions,
  `get` and `sync` are read-only. `power` validates against the system's
  advertised `ResetType` allowables, skips a no-op when already in the target
  state, and polls to a bounded timeout. `set_boot` sends `If-Match` when an
  ETag is available and reads the override back.
- Live matrix (target: sushy-tools `sushy-emulator` with the FAKE driver on a
  throwaway host, no libvirt needed):
  - get / sync: blocked (emulator not yet running)
  - power on / off / restart and the no-op: blocked
  - set_boot Pxe/Hdd/Cd Once/Continuous/Disabled and read-back: blocked
  - unreachable, bad credential, self-signed cert with strict vs
    insecure_skip_verify: blocked
- Unit tests use a fake fetch and DMTF-shaped fixtures; no socket is opened.
- 2026-10-17 (lane/d2-redfish): review round 1 (HEAD 761b6df). Dispositions:
  - HIGH: Basic auth (the password on every request) is refused over an
    unverified TLS connection unless the new `allow_insecure_basic` input is
    true; the SessionService 404/405 fallback obeys the same rule (strict-TLS
    only by default). Tests cover both refusals.
  - HIGH: every request now carries an abort deadline (`requestTimeoutMs`,
    clamped to the `power` deadline) including the body read and the session
    logout; a stalled BMC maps to a typed `timeout`, and the session DELETE
    still runs on that path.
  - MEDIUM: BMC `AllowableValues` are filtered to the local enums before being
    listed in an error, so a vendor value cannot inject text.
  - MEDIUM: restart actions follow a returned Redfish task monitor and require
    an observed state change before accepting `On`; a restart with no observed
    transition times out instead of succeeding on the first poll.
  - MEDIUM: `ca_pem` is documented as an additional trusted CA, not an exclusive
    pin (`caCerts` adds to the system roots).
  - MEDIUM: a session response without a `Location` header falls back to the
    body `@odata.id` (same-origin checked) for the logout DELETE.
  - MEDIUM: `set_boot` is now prefixed `DESTRUCTIVE.`.
  - MEDIUM: a `null`/non-object JSON body is refused, and a ComputerSystem
    without a usable `Id` is refused before it can be persisted.
