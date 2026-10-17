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
- 2026-10-17 (lane/d2-redfish): review round 2 (e1ecad1). Dispositions:
  - RULING: `allow_insecure_basic` became `allow_insecure_credentials`. Over
    `insecure_skip_verify` no credential is sent at all (session POST or Basic)
    unless it is true; the recommended path for a self-signed BMC is `ca_pem`
    with `tls_verify=strict`.
  - MEDIUM: a completed Task monitor (TaskState Completed) is success without
    requiring a power-state transition; a 204/empty/404 task read means
    completed; restart polling starts immediately and counts transitions, so a
    fast restart is accepted; `Nmi` is fire-and-forget (removed from
    RESTART_TYPES).
  - MEDIUM: an aborted body read is mapped to the typed `timeout`.
  - MEDIUM: logout is bounded by min(requestTimeoutMs, remaining deadline).
  - MEDIUM: a cross-origin session URI or task monitor is skipped with a warning
    instead of throwing.
  - TEST: stalled DELETE, cross-origin session URI and cross-origin task monitor
    added.
- 2026-10-17 (lane/d2-redfish): review round 3 (b3e629a). Dispositions:
  - HIGH: `awaitTask` checks the HTTP status first and returns true only for an
    explicit `TaskState` `Completed` with an `OK`/absent `TaskStatus`; 404/204
    or an empty body are unconfirmed and fall through to the power-state poll,
    and a non-2xx other than 404 throws (an empty 500 is an error). `power` no
    longer trusts a task alone for a non-restart action: every action except a
    restart reads back the desired `PowerState` before returning.
  - MEDIUM: a restart without a task polls until the deadline for an observed
    transition and is accepted with a warning (not a spurious timeout) if none
    is seen; a stuck restart still times out.
  - TEST: 404 task with the host still on times out; an empty 500 throws; a
    Completed task with a non-OK status throws; a confirmed task does not
    confirm a non-restart action that stays On.

## Round 5 (live emulator findings)

- HIGH: `insecure_skip_verify` could never work (`Deno.createHttpClient` has no
  such option; it was silently ignored). Removed with
  `allow_insecure_credentials`; `tls_verify` is the literal `strict`, `ca_pem`
  the way to trust a private CA.
- HIGH: `auth_mode` is now `auto` (default), `session` or `basic`. Sessions are
  discovered from the service root (`Links.Sessions` or the SessionService
  document); `auto` falls back to Basic when none is advertised, `session` fails
  with a typed `no_session_service`. Discovery sends no credential.
- MEDIUM: TLS failures are classified from the `cause` chain (UnknownIssuer,
  CaUsedAsEndEntity, expired, name mismatch) instead of "unreachable".
- MEDIUM: README documents the CA:FALSE leaf requirement.
- LOW: power description shortened, a stale task doc comment removed, the
  restart test renamed and its warning asserted.

## 2026-10-17 live e2e

Run sp-20261017. Target: DMTF sushy-tools 2.2.0 `sushy-emulator` with the FAKE
driver (one fake system `<system>`, no libvirt) on loopback, behind a throwaway
test CA and a CA:FALSE leaf, with HTTP Basic from a bcrypt htpasswd. Credentials
were random, stored in a local_encryption vault through stdin and wired as
`vault.get` references; nothing went on argv and no method run was captured with
`--json`. **No real BMC was tested: emulator only.** A first pass on d6374a4
scored 18/23 (FAIL: T3 TLS refusal mistyped as unreachable, T5
`insecure_skip_verify` could never work in Deno, A2 session mode against a BMC
without a SessionService); round 5 (0e97c93) fixed all three. Final run on
0e97c93, every cell on the default `auth_mode: auto` except A2 and A3:

| Cell                                                           | Result  | Detail                                                                                                  |
| -------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------- |
| T1 get, strict + ca_pem                                        | PASS    | anonymous `GET /redfish/v1`, then Systems and the system; data written                                  |
| T2 sync, strict + ca_pem                                       | PASS    | same 3 requests, data written                                                                           |
| T3 get/sync, strict, no ca_pem                                 | PASS    | typed TLS verification failure (untrusted CA); 0 requests reach the emulator                            |
| T4 `insecure_skip_verify` (adapted)                            | PASS    | rejected by the schema (`tls_verify` is the literal `strict`); 0 requests                               |
| T5 `allow_insecure_credentials` (adapted)                      | PASS    | rejected as an unknown input; 0 requests                                                                |
| A1 wrong password                                              | PASS    | typed `BMC rejected the credentials (HTTP 401)`                                                         |
| A2 auth_mode session (adapted: emulator has no SessionService) | PASS    | typed `no_session_service`; only the anonymous root GET, no POST, no credential sent                    |
| A3 auth_mode basic                                             | PASS    | no root discovery; Systems and system 200                                                               |
| P1 power On from Off                                           | PASS    | 1 Reset POST 204, On in 10.5 s                                                                          |
| P2 power On when already On                                    | PASS    | `already On`, no Reset POST                                                                             |
| P3 power ForceOff, then get                                    | PASS    | Off, read back Off                                                                                      |
| P4 power On                                                    | PASS    | On in 15.6 s                                                                                            |
| P5 power GracefulRestart                                       | PASS    | polled back to On, no warning                                                                           |
| P6 power ForceRestart                                          | PASS    | On, no warning                                                                                          |
| P7 power PushPowerButton (not allowed by the BMC)              | PASS    | typed refusal listing the allowed values; no Reset POST                                                 |
| B1 set_boot Pxe Once, then get                                 | BLOCKED | emulator ignores `BootSourceOverrideEnabled` (stays Continuous); the model correctly refuses, no data   |
| B2 set_boot Hdd Continuous, twice                              | PASS    | PATCH 204 and read-back; re-run `boot already Hdd`, no PATCH                                            |
| B3 set_boot Disabled                                           | BLOCKED | same emulator limitation; the model refuses with `BMC did not apply the boot override`                  |
| S1 get, no system_id                                           | PASS    | resolves the single system                                                                              |
| S2 get, explicit system_id                                     | PASS    |                                                                                                         |
| U1 get, unbound port                                           | PASS    | `BMC endpoint unreachable` in 1.9 s                                                                     |
| U2 power ForceOff, unbound port, timeout_seconds 10            | PASS    | `BMC endpoint unreachable` in 1.8 s                                                                     |
| X1 secret scan (343 files: logs, inputs, `.swamp`, vaults)     | PASS    | password, wrong password, Basic base64 and username: 0 hits; no session token was ever issued (vacuous) |
| Extra S3/S4 unknown system_id (get / sync)                     | PASS    | typed 404 / records `not_found`                                                                         |
| Extra X2/X3 header capture (session / auto)                    | PASS    | the discovery GET carries no Authorization; auto then sends Basic                                       |
| Extra T6 self-signed CA:TRUE server cert pinned as ca_pem      | PASS    | typed TLS error explaining CaUsedAsEndEntity and the CA:FALSE leaf fix                                  |

Result 21/23 PASS, 0 FAIL, 2 BLOCKED (B1, B3: emulator limitation). Session
auth, task monitors, real vendor firmware and a real BMC certificate were not
exercised, so the release stays on beta until a real BMC run.

- 2026-10-17 (merge-prep, main): review CLEAN at 0e97c93 (delta from d6374a4;
  earlier rounds 761b6df, e1ecad1, b3e629a, d6374a4). Residuals:
  - MEDIUM (open): a 5xx during session discovery counts as "no SessionService",
    so `auto` silently falls back to Basic over verified TLS. The credential
    still goes only over strict TLS, but a BMC with a flaky SessionService gets
    Basic instead of a session. Follow-up: treat a 5xx on discovery as an error.
  - LOW (fixed at merge-prep, description only): the `power` description had
    four sentences; now three.
  - LOW (fixed at merge-prep, comment only): the `TlsPolicy` comment in
    `_lib/http.ts` called `caPem` "pinned"; it is an additional trusted CA
    alongside the system store, not an exclusive pin.
