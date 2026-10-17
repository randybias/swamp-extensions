# Spec: `@randybias/redfish`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone controlling server power and boot through a BMC that speaks DMTF Redfish.

Q3: Yes. `redfish` names the protocol (Redfish); it covers power and boot only, so `redfish-power` if a second Redfish extension appears; short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `redfish` as a Redfish BMC client, which is what it does, and guesses wrong about nothing.

Status: written after the first published version, from the README and LOGBOOK; it describes the
behaviour as shipped. RFC 2119 keywords. Not clean-room (written from this repo's README, LOGBOOK and public docs).

## 1. Purpose

Read and control one server's power state and boot override over the DMTF Redfish API. One model
serves any BMC: endpoint, system id and vault-wired credentials are method arguments, the TLS
policy is explicit, and no credential is placed in a URL, log, argument or stored state.

## 2. Model contract

One model type `@randybias/redfish`, one `ComputerSystem` per method call.

| Method | Kind | Behaviour |
|---|---|---|
| `get` | READ-ONLY | Read `PowerState`, the boot override and `Status`; store an allowlist of metadata. |
| `sync` | READ-ONLY | Refresh stored state; records `not_found` when the system is gone. |
| `power` | action | `On`, `ForceOff`, `GracefulShutdown`, `GracefulRestart`, `ForceRestart`, `Nmi` (fire-and-forget): validate against the system's advertised allowables, no-op when already in the target state, follow a returned task monitor, read back the desired state. |
| `set_boot` | action, DESTRUCTIVE | Patch the boot override (`target`, `enabled: Once` or `Continuous`) with `If-Match` when an ETag is offered, and read it back. |

## 3. Inputs

`endpoint` (an `https` origin: no path, query, fragment or embedded credentials; every
`@odata.id` is resolved back onto it), `system_id`, `username` and `password` (vault references),
`tls_verify` (required, always `strict`), optional `ca_pem` (an additional trusted CA, not an
exclusive pin), `auth_mode` (`auto`, `session`, `basic`), per-call timeout and poll bounds.

## 4. Invariants

- `auto` reads the service root without credentials and opens a session when `Links.Sessions`
  or the `SessionService` advertises one, deleting it in a `finally`; a BMC that advertises none
  gets Basic over the same verified TLS connection. A BMC that advertises Sessions but refuses the
  credentials is `unauthorized`, never retried as Basic.
- Only a `TaskState` of `Completed` with an `OK` or absent `TaskStatus` is a confirmed task;
  anything else falls through to the power-state poll. Every action other than a restart must read
  back the desired state; a restart with no observed transition is accepted with a warning at the
  timeout.
- There is no insecure TLS mode. A TLS failure is a typed `tls` error naming the class (unknown
  issuer, CA used as end entity, expired, name mismatch).
- A cross-origin session URI or task monitor is skipped with a warning.

## 5. Failure modes

Typed: `no_session_service`, `unauthorized`, `tls`, `timeout`, `not_found`, malformed body (a
`null` or non-object JSON body is refused), an unsupported `ResetType`.

## 6. Test obligations

Unit: endpoint grammar, origin resolution, allowable filtering, task-state classification, TLS
error classification from the `cause` chain. Contract tests against a recorded Redfish emulator.
Adversarial: credentials never in URL, argv, log, result or state; a redirecting BMC; a 5xx on
discovery.

## 7. Live matrix

Against the Redfish emulator: `get`, `sync`, each `power` action, `set_boot` once and continuous,
session and basic modes, TLS failure classes. Real BMC cells stay untested with the reason until
hardware exists.

## Next version scope: next

Next `redfish` version (public, beta).

- This spec is written first.
- Medium: a 5xx during session discovery counts as "no SessionService" and
  `auto` falls back to Basic. Treat 5xx as an error; fall back only on 404.
- Live against the emulator only; the real BMC cells stay untested with the
  reason until hardware exists.
