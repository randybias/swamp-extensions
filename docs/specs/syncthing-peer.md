# Spec: `@randybias/syncthing-peer`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone peering Syncthing nodes and sharing folders between them.

Q3: Yes. `syncthing-peer` names the product (Syncthing) and the resource (a peer device and its shared folder); short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `syncthing-peer` as a Syncthing peering manager, which is what it does, and guesses wrong about nothing.

Status: written after the first published versions, from the README and LOGBOOK; it describes
the behaviour as shipped. RFC 2119 keywords. Not clean-room (written from this repo's README, LOGBOOK and public docs).

## 1. Purpose

Ensure a peer device and a shared folder on one Syncthing node through its REST API, reached
locally or over SSH, and inspect or remove them, without the API key ever leaving a request header.

## 2. Model contract

One generic model type `@randybias/syncthing-peer`. The definition holds nothing
instance-specific; state is keyed by `sha256(node, api_url)` after URL normalisation (lowercased
host, no trailing slash), with device and folder records appended by a length-prefixed id.

| Method | Kind | Behaviour |
|---|---|---|
| `get` | READ-ONLY | Read node status, devices and folders; store the summary. |
| `sync` | READ-ONLY | Refresh state; records `reachable: false` when the node is down (connect or timeout failures only; configuration, host-key and 401/403 failures are errors). |
| `ensure_device` | action, DESTRUCTIVE | Ensure one peer device exists exactly as declared (`PUT` creates, `PATCH` updates); re-read and refuse if it did not converge. |
| `remove_device` | action, DESTRUCTIVE | Remove one peer device and prove it is gone; absent, or a 404 on DELETE, is a no-op. |
| `ensure_folder` | action, DESTRUCTIVE | Ensure one shared folder and its peer device list; the node's own device is ignored in the comparison. |
| `remove_folder` | action, DESTRUCTIVE | Remove one shared folder; absent is a no-op. |

## 3. Inputs

- `access`: `local` (in-process fetch) or `ssh` (`curl` on the host, the request body streamed
  to `curl --config -` on stdin). SSH targets take `host`, `user`, `port`, `host_key_policy`
  (strict only) and a non-empty `host_keys`, plus `private_key` from a vault.
- `node` (label), `api_url` (default the loopback API; plain HTTP only on a loopback address,
  anything else HTTPS), `api_key` (vault reference), `timeout_s` (default 30).
- Device: `device_id` (Syncthing's 8-group id grammar), `name`, `addresses` (`dynamic` or
  structurally valid tcp/quic/relay URLs). Folder: `folder_id`, `label`, `path`, `devices`.
- Strict schemas; `api_key` and `private_key` are sensitive.

## 4. Invariants

- The API key appears only in the `X-API-Key` header; never a URL, argv, remote disk, log or state.
- A redirect is refused rather than re-sending the key.
- Every request is bounded by `timeout_s` (`AbortSignal` locally, `--max-time` and
  `--connect-timeout` remotely); remote `curl` runs with `-q` so `~/.curlrc` cannot interfere.
- Identical configuration is a no-op with `changed: false`; fields this model does not declare
  are left alone.

## 5. Failure modes

Typed: unreachable node, unauthorised (401/403), TLS or host-key failure, non-convergence after a
write, malformed device id or address, timeout. No partial state is recorded on failure.

## 6. Test obligations

Unit: id and address grammars, URL normalisation, the state key, PUT-versus-PATCH selection,
convergence comparison, redirect refusal. Contract tests with a fake API and a fake transport.
Adversarial: key never in any log, result or remote argv; a 3xx response; a non-loopback HTTP URL.

## 7. Live matrix

Twelve cells on two small servers: `get`, `sync` up and down, `ensure_device` create, identical
re-run, update, `remove_device` and remove-absent, `ensure_folder` create, identical, update,
`remove_folder`; both access modes; plus the upgrade row from the published version.

## Next version scope: next

Next `syncthing-peer` version (public; a stable candidate).

- This spec is written first; the first versions shipped without one.
- Lows: after a local timeout the remote `curl` runs until its own `--max-time`;
  remote stderr reaches errors as the last line only.
- Live: re-prove the 12 cells in section 7 on two small servers and record the
  upgrade row from the published version.
