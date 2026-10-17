# @randybias/syncthing-peer

[Swamp](https://github.com/swamp-club/swamp) extension that manages one
Syncthing node's device and folder peering through the Syncthing REST API,
reached either locally or over SSH.

## Models

### `@randybias/syncthing-peer`

One Syncthing node. The definition holds nothing instance-specific: every method
takes its own access and node, and state is keyed by a SHA-256 of the node label
and API endpoint.

| Method          | Description                                                             |
| --------------- | ----------------------------------------------------------------------- |
| `get`           | READ-ONLY. Read node status, devices and folders, and store the summary |
| `sync`          | READ-ONLY. Refresh state; records reachable false when the node is down |
| `ensure_device` | DESTRUCTIVE. Ensure one peer device config exists exactly as declared   |
| `remove_device` | DESTRUCTIVE. Remove one peer device; an absent device is a no-op        |
| `ensure_folder` | DESTRUCTIVE. Ensure one shared folder and its peer device list          |
| `remove_folder` | DESTRUCTIVE. Remove one shared folder; an absent folder is a no-op      |

## Dependencies

- The Syncthing REST API on the target. For the `ssh` transport, the vendored
  OpenSSH client tools (`ssh`, `ssh-agent`, `ssh-add`) and `curl` on the host.
- The API is normally `http://127.0.0.1:8384`; plain HTTP is allowed only on a
  loopback address, anything else must be HTTPS.

## Install

```bash
swamp extension pull @randybias/syncthing-peer
```

## Example

Create one definition and ensure peering on each node. The API key comes from a
vault and travels only in the `X-API-Key` header:

```bash
swamp model create @randybias/syncthing-peer syncthing-peer
```

```bash
swamp model method run syncthing-peer ensure_device \
  --input access=local --input node=edge-1 \
  --input 'api_key=${{ vault.get("default", "SYNCTHING_API_KEY") }}' \
  --input device_id=AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD-EEEEEEE-FFFFFFF-GGGGGGG-HHHHHHH \
  --input name=edge-2
```

Reach a node over SSH, where curl runs on the host and the key is uploaded as a
mode-0600 config over stdin:

```bash
swamp model method run syncthing-peer ensure_folder \
  --input access=ssh --input node=edge-1 \
  --input host=192.0.2.10 --input user=root \
  --input host_key_policy=strict \
  --input 'host_keys:json=["192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"]' \
  --input 'private_key=${{ vault.get("default", "SSH_PRIVATE_KEY") }}' \
  --input 'api_key=${{ vault.get("default", "SYNCTHING_API_KEY") }}' \
  --input folder_id=media --input label=Media --input path=/srv/media \
  --input 'devices:json=["AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD-EEEEEEE-FFFFFFF-GGGGGGG-HHHHHHH"]'
```

Read the change flag with
`data.latest("syncthing-peer", "<key>").attributes.changed`. Pass `api_key` and
`private_key` as vault references only.

## How it works

- The API key travels only in the `X-API-Key` header. A local call sets it as an
  in-memory request header; a remote call uploads a mode-0600 `curl --config`
  file over stdin to a random name in a 0700 `~/.cache/syncthing-peer/`
  directory, runs `curl` and its trap-based cleanup in **one** remote shell, and
  sweeps any config older than a few minutes before each upload. The key never
  reaches a URL, a process argument, a log or stored state.
- Plain HTTP is accepted only on a loopback address; any other origin must use
  HTTPS. A redirect is refused rather than re-sending the key.
- The SSH transport is strict-only: `host_key_policy=strict` and a non-empty
  `host_keys` are required, so the host is verified on every run.
- `ensure_device` and `ensure_folder` create what is missing with `PUT` and
  update what differs with `PATCH`, so fields this model does not declare are
  left alone; they re-read the config and refuse if it did not converge. An
  identical config is a no-op with `changed false`. Syncthing always adds the
  node's own device to a folder, so the comparison ignores it and stored state
  keeps the observed read-back.
- `remove_device` and `remove_folder` delete and prove the config is gone; an
  already-absent config, and a DELETE that returns 404, are a clean no-op.
- Every request is bounded: `timeout_s` (default 30) becomes an `AbortSignal`
  for a local fetch and `--max-time`/`--connect-timeout` for the remote curl.
- State is keyed by `sha256(node, api_url)` after normalizing the URL
  (lowercased host, no trailing slash), with device and folder records appended
  by a length-prefixed id.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
