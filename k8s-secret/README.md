# @randybias/k8s-secret

[Swamp](https://github.com/swamp-club/swamp) extension for writing a Kubernetes
`Secret` from vault values. Built against kubectl v1.35 and the `v1` Secret API.

## Models

### `@randybias/k8s-secret`

One Secret, addressed by method arguments (kubeconfig, context, namespace,
name), so a single definition serves any cluster. Secret values go to kubectl on
stdin as a server-side-apply manifest; they never appear on a command line, in
stored state or in method output. The kubeconfig is written to a `0600`
temporary file and removed after every call, even on error.

| Method   | Description                                                                   |
| -------- | ----------------------------------------------------------------------------- |
| `apply`  | Create or update the Secret; identical data and type is a no-op by sha256     |
| `get`    | Read metadata, key names and a sha256 per value, never the values (read-only) |
| `sync`   | Refresh stored state; records `not_found` when gone (read-only)               |
| `delete` | Delete the Secret; an absent Secret is a clean no-op                          |

`apply` manages the keys you give it. Keys added by other tools are left alone
and show up in `keys` and `data_sha256`.

## Dependencies

`kubectl` on the PATH and a reachable API server.

## Example

```sh
swamp model create @randybias/k8s-secret db-secret
swamp model method run db-secret apply \
  --input 'kubeconfig=${{ vault.get("cluster", "kubeconfig") }}' \
  --input namespace=app --input name=db-creds \
  --input 'data:json={"password":"${{ vault.get("app", "db-password") }}"}'
```

Read it back (hashes only) and delete it:

```sh
swamp model method run db-secret get \
  --input 'kubeconfig=${{ vault.get("cluster", "kubeconfig") }}' \
  --input namespace=app --input name=db-creds
swamp model method run db-secret delete \
  --input 'kubeconfig=${{ vault.get("cluster", "kubeconfig") }}' \
  --input namespace=app --input name=db-creds
```

Run it again with another `namespace` or kubeconfig for a second Secret. Do not
capture `--json` output of a run that carries these arguments: the swamp CLI
echoes sensitive arguments there.

## How it works

State is keyed by `{context}/{namespace}/{name}` and holds hashes only. Failures
are typed (`unreachable`, `unauthorized`, `namespace_not_found`, `not_found`,
`invalid_input`) and their messages are scrubbed of every supplied value.
Namespace, name, context, type and keys are validated against Kubernetes
grammars before any process starts.

## License

Apache-2.0
