# @randybias/k8s-secret

[Swamp](https://github.com/swamp-club/swamp) extension for writing a Kubernetes
`Secret` from vault values. Built against the Kubernetes `v1` Secret API and
`kubectl apply --server-side`.

## Models

### `@randybias/k8s-secret`

One Secret, addressed by method arguments (kubeconfig, context, namespace,
name), so a single definition serves any cluster. Secret values go to kubectl on
stdin as a server-side-apply manifest; they never appear on a command line, in
stored state or in method output, and no value hash is returned either. The
kubeconfig is written to a `0600` temporary file and removed after every call,
even on error.

| Method   | Description                                                             |
| -------- | ----------------------------------------------------------------------- |
| `apply`  | Create or update the Secret; identical keys, values and type is a no-op |
| `get`    | Read metadata and key names; never values or value hashes (read-only)   |
| `sync`   | Refresh stored state; records `not_found` when gone (read-only)         |
| `delete` | Delete the Secret; an absent Secret is a clean no-op                    |

`apply` owns the keys you give it: keys added by other tools are left alone and
still reported in `keys`, while a key this model previously owned and no longer
receives is pruned. It uses `--force-conflicts`, so a conflicting value is
overwritten. Failures are typed and carry no remote text.

`apply` takes exactly one of `data` (key to value, each value a vault reference)
or `data_from_vault` (key to `{vault, key}` names). The model resolves
`data_from_vault` itself through the runtime vault service, so a workflow can
pass vault and key names instead of resolving a dynamic map in an expression.
Both the vault name and the key are validated as names before any lookup, and a
failed lookup names the vault and key only, never a value.

## Dependencies

`kubectl` on the PATH and a reachable API server.

## Install

```sh
swamp extension pull @randybias/k8s-secret
```

## Example

One definition serves every Secret and cluster; the method arguments pick the
namespace, name and kubeconfig.

```sh
swamp model create @randybias/k8s-secret db-secret

for ns in app app-staging; do
  swamp model method run db-secret apply \
    --input 'kubeconfig=${{ vault.get("cluster", "kubeconfig") }}' \
    --input namespace=$ns --input name=db-creds \
    --input 'data:json={"password":"${{ vault.get("app", "db-password") }}"}'
done
```

In a workflow, pass vault and key names; the model resolves them at run time:

```sh
swamp model method run db-secret apply \
  --input 'kubeconfig=${{ vault.get("cluster", "kubeconfig") }}' \
  --input namespace=app --input name=db-creds \
  --input 'data_from_vault:json={"password":{"vault":"app","key":"db-password"}}'
```

Read it back (key names only) and delete it:

```sh
swamp model method run db-secret get \
  --input 'kubeconfig=${{ vault.get("cluster", "kubeconfig") }}' \
  --input namespace=app --input name=db-creds
swamp model method run db-secret delete \
  --input 'kubeconfig=${{ vault.get("cluster", "kubeconfig") }}' \
  --input namespace=app --input name=db-creds
```

Pass `kubeconfig` and every `data` value only as vault references (or over
stdin); never as literal `--input` values. `data_from_vault` carries vault and
key names, not values.

## How it works

State is keyed by a nonsecret cluster fingerprint plus context, namespace and
name, and holds key names and metadata, never values or value hashes. Value
comparison hashes exist only inside an `apply` call. Failures are typed
(`unreachable`, `unauthorized`, `namespace_not_found`, `not_found`) and carry a
fixed message: remote kubectl text is never returned, because it can echo the
manifest. Namespace, name, context, type and keys are validated against
Kubernetes grammars before any process starts, and data is bounded by key count
and total UTF-8 size. A kubeconfig is inspected before kubectl runs and rejected
if it uses `exec` or `auth-provider` credentials (which execute a local command)
or any credential that names a local file (`tokenFile`, `client-certificate`,
`client-key`, `certificate-authority`); only embedded `*-data` credentials and
`token`/`username`/`password` are accepted. YAML merge keys are refused, because
kubectl applies them while other parsers do not; kubectl's own
`config view --raw -o json` output is validated with default-deny at every level
and is the only kubeconfig kubectl then uses. Cluster TLS settings are the
caller's choice: `insecure-skip-tls-verify` is accepted if the kubeconfig sets
it. The server-side apply field manager is derived from the definition name, so
two definitions that target the same Secret do not prune each other's keys.

## License

Apache-2.0
