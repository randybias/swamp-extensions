# @randybias/azure-vm

[Swamp](https://github.com/swamp-club/swamp) extension for the lifecycle of one
Azure virtual machine through the Azure Resource Manager REST API. Built against
the Azure Compute API `2024-07-01`.

## Models

### `@randybias/azure-vm`

One generic VM. The definition holds nothing instance-specific: every method
takes its own tenant, subscription, resource group and name, and stored state is
keyed by all three.

| Method       | Description                                                               |
| ------------ | ------------------------------------------------------------------------- |
| `get`        | READ-ONLY. Fetch one VM and store its state                               |
| `sync`       | READ-ONLY. Refresh state; records `not_found` when the VM is gone         |
| `create`     | Create the VM or adopt the existing one; wait until provisioning succeeds |
| `start`      | Start the VM and wait for the running power state                         |
| `deallocate` | Deallocate the VM, releasing compute and stopping charges; or hibernate   |
| `stop`       | Power off without deallocating; compute charges continue                  |
| `delete`     | DESTRUCTIVE. Delete the VM; an already-absent VM is a clean no-op         |

## Dependencies

- Outbound HTTPS to `login.microsoftonline.com` and `management.azure.com`.
- An Entra service principal with permission to manage VMs in the target
  resource group. Pass its tenant id, client id and client secret as method
  inputs; the secret travels only in the token request body, never a URL, a
  header or a process argument.
- An existing network interface for the VM; this model does not create
  networking.

## Install

```bash
swamp extension pull @randybias/azure-vm
```

## Example

Create one definition and run it per VM. Secrets come from a vault:

```bash
swamp model create @randybias/azure-vm azure-vm
```

```bash
swamp model method run azure-vm create \
  --input tenantId=11111111-1111-1111-1111-111111111111 \
  --input clientId=22222222-2222-2222-2222-222222222222 \
  --input 'clientSecret=${{ vault.get("default", "AZURE_CLIENT_SECRET") }}' \
  --input subscriptionId=33333333-3333-3333-3333-333333333333 \
  --input resourceGroup=rg-example --input name=web-1 \
  --input location=eastus2 --input vmSize=Standard_B2s \
  --input 'image:json={"publisher":"Canonical","offer":"ubuntu-24_04-lts","sku":"server","version":"latest"}' \
  --input adminUsername=azureuser \
  --input 'sshPublicKey=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey user@example' \
  --input networkInterfaceId=/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-example/providers/Microsoft.Network/networkInterfaces/nic-1
```

Redeploying the same name adopts the existing VM. Deallocate to stop charges:

```bash
swamp model method run azure-vm deallocate \
  --input tenantId=11111111-1111-1111-1111-111111111111 \
  --input clientId=22222222-2222-2222-2222-222222222222 \
  --input 'clientSecret=${{ vault.get("default", "AZURE_CLIENT_SECRET") }}' \
  --input subscriptionId=33333333-3333-3333-3333-333333333333 \
  --input resourceGroup=rg-example --input name=web-1
```

Read a state field with
`data.latest("azure-vm", "<subscription>-<resource-group>-<name>").attributes.powerState`.
Pass `clientSecret` as a vault reference only: the swamp CLI prints literal
sensitive arguments under `--json`.

## How it works

- Authentication is OAuth2 client credentials. The secret is sent in the body of
  one token POST and the access token stays in memory for the call; it is never
  written to state, logs or an argument.
- `create` checks for the VM first and adopts it, so a re-run never creates a
  second VM. A new VM is created with password authentication disabled and the
  given SSH public key, then polled until its provisioning state is `Succeeded`.
- `deallocate` calls the deallocate action (optionally hibernating) and waits
  for the deallocated power state; `stop` powers off without releasing compute.
- `delete` is an action: it removes only this VM's record, waits until Azure no
  longer returns it, and is a clean no-op when the VM is already gone.
- Stored state is keyed unambiguously by subscription, resource group and name.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
