# @randybias/azure-nsg

[Swamp](https://github.com/swamp-club/swamp) extension for one Azure network
security group and its security rules through the Azure Resource Manager REST
API. Built against the Azure Network API `2024-05-01`.

## Models

### `@randybias/azure-nsg`

One generic NSG. The definition holds nothing instance-specific: every method
takes its own tenant, subscription, resource group and name, and stored state is
keyed by all three, with rules keyed by their parent plus rule name.

| Method           | Description                                                                     |
| ---------------- | ------------------------------------------------------------------------------- |
| `get`            | READ-ONLY. Fetch one NSG and store its state                                    |
| `sync`           | READ-ONLY. Refresh state; records `not_found` when the NSG is gone              |
| `ensure_rule`    | DESTRUCTIVE. Create or converge one rule; identical is a no-op                  |
| `remove_rule`    | DESTRUCTIVE. Delete one rule; an absent rule is a clean no-op                   |
| `apply_rule_set` | DESTRUCTIVE. Converge a declared rule set; plans first, applies only when asked |
| `delete`         | DESTRUCTIVE. Delete the NSG; an already-absent NSG is a clean no-op             |

## Dependencies

- Outbound HTTPS to `login.microsoftonline.com` and `management.azure.com`.
- An Entra service principal with permission to manage NSGs in the target
  resource group. Pass its tenant id, client id and client secret as method
  inputs; the secret travels only in the token request body, never a URL, a
  header or a process argument.

## Install

```bash
swamp extension pull @randybias/azure-nsg
```

## Example

One definition, any NSG. Secrets come from a vault:

```bash
swamp model create @randybias/azure-nsg azure-nsg
```

```bash
swamp model method run azure-nsg ensure_rule \
  --input tenantId=11111111-1111-1111-1111-111111111111 \
  --input clientId=22222222-2222-2222-2222-222222222222 \
  --input 'clientSecret=${{ vault.get("default", "AZURE_CLIENT_SECRET") }}' \
  --input subscriptionId=33333333-3333-3333-3333-333333333333 \
  --input resourceGroup=rg-example --input nsgName=nsg-1 \
  --input ruleName=allow-ssh --input priority=100 \
  --input direction=Inbound --input access=Allow --input protocol=Tcp \
  --input 'sourceAddressPrefixes:json=["192.0.2.0/24"]' \
  --input 'destinationAddressPrefixes:json=["*"]' \
  --input 'sourcePortRanges:json=["*"]' \
  --input 'destinationPortRanges:json=["22"]'
```

Plan a whole rule set before applying it:

```bash
swamp model method run azure-nsg apply_rule_set \
  --input tenantId=11111111-1111-1111-1111-111111111111 \
  --input clientId=22222222-2222-2222-2222-222222222222 \
  --input 'clientSecret=${{ vault.get("default", "AZURE_CLIENT_SECRET") }}' \
  --input subscriptionId=33333333-3333-3333-3333-333333333333 \
  --input resourceGroup=rg-example --input nsgName=nsg-1 \
  --input 'rules:json=[{"ruleName":"allow-ssh","priority":100,"direction":"Inbound","access":"Allow","protocol":"Tcp","sourceAddressPrefixes":["192.0.2.0/24"],"destinationAddressPrefixes":["*"],"sourcePortRanges":["*"],"destinationPortRanges":["22"]}]' \
  --input apply=false
```

`apply=false` (the default) records the plan and changes nothing; `apply=true`
creates and updates the declared rules and leaves undeclared rules alone. Pass
`clientSecret` as a vault reference only.

## How it works

- Authentication is OAuth2 client credentials. The secret is sent in the body of
  one token POST and the access token stays in memory for the call; it is never
  written to state, logs or an argument.
- `ensure_rule` and `apply_rule_set` compare the desired rule with the existing
  one (arrays order-insensitively) and only issue a PUT when something differs.
- A single-element address or port list — and any `*` or service tag — is sent
  in Azure's singular field; a multi-element list must be all CIDRs or ranges
  and is sent in the plural field.
- `apply_rule_set` is plan-first: it records create, update, unchanged and
  undeclared rule names, and only applies when `apply` is explicitly true. It
  also records priority collisions (a duplicate rule name or priority inside the
  declared set, or a declared priority already held by an undeclared or swapped
  rule) and, with `apply` true, writes the record and refuses without issuing
  any PUT, so the NSG is never half-converged.
- Rule writes and deletes are polled until the rule reports `Succeeded` or is
  gone, so state is only recorded once Azure has settled.
- `delete`, `remove_rule` and `ensure_rule` are actions, so they do not
  tombstone the definition; state is keyed unambiguously by subscription,
  resource group, name and rule.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
