# Spec: `@randybias/azure-nsg`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone converging Azure network security group rules with a service principal.

Q3: Yes. `azure-nsg` names the provider (Azure) and Azure's own term for the resource (NSG); short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `azure-nsg` as an Azure network security group manager, which is what it does, and guesses wrong about nothing.

Status: written after the first published version, from the README and LOGBOOK; it describes the
behaviour as shipped. RFC 2119 keywords. Not clean-room (written from this repo's README, LOGBOOK and public docs).

## 1. Purpose

Inspect and delete one Azure network security group and converge its security rules through the
Azure Resource Manager REST API (Network `2024-05-01`) with a service principal held in a vault,
planning before applying so the NSG is never half-converged.

## 2. Model contract

One generic model type `@randybias/azure-nsg`; state keyed by subscription, resource group and
NSG name, with rules keyed by their parent plus rule name.

| Method | Kind | Behaviour |
|---|---|---|
| `get` | READ-ONLY | Fetch one NSG and store its state. |
| `sync` | READ-ONLY | Refresh state; records `not_found` when the NSG is gone. |
| `ensure_rule` | action, DESTRUCTIVE | Create or converge one rule; identical (arrays compared order-insensitively) is a no-op. |
| `remove_rule` | action, DESTRUCTIVE | Delete one rule; absent is a no-op. |
| `apply_rule_set` | action, DESTRUCTIVE | Plan create, update, unchanged and undeclared rules and priority collisions; apply only when `apply` is explicitly true, and refuse without any PUT when the plan has collisions. Undeclared rules are left alone. |
| `delete` | action, DESTRUCTIVE | Delete the NSG; absent is a no-op. |

## 3. Inputs

`tenantId`, `clientId`, `clientSecret` (vault reference), `subscriptionId`, `resourceGroup`,
`nsgName`; rule fields `ruleName`, `priority`, `direction`, `access`, `protocol`, source and
destination address prefixes and port ranges, `description`; `rules` and `apply` (default
false) for the rule set. A single-element list, `*` or a service tag is sent in Azure's singular
field; a multi-element list must be all CIDRs or ranges and is sent in the plural field.

## 4. Invariants

- The secret is sent once in the token request body; the token stays in memory and never reaches
  state, logs or an argument.
- A PUT is issued only when something differs; writes and deletes are polled until the rule
  reports `Succeeded` or is gone before state is recorded.
- Actions never tombstone the definition.

## 5. Failure modes

Typed: token failure, 401/403, 404 on an expected resource, a plan with collisions when `apply`
is true, timeout while polling, malformed prefixes or ranges.

## 6. Test obligations

Unit: singular-versus-plural field selection, order-insensitive comparison, plan computation and
collision detection, prefix grammars. Contract tests against a recorded ARM fake. Adversarial:
secret never in URL, argv, log, result or state; a half-applied set is impossible by construction.

## 7. Live matrix

Blocked until the same throwaway subscription and service principal as `azure-vm` exist:
`ensure_rule` create, identical, update; `remove_rule` and remove-absent; `apply_rule_set` plan,
apply, collision refusal; `delete`.

## Next version scope: next

Next `azure-nsg` version (public, beta).

- This spec is written first.
- Residual Mediums: rule writes poll the rule GET instead of the
  async-operation URL, so an async failure shows as a timeout; the rule
  description has a length bound but no character allowlist; deleting the NSG
  does not mark its recorded rule resources deleted; IPv6 prefix validation
  accepts malformed forms (shared fix with `azure-vm`, done in sequence).
- Live stays untested until the same throwaway subscription and service
  principal as `azure-vm` exist.
