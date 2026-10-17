# Spec: `@randybias/azure-vm`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone managing the lifecycle of Azure virtual machines with a service principal.

Q3: Yes. `azure-vm` names the provider (Azure) and the resource (a VM); short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `azure-vm` as an Azure VM lifecycle manager, which is what it does, and guesses wrong about nothing.

Status: written after the first published version, from the README and LOGBOOK; it describes the
behaviour as shipped. RFC 2119 keywords. Not clean-room (written from this repo's README, LOGBOOK and public docs).

## 1. Purpose

Create, adopt, start, deallocate, stop, inspect and delete one Azure virtual machine through the
Azure Resource Manager REST API (Compute `2024-07-01`) with a service principal held in a vault,
with no credential on a command line or in state.

## 2. Model contract

One generic model type `@randybias/azure-vm`; state keyed by subscription, resource group and
VM name (length-prefixed instance name).

| Method | Kind | Behaviour |
|---|---|---|
| `get` | READ-ONLY | Fetch one VM and store its state. |
| `sync` | READ-ONLY | Refresh state; records `not_found` when the VM is gone. |
| `create` | action | Create the VM or adopt the existing one by name; poll until provisioning is `Succeeded`. Password authentication disabled; the given SSH public key installed. |
| `start` | action | Start and wait for the running power state. |
| `deallocate` | action, DESTRUCTIVE | Deallocate (optionally hibernate) and wait for the deallocated state. |
| `stop` | action, DESTRUCTIVE | Power off without releasing compute. |
| `delete` | action, DESTRUCTIVE | Delete this VM's record, wait until Azure no longer returns it; absent is a no-op. |

## 3. Inputs

`tenantId`, `clientId`, `clientSecret` (vault reference), `subscriptionId`, `resourceGroup`,
`name`; for `create`: `location`, `vmSize`, `image` (publisher, offer, sku, version),
`adminUsername`, `sshPublicKey`, `networkInterfaceId` (an existing NIC; this model does not create
networking), optional `tags`. Strict schemas.

## 4. Invariants

- OAuth2 client credentials: the secret is sent once in the token request body; the token stays in
  memory for the call and is never written to state, logs or an argument.
- `create` checks first and adopts, so a re-run never creates a second VM.
- Every mutating verb is `kind: "action"`, so none tombstones the definition.
- Long operations are polled with a bounded deadline; state is recorded only once Azure settles.

## 5. Failure modes

Typed: token failure, 401/403, 404 on an expected resource, a provisioning state other than
`Succeeded`, timeout while polling, malformed inputs (resource ids, prefixes).

## 6. Test obligations

Unit: instance-name derivation, request bodies, poll classification, input grammars. Contract
tests against a recorded ARM fake. Adversarial: secret never in URL, argv, log, result or state.

## 7. Live matrix

Blocked until a throwaway subscription and a service principal scoped to one resource group
exist: create, adopt, start, stop, deallocate, delete, delete-absent, `sync` after deletion.

## Next version scope: next

Next `azure-vm` version (public, beta).

- This spec is written first. Version 2026.10.17.2 has a release note but was
  never published: fold it in.
- Residual Mediums: `tags` is not bounded to the provider's tag-count limit;
  `deallocate` and `stop` always POST even when the VM is already in the target
  state; the README's state-key format does not match the length-prefixed
  instance name; IPv6 prefix validation in the shared lib accepts malformed
  forms (shared fix with `azure-nsg`, one lane takes both in sequence).
- Live stays untested until a throwaway subscription and a service principal
  scoped to one resource group exist; the version publishes to beta regardless.
