# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17: initial release. Built because a registry review found no
  first-party Azure VM model and the third-party `@dougschaefer/azure` has real
  gaps for this repo's standard: its `delete` methods have no `kind: "action"`
  (a literal `delete` tombstones the whole model), its VM create puts
  `--admin-password` and `--ssh-key-value` on the `az` argv, and it supports
  only an out-of-band `az login`, not a service principal from a vault. This
  extension calls Azure Resource Manager REST directly instead.
- Auth is OAuth2 client credentials: the client secret is sent only in the token
  POST body, the token lives in memory for one call, and the fetch seam is
  injectable so tests open no socket. Every secret field is sensitive-marked.
- `delete` is `kind: "action"` and idempotent; `create` adopts an existing VM
  and polls to `Succeeded`; `deallocate` is a real deallocate (with optional
  hibernation), not a stop. Admin access is SSH public key only, with password
  authentication disabled in the request body.
- `_lib/arm.ts` and `_lib/validate.ts` are shared byte-identical with
  `@randybias/azure-nsg`.
- Live testing is **blocked**: Randy must confirm an Azure subscription and a
  service principal scoped to a throwaway resource group, and the account must
  be tagged for the run. Live cells are marked blocked in the run matrix, not
  skip. Everything here is unit/contract tested against a scripted fetch.
- 2026-10-17 review round 1: `create`, `start`, `deallocate` and `stop` are now
  `kind: "action"` like `delete`, so no lifecycle verb tombstones the
  definition; `deallocate` and `stop` are prefixed `DESTRUCTIVE.` because they
  stop the workload. The shared `_lib/arm.ts` now unwraps Resource Manager's
  nested `{error:{code,message}}` and AAD's `{error, error_description}`,
  redacts the secret before truncating the message, and redacts the code; both
  `_lib` copies stay byte-identical.

## 2026-10-17 live e2e: blocked

Reason: Azure subscription + service principal scoped to a throwaway resource
group not yet provided (Randy). Every cell below is `blocked`, not skipped; run
them through `swamp model method run` against a throwaway resource group before
promoting to stable. Unit/contract tests (scripted fetch) cover every path.

| Cell                                            | Result  |
| ----------------------------------------------- | ------- |
| 1 get, VM absent                                | blocked |
| 2 create new VM (SSH key only, polls Succeeded) | blocked |
| 3 create again adopts, no second PUT            | blocked |
| 4 get / sync present                            | blocked |
| 5 stop                                          | blocked |
| 6 start                                         | blocked |
| 7 deallocate                                    | blocked |
| 8 deallocate with hibernation                   | blocked |
| 9 delete                                        | blocked |
| 10 delete again, clean no-op                    | blocked |
| 11 bad client secret, typed AAD error redacted  | blocked |
| 12 invalid name/grammar refused before any call | blocked |

## Review ledger: final verify and merge prep

- No Critical/High open; azure-vm code is unchanged since round 1 (85a59da) and
  the round-3 delta touched only azure-nsg. `_lib/arm.ts` and `_lib/validate.ts`
  remain byte-identical with `@randybias/azure-nsg`.
- Known residuals for the next version: MEDIUM `tags` is not bounded to Azure's
  tag-count limit; MEDIUM `deallocate`/`stop` always POST even when the VM is
  already in the target state (Azure accepts the repeat; not verified live);
  MEDIUM README documents the state key as
  `<subscription>-<resource-group>-<name>` but the instance name is
  length-prefixed (`resourceInstanceName`); MEDIUM IPv6 prefix validation
  accepts some malformed forms (shared `_lib`); LOW duplicated power-state
  polling and state writing in start/deallocate/stop.

## Prior art

Registry search on stable and beta (`swamp extension search`, whole-word
matches in the package name or description) for `azure-vm` and `azure`.

- azure-vm: no hits.
- azure:
  - `@dougschaefer/azure` (stable): 43 model types over the `az` CLI; its
    `azure-vm` type has list, get, sync, create, delete, start, stop,
    deallocate, restart, resize and runCommand. It relies on the ambient
    `az login` session (no vault-wired service principal), passes the admin
    password on argv in create, and has no adopt or converge semantics.
    OVERLAP, justified: this extension uses the ARM REST API with a service
    principal from a vault, no `az` dependency, and create/adopt converge.
  - `@nedbellavance/azure-ssh-key` (stable): Azure sshPublicKeys resources
    through the az CLI; a related resource, not compute. NONE (adjacent).
  - `@rkcoleman/azure-containers` (stable), `@rkcoleman/azure-app-service`
    (stable): Container Apps and App Service over the az CLI; different
    resource families. NONE.
  - `@swamp/azure-kv` (stable): the Key Vault secret backend; a source this
    extension can read from, not compute. NONE.
  - `@webframp/azure-blob-datastore` (stable),
    `@webframp/azure-blob-datastore-bootstrap` (stable): a swamp datastore on
    Blob Storage. NONE.
  - `@webframp/azure/openai-usage` (stable), `@webframp/ai-usage` (stable),
    `@webframp/ai-research-mapper` (stable), `@webframp/cost-projection`
    (stable), `@twonines/cloud-cost-focus` (stable): usage and cost
    reporting; read-only. NONE.
  - `@dougschaefer/ms-graph` (stable), `@dougschaefer/purview` (stable):
    Microsoft Graph and Purview; not Azure compute. NONE.
  - `@randybias/azure-nsg` (beta): ours; the sibling network security group
    type. Not prior art.

Verdict: OVERLAP, justified. Worth filing upstream for `@dougschaefer/azure`:
vault or service-principal auth instead of `az login`, and taking the admin
password off argv in `azure-vm create`.
