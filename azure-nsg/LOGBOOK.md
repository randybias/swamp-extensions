# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17: initial release. Built beside `@randybias/azure-vm` because a
  registry review found no first-party Azure NSG model and the third-party
  `@dougschaefer/azure` has real gaps for this repo's standard: its `delete`
  methods have no `kind: "action"` (a literal `delete` tombstones the whole
  model) and it authenticates only through an out-of-band `az login`. This
  extension calls Azure Resource Manager REST directly with a service principal.
- Auth is OAuth2 client credentials: the client secret is sent only in the token
  POST body, the token lives in memory for one call, and the fetch seam is
  injectable so tests open no socket. Every secret field is sensitive-marked.
- `delete`, `ensure_rule`, `remove_rule` and `apply_rule_set` are all
  `kind: "action"`. `apply_rule_set` plans first (create, update, unchanged,
  undeclared) and only writes when `apply` is true; it never deletes undeclared
  rules.
- `_lib/arm.ts` and `_lib/validate.ts` are shared byte-identical with
  `@randybias/azure-vm`.
- Live testing is **blocked**: Randy must confirm an Azure subscription and a
  service principal scoped to a throwaway resource group, and the account must
  be tagged for the run. Live cells are marked blocked in the run matrix, not
  skip. Everything here is unit/contract tested against a scripted fetch.
- 2026-10-17 review round 1: `buildRuleBody` now uses Azure's singular
  `sourceAddressPrefix`/`destinationAddressPrefix`/`sourcePortRange`/
  `destinationPortRange` for a single value (and for `*` and service tags), and
  the plural fields only for multi-element lists, which must be all CIDRs or
  ranges; `ruleMatches` compares either form. `ensure_rule`, `remove_rule` and
  `apply_rule_set` poll rule writes to `Succeeded` and deletes to gone before
  recording state. `apply_rule_set` records priority collisions (duplicate rule
  name or priority in the declared set, or a declared priority held by an
  undeclared or swapped rule) and, with `apply` true, writes the plan and
  refuses without issuing any PUT, so a partial converge cannot happen. The
  model and manifest descriptions no longer claim a `create` method, which does
  not exist. Shared `_lib/arm.ts` error parsing fixed as in
  `@randybias/azure-vm`.
- 2026-10-17 review round 2: `apply_rule_set` now builds every desired body
  before any PUT, so a grammar or plural-list violation is recorded in the plan
  (as `invalid rule <name>: ...` in `collisions`) and refuses the whole set with
  zero PUTs. `fieldList` prefers a non-empty plural array, else the singular
  string, because a real ARM read returns both forms (a set singular beside an
  empty plural array); `toRuleState` stores the normalized list via `fieldList`,
  so a single-value rule is recorded as the value, not `[]`. `awaitRule` now
  waits for `Succeeded` **and** a live match (and fails on `Failed`/`Canceled`),
  and `portField` rejects `*` in a multi-element port list. Tests add the real
  ARM read-back shape, the invalid-later-rule zero-PUT case, the `*`-in-plural
  case, and a Failed settle.

## 2026-10-17 live e2e: blocked

Reason: Azure subscription + service principal scoped to a throwaway resource
group not yet provided (Randy). Every cell below is `blocked`, not skipped; run
them through `swamp model method run` against a throwaway resource group before
promoting to stable. Unit/contract tests (scripted fetch, including the real ARM
singular-plus-empty-plural read-back shape) cover every path.

| Cell                                                  | Result  |
| ----------------------------------------------------- | ------- |
| 1 get / sync existing NSG                             | blocked |
| 2 ensure_rule create                                  | blocked |
| 3 ensure_rule identical re-run, changed false, no PUT | blocked |
| 4 ensure_rule update, state from settled read-back    | blocked |
| 5 remove_rule                                         | blocked |
| 6 remove_rule again, clean no-op                      | blocked |
| 7 apply_rule_set plan only (apply false), no writes   | blocked |
| 8 apply_rule_set apply true converges                 | blocked |
| 9 apply_rule_set re-run, all unchanged                | blocked |
| 10 apply_rule_set priority collision, zero PUTs       | blocked |
| 11 apply_rule_set valid-then-invalid list, zero PUTs  | blocked |
| 12 delete NSG, delete again no-op                     | blocked |
| 13 bad client secret, typed AAD error redacted        | blocked |

## Review ledger: final verify (codex astra + terra, delta 85a59da..1afafcc) and merge prep

- Round 3 delta: 0 Critical/High from either seat. Confirmed at 1afafcc: every
  desired rule body is built before any PUT (valid-then-invalid list issues zero
  PUTs, tested); `fieldList` prefers a non-empty plural else the singular,
  tested on the real ARM read-back shape; `awaitRule` requires `Succeeded` and a
  live match and fails on `Failed`/`Canceled`; `*` is refused in a multi-element
  port list.
- Refuted (run rulings): rename `delete` (kind `action` is correct); priority
  collisions are per direction; no armed-revert on rule changes (recovery is the
  ARM control plane).
- Known residuals for the next version: MEDIUM rule writes poll the rule GET,
  not the `Azure-AsyncOperation` URL (an async failure that leaves the old rule
  surfaces as a timeout, not a typed failure); MEDIUM rule `description` has a
  length bound but no character allowlist (sent as JSON, not a shell); MEDIUM
  deleting the NSG does not mark its recorded `rule` resources deleted; MEDIUM
  IPv6 prefix validation accepts some malformed forms (shared `_lib`); LOW a
  safe ordered priority swap is refused (conservative); LOW tightness
  (`values.includes("*")`, duplicated grammars and arg interfaces).

## Prior art

Registry search on stable and beta (`swamp extension search`, whole-word
matches in the package name or description) for `azure-nsg`, `azure` and
`nsg`.

- azure-nsg, nsg: no hits.
- azure:
  - `@dougschaefer/azure` (stable): its `azure-nsg` type has list, get,
    sync, create and delete, rule CRUD, and `applyRuleSet`, which converges an
    NSG onto a declared rule set with a plan step, acts only when
    `dryRun=false` and prunes undeclared rules only when `pruneUndeclared` is
    set. That is functionally the same idea as this extension. It relies on
    the ambient `az login` session with no vault-wired service principal.
    OVERLAP, weakly justified: the justification rests only on the transport
    and auth model (ARM REST with a vault service principal, no `az`). If
    `az login` were acceptable, theirs would do the job.
  - `@nedbellavance/azure-ssh-key` (stable): Azure sshPublicKeys resources
    through the az CLI. NONE.
  - `@rkcoleman/azure-containers` (stable), `@rkcoleman/azure-app-service`
    (stable): Container Apps and App Service over the az CLI. NONE.
  - `@swamp/azure-kv` (stable): the Key Vault secret backend. NONE.
  - `@webframp/azure-blob-datastore` (stable),
    `@webframp/azure-blob-datastore-bootstrap` (stable): a swamp datastore on
    Blob Storage. NONE.
  - `@webframp/azure/openai-usage` (stable), `@webframp/ai-usage` (stable),
    `@webframp/ai-research-mapper` (stable), `@webframp/cost-projection`
    (stable), `@twonines/cloud-cost-focus` (stable): usage and cost
    reporting; read-only. NONE.
  - `@dougschaefer/ms-graph` (stable), `@dougschaefer/purview` (stable):
    Microsoft Graph and Purview; not Azure networking. NONE.
  - `@randybias/azure-vm` (beta): ours; the sibling compute type. Not prior
    art.

Verdict: OVERLAP, weakly justified. Worth filing upstream: vault or
service-principal auth for `@dougschaefer/azure`, which would remove most of
the reason to keep this extension.
