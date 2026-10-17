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
