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
