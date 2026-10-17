# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17: initial model. Evaluated `@swamp/kubernetes` 2026.10.13.1 first:
  its Secret type takes literal `data` arguments, returns decoded values from
  `get`/`create`/`update`, updates by read-then-replace (no hash no-op), and
  exposes `delete` as a model method. That is the gap this extension fills.
  Drafted by hand rather than with pi: the surface is small and every line is
  secret-handling.
- Design: manifest streamed on stdin to
  `kubectl apply --server-side
  --force-conflicts -f -`, so removed keys owned
  by this field manager are pruned and keys added by others are kept. No-op
  detection compares type and per-key sha256 of the live Secret, not an
  annotation, so external drift is corrected. kubeconfig goes through a `0600`
  temp file because stdin carries the manifest.
- Real-swamp check with a stub `kubectl` on PATH (not a live cell): vault
  expressions in `--input` (including inside `data:json=`) resolve; kubectl argv
  carries no value, stdin carries the base64 manifest, output and state hold
  hashes only, no temp kubeconfig is left in the temp directory, and the value
  appears nowhere under the repo's `.swamp/`.
- Live matrix (no cluster yet; waiting on a k0s target):
  - apply (create): blocked
  - get: blocked
  - apply (idempotent): blocked
  - apply (update a key): blocked
  - sync after external delete: blocked
  - delete: blocked
  - delete again: blocked
  - unreachable API: blocked
  - bad credential, temp kubeconfig deleted: blocked
