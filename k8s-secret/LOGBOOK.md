# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17: initial model. Evaluated `@swamp/kubernetes` 2026.10.13.1 first
  (its `secret` type is 2026.08.01.1; `@john/k8s` ships the same types): the
  Secret type takes literal `data` arguments, returns decoded values from
  `get`/`create`/`update`, updates by read-then-replace (no hash no-op), and
  exposes `delete` as a plain model method. That is the gap this extension
  fills; recommend building rather than adopting.
- 2026-10-17 (lane/d2): adopted the offline-green base from lane/b2 commit
  `9e136d4` rather than drafting cold. Hardened it: per-key hashes now digest
  the stored bytes (binary-safe) instead of a lossy UTF-8 decode, a malformed
  `kubectl -o json` body is a typed error that never echoes the payload, the
  README gained the `Install` section and a two-instance example, and two
  leak-regression tests were added.
- Design: manifest streamed on stdin to
  `kubectl apply --server-side
  --force-conflicts -f -`, so removed keys owned
  by this field manager are pruned and keys added by others are kept. No-op
  detection compares the desired keys and values against the keys this field
  manager owns (read from `metadata.managedFields`), so an externally-added key
  is preserved and a dropped owned key is pruned. kubeconfig goes through a
  `0600` temp file because stdin carries the manifest.
- 2026-10-17 (lane/d2): review ledger (codex astra + terra; ocr sonnet5/glm
  timed out at the 10m wall, to rerun on this revision). Dispositions:
  - REFUTED: rename `delete` to `remove`. Swamp tombstones the whole model only
    for `kind: "delete"`, not for the method name; cherry-servers ships a method
    named `delete` with `kind: "action"`, verified live. Kept as is.
  - HIGH-1: remote `kubectl` stderr/exception text is no longer returned.
    `classify` returns fixed typed messages and the spawn-failure path uses a
    fixed message; `scrub` was removed. Base64 forms of a value can no longer
    reach an error or `--json` output.
  - MEDIUM-2: the whole `data` record is `.meta({ sensitive: true })`, not only
    its values.
  - MEDIUM-3: `writePrivateTempFile` removes the temp kubeconfig if `chmod` or
    the write fails after creation; covered by an injected-IO test.
  - MEDIUM-4: state ids now combine a nonsecret cluster fingerprint (sha256 of
    the kubeconfig server URL) with the context/namespace/name and a 16-hex
    digest, so `a/b` and `a_b`, or the same context name in two clusters, no
    longer collide.
  - MEDIUM-5: no-op compares only desired keys against this field manager's
    owned keys; external keys are preserved and no longer force a rewrite, and
    an owned key that is no longer given is pruned (tests for both).
  - MEDIUM-6: a raw per-value sha256 is neither returned nor stored (it is
    brute-forceable for low-entropy secrets). Comparison hashes live only
    in-process. This intentionally supersedes the spec's `data_sha256` output.
  - MEDIUM-7: `data` is bounded to 256 keys and 1 MiB total UTF-8 bytes before
    kubectl is spawned.
  - MEDIUM-8: `apply`'s description now starts with DESTRUCTIVE and states that
    it prunes owned keys and force-overwrites conflicts.
  - LOW: the model gained a type description; README examples carry no `--json`.
- 2026-10-17 (lane/d2): review round 3 (codex astra + terra on 56970c4).
  Dispositions:
  - HIGH-1 kubeconfig exec-auth local RCE: a new `_lib/kubeconfig.ts` parses the
    kubeconfig with `npm:yaml` and `maxAliasCount: 100` (so alias-expansion
    input is refused, not expanded) and rejects any `users[].user.exec` or
    `auth-provider` credential plugin. The check runs inside the kubeconfig
    field's schema, before any kubectl spawn, so a hostile kubeconfig cannot run
    a local command. Only static credentials are accepted.
  - MEDIUM-2: the state-id fingerprint now resolves the selected context (or
    `current-context`) to its cluster and server from the parsed kubeconfig, so
    two contexts that share a server no longer collide.
  - MEDIUM-3: README no longer mentions `--json`; it states that kubeconfig and
    data values are vault references or stdin only.
  - REFUTED (held): rename `delete` to `remove`.
  - LOW: removed `totalDigest`/`total`; hashes are plain per-key maps. Extracted
    `persistState` for the shared state write. Dependency added:
    `npm:yaml@2.9.1` (alias-safe parse).
- 2026-10-17 (lane/d2): review round 4 (codex astra + terra on 264c595).
  Dispositions:
  - HIGH file-path credential exfiltration: `checkKubeconfig` now default-denies
    every user field except `client-certificate-data`, `client-key-data`,
    `token`, `username` and `password`, and every cluster field except `server`,
    `certificate-authority-data`, `insecure-skip-tls-verify`, `tls-server-name`,
    `proxy-url` and `disable-compression`. `tokenFile`, `client-certificate`,
    `client-key` and `certificate-authority` are rejected by name (one test per
    key); unknown fields are rejected too. A caller kubeconfig can no longer
    make kubectl read a local host file and send it as a credential.
  - MEDIUM shared field manager: the server-side apply field manager is now
    derived per definition (`swamp-k8s-secret-<sha256(name)[0:12]>`), so two
    definitions that target the same Secret do not prune each other's keys.
  - LOW: the manifest description now says state carries metadata and key names,
    not hashes.
  - REFUTED (held): rename `delete` to `remove`.
- Real-swamp check with a stub `kubectl` on PATH (not a live cell): vault
  expressions in `--input` (including inside `data:json=`) resolve; kubectl argv
  carries no value, stdin carries the base64 manifest, output and state hold key
  names only, no temp kubeconfig is left in the temp directory, and the value
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
- 2026-10-17 (round 5, CRITICAL): the `yaml` package (YAML 1.2) reads `<<` as a
  plain key but kubectl's loader applies the merge, so a merge could hide an
  `exec` plugin or `tokenFile` from the validator and kubectl would run it.
  Reproduced with kubectl 1.35.3. Fix: merge keys and tags are refused up front;
  then `kubectl config view --raw -o json` (applies merges exactly as kubectl
  will; does not authenticate, run plugins or read credential files, unlike
  `--flatten`) produces the canonical document, which is validated with
  default-deny at the top level, per entry and for user, cluster and context
  fields, and is the only thing written to the kubeconfig file used for every
  later call. Also `__proto__` is no longer an accepted data key and the key
  maps are null-prototype objects. `insecure-skip-tls-verify` stays the caller's
  choice. Tests include a run against the real kubectl when it is available.
