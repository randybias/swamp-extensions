# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17 (lane/d2-k8svault, base lane/b2-k8s `073f868`): added
  `data_from_vault` for the item-7 workflow. It is a map of Secret key to
  `{vault, key}` names that the model resolves itself through the runtime's
  `context.vaultService` (a plain `{get, put}` object, not a factory), so a
  workflow can pass vault and key names where a dynamic map would not resolve in
  an expression. Exactly one of `data` / `data_from_vault` is required. Vault
  and key names are grammar-validated before any lookup; a failed lookup fails
  with a fixed message naming the vault and key only. Resolved values live in
  memory only and are bounded by the same total-byte limit. Tests drive a
  plain-object `{get, put}` context; a new `_lib/vault.ts` plus
  `_lib/vault_test.ts` covers the resolver.
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

## 2026-10-17: live e2e (supersedes the blocked matrix above)

Target: a k0s single node on `<vps2>` (k0s v1.36.4+k0s.1). kubeconfig and every
value by vault reference (`<vault>/<kubeconfig-key>`, written by k0s-cluster
`kubeconfig` with `store_in_vault`; data keys `<vault>/<key-a>`,
`<vault>/<key-b>`). No value was printed; value checks are boolean comparisons
against the known test strings. Receipt = first 16 hex of sha256 of the console
output with timestamps stripped. Cells 1-14 ran on lane/b2-k8s `073f868`; V1-V8
on lane/d2-k8svault `7dfcd38` (adds `data_from_vault`; every other code path is
unchanged from `073f868`).

| Cell                                 | Result | Detail                                                                            | Head      | Receipt          |
| ------------------------------------ | ------ | --------------------------------------------------------------------------------- | --------- | ---------------- |
| 1 apply (create)                     | PASS   | Secret exists with keys alpha, beta; cluster == vault y/y; value text in output 0 | `073f868` | 62a450cf5fbe97eb |
| 2 get                                | PASS   | metadata and key names only; value text in output 0                               | `073f868` | a1d61f4aace73b7a |
| 3 apply (idempotent)                 | PASS   | resourceVersion unchanged                                                         | `073f868` | b02ab2f33f272015 |
| 4 apply (update a key)               | PASS   | resourceVersion advanced; alpha equals the second vault value                     | `073f868` | c452391cef295ec3 |
| 5 sync after external delete         | PASS   | reports not_found                                                                 | `073f868` | 141d559d3aaa113a |
| 6 delete                             | PASS   | Secret gone (NotFound)                                                            | `073f868` | ea6dc7720264798b |
| 7 delete again (absent)              | PASS   | clean no-op                                                                       | `073f868` | 3354063d31db58d0 |
| 8 unreachable API (192.0.2.1)        | PASS   | typed "API server unreachable"; temp kubeconfigs left 0                           | `073f868` | c1c92fb1b6db2987 |
| 9 bad credential                     | PASS   | typed "Not authorized"; temp kubeconfigs left 0                                   | `073f868` | 233b8f5d01bf7f11 |
| 10 namespace absent                  | PASS   | typed "Namespace ... does not exist"                                              | `073f868` | 47e529547d54f328 |
| 11 invalid key name                  | PASS   | rejected by schema before kubectl                                                 | `073f868` | 04c68d2911b24a97 |
| 12 injection in name/namespace       | PASS   | 5 hostile values each in name and namespace, all rejected                         | `073f868` | 371c535439341f5d |
| 13 unknown context                   | PASS   | typed "kubectl failed"                                                            | `073f868` | d3f3b3cb1f1d16d0 |
| 14 residue                           | PASS   | no test Secret remains; leaked value text 0                                       | `073f868` | 99a17142bef22b8e |
| V1 apply data_from_vault             | PASS   | keys resolved from vault; cluster == vault y/y; value text in output 0            | `7dfcd38` | e9317aff916989c3 |
| V2 apply data_from_vault idempotent  | PASS   | resourceVersion unchanged                                                         | `7dfcd38` | 68133935eee9e043 |
| V3 missing vault key                 | PASS   | fixed "Could not read vault ... key ..." message                                  | `7dfcd38` | a045ed498571d768 |
| V4 missing vault                     | PASS   | fixed "Could not read vault ... key ..." message                                  | `7dfcd38` | 3f59931152523711 |
| V5 data and data_from_vault together | PASS   | schema: exactly one of data or data_from_vault is required                        | `7dfcd38` | b836b7c497f663a3 |
| V6 data_from_vault invalid key name  | PASS   | schema: invalid key rejected                                                      | `7dfcd38` | 1f9a14ce6fe46211 |
| V7 empty data_from_vault             | PASS   | schema: data_from_vault must not be empty                                         | `7dfcd38` | 85bfb4b3afd06a18 |
| V8 delete and residue                | PASS   | Secret removed; value text anywhere in receipts 0                                 | `7dfcd38` | 611496f412cac947 |

22/22 pass. Released on the beta channel.

## 2026-10-17: merge prep and known residuals (2026.10.17.1)

Review-clean (no unrefuted Critical/High). Gate 7 needed one comment-only
change: `swamp-quality-ignore deno-command` on the kubectl spawn in
`_lib/kubectl.ts`. Gate-8 report: `reviews/k8s-secret/7ec9b952….json`.
Dispositions: rename `delete` refuted (run ruling 1); `__proto__` loss in the
vault resolver refuted (`isDataKey` rejects `__proto__`). Residuals, all MEDIUM
unless noted, for a later release:

- Cleanup loop in `withKubectl` stops if the first temp-file remove throws a
  non-NotFound error (raised HIGH, downgraded: it fails loudly on a `0600`
  private file). Attempt every removal, then report.
- Field manager derives from the definition name, so two independent repos with
  the same definition name on the same Secret share it (raised HIGH, downgraded:
  operator naming collision).
- With no explicit `server` on the selected cluster, the state-id fingerprint
  digests the whole kubeconfig. Require and fingerprint an explicit server.
- A delete between apply and the follow-up observe records `present` with no
  keys.
- `data_from_vault` values are all resolved before the total-byte check; enforce
  the budget during resolution.
- The `.optional()` wrapper on `data` is not itself sensitive-marked (the inner
  record is).
- Cluster `server`, `proxy-url`, `tls-server-name` accept any scalar.
- LOW: `apply` description is four sentences; `digestHex` duplicates
  `sha256Hex`; `isVaultName`/`isVaultKey` are identical.

## Prior art

Prior art terms: kubernetes, k8s, secret

Registry search on stable and beta (`swamp extension search`, whole-word matches
in the package name or description). `kubernetes` is added to the package name's
own segments because the first-party toolkit does not use the abbreviation in
its name or description.

- kubernetes:
  - `@swamp/kubernetes` (stable): the first-party toolkit; its `secret` type has
    list, get, create, update and delete through the Kubernetes client API with
    `data` marked sensitive. `get` returns the decoded values into stored data;
    create and update are separate calls (create fails when the Secret exists),
    so there is no idempotent ensure or sync; the kubeconfig comes from a
    context or path, not a validated vault reference. OVERLAP, justified: values
    here reach kubectl only on stdin and are never returned, sync is idempotent,
    and the kubeconfig is validated default-deny.
  - `@john/k8s` (stable): the same code base as the first-party toolkit at an
    earlier revision (15 types, 13 workflows), with the same `secret` semantics.
    OVERLAP, justified for the same reasons.
  - `@bixu/k8s/exec` (stable): exec into pods; no Secret management. NONE.
  - `@twonines/k8s-fleet` (stable): read-only health across kubeconfig contexts.
    NONE.
  - `@rjeschmi/helm-chart` (stable): Helm install, upgrade and uninstall;
    Secrets only as a side effect of a chart. NONE.
  - `@sntxrr/scaleway-kapsule` (stable): managed cluster lifecycle through the
    Scaleway API; no in-cluster objects. NONE.
  - `@shelson/k3s` (stable): installs k3s on a host; no Secret management. NONE.
  - `@webframp/aws/pricing` (stable), `@svendowideit/sudo` (stable): word
    matches only. NONE.
  - `@randybias/k0s-cluster` (beta), `@randybias/kubevirt` (beta): ours; a
    cluster installer and a KubeVirt operator, neither manages Secrets. Not
    prior art.
- k8s: no whole-word hits beyond the packages above.
- secret:
  - Vault backends and secret stores: `@sntxrr/scaleway-secret-manager`
    (stable), `@sntxrr/scaleway-secret-manager-vault` (stable),
    `@webframp/griptape/secrets` (stable), `@swamp/gcp-sm` (stable),
    `@swamp/azure-kv` (stable), `@swamp/aws-sm` (stable),
    `@webframp/hashicorp-vault` (stable), `@swamp/1password` (stable),
    `@dataverket/sops` (stable), `@zocc/sops-age` (stable),
    `@svendowideit/systemd-creds` (stable and beta). Each is a store this
    extension reads from through the vault; none writes a Kubernetes Secret.
    NONE.
  - `@thomas/woodpecker` (stable), `@thomas/forgejo` (stable): CI and forge
    secrets through their own APIs; not Kubernetes. NONE.
  - `@mgreten/notification-outbox` (stable), `@sntxrr/scaleway-object-storage`
    (stable), `@kneel/super-productivity` (beta), `@kneel/jlcpcb` (beta),
    `@svendowideit/test-factory` (beta): word matches only. NONE.
  - `@randybias/secret-file` (beta), `@randybias/server-stack` (beta): ours; the
    host-file counterpart and the stack that composes this extension. Not prior
    art.

Verdict: OVERLAP, justified. Worth filing upstream: an idempotent `ensure` or
sync method and a metadata-only `get` for `@swamp/kubernetes`'s `secret` type.
