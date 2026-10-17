# Spec: `@randybias/k8s-secret`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone writing Kubernetes Secrets from a vault.

Q3: Yes. `k8s-secret` names the system (Kubernetes) and the resource (a Secret); short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `k8s-secret` as a Kubernetes Secret writer, which is what it does, and guesses wrong about nothing.

Status: implemented and published (beta); the next-version scope is at the end.
Not clean-room (net-new). RFC 2119 keywords.

## 1. Purpose

Write a Kubernetes `Secret` into a cluster from values supplied as vault
references, delivered to `kubectl` over **stdin** — never on argv, never in a
file left on disk, never in `--json` output. Self-contained: depends only on a
kubeconfig and a reachable API server, not on the SSH transport.

## 2. First task: evaluate, do not duplicate

`@swamp/kubernetes` (v2026.10.13.1, 16 model types) and `@john/k8s` likely ship
a Secret type already. Before writing code, pull `@swamp/kubernetes`, run
`swamp model type describe` on its Secret type, and report:

- Does it create/update a Secret from **vault values over stdin** with no
  plaintext on argv or disk? If yes and it is idempotent with a clean delete,
  **recommend adopting it** and stop — do not republish a redundant model.
- If it only takes literal data, or writes the secret via a temp manifest file,
  or exposes data in output, that is the gap this item fills: a focused,
  secret-safe `@randybias/k8s-secret`.

Escalate the adopt-vs-build call. The contract below is for build.

## 3. Model contract

- **Type** `@randybias/k8s-secret`. CalVer == manifest version.
- **`globalArguments` empty.** Every method takes its target (kubeconfig,
  context, namespace, name) as arguments; one definition serves any cluster.
- State keyed by `{context}/{namespace}/{name}` (instance values), never the
  definition name.
- **Factory with overridable deps** (kubectl spawner, clock) — unit tests spawn
  no process and reach no API server.

### Methods

| Method | Kind | Description |
|---|---|---|
| `apply` | action | Create or update an `Opaque` (or typed) Secret from the given keys. Idempotent: re-apply with identical data is a no-op by data hash. Returns `{name, namespace, type, keys, resource_version, data_sha256}` — **never the values**. |
| `get` | — | READ-ONLY. Return the Secret's metadata and key names and a sha256 of each value; never the decoded values. |
| `sync` | — | READ-ONLY. Reconcile recorded state with the cluster; `deleted`→`not_found`. |
| `delete` | action | DESTRUCTIVE. Delete the Secret. `kind: "action"` (a model `delete` method tombstones the whole model — cherry-servers lab). |

### Inputs

- `kubeconfig` — `.meta({ sensitive: true })`, vault ref, delivered to kubectl
  via `KUBECONFIG` pointing at a `umask 077` temp file written from the vault
  value and deleted in a `finally`, or over stdin where kubectl supports it.
- `context` — string, optional (default: current-context).
- `namespace` — DNS-1123 label, required.
- `name` — DNS-1123 subdomain, required.
- `type` — default `Opaque`; allow e.g. `kubernetes.io/tls` etc.
- `data` — a map of key → **vault reference**, each value `.meta({ sensitive:
  true })`. Keys validated against `[-._a-zA-Z0-9]+`. Values reach kubectl only
  via `kubectl create secret ... --from-file=/dev/stdin` style stdin or a
  server-side-apply manifest streamed on stdin — never `--from-literal` (argv).
- Strict `z.object`, no `.passthrough()`.

### Outputs

Metadata + per-key sha256 only. The README example and every test MUST show
vault refs, never a literal secret value.

## 4. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| API server unreachable | Typed error, no secret in message. |
| Bad kubeconfig / unauthorized | Typed error; temp kubeconfig still deleted. |
| Namespace absent | Typed error naming the namespace. |
| Invalid secret key name | Rejected by schema before any kubectl call. |
| Re-apply identical data | No-op (data_sha256 unchanged), resource_version may be unchanged. |
| delete already-absent | Clean no-op. |
| Injection in name/namespace/key | Rejected by grammar; never reaches a shell unquoted. |

## 5. Tests (offline, increasing risk)

1. Schema/secret/license: every `data` value and `kubeconfig` sensitive; no
   value appears in any output type.
2. Pure mapping: the kubectl argv / manifest built from inputs contains **no
   secret value and no `--from-literal`**; stdin carries the data.
3. Failure + adversarial: §4 rows; injection on name/namespace/context/keys.
4. A regression test greps fixtures and output for anything that looks like a
   real token / base64 secret.
5. Packaging.

Fixtures synthetic: `example.com`, `.test`, placeholder base64.

## 6. Live e2e matrix

Target: a throwaway single-node cluster. **Provisioning is a dependency** — the
cleanest source is `k0s-cluster` once it is live, giving a kubeconfig;
until then, mark live cells `blocked` on the k0s target, not `skip`. (A kind/k3s
single node on the shared VPS is an acceptable interim target if the maintainer
approves; record which was used.)

| Cell | Expected |
|---|---|
| apply (create) | Secret exists, keys match, values never printed |
| get | metadata + per-key sha256, no values |
| apply (idempotent) | no-op by data hash |
| apply (update a key) | new resource_version, new data_sha256 |
| sync after external delete | `not_found` |
| delete | gone |
| delete again | clean no-op |
| unreachable API | typed error |
| bad credential | typed error, temp kubeconfig deleted |

Receipts into `k8s-secret/LOGBOOK.md`. No `stable` while any cell is
`untested`/`skip`.

## 7. Carry-overs

- Never capture `--json` of a run carrying the kubeconfig or data (lab 3555).
- Delete the temp kubeconfig in a `finally`, even on error.

## Next version scope: next

Next `k8s-secret` version (public, beta).

- Residual Mediums: the temp-file cleanup loop stops at the first non-NotFound
  error; the field manager derives from the definition name, so same-named
  definitions in separate repos share it (key it by an instance value); with no
  explicit cluster server the state-id fingerprint hashes the whole kubeconfig;
  a delete between `apply` and the follow-up observe records present with no
  keys; `data_from_vault` values are all resolved before the total-byte check;
  the optional wrapper on `data` is not itself sensitive-marked; cluster server,
  proxy-url and tls-server-name accept any scalar.
- Live on the cluster the `kubevirt` version uses.
