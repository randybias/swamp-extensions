# Spec: `@randybias/k0s-cluster`

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone installing k0s on a Linux host.

Q3: Yes, with one caveat. `k0s-cluster` names the system (k0s) and is short; it installs and operates k0s on one host. Naming audit verdict: keep, tighten the README (`k0s-node` would be more exact but has dependents).

Q4: Not applicable (public and general).

Q5: Mostly. A stranger guesses a k0s installer, which is right, but may expect multi-node scope, which `k0s-multinode` covers; the README says "one node" from the next version.

Status: implemented and published (beta); the next-version scope is at the end.
Not clean-room (net-new). RFC 2119 keywords.

## 1. Purpose

Install and operate a [k0s](https://docs.k0sproject.io) Kubernetes cluster on a
Linux host reached over SSH: a **SHA-pinned** k0s binary, a rendered `k0s.yaml`,
bring-up, wait-for-Ready, admin kubeconfig out, and reconciled **manifest stacks**
and **Helm charts**. Registry has no k0s extension (search empty) — net new.
This cluster is also the live-test target for `k8s-secret`.

## 2. Transport

Vendor the canonical `_lib/ssh.ts` from `@randybias/ssh-host`,
byte-identical. All remote exec/upload goes through it (strict host-key policy
required; key over stdin). Until that helper is reviewed, build against the
injectable spawner seam; the final copy is vendored in afterwards.

## 3. Model contract

- **Type** `@randybias/k0s-cluster`. CalVer == manifest version.
- **`globalArguments` empty.** Every method takes its SSH target + inputs per
  call. One definition serves any host/cluster. State keyed by `host` (or a
  caller `cluster_name`), never the definition name.
- **Factory with overridable deps** (transport spawner, binary fetcher, clock,
  sleep). Unit tests render config and assemble argv only — no download, no host.

### Methods

| Method | Kind | Description |
|---|---|---|
| `render_config` | — | READ-ONLY. Return the `k0s.yaml` text from inputs (version, API SANs, CIDRs, manifest stacks, Helm extensions). Deterministic. |
| `install` | action | Idempotent. Fetch the pinned k0s binary, **verify SHA256 before use** (refuse on mismatch), upload it, write `k0s.yaml`, install the role (`controller+worker` single-node by default), start the service. Re-run adopts the running install, no second node. Returns `{host, k0s_version, role, config_sha256}`. |
| `wait_ready` | action | READ-ONLY semantics. Poll until the node is `Ready` and system pods are running, up to `ready_timeout_s`. Returns `{ready, node, system_pods}`. |
| `kubeconfig` | action | Fetch the admin kubeconfig (`k0s kubeconfig admin`). Returns it as a **sensitive** value delivered over stdin; it MUST NOT appear in `--json` stdout or logs. Also returns a sha256 and the server URL only. |
| `apply_manifests` | action | Idempotent. Place a named manifest stack under the k0s manifest-deployer dir; k0s applies it. Returns `{stack, files, applied}`. |
| `apply_helm` | action | Idempotent. Reconcile the declared Helm extensions in `k0s.yaml` (chart, repo, version, namespace, values) and let k0s's Helm extension apply them. Returns `{charts[]}`. |
| `get` | — | READ-ONLY. k0s version, node status, kubeconfig presence, reconciled stacks/charts. |
| `sync` | — | READ-ONLY. Reconcile recorded state with the host. |
| `reset` | action | DESTRUCTIVE. `k0s stop` + `k0s reset`. `kind:"action"`. Re-run is a clean no-op. |

### Inputs (selected)

- `ssh` — transport target block (host, user, port, `host_key_policy` + pinned
  `host_keys`, key over stdin, sensitive).
- `k0s_version` — pinned, e.g. `v1.31.2+k0s.0` (string, required).
- `k0s_binary_sha256` — **required** hex digest; install refuses if the
  downloaded binary does not match. No install from an unverified binary.
- `k0s_download_url` — optional override (default: the official release URL for
  the version + host arch); still SHA-checked.
- `role` — `single` (controller+worker, default) | `controller` | `worker`.
- `api_sans[]`, `pod_cidr`, `service_cidr` — validated CIDRs / hostnames.
- `manifests[]` — `{name, files:[{path, content}]}`; names are DNS-1123 labels.
- `helm[]` — `{chart, repo, version, namespace, values(object)}`.
- Strict `z.object`, no `.passthrough()`. kubeconfig output marked sensitive.

### Outputs

Typed objects as above. Kubeconfig value never in output stdout/logs — only its
sha256 and server URL.

## 4. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| Binary SHA mismatch | Refuse before install; no binary executed; typed error. |
| Download failure / 404 | Typed error naming the URL (no secret). |
| Node never Ready | `wait_ready` returns `ready:false` after timeout; typed, not a hang. |
| install idempotent | Re-run adopts running node; no second install. |
| apply_manifests idempotent | Re-apply identical stack = no change. |
| Helm chart not found / bad version | Typed error from reconcile; partial state surfaced in `get`. |
| reset already-reset | Clean no-op. |
| kubeconfig not leaked | kubeconfig absent from any `--json` stdout, logs, fixtures. |
| Injection in names/version/url | Rejected by grammar; argv-quoted. |

## 5. Tests (offline, increasing risk)

1. Schema/secret/license: kubeconfig sensitive; strict object.
2. Pure mapping: golden `k0s.yaml` renders (single-node, with manifest stack,
   with Helm extension); SHA-verify logic (match→proceed, mismatch→refuse);
   argv has no secret, no shell-metachar interpolation.
3. Failure + adversarial: §4 rows; injection on every remote-bound input.
4. A regression test greps output/fixtures for anything kubeconfig-shaped.
5. Packaging.

Fixtures synthetic: RFC 5737 IPs, `example.com`, a clearly-fake SHA256 and a
placeholder kubeconfig.

## 6. Live e2e matrix (shared throwaway VPS, ≥2 GB)

Target: a shared hourly throwaway VPS.

| Cell | Expected |
|---|---|
| render_config | matches golden for the live inputs |
| install (SHA ok) | k0s running, correct version |
| install bad-SHA (negative) | refuses, nothing installed |
| wait_ready | node Ready, system pods up |
| kubeconfig | usable kubeconfig fetched, value never printed |
| apply_manifests | a trivial stack (a namespace + configmap) appears in-cluster |
| apply_manifests idempotent | no change on re-run |
| apply_helm | a small chart (e.g. a lightweight test chart) reconciled |
| get / sync | reflect real cluster state |
| install idempotent | no second install |
| reset | cluster gone |
| reset again | clean no-op |

On `kubeconfig` success, **hand the kubeconfig (via vault, not stdout) to the
`k8s-secret` live tests** — this unblocks that item. Receipts into
`k0s-cluster/LOGBOOK.md`. No `stable` while any cell `untested`/`skip`.

## 7. Carry-overs

- Mutating verbs are `kind:"action"`.
- Never capture `--json` of a run carrying the SSH key or the kubeconfig (lab 3555).
- Pin the exact k0s version in the README tested-version line only after a live pass.

## Next version scope: next

Next `k0s-cluster` version (public, beta).

- Re-vendor the canonical transport (`8f132c4329c9e64bed686731cd5a0e02980194ea`).
- Feature: host-side sha-verified binary download (`binary_source:
  host-download`, pinned URL and SHA-256; the default above 50 MB), so the
  binary never crosses a lossy link through swamp.
- Residual Mediums: drift is always unknown for an install with Helm values; a
  failed state write or old-binary cleanup after a successful upgrade blocks
  later upgrades until removed by hand; `reset` runs whatever binary sits at the
  install path even when its digest differs; `/etc/k0s` is removed wholesale,
  operator drop-ins included; a failed read of an existing config is treated as
  absence; the private-directory helper follows directory symlinks; observation
  helpers turn some non-zero exits into empty results; the ExecStart classifier
  matches too loosely; `kubeconfig` is described READ-ONLY although
  `store_in_vault` writes a key; `upload` returns the content hash.
- README: say "one node" (naming audit, Q5).
- Live: download path, upgrade, reset, on a small server.
