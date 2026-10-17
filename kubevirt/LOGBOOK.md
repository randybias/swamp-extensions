# `@randybias/kubevirt` LOGBOOK

Maintainer notes. Not packaged with the extension.

## Scope

Clean-room build of the P2 KubeVirt extension from the approved spec. One
extension, two model types: `@randybias/kubevirt` (the operator install) and
`@randybias/kubevirt-vm` (one VirtualMachine). Everything is `kubectl` against
the API; there is no SSH path.

Inputs were the approved spec, this repo, and public KubeVirt/CDI/Kubernetes
documentation only. No prior implementation, ex-employer repo, archive or
shared-docs material was read.

## Vendored transport (byte-identical)

`k8s-secret`'s reviewed kubeconfig and kubectl helpers are vendored unchanged; a
change they need goes back to `k8s-secret` first.

| File                      | git blob                                   |
| ------------------------- | ------------------------------------------ |
| `_lib/kubeconfig.ts`      | `05f20032da5eaf8af89075d76bef9645e8630eba` |
| `_lib/kubeconfig_test.ts` | `0c075519bcc1a137d30644acc16875535ca1a488` |
| `_lib/kubectl.ts`         | `530011d3274ff5826d36d855adb26e50e1b509df` |
| `_lib/kubectl_test.ts`    | `9d13379ae0d06bfdce872975c98d71c44d956911` |
| `_lib/vault.ts`           | `3bd4985aa6e2940ddbebf11e9e18141983a8f030` |
| `_lib/vault_test.ts`      | `aea2f49dce127ba10e97af083e87b66a22046159` |

`_lib/k8s.ts` is the KubeVirt-specific layer: it reuses the vendored
`withKubectl` (and its temp-file `finally`), and adds the cluster fingerprint,
field manager, formatters/grammars, manifest fetch + SHA verify, typed errors
and a bounded poll.

## Decisions for Randy review

1. **`virtctl` or kubectl-only — took the spec's recommendation.** No second
   pinned binary. `start`/`stop` set `spec.runStrategy`; `restart` calls
   `PUT /apis/subresources.kubevirt.io/v1/namespaces/{ns}/virtualmachines/{name}/restart`
   through `kubectl replace --raw -f -` with an empty body on stdin. If that PUT
   fails on a live cluster, the fallback is a SHA-pinned `virtctl` dependency.
2. **Component images.** Accepted tag pinning via the SHA-pinned operator
   manifest; digest env overrides are not implemented. Left as an explicit open
   question in the README and spec, not silently claimed.
3. **One extension, two types.** As drafted: `@randybias/kubevirt` and
   `@randybias/kubevirt-vm` in one directory and one manifest.
4. **`manifest_base_url` semantics.** A single optional HTTPS mirror prefix that
   shadows the GitHub host and mirrors the release-download path layout: the
   effective URL is `<base>/<org>/<repo>/releases/download/<tag>/<asset>`,
   default base `https://github.com`, asset `kubevirt-operator.yaml` and
   `cdi-operator.yaml`. It applies to both KubeVirt and CDI.
5. **`cluster_fp`.** First 16 hex of sha256 over the selected context's server
   URL, normalized to scheme + lowercased host + explicit port. This follows the
   spec's key format (`{fp}/kubevirt`, `{fp}/{namespace}/{name}`) and uses the
   vendored parser for the facts; it is deliberately not the vendored 12-hex
   `clusterFingerprint` (which hashes the raw server text), because the spec
   fixes 16 hex and the normalized form.
6. **`kvm_nodes` source.** A node is counted as KVM-capable when it carries the
   node label `kubevirt.io/kvm=true`; `schedulable_nodes` uses
   `kubevirt.io/schedulable=true`. **Must be confirmed in the first live cell**;
   if the pinned KubeVirt release names the label differently, only that mapping
   changes.
7. **CDI custom resource.** `install` applies the CDI operator manifest only
   (the spec's "optionally the same for CDI"), then reads the `CDI` CR for its
   `Available`/observed version. It assumes the release asset carries the CDI
   CR; **to confirm live.** If it does not, a rendered minimal CDI CR is the
   fix, and `render_cr`/`install` would gain a CDI branch.
8. **Timeouts.** `install`/`upgrade` default 600 s, operator `wait_ready` 300 s,
   VM `wait_ready` 600 s, `stop` grace 120 s; all bounded 10–3600 s.
9. **`uninstall` re-fetches.** Deleting the operator manifest's objects needs
   the manifest, so `uninstall` takes the same version + SHA inputs as `install`
   and re-verifies before `kubectl delete -f -`. The CDI branch runs only when a
   stored state record shows CDI was installed.

## Failure modes covered offline

| Mode                                 | Test                                                   |
| ------------------------------------ | ------------------------------------------------------ |
| Manifest SHA mismatch                | `manifest_mismatch`; no apply spawned                  |
| Manifest 404 / empty                 | `manifest_fetch`; URL named, no body echoed            |
| Different version installed          | `version_conflict`; no fetch, no apply                 |
| Downgrade / minor skip               | `version_skew`; no apply                               |
| `use_emulation:false`, no `/dev/kvm` | `kvm_nodes: []`; VM `wait_ready` `ready:false`         |
| CR never Deployed                    | `wait_ready` `ready:false` after timeout, never throws |
| VM source both / neither             | rejected by schema                                     |
| Tag-only container image             | rejected by schema                                     |
| `delete`/`uninstall` absent          | clean `not_found` no-op                                |
| `restart` on Halted VM               | `restart_halted`; no subresource call                  |
| `uninstall` with workloads           | `uninstall_blocked`                                    |
| Adopting a `spec.running` VM         | `running_field`; no apply                              |
| Hostile kubeconfig                   | vendored validator refuses before any kubectl spawn    |
| Injection in names/images/urls/gates | grammars; manifest on stdin, argv carries no secret    |

## Live testing

Not run in this release: no KVM-capable throwaway cluster was available. Every
live cell in the spec's matrix is recorded as **blocked**, so the version is
published to `beta` (see `release.yaml`). `ci: false` until the first push.

## Test count

90 tests pass offline (0 failed): grammars and helpers, golden CR/VM renders,
schema/secret checks, and the failure-mode table above.
