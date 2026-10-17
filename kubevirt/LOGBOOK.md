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

## Round 1 review fixes

- **CRITICAL namespace.** `withCluster` took no namespace, so the vendored
  `withKubectl` appended `--namespace default` to every argv and overrode any
  per-call `-n`; every KubeVirt read hit `default` and every apply of a
  `kubevirt` object failed. `withCluster` now takes a namespace and one is
  opened per target: `kubevirt` for the CR/operator, `cdi` for CDI,
  `a.namespace` for VMs; the per-call `-n` is dropped. Tests assert the final
  argv namespace for the operator, CDI and VM calls.
- **HIGH CDI custom resource.** `cdi-operator.yaml` does not contain the CR, so
  `install_cdi` now applies a rendered minimal `CDI` (`cdi.kubevirt.io/v1beta1`,
  name `cdi`) after the CDI operator, and uninstall deletes the CDI CR with
  `--wait` before the CDI manifest. Decision 7 above is superseded.
- **HIGH uninstall order.** Every needed manifest (KubeVirt, and CDI when
  installed by this model) is fetched and SHA-verified before anything is
  deleted, so a fetch/SHA failure cannot leave the operator half-removed. When
  the CR is absent but the `kubevirt` namespace or the `kubevirts.kubevirt.io`
  CRD remains, uninstall continues with the manifest delete instead of returning
  `not_found`; only a fully absent install is a no-op.
- **HIGH CDI ownership.** Install persists `cdi_installed_by_model` and the CDI
  SHA. Uninstall deletes CDI only when that flag is set, requires the matching
  CDI version and digest, and fails before any deletion when they are missing;
  read-only methods carry the flag forward and never set it.
- **HIGH URL userinfo.** The DataVolume `http` URL now parses with `URL` and
  rejects a non-empty username or password, so a credential cannot reach the VM
  spec, rendered YAML or state.
- **MEDIUM restart.** `restart` waits, bounded by `timeout_s`, until the VMI has
  a new uid and is `Running`, then reports the new uid.
- **MEDIUM KVM detection.** `kvm_nodes` now counts nodes whose
  `status.allocatable["devices.kubevirt.io/kvm"]` is greater than zero, instead
  of a `kubevirt.io/kvm` node label. Decision 6 above is superseded.
- **MEDIUM downgrade.** `isDowngrade` now compares patch as well as major and
  minor; `v1.3.2` to `v1.3.1` is refused.
- **MEDIUM DataVolume CRD.** `define` with a `data_volume` source reads the
  `datavolumes.cdi.kubevirt.io` CRD and raises a typed `crd_missing` before
  apply when CDI is not installed.
- **MEDIUM RemoveWorkloads.** The `uninstall` description and README now state
  that a running workload blocks the delete only under the default
  `BlockUninstallIfWorkloadsExist`; `RemoveWorkloads` lets upstream delete the
  running VMs.

## Round 2 review fixes

- **HIGH CDI record match.** Uninstall required only that the CDI inputs were
  present, not that they matched the record; a mismatched version would delete
  the CDI CR and another manifest's objects. It now requires
  `a.cdi_version === prior.cdi_version` and
  `a.cdi_operator_manifest_sha256 === prior.cdi_operator_sha256` before any
  fetch or delete (`invalid_input` otherwise). `get`/`sync`/`wait_ready` no
  longer overwrite the recorded `cdi_version`; the observed version is kept in a
  new `observed_cdi_version` field.
- **HIGH independent CDI cleanup.** When KubeVirt was already gone, uninstall
  returned `not_found` before touching CDI and then cleared
  `cdi_installed_by_model`. KubeVirt and CDI cleanup are now decided separately:
  if the record owns CDI and any CDI object remains (the `cdi` CR, the `cdi`
  namespace or the `cdis.cdi.kubevirt.io` CRD), the CDI manifest is fetched,
  verified and deleted even with KubeVirt absent; the flag is cleared only after
  that delete succeeds.
- **HIGH CDI ownership at install.** Install now reads the CDI CR/CRD before
  applying. An existing CDI with no ownership record is adopted without claiming
  it (flag false, no apply). A prior true flag with its version and digest is
  preserved when install runs again without `install_cdi`.
- **HIGH HTTP URL grammar.** `isHttpUrl` keeps the strict grammar again
  (`^https?://[A-Za-z0-9._~:/%+,;=!$&'()*-]+$`) and still parses with `URL` and
  rejects a username or password, so `?`, `#`, `@`, backslash, whitespace and
  encoded userinfo are all refused and cannot reach the spec, rendered YAML or
  state.
- **MEDIUM fetch before first apply.** Install fetches and verifies the CDI
  manifest before the first KubeVirt apply, so a CDI fetch/SHA failure no longer
  leaves an untracked KubeVirt install.
- **MEDIUM CDI delete bound.** `delete cdi cdi` now carries
  `--timeout=${timeout_s}s`.
- **LOW.** `renderCdiCr` no longer sets `metadata.namespace` on the
  cluster-scoped CR; uninstall persists `status: "not_found"` after a successful
  delete; the unused `installed_by_model` state field is removed.
