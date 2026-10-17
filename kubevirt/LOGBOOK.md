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

## Prior art

None found in the registry. The run-wide sweep (`swamp extension search` on the
stable and beta channels for kubevirt, vm, virtual, kubernetes, k8s, kvm, qemu
and libvirt, plus the first-party `@swamp/*` listing) found no KubeVirt, CDI or
VirtualMachine package; `@swamp/kubernetes` covers core kinds only. Re-checked
at merge on 2026-10-17 for kubevirt, virtualmachine, cdi and "virtual machine"
on both channels: no KubeVirt package (the hits are unrelated VM or host tools,
such as `@randybias/libvirt` and `@randybias/azure-vm`).

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
   spec's key format (`{fp}/kubevirt`, `{fp}/{namespace}/{name}`; the separator
   became `_` in round 5, because swamp rejects `/` in a data name) and uses the
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

Live on a single-node k0s v1.36.4 cluster (`<bm1>`) with KubeVirt v1.9.1 and CDI
v1.66.1: 23 of 24 cells on 3966f44 with no patches, then 9 of 9 on bd22e15. See
"2026-10-17 live e2e" below. The DataVolume cells were not run (no default
StorageClass), so the version stays on `beta`.

## Test count

115 tests pass offline (0 failed) at merge: grammars and helpers, golden CR/VM
renders, schema/secret checks, the failure-mode table above, and the live
regressions (state-key names, real condition shapes, re-run no-op).

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

## Round 4 (r3 review, lane/b2-kubevirt)

- HIGH: on a real cluster `get <kind> --ignore-not-found` for a kind whose CRD
  is not installed exits 1 with "the server doesn't have a resource type", which
  classified as `crd_missing` and failed install on a fresh cluster, install_cdi
  without CDI, get/sync without a CDI CRD and a clean-no-op uninstall. The
  KubeVirt and CDI reads now treat `crd_missing` as absent. The CR applied right
  after its operator manifest is retried while the CRD is not yet served.
  Checked with real kubectl against a fake API server that serves a group only
  once its CRD exists (fresh install with CDI, get/sync without CDI, owned CDI
  uninstall with KubeVirt gone).
- MEDIUM: uninstall plans both cleanups and fetches and verifies every manifest
  before the first delete.
- MEDIUM: CDI ownership no longer treats a bare namespace or CRD as an existing
  CDI. A real CDI resource is adopted (flag false); a namespace or CRD carrying
  this definition's field manager is its own partial install (owned,
  re-applied); a namespace or CRD with no CDI resource that someone else owns is
  refused.
- LOW: uninstall description shortened; `.test` host names in URL fixtures; the
  recorded flag is false after an uninstall.

## Round 5 (live blockers on a real swamp)

- HIGH: state keys contained `/` (`<fp>/kubevirt`, `<fp>/<ns>/<name>`), which
  swamp rejects in a data name, so every state write failed. DEVIATION FROM THE
  SPEC key format, forced by the platform: the keys are now `<fp>_kubevirt` and
  `<fp>_<ns>_<name>`. `_` cannot occur in a hex fingerprint or in a DNS-1123
  namespace or name, so the mapping stays injective; the operator record has one
  part fewer than a VM record. A test checks every written name against swamp's
  rule (no `..`, `/`, `\` or NUL).
- HIGH: `get` on a cluster without KubeVirt returned an error. It now records
  and returns `status: not_found` (the spec's only absent status; the spec has
  no `not_installed`), like `sync`.
- Live fix 3: `ConditionSchema` is strict and the state was built from the CR's
  raw conditions, so a settled CR (conditions with `lastProbeTime`,
  `lastTransitionTime`) failed install-adopt, get and sync. Observed Kubernetes
  objects are never parsed with a strict schema now: conditions are projected to
  `type/status/reason/message` (strings only) when the state is built; strict
  schemas stay for inputs and for the model's own records. `withCluster` no
  longer flattens an error thrown by a method body into "kubectl failed": a
  validation failure is `invalid_response` naming issue paths and codes only,
  anything else its error name; only the vendored wrapper's own failures are
  rewrapped. Fixtures now carry real condition shapes.
- Live fix 4: an `install` re-run right after Available bumped the KubeVirt CR
  generation (2 to 3); later re-runs were clean. The operator rewrites the CR
  spec after it settles and a re-apply of an unchanged desired state bumped it
  again. The CR is applied only when a managed field (emulation, feature gates,
  uninstall strategy, workload update methods) differs from the live spec;
  fields the operator adds are ignored (`crSpecSatisfied`). The root cause was
  not reproduced here (no cluster); the skip makes a re-run a no-op whatever the
  operator does to unmanaged fields. README documents the live node
  prerequisites (/dev/kvm mode, k0s kubelet directory, no default StorageClass).

## 2026-10-17 live e2e

Target: `<bm1>`, a single-node k0s v1.36.4+k0s.1 cluster (no taints, `/dev/kvm`
present, libvirt installed but idle), kubeconfig by vault reference. Pins:
KubeVirt v1.9.1 (`kubevirt-operator.yaml` sha256 `9ac45a436c49…a1d292da`), CDI
v1.66.1 (`cdi-operator.yaml` sha256 `c7d92bd1b2ee…27a13e224`),
`cirros-container-disk-demo` by digest. Each extension was installed from a
`git archive` of the head named. Receipt = first 16 hex of the sha256 of the
console output with timestamps stripped.

### 3966f44, no patches: 23/24

| Cell                                                     | Result | Receipt            |
| -------------------------------------------------------- | ------ | ------------------ |
| 1a `get` on a fresh cluster persists `not_found`         | PASS   | `21cb9f58f204e234` |
| 1b `sync` on a fresh cluster                             | PASS   | `8d7c6e37fcb5bd3a` |
| 4a wrong KubeVirt manifest SHA: refused, nothing applied | PASS   | `ff77049f6026861b` |
| 4b wrong CDI manifest SHA: refused, nothing applied      | PASS   | `31ff41ce0ea3f541` |
| 2a `install` with `install_cdi`                          | PASS   | `665ec0214eb7336e` |
| 2b `wait_ready`: KubeVirt and CDI Deployed               | PASS   | `44289600d97d9d04` |
| 3 `install` re-run right after Available                 | FAIL   | `6205ad1f7c7676a8` |
| 1c `get` on the settled CR                               | PASS   | `cf027c7efe8136c4` |
| 1d `sync` on the settled CR                              | PASS   | `33f5be89fd1804a7` |
| 8 `kvm_nodes` reports the node (kvm device = 1k)         | PASS   | `7386dca777a79e7e` |
| 5a VM `define` (cirros containerDisk, Halted)            | PASS   | `c880739bcf19db4c` |
| 5b VM `start` (Running)                                  | PASS   | `8fe3db1a5ccb56f3` |
| 5c VM `wait_ready`                                       | PASS   | `5bbbb12a11e1602e` |
| 5d VM `get` (VMI Running, node, IP)                      | PASS   | `3469ca0683b6c562` |
| 5e VM `restart`: new VMI uid                             | PASS   | `a05a5ef2d6ec23a0` |
| 5f VM `stop` (Halted, no VMI)                            | PASS   | `95e6aca07263e1e5` |
| 5g VM `delete`                                           | PASS   | `b0342e030784047e` |
| 5h VM `delete` again: no-op                              | PASS   | `50bee5c7cac49f0a` |
| 3.1 `install` re-run on the settled install              | PASS   | `b468b1e22dc4159d` |
| 3.2 `install` re-run on the settled install              | PASS   | `5743ff5919319d4c` |
| 6 `uninstall` with a wrong confirm: refused              | PASS   | `7b85434e930dd400` |
| 7a `uninstall`: KubeVirt and CDI removed, 0 CRDs         | PASS   | `6e519acd8dbc73c6` |
| 7b `uninstall` again: no-op                              | PASS   | `aa6ff99f61c4e8c5` |
| 1e `get` after uninstall: `not_found`                    | PASS   | `3e49b3fa9cf8d5c9` |

Cell 3 failed because the KubeVirt CR generation went from 2 to 3 on the first
re-run; later re-runs were clean. Fixed in bd22e15 (live fix 4 above).

Two node problems were found and fixed on `<bm1>` before the VM cells, both
documented in the README under "Node prerequisites": `/dev/kvm` was
`root:kvm 0660` and `virt-launcher` could not open it, and k0s keeps the pods
under `/var/lib/k0s/kubelet/pods` while `virt-handler` reads
`/var/lib/kubelet/pods` ("Domain does not exist"; fixed with an rbind mount,
`make-rshared` and a `virt-handler` restart).

### bd22e15, no patches: 9/9

| Cell                                                     | Result        | Receipt            |
| -------------------------------------------------------- | ------------- | ------------------ |
| 1a fresh `install` with CDI                              | PASS          | `03900dbec6592147` |
| 1b `wait_ready`                                          | PASS          | `44289600d97d9d04` |
| 1.1 immediate re-run: generation and resourceVersions    | PASS          | `fe81e749fd227d98` |
| 1.2 immediate re-run: generation and resourceVersions    | PASS          | `fe81e749fd227d98` |
| 2a k0s `--kubelet-root-dir` flag exists (help text only) | PASS (exists) | `da7fec712e541c4b` |
| 2b `/dev/kvm` udev rule gives `0666` (replaces chmod)    | PASS          | `5bf7af8f180b4d91` |
| 3a `uninstall` with a wrong confirm: refused             | PASS          | `7b85434e930dd400` |
| 3b `uninstall`: KubeVirt and CDI removed                 | PASS          | `0eb342cbecc825a7` |
| 3c `uninstall` again: no-op                              | PASS          | `a3e9cdd93c72a432` |

Immediate re-runs are true no-ops: the CR generation stayed 2 and every
resourceVersion was unchanged.

### Earlier patched passes (history)

- a2f86c0 with a local state-key patch: `sync` on a fresh cluster passed, `get`
  raised "KubeVirt is not installed", both SHA refusals and the install passed.
  This found the `/` state keys and the `get` error (fixed in 75b7dfe).
- 75b7dfe: wrong-confirm refusal, uninstall and repeat uninstall passed; the
  strict condition parse failed on a settled CR (fixed in 3966f44).

### Not run

- DataVolume VM cells: the cluster has no default StorageClass.
- `upgrade` across releases, `use_emulation: true`, `RemoveWorkloads` uninstall.

## Merge prep (2026-10-17)

- Quality pass: `kubevirt.ts` imported the release-tag, SHA-256 and feature-gate
  regexes instead of redefining them; the unused `isRecord` and the test-only
  `isReleaseTag`/`isSha256`/`isFeatureGate` wrappers were removed. No behaviour
  change.
- README "Node prerequisites" rewritten from the live run: the udev rule, the
  k0s kubelet root (the flag exists but is untested; the rbind mount is the
  verified workaround) and the missing StorageClass.
- Decisions 1 to 5, 8 and 9 above stand; 6 and 7 are superseded (round 1).
- Gate 7: `cloud_init_secret` and `ssh_public_key_secret` carry a
  `swamp-quality-ignore credentials-sensitive-field` comment; they name an
  existing Secret and hold no secret material.

## Residuals (known, do not block beta)

- **Pending-owned marker gap.** No marker is persisted before the CDI apply.
  Ownership of a partial CDI install is inferred from this definition's field
  manager on the `cdi` namespace or the CDI CRD, and one such object is enough:
  mixed ownership is not refused.
- **Fingerprint = server URL only.** `cluster_fp` hashes the normalized server
  URL, so two clusters behind one URL (a load balancer or a re-created cluster)
  share state keys and the uninstall confirm.
- **DataVolume untested live.** The `data_volume` source is covered offline
  only.
- **CDI CRD gone, namespace left (review MEDIUM, not run live).** When this
  model owns CDI and the `cdi` namespace survives without the CDI CRD,
  `uninstall` fails at `delete cdi cdi` (the kind is not served) before the
  manifest delete; remove the `cdi` namespace by hand.
- **RemoveWorkloads.** Uninstall with `uninstall_strategy: RemoveWorkloads` lets
  upstream delete running VMs; this is documented in the method description and
  README, not guarded.
