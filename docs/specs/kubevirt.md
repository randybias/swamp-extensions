# Spec: P2 — `@randybias/kubevirt`

Status: DRAFT — awaiting Randy's approval (P2, written from public docs only; no prior implementation consulted)
RFC 2119 keywords.
Sources: kubevirt.io user guide + release assets, CDI (containerized-data-importer)
public docs, kubernetes.io (kubectl, server-side apply), docs.k0sproject.io. This
repo: CONVENTIONS.md, `k8s-secret` (kubeconfig handling), `k0s-cluster` (target).

## 1. Purpose

Install and upgrade [KubeVirt](https://kubevirt.io) on an existing Kubernetes
cluster at a **pinned version with a SHA-256-pinned operator manifest**, wait for
it to be usable, and manage **VirtualMachine** lifecycle: define (from a
containerDisk image or a CDI DataVolume), start/stop/restart, get/sync, delete.
The cluster is reached only through a kubeconfig delivered exactly as
`@randybias/k8s-secret` does it. No SSH: everything is `kubectl` against the API.

Two model types, one extension (different resource kinds, CONVENTIONS §2):
`@randybias/kubevirt` (the operator install) and `@randybias/kubevirt-vm` (one VM).

## 2. Transport and kubeconfig (reuse, do not re-invent)

Vendor `k8s-secret`'s reviewed `_lib/kubeconfig.ts` and `_lib/kubectl.ts`
**byte-identical**. That gives, for free and already reviewed:

- kubeconfig arrives as a vault reference, `.meta({ sensitive: true })`;
- YAML merge keys/tags refused; `kubectl config view --raw -o json` produces the
  **canonical** document, which is validated **default-deny** (no `exec` /
  `auth-provider` plugins, no `tokenFile` or any file-path credential, unknown
  fields rejected) and is the only kubeconfig any later call uses;
- written to a `0600` temp file, deleted in a `finally`, even on error;
- manifests reach kubectl on **stdin** (`kubectl apply --server-side -f -`).

Any change these models need in those files goes back to `k8s-secret` first.

## 3. Model contract

- **Types** `@randybias/kubevirt`, `@randybias/kubevirt-vm`. CalVer == manifest.
- **`globalArguments` empty.** Every method takes `kubeconfig`, optional
  `context`, and its operands per call; one definition serves any cluster.
- **State keys** (instance values, never the definition name):
  - operator: `{cluster_fp}/kubevirt`;
  - VM: `{cluster_fp}/{namespace}/{name}`;
  - `cluster_fp` = first 16 hex of sha256 over the canonical kubeconfig's
    *selected context → cluster → server URL* (scheme + lowercased host +
    explicit port). Two contexts on one server share a fingerprint; a context
    name alone never keys state.
- **Factory with injectable deps**: kubectl spawner, manifest fetcher, clock,
  sleep. Unit tests render manifests and assemble argv only — no network, no
  cluster.
- Server-side-apply field manager per definition:
  `swamp-kubevirt-<sha256(definition)[0:12]>` (k8s-secret precedent).

### Methods — `@randybias/kubevirt`

| Method | Kind | Description |
|---|---|---|
| `render_cr` | — | READ-ONLY. Return the `KubeVirt` CR YAML for the inputs (emulation, feature gates, workload-update strategy, uninstall strategy). Deterministic. |
| `install` | action | Idempotent. Fetch the operator manifest for `kubevirt_version`, **verify SHA-256 before apply** (refuse on mismatch), server-side apply it, then apply the rendered CR; optionally the same for CDI. Adopts an install at the same version; **refuses a different installed version** (points to `upgrade`). Returns `{kubevirt_version, cdi_version, operator_sha256, cr_sha256}`. |
| `wait_ready` | action | READ-ONLY semantics. Poll until the CR is `phase: Deployed`, `Available=True`, `Progressing=False`, `Degraded=False`, `observedKubeVirtVersion == kubevirt_version`, and (if installed) CDI `Available`. Returns `{ready, phase, conditions[], schedulable_nodes[], kvm_nodes[]}`. |
| `upgrade` | action | Move to a new pinned version: verify the new manifest SHA, apply it (operator first; CR keeps no `imageTag`, so it follows the operator), wait as `wait_ready`. Refuses a downgrade and a jump of more than one minor unless `allow_minor_skip` is set. Returns `{from, to, outdated_vmis}`. |
| `get` | — | READ-ONLY. Installed version, CR phase/conditions, emulation flag, feature gates, CDI version, nodes labelled `kubevirt.io/schedulable=true`, outdated workloads count. |
| `sync` | — | READ-ONLY. Reconcile recorded state with the cluster; absent CR → `not_found`. |
| `uninstall` | action | DESTRUCTIVE. Delete the CR with `--wait` (upstream blocks while VMIs exist under `BlockUninstallIfWorkloadsExist`; surfaced as a typed error), then delete the operator manifest's objects, then CDI if this model installed it. Absent → clean no-op. Requires `confirm` = `cluster_fp`. |

### Methods — `@randybias/kubevirt-vm`

| Method | Kind | Description |
|---|---|---|
| `render_vm` | — | READ-ONLY. Return the `VirtualMachine` YAML for the inputs. Deterministic. |
| `define` | action | Idempotent create/update of the VM by server-side apply. Source is exactly one of `container_disk` or `data_volume` (rendered as a `dataVolumeTemplates` entry). Always writes `spec.runStrategy`, never `spec.running`. Returns `{namespace, name, uid, generation, run_strategy, spec_sha256}`. |
| `start` | action | Set `runStrategy: Always` (no-op if already). Optional wait. Returns `{printable_status}`. |
| `stop` | action | Set `runStrategy: Halted`; wait until no VMI exists or `grace_s` elapses. Returns `{printable_status}`. |
| `restart` | action | PUT the public `subresources.kubevirt.io/v1 …/virtualmachines/{name}/restart` subresource via `kubectl replace --raw -f -` (empty body on stdin). Refuses on a Halted VM. Returns `{vmi_uid_before, vmi_uid_after}`. |
| `wait_ready` | action | READ-ONLY semantics. Poll until `printableStatus: Running` and the VMI `Ready` condition is true (optionally `AgentConnected`); DataVolume `Succeeded` first if present. Returns `{ready, printable_status, node, interfaces[], dv_phase, dv_progress}`. |
| `get` | — | READ-ONLY. VM spec summary, printableStatus, VMI phase/node/IPs, DataVolume phase/progress, conditions. |
| `sync` | — | READ-ONLY. Reconcile recorded state; absent → `not_found`. |
| `delete` | action | DESTRUCTIVE. Delete the VM (cascades its VMI and any DataVolume/PVC it owns through `dataVolumeTemplates` — disk data is lost). Requires `confirm` = VM name when it owns a DataVolume. Absent → clean no-op. `kind:"action"` (a model `delete` tombstones the model). |

### Inputs and grammars

- `kubeconfig` — vault ref, sensitive (§2). `context` — `[A-Za-z0-9._@:-]{1,253}`.
- `kubevirt_version`, `cdi_version` — `^v\d{1,3}\.\d{1,3}\.\d{1,3}$`.
- `operator_manifest_sha256`, `cdi_operator_manifest_sha256` — **required**,
  `^[0-9a-f]{64}$`. No install or upgrade from an unverified manifest.
- `manifest_base_url` — optional mirror override, `https://` only, no userinfo,
  no query; still SHA-checked. Default: the GitHub release asset URL.
- `install_cdi` — bool, default false (required for any `data_volume` VM).
- `use_emulation` — bool, default false; sets
  `spec.configuration.developerConfiguration.useEmulation`. Rendered explicitly
  so `get` and the README can show it.
- `feature_gates[]` — `^[A-Z][A-Za-z0-9]{1,63}$`, max 32, sorted on render.
- `workload_update_methods[]` — subset of `LiveMigrate`, `Evict`; default `[]`
  (single-node clusters cannot live-migrate).
- `namespace` — DNS-1123 label; `name` — DNS-1123 label (VM names become pod
  and hostname labels, so the stricter grammar).
- `cpu_cores` 1–64, `memory` — `^\d{1,6}(Mi|Gi)$`, bounded 64Mi–256Gi.
- `container_disk.image` — **must be digest-pinned**:
  `^[a-z0-9.-]+(:\d+)?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$`. Tags refused.
- `data_volume` — `{source: {http: url} | {registry: digest-pinned image},
  size (Gi grammar), storage_class (DNS-1123 subdomain, optional)}`.
- `cloud_init_secret` — name of an existing Secret (DNS-1123 subdomain) used as
  `cloudInitNoCloud.userDataSecretRef`. **Inline user-data is not accepted**
  (it would land in VM spec and state). Create the Secret with `k8s-secret`.
- `ssh_public_key_secret` — optional Secret name for `accessCredentials`.
- `run_strategy` (define) — `Always | Halted | Manual | RerunOnFailure`, default
  `Halted`. `confirm` — exact-match string as above. Timeouts bounded 10–3600 s.
- Strict `z.object`, no `.passthrough()`.

### Outputs

Typed objects above. No kubeconfig, token, cloud-init content or Secret data in
any output, state or log. Errors are typed and carry no remote body text that
could echo a credential.

## 4. Failure modes (test + live cell each)

| Mode | Expected |
|---|---|
| Manifest SHA mismatch | Refuse before apply; nothing applied; typed error. |
| Manifest 404 / fetch error | Typed error naming the URL only. |
| Different version installed (`install`) | Refuse; points to `upgrade`. |
| Downgrade / minor skip (`upgrade`) | Refuse unless `allow_minor_skip`; never downgrade. |
| No `/dev/kvm`, `use_emulation:false` | `wait_ready` (operator) reports `kvm_nodes: []`; VM `wait_ready` returns `ready:false` with `ErrorUnschedulable`, typed, not a hang. |
| CR never `Deployed` | `ready:false` with conditions after timeout. |
| VM source both / neither | Rejected by schema. |
| Tag-only container image | Rejected by schema. |
| `data_volume` without CDI installed | Typed error before apply (CRD absent). |
| DV on `WaitForFirstConsumer` storage, VM Halted | `get` shows DV pending-consumer; documented, not an error. |
| `restart` on Halted VM | Typed refusal. |
| `uninstall` with VMIs running | Typed error from the blocked delete; operator untouched. |
| delete / uninstall already absent | Clean no-op. |
| Hostile kubeconfig (exec plugin, tokenFile, merge key) | Refused before any kubectl spawn (vendored validator). |
| Injection in names/images/urls/gates | Rejected by grammar; values never reach a shell (argv only). |

## 5. Tests (offline, increasing risk)

1. Schema/secret/license: `kubeconfig` sensitive; strict objects; no output
   type can hold a kubeconfig or cloud-init text.
2. Pure mapping: golden CR (emulation on/off, gates, update strategy); golden VM
   (containerDisk; DataVolume template; cloud-init Secret ref); SHA verify
   (match→apply, mismatch→refuse, apply never spawned); version-skew guard table;
   argv contains no secret and no `--from-literal`; `spec.running` never rendered.
3. Failure + adversarial: §4 rows; injection on every input that reaches argv or
   a manifest; vendored kubeconfig tests pass unchanged.
4. A regression test greps outputs/fixtures for kubeconfig- or token-shaped text.
5. Packaging; byte-identity check of vendored `_lib` files against `k8s-secret`.

Fixtures synthetic: RFC 5737 servers, `example.com` registries, fake 64-hex
digests, placeholder kubeconfig.

## 6. Live e2e matrix (single-node k0s, throwaway VPS)

Target: an hourly x86_64 VPS (≥4 vCPU, ≥8 GB) tagged `swamp-e2e=<run-id>`,
k0s single-node from `@randybias/k0s-cluster`, kubeconfig handed over via vault.
A default StorageClass (e.g. the OpenEBS local-PV Helm extension documented by
k0s, applied with `k0s-cluster apply_helm`) is a prerequisite for DV cells.
Record `ls -l /dev/kvm` and `/sys/module/kvm_*/parameters/nested` in the LOGBOOK.
Cells marked **KVM** need `/dev/kvm` (nested virt); on a host without it they are
`blocked`, never `skip`, and every other cell runs with `use_emulation:true`.

| Cell | Needs | Expected |
|---|---|---|
| render_cr / render_vm | — | match golden for live inputs |
| install bad-SHA (negative) | — | refused, no `kubevirt` namespace created |
| install (emulation) | — | operator + CR applied |
| wait_ready | — | `Deployed`, Available; node `kubevirt.io/schedulable=true` |
| install idempotent | — | no change, same versions |
| install (hardware) | **KVM** | `use_emulation:false`, `kvm_nodes` non-empty |
| define containerDisk (Halted) | — | VM exists, `Stopped` |
| define idempotent | — | same generation |
| start + wait_ready | — (KVM run noted) | `Running`, Ready, has IP |
| restart | — | new VMI uid, Running again |
| stop | — | `Stopped`, no VMI |
| install CDI + define DataVolume VM | — | DV `Succeeded` after start, VM Running |
| guest agent connected | image with agent | `AgentConnected` true |
| get / sync (both types) | — | reflect cluster; `not_found` after external delete |
| unschedulable without KVM | host w/o KVM | `use_emulation:false` VM → `ErrorUnschedulable`, typed |
| upgrade n→n+1 minor | — | `observedKubeVirtVersion` = target; running VM reported outdated, still Running |
| upgrade skip / downgrade | — | refused |
| uninstall with VM running | — | typed refusal |
| delete VM (DV owned, with confirm) | — | VM, VMI, DV, PVC gone |
| delete again | — | clean no-op |
| uninstall / uninstall again | — | namespace + CRDs gone; then no-op |
| bad kubeconfig / unreachable API | — | typed error, temp kubeconfig deleted |

Afterwards confirm with `kubectl get crd | grep kubevirt` that nothing remains.
Receipts into `kubevirt/LOGBOOK.md`. No `stable` while any cell is
`untested`/`skip`; KVM cells `blocked` also block `stable`.

## 7. Credential policy

Per RULINGS ¶3: credentials are vault references only. The kubeconfig is a
`vault.get(...)` expression (or a `{vault,key}` pair resolved through the runtime
vault service, as in `k8s-secret`); never a file path, never argv, never state,
never `--json` stdout. Guest secrets (cloud-init, SSH keys) live in Kubernetes
Secrets created by `k8s-secret`; this extension takes only their **names**.
Private registry pull secrets: Secret name only, same rule.

## 8. Known traps (from public docs; verify at the pinned version)

- **Large CRDs.** Client-side `kubectl apply` of the operator manifest can exceed
  the `last-applied-configuration` annotation limit; use server-side apply.
- **Emulation is slow** and upstream labels it for development; the README says
  so. Without it and without `/dev/kvm`, VMs stay unschedulable. Many VPS
  providers do not expose nested virtualization.
- **Architecture.** Upstream emulation support and containerDisk images differ
  by arch; v1 of this spec is tested on x86_64 only and the README says so.
- **`spec.running` is deprecated** in favour of `spec.runStrategy`; the two are
  mutually exclusive. Adopting a VM that uses `running` is a typed refusal.
- **Manifest SHA ≠ image pinning.** The operator pulls component images by the
  release tag; the manifest SHA pins only the YAML. Recorded as an open
  question (digest overrides), not silently claimed.
- **Uninstall order.** Delete the CR (and wait) before the operator/namespace,
  or finalizers strand the namespace in `Terminating`.
- **Upgrades** are supported one minor at a time; running VMIs keep the old
  `virt-launcher` until restarted or migrated (`outdatedVirtualMachineInstanceWorkloads`).
- **CDI needs a StorageClass**; k0s ships none by default. With
  `WaitForFirstConsumer` binding, a Halted VM's DataVolume does not import until
  first start.
- **containerDisk is ephemeral**: guest disk changes are lost on stop/restart.
- **k0s paths.** k0s places kubelet state under `/var/lib/k0s` and its
  containerd socket under `/run/k0s`, not the upstream defaults; the first live
  cell MUST confirm `virt-handler` runs cleanly on k0s before any VM cell, and
  any required k0s worker flag goes back to `k0s-cluster` as an input.

## 9. Carry-overs

- Mutating verbs are `kind:"action"`; `READ-ONLY.`/`DESTRUCTIVE.` prefixes.
- Never capture `--json` of a run carrying the kubeconfig (lab 3555).
- README tested-version line names only the KubeVirt, CDI and k0s versions that
  passed live, and whether hardware or emulation was used.

## 10. Open questions for Randy

1. **`virtctl` or kubectl-only?** This draft avoids a second pinned binary:
   start/stop by `runStrategy`, restart by the public subresource through
   `kubectl replace --raw`. If that PUT fails live, the fallback is a SHA-pinned
   `virtctl` dependency — approve which.
2. Pin component images by digest (operator env overrides) or accept tag pinning
   via the SHA-pinned manifest?
3. One extension with two types (as drafted) or `@randybias/kubevirt-vm`
   published separately?
