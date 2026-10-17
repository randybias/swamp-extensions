# @randybias/kubevirt

[Swamp](https://github.com/swamp-club/swamp) extension for installing
[KubeVirt](https://kubevirt.io) on an existing Kubernetes cluster and managing
one `VirtualMachine`. Built against the public KubeVirt and CDI APIs and
`kubectl`; reached only through a kubeconfig, never SSH.

## Models

### `@randybias/kubevirt`

One KubeVirt installation per cluster, addressed by method arguments
(kubeconfig, context), so a single definition serves any cluster.

| Method       | Description                                                                      |
| ------------ | -------------------------------------------------------------------------------- |
| `render_cr`  | Render the KubeVirt custom resource for the inputs (read-only)                   |
| `install`    | Verify the pinned operator manifest, apply it and the CR, optionally CDI         |
| `wait_ready` | Poll until the CR is Deployed, Available and reports the version (read-only)     |
| `upgrade`    | Apply a newer pinned manifest and wait; refuses a downgrade or a minor skip      |
| `get`        | Installed versions, CR conditions, node facts and outdated workloads (read-only) |
| `sync`       | Refresh stored state; an absent CR is recorded as `not_found` (read-only)        |
| `uninstall`  | Delete the CR, the manifest's objects and any CDI this model installed           |

`install` requires `operator_manifest_sha256`; the fetch is refused unless the
bytes match, so nothing is applied from an unverified manifest. It adopts an
installation already at the same version and refuses a different one with a
pointer to `upgrade`. `upgrade` moves one minor at a time unless
`allow_minor_skip` is set, and never downgrades. With `install_cdi`, the CDI
operator manifest and a minimal `CDI` custom resource are applied in the `cdi`
namespace; an existing CDI this model did not install is adopted without being
claimed. `uninstall` uses `confirm`, deletes CDI only when this definition
installed it, with the recorded version and digest, and cleans up CDI even when
KubeVirt is already gone. With the default `BlockUninstallIfWorkloadsExist`
strategy a running workload blocks the delete (typed error), while
`RemoveWorkloads` lets upstream delete running VMs.

### `@randybias/kubevirt-vm`

One `VirtualMachine`, addressed by method arguments (kubeconfig, context,
namespace, name).

| Method       | Description                                                                   |
| ------------ | ----------------------------------------------------------------------------- |
| `render_vm`  | Render the VirtualMachine YAML for the inputs (read-only)                     |
| `define`     | Create or update the VM by server-side apply; `runStrategy` only              |
| `start`      | Set `runStrategy: Always` and optionally wait until Running                   |
| `stop`       | Set `runStrategy: Halted` and wait until no VMI exists                        |
| `restart`    | Call the public restart subresource; refuses a Halted VM                      |
| `wait_ready` | Poll until Running and VMI Ready, DataVolume Succeeded first (read-only)      |
| `get`        | VM spec summary, printable status, VMI node/IPs, DataVolume state (read-only) |
| `sync`       | Refresh stored state; an absent VM is recorded as `not_found` (read-only)     |
| `delete`     | Delete the VM and its VMI and owned DataVolume; disk data is lost             |

The source is exactly one of `container_disk` (a digest-pinned image; guest
changes are lost on stop or restart) or `data_volume` (a CDI DataVolume
template, which needs CDI installed). `define` always writes `spec.runStrategy`
and never the deprecated `spec.running`, and refuses an existing VM that uses
`running`. `cloud_init_secret` and `ssh_public_key_secret` name Secrets created
with `@randybias/k8s-secret`; inline user-data is not accepted, so no secret
content enters the manifest.

## Dependencies

`kubectl` on the PATH and a reachable API server. KubeVirt and (for DataVolume
VMs) CDI are installed by this extension from their public release assets, each
verified against a required SHA-256; the CDI operator manifest ships no custom
resource, so a minimal `CDI` object is applied after it.

## Install

```sh
swamp extension pull @randybias/kubevirt
```

## Example

One definition serves every cluster and every VM. The kubeconfig is always a
vault reference.

```sh
swamp model create @randybias/kubevirt cluster
swamp model method run cluster install \
  --input 'kubeconfig=${{ vault.get("cluster", "kubeconfig") }}' \
  --input kubevirt_version=v1.2.0 \
  --input operator_manifest_sha256=<sha256 of kubevirt-operator.yaml> \
  --input install_cdi=true --input cdi_version=v1.2.0 \
  --input cdi_operator_manifest_sha256=<sha256 of cdi-operator.yaml>

swamp model create @randybias/kubevirt-vm app-vm
for name in web api; do
  swamp model method run app-vm define \
    --input 'kubeconfig=${{ vault.get("cluster", "kubeconfig") }}' \
    --input namespace=app --input name=$name \
    --input 'container_disk:json={"image":"quay.io/kubevirt/cirros-container-disk-demo@sha256:<digest>"}' \
    --input 'cloud_init_secret=vm-cloud-init'
done
```

The manifest digests pin the YAML; the operator still pulls its component images
by release tag. Pass `kubeconfig` only as a vault reference.

## How it works

State is keyed by a nonsecret cluster fingerprint (16 hex of sha256 over the
normalized API server URL) plus the namespace and name, so two contexts on one
server share state and a context name never keys it. The kubeconfig is inspected
before `kubectl` runs and rejected if it uses `exec` or `auth-provider`
credentials, a `tokenFile` or any path credential, or a YAML merge key;
`kubectl config view --raw -o json` is then validated default-deny and is the
only kubeconfig used. It is written to a `0600` temporary file for one `kubectl`
call and removed in a `finally`, even on error. Manifests reach
`kubectl apply -f -` on stdin. Failures are typed (`manifest_fetch`,
`manifest_mismatch`, `version_conflict`, `version_skew`, `not_found`,
`crd_missing`, `unreachable`, `unauthorized`) and carry a fixed message, never
remote output.

`wait_ready` returns `ready: false` with the last conditions after its timeout
rather than throwing; a host without `/dev/kvm` and `use_emulation: false`
reports no KVM-capable nodes (nodes are counted through the
`devices.kubevirt.io/kvm` allocatable resource) and a VM stays
`ErrorUnschedulable`. Every mutating verb is an action; `uninstall` always
requires a `confirm` value equal to the cluster fingerprint, and VM `delete`
requires `confirm` equal to the VM name when the VM owns a DataVolume. Both are
clean no-ops when the object is already absent. This version is published to
`beta`: it has not yet been run against a live cluster.

## License

Apache-2.0
