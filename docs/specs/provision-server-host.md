# Spec: workflows `provision-server-host` and `teardown-server-host` (`server-stack`)

visibility: private
audience: personal

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Private. The composition is one operator's ops stack; the generic code passed the gates, but the package belongs on the private shelf.

Q2: Individual usage: one operator and one environment.

Q3: Not applicable (private). The public name `server-stack` fails this question: "stack" is a banned noun and says nothing, which is why the package moves.

Q4: Yes. The replacement follows `<environment>-<system>-<purpose>` so its owner picks it out of a list at a glance; it is prepared in the private sibling repo and is not written here, because private names stay out of the public repo. Naming audit verdict: rename, pending Randy's confirmation.

Q5: Not applicable to a private name. A stranger reading `server-stack` would guess wrong about nearly everything; the private name is read only by the person who runs the environment.

Status: implemented and published publicly as `server-stack`; moving to the private
sibling repo under a private name (see the next-version scope at the end).
Not clean-room (net-new composition). RFC 2119 keywords.

## 1. Purpose

Compose `cherry-servers`, `ssh-host`, `wireguard-mesh`, `server-host`, `k0s-cluster`
and `k8s-secret` plus Cloudflare DNS into one workflow that builds a hardened
single-node k0s host from nothing: order the server, harden it, join it to the
WireGuard mesh, close public SSH, install k0s, load cluster secrets, run a NATS
server, prove NATS answers, and only then publish the host's DNS record. A
companion teardown workflow undoes it and proves via the provider APIs that
nothing remains.

Both workflows are **generic and public**. Every instance value arrives as a
workflow input; no host, IP, account or project id, domain, zone or CIDR is
baked into the YAML, a definition or an example. Credentials arrive only as
vault name + key inputs resolved with `vault.get` inside a step (workflow inputs
are stored in plain text, so a value never passes through one).

**The concrete private invocation (its input file) is the maintainer's own and
MUST live in a private sibling repo, never in this one.** This repo ships only
the workflows, a README example with `example.com` / RFC 5737 values, and
synthetic fixtures.

## 2. Building blocks

| Item | Model type | Methods used |
|---|---|---|
| 1 | `@randybias/cherry-servers/servers` (by `server_model` name, as its own workflows do) | `list`, `create`, `wait_ready`, `sync`, `delete` |
| 2 | `@randybias/ssh-host` (the SSH transport) | `wait_connection` |
| 3 | `@randybias/wireguard-mesh` | `apply`, `get` |
| 4 | `@randybias/server-host` | `apply_base`, `apply_firewall`, `lockdown`, `commit`, `get` |
| 5 | `@randybias/k0s-cluster` | `install`, `wait_ready`, `kubeconfig`, `apply_manifests`, `apply_helm`, `reset` |
| 6 | `@randybias/k8s-secret` | `apply` |
| — | `@swamp/cloudflare/dns/dns-records` (first-party, v2026.10.17.1) | `lookup`, `create`, `sync`, `delete` |
| — | `command/shell` (built-in) | `execute` (the NATS probe) |

Facts about `@swamp/cloudflare/dns/dns-records` that shape this spec (read from
its pulled source):

- All record fields are **global arguments** (`zone_id`, `name`, `type`,
  `content`, `ttl`, `proxied`, `comment`, `tags`) plus a sensitive `apiToken`.
  Steps MUST use direct type execution with explicit `globalArgs`, `apiToken:
  ${{ vault.get(inputs.secrets_vault, inputs.cloudflare_token_key) }}`.
- `create` is a plain POST with no adopt; it is **not idempotent**. It MUST be
  guarded by a prior `lookup`.
- `lookup` filters on every set global argument and **throws on zero matches**
  (and on more than one). An absence probe MUST set only `zone_id`, `name`,
  `type`, and cannot tell "absent" from "bad token" by status alone (§9 Q1).
- `delete` takes an `id`, treats 404 as `existed:false`, and is a clean no-op on
  repeat. `sync` records `not_found` when the record is gone.
- State is keyed by the record `name`, which suits the factory pattern.

## 3. Naming and descriptions (CONVENTIONS §2, §5)

- `provision-server-host` — description: `Build a hardened k0s host running NATS
  on the mesh, then publish its DNS` (verb first, one line, 40–90 chars).
- `teardown-server-host` — description: `Remove a provisioned host's DNS record,
  k0s cluster and server`.
- Both are destructive, so **every step carries a description** of the form
  `<Verb> <what> [via <mechanism>]` (the Description column in §5 and §6 is the
  literal string). Step names are single-hyphen kebab case.
- The names do not fit `<kind>-<verb>-<object>` because the workflow spans six
  kinds; see §9 Q3.

## 4. Inputs (provision)

Every input has a noun-phrase description with unit or format. "vault key"
means a key in `secrets_vault`. 53 inputs.

| Group | Input | Type / notes |
|---|---|---|
| Safety | `hostname` | Server hostname; keys every model's state. Required. |
| | `adopt` | Boolean, default `false`. Allow an existing server and record (§7). |
| | `ownership_tag` | `key=value` string. Merged into server tags; adopt requires it on the existing server. Required. |
| Cherry | `server_model` | Name of a generic servers definition. Required. |
| | `project_id`, `plan`, `region`, `image`, `cycle` | As in `cherry-servers-create-server`. Required. |
| | `ssh_keys` | Array of Cherry SSH key IDs. |
| | `tags` | Object of key/value server tags (the e2e run tag goes here). |
| | `os_partition_size` | Integer GB, optional (bare metal). |
| Vault refs | `secrets_vault` | Vault holding every secret below. Required. |
| | `ssh_private_key_key` | Vault key of the admin SSH private key. Required. |
| | `user_data_key` | Vault key of cloud-init user data that installs the pre-generated host keys. Required for `strict`. |
| | `cloudflare_token_key` | Vault key of a Cloudflare API token scoped to DNS edit on the zone. Required. |
| | `wg_private_key_key` | Vault key of the node's WireGuard private key. Required. |
| | `kubeconfig_key` | Vault key the admin kubeconfig is written to. Required. |
| SSH | `ssh_user`, `ssh_port` | Remote user; port 1–65535, default 22. |
| | `host_key_policy` | `strict` \| `accept-new`. Required, no default; acceptance uses `strict`. |
| | `known_hosts` | Expected host keys, known_hosts format (public). Required for `strict`. |
| | `ready_timeout_s` | Seconds for Cherry readiness, default 2700. |
| Base | `base_packages`, `admin_user`, `authorized_keys`, `sysctl`, `timezone` | Passed to `apply_base`. |
| Mesh | `mesh_node` | Object `{name, address (CIDR), listen_port, endpoint?}`. Required. |
| | `mesh_peers`, `mesh_peers_allowlist`, `mesh_relay_exclusion` | As in `wireguard-mesh`. Required (first two). |
| | `mesh_handshake_max_age_s` | Seconds; a handshake older than this fails verification, default 180. |
| Firewall | `management_cidrs` | Array of CIDRs allowed to reach SSH and admin ports. Required, non-empty. |
| | `allow_tcp`, `allow_udp` | Arrays of public ports. `allow_udp` MUST contain `mesh_node.listen_port`. |
| | `revert_after_s` | Seconds before an uncommitted change reverts, 60–1800, default 300. |
| | `verify_timeout_s` | Seconds to prove reachability after a change; MUST be ≤ `revert_after_s` − 60. |
| k0s | `k0s_version`, `k0s_binary_sha256` | Pinned version string; 64-hex digest. Required. |
| | `k0s_download_url` | Optional override; still SHA-checked. |
| | `k0s_api_sans`, `k0s_pod_cidr`, `k0s_service_cidr` | SANs MUST include the mesh address. |
| Cluster | `cluster_namespaces` | Array of DNS-1123 namespace names created before secrets. |
| | `cluster_secrets` | Array of `{namespace, name, type?, data: {key: vault key}}`. |
| NATS | `nats_chart` | Object `{chart, repo, version, namespace, values}`; values MUST expose the client port on the mesh address. Required. |
| | `nats_probe_port` | Integer client port reached over the mesh, default 4222. |
| | `nats_expect_server_name` | Optional string the INFO banner's `server_name` must equal. |
| DNS | `cloudflare_zone_id` | Zone id (an account identifier, not a secret). Required. |
| | `dns_record_name` | Fully qualified record name. Required. |
| | `dns_record_target` | `public` \| `mesh`: which address the A record points at. Required. |
| | `dns_ttl` | Seconds 60–86400, default 300. `proxied` is always `false`. |

The input schema MUST bound every string with a `pattern` (hostname, CIDR,
port, version, sha256, DNS-1123) so a malformed value fails before any step.

## 5. Provision steps

Jobs run in order, each `dependsOn` the previous with `succeeded`; inside a job
each step `dependsOn` the one before with `succeeded` unless noted. `pub` is the
server's public IPv4 (`steps.create.outputs.public_ipv4`, refreshed by
`wait-ready`); `mesh` is `mesh_node.address` without its prefix length. "SSH
block" = `{host, user, port, host_key_policy, host_keys: known_hosts,
private_key: vault.get(secrets_vault, ssh_private_key_key)}`.

| # | Job / step | Call | Description (literal) | Consumes | On failure |
|---|---|---|---|---|---|
| 1 | preflight / `check-inputs` | `assert` | Check cross-input invariants before any remote call | inputs | Run stops; nothing created. |
| 2 | preflight / `probe-server` | servers `list` | List the project's servers via the Cherry Servers API | `project_id` | Stops (bad Cherry token, wrong project). |
| 3 | preflight / `probe-record` | dns-records `lookup`, `allowFailure: true` | Look up the target A record via the Cloudflare API | zone, name, token | Absent record is the expected failure; see §9 Q1 for token errors. |
| 4 | preflight / `refuse-existing` | `assert` | Refuse an existing server or record unless adopt is set | 2, 3, `adopt`, `ownership_tag` | Stops before any order (§7). |
| 5 | host / `create` | servers `create` | Order or adopt the server via the Cherry Servers API | inputs, tags + `ownership_tag`, user data from vault | Stops; an accepted order is billed and left for teardown. |
| 6 | host / `wait-ready` | servers `wait_ready` | Wait for SSH with pinned host keys via the Cherry Servers model | `known_hosts`, policy | Stops; host left for teardown or resume. Guarded off on adopt (step 9 proves reachability instead). |
| 7 | host / `apply-base` | server-host `apply_base` | Apply base packages, admin user and sysctl via SSH | SSH block at `pub` | Stops; idempotent on resume. |
| 8 | host / `join-mesh` | wireguard-mesh `apply` | Render and push the node's WireGuard config via SSH | SSH block at `pub`, mesh inputs, wg key from vault | Stops; nothing armed yet, public SSH still open. |
| 9 | host / `verify-mesh` | wireguard-mesh `get` + `assert` | Verify a recent peer handshake via wg show | 8, `mesh_handshake_max_age_s` | Stops **before any firewall change**. |
| 10 | harden / `apply-firewall` | server-host `apply_firewall` | Apply the nftables ruleset with a revert armed first | SSH block at `mesh`, firewall inputs | Stops; if armed, the revert fires host-side. |
| 11 | harden / `verify-firewall` | ssh-host `wait_connection` | Verify SSH answers over the mesh after the firewall | SSH block at `mesh`, `verify_timeout_s` | Commit skipped; revert left to fire; run fails. |
| 12 | harden / `commit-firewall` | server-host `commit` | Commit the firewall by cancelling its armed revert | 10 `revert_token` | Guarded off when 10 returned no token (no-op re-apply). On error the revert fires; run fails. |
| 13 | harden / `lockdown` | server-host `lockdown` | Close public SSH to the management CIDRs with a revert armed | SSH block at `mesh`, `management_cidrs` | Stops; revert fires. |
| 14 | harden / `verify-lockdown` | ssh-host `wait_connection` + server-host `get` | Verify SSH over the mesh and management-only exposure | `mesh`, 13 | Commit skipped; revert restores public SSH; run fails. |
| 15 | harden / `commit-lockdown` | server-host `commit` | Commit the lockdown by cancelling its armed revert | 13 `revert_token` | Guarded as step 12. |
| 16 | cluster / `install-k0s` | k0s `install` | Install the SHA-pinned k0s binary and start the node via SSH | SSH block at `mesh`, k0s inputs | Wrong sha256 refuses before execution; stops. |
| 17 | cluster / `wait-k0s` | k0s `wait_ready` + `assert` | Wait for the node and system pods to be Ready | 16 | `ready:false` fails the assert; stops. |
| 18 | cluster / `kubeconfig` | k0s `kubeconfig` | Write the admin kubeconfig to the vault via k0s | sensitive output → `secrets_vault`/`kubeconfig_key` | Stops; nothing printed. Assert its server URL host equals `mesh`. |
| 19 | cluster / `apply-namespaces` | k0s `apply_manifests` | Create the cluster namespaces via the k0s manifest deployer | `cluster_namespaces` | Stops. Guarded off when the list is empty. |
| 20 | cluster / `apply-secrets` | k8s-secret `apply`, `forEach` over `cluster_secrets` | Write each cluster Secret from vault values via kubectl stdin | kubeconfig + data from vault | Stops; earlier Secrets stay (idempotent on resume). |
| 21 | cluster / `apply-nats` | k0s `apply_helm` | Reconcile the NATS chart via the k0s Helm extension | `nats_chart` | Stops; no DNS. |
| 22 | verify / `probe-nats` | `command/shell` `execute` | Read the NATS INFO banner over the mesh via a TCP probe | env `NATS_HOST=mesh`, `NATS_PORT` | Retries until `verify_timeout_s`, then fails; no DNS. |
| 23 | verify / `check-nats` | `assert` | Check the banner is NATS INFO with the expected server name | 22 stdout | Stops; **no DNS record is created**. |
| 24 | publish / `create-record` | dns-records `create` | Create the host's A record via the Cloudflare API | `pub` or `mesh`, zone, name, ttl, comment marker | Stops; a host without a name is safe. Guarded off when step 3 found a matching adopted record. |
| 25 | publish / `verify-record` | dns-records `sync` + `assert` | Re-read the record and check it points at the host | 24 | Run fails; record left for teardown. |

Rules:

- The probe in step 22 MUST be a fixed script reading `NATS_HOST` and
  `NATS_PORT` from `env`; no input is interpolated into `run`. It passes when the
  first line starts `INFO {` and parses as JSON with a `server_id`. It SHOULD
  also complete a `CONNECT`/`PING`→`PONG` exchange (credentials, if the server
  requires them, over stdin from the vault).
- Every SSH step from 10 onward targets `mesh`, never `pub`. The control host
  running the workflow MUST be a mesh peer (or inside `management_cidrs`); this
  is a documented precondition.
- **At most one armed revert is outstanding.** Step 13 MUST NOT start until 12
  has committed. `verify_timeout_s` < `revert_after_s` is checked in step 1 so
  verification cannot outlive the revert window.
- The kubeconfig MUST NOT pass through `steps.*` outputs, logs or `--json`; steps
  20–21 read it with `vault.get(inputs.secrets_vault, inputs.kubeconfig_key)`.
- The DNS record `comment` MUST carry an ownership marker
  (`managed-by=provision-server-host host=<hostname>`); teardown relies on it.

## 6. Teardown (`teardown-server-host`)

Inputs (15): `hostname`, `confirm_hostname` (must equal `hostname`), `server_model`,
`project_id`, `ownership_tag`, `secrets_vault`, `ssh_private_key_key`,
`ssh_user`, `ssh_port`, `host_key_policy`, `known_hosts`, `mesh_address`,
`cloudflare_zone_id`, `dns_record_name`, `cloudflare_token_key`. DNS is removed
first, so the name never points at an IP that is about to be released.

| # | Step | Call | Description (literal) | On failure / re-run |
|---|---|---|---|---|
| 1 | `check-inputs` | `assert` | Check the hostname confirmation before any change | Stops. |
| 2 | `sync-server` | servers `sync` | Refresh the recorded server via the Cherry Servers API | `not_found` is fine. |
| 3 | `check-ownership` | `assert` | Refuse a server that lacks the ownership tag | Stops before anything is deleted; protects untagged live hosts. Passes when the server is already gone. |
| 4 | `find-record` | dns-records `lookup`, `allowFailure: true` | Look up the host's A record via the Cloudflare API | Absent → steps 5–6 skip. |
| 5 | `check-record` | `assert` | Refuse a record without this host's ownership marker | Stops; record and server untouched. |
| 6 | `delete-record` | dns-records `delete` | Delete the host's A record via the Cloudflare API | 404 is `existed:false`, a no-op. |
| 7 | `reset-k0s` | k0s `reset`, `allowFailure: true` | Stop and reset k0s over the mesh via SSH | Guarded off when step 2 is `not_found`. Best effort: the server delete destroys the disk; failure is recorded, not hidden. |
| 8 | `delete-server` | servers `delete` | Delete the server after hostname and project checks | Repeat is a no-op on `not_found`. |
| 9 | `verify-cherry` | servers `list` + `assert` | Verify no server with this hostname remains in the project | Run fails; residue named. |
| 10 | `verify-dns` | dns-records `lookup` + `assert` | Verify no record with this name remains in the zone | Run fails; residue named. |

Teardown MUST be idempotent: a second run against a clean state skips or no-ops
every mutating step and passes steps 9–10. It does not remove peer entries for
this node from other mesh members (out of scope; see §9 Q2). It SHOULD delete
the `kubeconfig_key` vault entry (§9 Q5).

## 7. Safety (MUST)

1. **Never touch an existing live host.** Step 4 refuses when step 2 lists a
   server named `hostname` or step 3 finds a record named `dns_record_name`,
   unless `adopt: true`. With `adopt`, the existing server MUST carry
   `ownership_tag` and an existing record MUST already point at the host's
   address and carry the ownership marker; otherwise refuse. This is what keeps
   `cherry-servers` `create` (which silently adopts by hostname) away from a
   production server of the same name.
2. **Adopt goes over the mesh.** An adopted host may already be locked down, so
   with `adopt` steps 6–8 target `mesh` (step 6 is skipped) and the host MUST
   already be a mesh member.
3. **No commit without proof.** Steps 12 and 15 depend on 11 and 14
   `succeeded`; a failed or skipped verification leaves the revert to fire.
4. **No DNS before NATS.** Steps 24–25 depend on 23 `succeeded`.
5. **No credential in inputs, argv, logs or `--json`.** Never capture `--json`
   of a run that resolves the SSH key, WireGuard key or kubeconfig (lab 3555).
6. **Resume, don't re-run.** After a mid-run failure, `swamp workflow resume
   --run <id>` retries from the failed step. A fresh run against the half-built
   host needs `adopt: true` and passes the ownership check.

## 8. Live e2e matrix (CONVENTIONS §8)

Throwaway targets are hourly, tagged as end-to-end test hosts, with a
scratch record name in a zone the maintainer owns. Receipts into the shipping
extension's `LOGBOOK.md`. Every cell `pass` before `stable`.

| Cell | Run | Expected |
|---|---|---|
| a. provision | `provision-server-host` from its entry point, consumer inputs | All 25 steps succeed; NATS INFO read over the mesh; A record resolves to the host; public SSH closed from outside `management_cidrs`. |
| a2. revert fires | Run with a `management_cidrs` that excludes the control host's path | `verify-lockdown` fails, commit skipped, public SSH back after `revert_after_s`. |
| b. teardown | `teardown-server-host` | Cherry API lists no server by hostname or tag; Cloudflare API has no record by name; vault key gone. |
| b2. teardown again | Repeat b | Every mutating step skips or no-ops; verify steps pass. |
| c. adopt | Re-run a. on the live host with `adopt: true` | No second order, no second record, firewall/lockdown no-op (no revert armed), NATS still answers. |
| c2. refuse | Re-run a. on the live host with `adopt: false` | Step 4 refuses; Cherry and Cloudflare unchanged. |
| c3. foreign host | `adopt: true` on a server lacking `ownership_tag` | Refused at step 4. |
| d1. bad Cloudflare token | Vault key pointing at a revoked token | Fails in preflight, before any order (requires §9 Q1). |
| d2. wrong k0s sha256 | Altered digest | Step 16 refuses; nothing executed; no DNS. |
| d3. unreachable host | `mesh_node.address` with no peer route, or a dead mesh peer | Step 9 fails before any firewall change; no DNS. |
| d4. NATS not answering | Chart values that don't expose the port | Step 23 fails; no DNS record exists afterwards. |
| e. acceptance | The operator's private inputs from the private repo, beside the existing production host | a. passes; NATS answers; host left running. Before and after, the production server's Cherry state, its DNS record and its mesh handshake are unchanged (captured read-only). |

Cell e never runs teardown. Nothing in the production host's records may be
written; the only operations allowed against it are read-only lookups.

## 9. Open questions

1. **Cloudflare absence probe.** `dns-records` `lookup` throws on zero matches,
   so `allowFailure` cannot tell "absent" from "bad token". Options: file an
   issue upstream for a non-throwing lookup or `list`; or add a preflight step
   that verifies the token (e.g. via `@swamp/cloudflare/tokens`) so a failed
   lookup after it means absent. Recommend both; cell d1 depends on it.
2. **Mesh membership of existing peers.** `wireguard-mesh` pushes one node. The other
   peers (a hub/relay) must already list the new node's public key, or the
   handshake in step 9 fails. Updating them would touch live hosts. Recommend:
   pre-registration is a precondition, done outside this workflow.
3. **Name and package.** Neither name is `<kind>-<verb>-<object>`. Ship in a new
   `@randybias/server-host-stack` (depending on the six extensions and
   `@swamp/cloudflare/dns`), or in `@randybias/server-host`?
4. **Requirements on `server-host` and `k0s-cluster`.** The firewall MUST own its own nftables
   table and never `flush ruleset` (a re-apply after k0s would wipe CNI and
   kube-proxy rules); `lockdown` re-run with identical inputs MUST be a no-op
   with no revert armed; k0s `kubeconfig` MUST support storing to a named
   vault key. Confirm before those items freeze their contracts.
5. **`vaults:` allow-list and vault cleanup.** The vault name is an input, so a
   static `vaults:` list cannot name it, and there is no known workflow step that
   deletes a vault key. Accept omitting both, or add a small helper?

## Next version scope: 2026.10.17.5 (private replacement package)

Version 2026.10.17.5: the private replacement for `server-stack`.

- Blocked on Randy confirming the private package name (prepared in the
  private sibling repo; not recorded here, private names stay out of the public
  repo).
- Publish from the private repo branch already prepared (`visibility: private`,
  `audience: personal`): add a whole-tree leak-scan and gitleaks exemption for
  the instance-input directories, restore the CI triggers, re-run gates 0 to 9,
  push with `--visibility private --channel beta`, record `release.yaml`.
- Then deprecate every public `server-stack` version on the registry (never
  delete) and remove the gate-9 waiver for `server-stack` in this repo.
- Stretch, same package only: NATS TLS and token rotation.
- Kept infrastructure is never touched; the live instance adopts the new
  package later, by Randy's hand.
