# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-17: initial model (`@randybias/k0s-cluster`, 2026.10.17.1). Net new:
  the registry has no k0s extension. Layout mirrors cherry-servers: model entry
  point plus `_lib/` helpers, a sibling `_test.ts` for every `.ts`, golden
  fixtures under `_lib/testdata/`.

## Design decisions

- **Transport seam.** All remote work goes through `_lib/ssh.ts`, whose
  functions take an injectable `Spawner`. The model's `K0sDeps` carries an
  `SshTransport`, so unit tests call model methods with fakes and never open a
  socket. The canonical `_lib/ssh.ts` from the shared ssh-host transport is
  vendored in later behind this interface; the production `createSshTransport`
  here uses a per-call `ssh-agent` (key over stdin) and a throwaway
  `known_hosts` file, so the key never reaches argv and trust never outlives a
  call.
- **Host-key policy is required** (`strict` or `insecure_tofu`), never a silent
  default. `strict` refuses before any connection when no keys are pinned. The
  schema keeps the policy as data and `_lib/ssh.ts` enforces it.
- **globalArguments empty.** Every method takes the SSH target and cluster
  inputs per call, and state is keyed by `ssh.host`, so one definition serves a
  fleet. This follows the item spec, which overrides the usual
  definition-with-inputs shape.
- **Mutations are `kind: "action"`.** A method named `delete` would tombstone
  the whole model; `reset` is therefore an action, matching the lesson from the
  server extension.
- **SHA-256 before execution.** `install` verifies the downloaded artifact
  against `k0s_binary_sha256` and refuses on a mismatch before uploading or
  running anything. Tests cover both the match and the mismatch branch.
- **kubeconfig is sensitive output only.** `kubeconfig` stores the text in a
  resource field marked `.meta({ sensitive: true })`, so swamp writes it to the
  vault. The method returns only the SHA-256 and server URL, and never logs the
  text. A regression test runs the method with a fake kubeconfig and asserts the
  returned value and the logs contain no kubeconfig-shaped material, plus a
  static check that no production source embeds key or certificate material.
- **k0s.yaml does not carry manifest stacks.** k0s reads stacks as files under
  `/var/lib/k0s/manifests`; `render_config` returns the config text and a
  deterministic plan of the stack layout. Golden fixtures cover the single node,
  the Helm block, and the manifest-stack layout.
- **Helm reconcile** writes `k0s.yaml` only when its digest changed, restarts
  the controller only then, and waits for the Helm release secrets to appear. A
  chart that never reconciles fails with the missing release named, and `get`
  still surfaces partial state.
- **Worker role.** `role: worker` writes `join_token` to `/etc/k0s/worker-token`
  (mode 0600) over stdin and installs `k0s worker --token-file`. `wait_ready`,
  `get` and `sync` need a control plane, so they apply to `single` and
  `controller`.

## Fixtures

- All addresses are RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`), names are
  `example.com` or `.test`, and the key is a placeholder string, never a PEM.
- The fake kubeconfig in the tests carries no real material.

## Live end-to-end status

- Offline gates green. No live pass yet, so this version is `beta`. The live
  matrix in the item spec is the lead's slot. On a `kubeconfig` success the
  value is handed to the k8s-secret item through the vault, never stdout.
- Pin an exact k0s version in the README only after a live pass.

## Review findings

Review round 1 (codex astra + terra; the ocr sonnet5/glm seats timed out at the
10-minute wall and rerun on this revision). All High and Medium findings fixed;
Low findings fixed as noted.

- HIGH-1 transport failure treated as data. `_lib/ssh.ts` now raises a typed
  `SshError` on a local `ssh` failure (exit 255 or a spawn error) instead of
  returning it as an exit code, and `classifySshFailure` maps known diagnostics
  to a fixed reason. `wait_ready` no longer swallows errors, and `get`, `sync`
  and `reset` write no state when the host cannot be reached. Tests cover 255,
  wait_ready and get transport failures, and the no-write guarantee.
- HIGH-2 reset ignored failed cleanup. `reset` now checks `k0s stop`,
  `k0s
  reset` and the `rm -f` cleanup and writes the reset state only when all
  three succeed. A test covers the cleanup-failure path.
- HIGH-3 download URL credentials. A URL that embeds user info is rejected by
  the schema; a mirror token comes from the sensitive `k0s_download_token` input
  or `K0S_DOWNLOAD_TOKEN` and is sent as an `Authorization` header; and
  `redactUrl` strips user info, query and fragment from every error message.
- HIGH-4 remote stderr leaked. The model no longer reflects remote stderr into
  errors or state; failures name the operation and exit code. The transport's
  upload error drops remote text, and 255 reasons come from a fixed allowlist.
- HIGH-5 unsafe upload temp file. Uploads now run under `umask 077` and write to
  a `mktemp` file unique to the destination directory before an atomic rename,
  so a join token is never briefly world-readable and a pre-created symlink
  cannot redirect the write.
- MEDIUM-6 Helm values. `values` is a bounded JSON object (depth 8, 128 entries
  per level, 64 KiB) marked sensitive, and `render_config` returns a redacted
  render (`values_redacted: true`) and writes no file whenever values are
  present.
- MEDIUM-7 deletion path injection. `apply_manifests` lists stack files with
  `find -type f`, validates every relative path segment and the full path before
  deleting, and fails if a stale file cannot be removed.
- MEDIUM-8 hardcoded private CIDRs. The pod and service CIDRs have no baked
  defaults; callers must supply them.
- MEDIUM-9 duplicate manifest paths. The stack schema rejects duplicate paths
  after normalization, before any remote change.
- MEDIUM-10 adoption without pin verification. Adoption now re-verifies the
  installed binary SHA-256 and the running k0s version and refuses on either
  mismatch.
- MEDIUM-11 descriptions. The model carries a description; `apply_manifests`
  starts with `DESTRUCTIVE.`; `wait_ready` and `kubeconfig` start with
  `READ-ONLY.`
- LOW-1 unused transport code. `waitConnection`, `ReachResult` and the
  `SshTransport.waitConnection` member were removed.
- LOW-2 duplicated grammars. Host, user, name, path, mode, filename and URL
  grammars moved to `_lib/grammar.ts` and are imported by the transport and the
  model. LOW-3 `podView` was removed; `PodStatus` already matches the schema.

- 2026-10-17 escalation round (Claude): the homegrown transport was replaced by
  the shared SSH transport (`_lib/ssh.ts`, byte-identical to the SSH host
  extension) behind a thin `_lib/transport.ts`.
  - HIGH-1 role clobber: both `k0scontroller` and `k0sworker` units are checked
    before install; a different installed role is refused unless
    `allow_role_change`, which stops and resets it first.
  - HIGH-2 restart exit ignored: restart results are checked and the unit (and
    for a controller `/readyz`) must turn healthy before state is written.
  - HIGH-3 kubeconfig server URL: user info, query and fragment are dropped.
  - HIGH-4 keying: records are keyed by user, host and port.
  - HIGH-5 ephemeral TOFU: keys are learned once, recorded, and pinned for every
    later call; the shared transport verifies against them.
  - HIGH-6 secret uploads: config, token and manifests are mode 0600 in
    root-only directories.
  - HIGH-7 URL credentials: query, fragment and user info are rejected.
  - MEDIUM: join token now sent only on a fresh install; config and manifest
    digests are sensitive or omitted; manifest paths that normalize to nothing
    are rejected; `k0s stop` failures are checked; strings keep their type in
    rendered YAML and Helm values (JSON); `install` and `apply_helm` start with
    `DESTRUCTIVE.`
  - Receipts: live cells still blocked until a host is provided.
- 2026-10-17 verification round: uploads always go through the shared
  transport's convergence (bytes and mode), so an existing file with the right
  bytes under a looser mode is tightened to 0600 and a changed result, not a
  digest shortcut, decides whether to restart. A role change now downloads and
  verifies the replacement before stopping or resetting anything and needs
  `confirm_role_change` to equal the host; a failure after the reset cannot
  restore the old role, so it is reported and state records nothing installed.
- 2026-10-17 conformance round: Helm charts are now written with the generated
  repository name as the chartname prefix (it did not resolve before).
  `apply_helm` waits until the latest release revision is `deployed` and the k0s
  `Chart` resource reports the requested chart version, and fails at once on a
  `failed` release; the Chart `status.version` field is read from the CRD and is
  unverified against a live cluster. Also: a failed manifest listing stops the
  call, a partial stack upload names the files that landed, `reset` and
  `install` treat only systemd's "not found" as an absent unit, an installed but
  stopped unit is started rather than reinstalled, a failed restart puts the
  previous k0s.yaml back, IPv6 CIDRs are parsed strictly, and remote-bound
  strings have length caps. Residual: manifest stacks are not applied
  atomically. Transport resynced to ssh.ts cb61c4ad.
- 2026-10-17: `single` and `controller` share the k0scontroller unit, so the
  unit's own `ExecStart` is read (`--enable-worker` or not) and a mismatch with
  the requested role is treated as a role change: refused without
  `confirm_role_change`, reset and reinstalled with it. The ExecStart format
  from `systemctl show --value` is unverified until a live run.
- 2026-10-17: `kubeconfig` takes `store_in_vault` ({vault, key}) and writes the
  kubeconfig there through `context.vaultService.put`, which is not part of the
  documented method context. It was found by probing a real run (the put works
  and the key lists afterwards); the method checks for it by shape and fails
  clearly if a swamp version drops it. The stored record then holds the vault
  and key names, not the value.
- 2026-10-17: `api_address` (validated IP) renders into `spec.api.address` and
  is always a SAN; `kubeconfig` takes `api_address` and `api_port` and rewrites
  the server URL of the returned and vaulted kubeconfig from them. Whether k0s
  itself writes the mesh address into its kubeconfig is unverified until a live
  run, which is why the method sets it explicitly.
- 2026-10-17: live bug: role `single` installed `--enable-worker` without
  `--no-taints`, so the node kept the control-plane NoSchedule taint and no
  workload (the Helm controller included) ever scheduled. `single` now installs
  with `--enable-worker --no-taints` rather than `--single`, which also switches
  the datastore to kine and would override `storage_type`. The installed mode is
  read from the `argv[]=` field of the real `systemctl show -p ExecStart` struct
  and classified as single, controller+worker (the old tainted mode) or
  controller; any mismatch with the requested role needs `confirm_role_change`.
  The pinned-version behaviour of `--no-taints` is from the k0s docs, not tried
  here: swamp-live's re-run is the check.

## 2026-10-17: live e2e

Target: `<vps2>` (4 GB, Ubuntu 24.04 x86_64, root, strict host-key pins, SSH key
from vault). k0s v1.36.4+k0s.1 amd64, binary SHA-256 matching the release's
`sha256sums.txt` and an independent download. Heads: lane/b2 `6554ea0` (base
cells), `3cc23a3` (role migration, no taint, api_address), `27a214e` (reset;
transport resync only). Receipt = first 16 hex of sha256 of the console output
with timestamps stripped. Addresses, node names and vault names are redacted.

| Cell                                            | Result    | Detail                                                                                               | Head      | Receipt          |
| ----------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------- | --------- | ---------------- |
| render_config                                   | PASS      | rendered                                                                                             | `6554ea0` | 6c91fe1d6a2d9bc3 |
| install bad SHA (negative)                      | PASS      | refused before anything ran; no binary, no unit left                                                 | `6554ea0` | 96b9e8e1cf933a0b |
| install (SHA ok)                                | PASS      | k0scontroller active; config_sha256 equals render_config's                                           | `6554ea0` | 822719b134592bf8 |
| wait_ready                                      | PASS      | ready after 59 s, 5 system pods                                                                      | `6554ea0` | 0e06b84496798ba8 |
| kubeconfig (store_in_vault)                     | PASS      | key present in the vault; kubeconfig-shaped console text 0                                           | `6554ea0` | 8c93f98b2bba232d |
| kubeconfig usable                               | PASS      | vault copy reaches the API; server equals the recorded URL; node Ready                               | `6554ea0` | -                |
| apply_manifests                                 | PASS      | namespace and configmap appear in-cluster                                                            | `6554ea0` | 820f7080f13f8c51 |
| apply_manifests idempotent                      | PASS      | configmap uid.resourceVersion unchanged; changed false                                               | `6554ea0` | ddc4f3fcb587b1d2 |
| apply_helm bad version (negative)               | PASS      | typed "Helm release ... failed"                                                                      | `6554ea0` | 924f1053c76a0deb |
| apply_helm before the taint fix                 | FAIL      | pod Pending on the control-plane NoSchedule taint (role single lacked --no-taints); fixed in 3cc23a3 | `6554ea0` | -                |
| apply_helm (taint removed by hand, diagnostic)  | PASS      | hello-world 0.1.0: 1 pod Running                                                                     | `6554ea0` | 70f74cc38e79580c |
| get                                             | PASS      | installed, version, 1 node, 5 system pods, stacks, helm_releases                                     | `6554ea0` | 6dd23b33f196a48d |
| sync                                            | PASS      | no drift                                                                                             | `6554ea0` | 3607c8ddfe773880 |
| install re-run without the helm block           | EXPLAINED | k0s.yaml rewritten without the applied Helm extension and the controller restarted; now in README    | `6554ea0` | 281c25eb91fc54e2 |
| install idempotent (same inputs)                | PASS      | MainPID and config SHA unchanged                                                                     | `6554ea0` | 7a69bda18b4d0860 |
| M1 role migration without confirm (negative)    | PASS      | refused; MainPID, ExecStart and config identical                                                     | `3cc23a3` | 021424dd2c8d17d5 |
| M2 role migration with confirm_role_change      | PASS      | stop/reset/reinstall; ExecStart has --enable-worker=true --no-taints=true                            | `3cc23a3` | ea9ec155934c7470 |
| M3 wait_ready after migration                   | PASS      | ready after 66 s                                                                                     | `3cc23a3` | acd67cfd686d707d |
| M4 kubeconfig store_in_vault after migration    | PASS      | overwrote the earlier copy; kubeconfig-shaped console text 0                                         | `3cc23a3` | c7b481df49b49e4c |
| M5 no control-plane taint                       | PASS      | node Ready, spec.taints empty                                                                        | `3cc23a3` | bf7d847e4a33fbf3 |
| M6 apply_helm on the migrated single node       | PASS      | 1 pod Running, no manual untaint                                                                     | `3cc23a3` | 13371e3dbc61dad8 |
| A1 render_config with api_address               | PASS      | spec.api.address set and in the SANs                                                                 | `3cc23a3` | 22c775e98dceefe9 |
| A2 install with api_address                     | PASS      | adopted the running node; k0s.yaml carries the address; controller restarted                         | `3cc23a3` | 3c3bf7f4802e281c |
| A3 wait_ready after the api_address change      | PASS      | ready after 3 s                                                                                      | `3cc23a3` | 6e54d62180aca30a |
| A4 kubeconfig with api_address (store_in_vault) | PASS      | recorded and stored server URL use api_address; cluster answers through it                           | `3cc23a3` | 17781ac947d66b71 |
| A5 apply_helm after the api_address change      | PASS      | 1 pod Running                                                                                        | `3cc23a3` | 83f6f5aa264d4e14 |
| R0 get (carry check)                            | PASS      | cluster answers before reset                                                                         | `27a214e` | 129e461b7cdd1995 |
| R1 reset with wrong confirm_host (negative)     | PASS      | refused; k0scontroller still active                                                                  | `27a214e` | 3369fbe8a614175a |
| R2 reset                                        | PASS      | no unit, no /var/lib/k0s, no process, k0s.yaml removed; residue below                                | `27a214e` | dbfb93f92a5db433 |
| R3 reset again                                  | PASS      | clean no-op                                                                                          | `27a214e` | 112a85f6e4784db1 |

An earlier apply_helm attempt on `6554ea0` (run right after the bad-version
negative, which left the chart controller wedged) is superseded by the cells
above. Every cell passes on the merged heads. Released on the beta channel.

Follow-up (reset leftovers): `reset` leaves the k0s binary
(`/usr/local/bin/k0s`) and k0s's own `/etc/k0s/containerd.toml` placeholder plus
an empty `/etc/k0s/containerd.d` on the host (cell R2; removed by hand after the
run). The README now says so. Decide whether `reset` removes them (an option to
remove the binary, and `/etc/k0s` when it holds only k0s's placeholders).

## 2026-10-17: merge prep and known residuals (2026.10.17.1)

Review-clean (no unrefuted Critical/High). Gate 7 needed the plain-object model
export (type and version repeated, checked with `satisfies`); no behaviour
change. Gate-8 report: `reviews/k0s-cluster/617b2313….json`. Residuals, MEDIUM
unless noted:

- `applyConfig` treats a failed `cat` of an existing `k0s.yaml` as absence, so a
  later failed restart removes it (raised HIGH, downgraded: as root this needs
  an I/O error, the file is a render of the caller's inputs and `install`
  recreates it). Distinguish "not found" from a read failure.
- `ensurePrivateDir` follows an existing directory symlink (raised HIGH,
  downgraded: planting one under `/etc/k0s` or the manifest dir needs root on
  the target). Reject symlink components.
- get/sync and apply_helm observation helpers turn some non-zero exits into
  empty results; rollback ignores the exit of `rm` and the recovery restart.
- ExecStart classifier matches `controller` and the first `true` flag anywhere
  in `argv[]`; require `/usr/local/bin/k0s controller` and last-occurrence
  flags.
- `kubeconfig` is described READ-ONLY while `store_in_vault` overwrites a key.
- Upload result returns the content SHA-256 (vendored transport, carried from
  ssh-host).
- LOW: `confirm_host`/`confirm_role_change` unbounded; ExecStart fixture copied
  from a live host; SSH grammars duplicate the transport's; test-only YAML
  serializer.

- 2026-10-17 (2026.10.17.2): `reset` now removes the `/etc/k0s` directory
  (including k0s's own `containerd*` placeholders) and the k0s binary, but only
  the binary at the recorded path whose SHA-256 still matches what `install`
  recorded; a differing or unrecorded binary is left in place. A host with no
  k0s unit is still a clean no-op, so a second reset does nothing. Three unit
  tests cover the matching, differing and unrecorded cases. Not yet run live.

## 2026-10-17: live e2e (2026.10.17.2)

Target: `<vps2>` (idle, root, strict host-key pins, SSH key from vault), the
same k0s v1.36.4+k0s.1 amd64 binary as above. Heads: lane/d3-k0s `356bb45`
(reset cleanup cells) and `3832bdf` (stopped-unit fix re-run). `50e2f2d` (refuse
unknown unit states, persist the removal outcome) was not run live; it is
reviewed against the 3832bdf diff only. Receipt = first 16 hex of sha256 of the
console output with timestamps stripped. Addresses, node names and vault names
are redacted.

| Cell                                                           | Result           | Detail                                                                                                                                                           | Head      | Receipt          |
| -------------------------------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ---------------- |
| 1 install single + wait_ready                                  | PASS             | unit active, binary digest recorded, node Ready                                                                                                                  | `356bb45` | acb13b3a7c01b0fe |
| 2 reset                                                        | PASS             | no unit, /var/lib/k0s, /etc/k0s, binary or process; state installed=false                                                                                        | `356bb45` | 7552cfe07bdebac4 |
| 3 reset again                                                  | PASS             | clean no-op ("No k0s service")                                                                                                                                   | `356bb45` | 8daa576ecfe25fee |
| 4 reset with a foreign binary (copy of /bin/true, k0s stopped) | PASS             | binary left in place and logged; see residuals                                                                                                                   | `356bb45` | 1a0aee20b2b864b3 |
| 5a reset with an immutable file in /etc/k0s                    | PASS             | "could not remove /etc/k0s"; state cleanup_pending=true, binary digest kept                                                                                      | `356bb45` | 3dae002f21f1e378 |
| 5b chattr -i, reset again                                      | PASS             | pending cleanup finished; nothing left                                                                                                                           | `356bb45` | a08550188f1570a7 |
| 6a failing k0s reset (wrapper exits 1)                         | PASS             | typed error; nothing removed, state unchanged                                                                                                                    | `356bb45` | b1d2f07b792f4b20 |
| 6b k0s binary non-executable                                   | PASS             | stops at k0s stop (exit 126); host and state unchanged                                                                                                           | `356bb45` | fec28c2d41b88b80 |
| F1 reset of an installed but stopped unit                      | FAIL             | k0s stop exits 1 "already stopped" and reset treated it as fatal; fixed in `3832bdf`                                                                             | `356bb45` | 2823f97fa0f130d2 |
| F1 install, systemctl stop, reset                              | PASS             | nothing left; state installed=false                                                                                                                              | `3832bdf` | 8127974c093eab4c |
| F1b install, reset while running                               | PASS             | nothing left; state installed=false                                                                                                                              | `3832bdf` | 666741df58f98132 |
| 4' foreign binary, unit stopped, reset                         | PASS (behaviour) | binary kept and logged; the binary_removed/reason result fields were not observable (swamp prints no method result without --json, ruled out for sensitive args) | `3832bdf` | 5fd3c8ffcac917a8 |
| 3 reset again                                                  | PASS             | clean no-op                                                                                                                                                      | `3832bdf` | 8daa576ecfe25fee |

Cells 1-6 pass on `356bb45` (6 of 6); F1 failed there and passes on `3832bdf`,
with F1b and 3. Final: `<vps2>` has no k0s unit, data, config, binary or
process; state installed=false.

## 2026-10-17: merge prep and known residuals (2026.10.17.2)

Review: `c5c84ab` CLEAN after triage (astra's cleanup-retry HIGH fixed in
`356bb45` with cleanup_pending; terra's two HIGHs downgraded below); `356bb45`
polish (typed sha256sum error, README warning, failing-reset test); `3832bdf`
reviewed by the live worker, no Critical/High; `50e2f2d` self-reviewed against
the triage checks, no Critical/High. `_lib/ssh.ts` is the canonical blob
`fe0139f0`. Residuals:

- MEDIUM: `reset` still runs whatever binary is at `/usr/local/bin/k0s` for
  `k0s stop` and `k0s reset`, even when its digest is not the installed one; it
  trusts their exit 0, so with a foreign binary the unit and `/var/lib/k0s` can
  remain while state records installed=false (cell 4). Check the digest before
  running stop/reset and refuse or report.
- MEDIUM (documented in the README): `/etc/k0s` is removed wholesale, including
  user drop-ins such as `containerd.d` and registry credentials, notably on
  adopted hosts (terra HIGH, downgraded: documented and the directory is
  k0s-owned).
- LOW: hash-then-`rm` race on the binary; a replacement written between the
  `sha256sum` and the `rm` is removed (terra HIGH, downgraded: needs a
  concurrent root writer on the target).
