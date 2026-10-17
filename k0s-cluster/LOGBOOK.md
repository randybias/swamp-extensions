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
