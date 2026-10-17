# Spec: `@randybias/ssh-host` — host transport (SSH exec and payload upload)

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public.

Q2: General usage: anyone who runs commands or pushes files to a host over OpenSSH.

Q3: Yes. `ssh-host` names the system (`ssh`) and the resource (a host reached over it); the convention's own example of a qualified "host"; short and unambiguous. Naming audit verdict: keep.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads `ssh-host` as an SSH-reached host (exec and upload under a strict host-key policy), which is what it does, and guesses wrong about nothing.

Status: implemented and published; the canonical transport vendored by the other SSH
extensions. The next-version scope is at the end.
Not clean-room (net-new / adoption). RFC 2119 keywords.

## 1. Purpose

`wireguard-mesh`, `server-host` and `k0s-cluster` all need to
run a command on a remote host over SSH and push a file (a rendered config, a
unit, a binary) to it, under a strict host-key policy and with no credential on
argv. This item decides **how** those extensions get that transport, and
delivers it.

## 2. First task: evaluate, do not build yet

Pull and read both candidates before writing any code, and report with a
recommendation:

- `@swamp/ssh` (first-party, v2026.10.16.1): "Run commands, copy files, and
  open port forwards across a declared set of hosts over SSH."
- `@keeb/ssh` (v2026.07.18.1): "exec, upload, wait for connection."

For each, establish from its real source and `swamp model type describe`:

1. **Host-key policy.** Does it support a *strict* pinned-host-key mode, or only
   `StrictHostKeyChecking=no`? CONVENTIONS §7 requires an explicit strict vs.
   explicitly-insecure input — a silent `no` disqualifies it as-is.
2. **Credential path.** Key/password over stdin, header or askpass — never on
   argv (`/proc/<pid>/cmdline`) and never captured in `--json`.
3. **Shape of reuse.** Can 3/4/5 *depend on* its model (declare a host set, call
   an exec/upload method), or does the cherry-servers pattern (shell out to the
   `ssh` binary via a copied `_lib/` helper) fit better? cherry-servers today
   has its own `_lib/ssh_probe.ts` and depends on no SSH extension.
4. Injection surface on any caller-supplied argument reaching the remote shell.

**Escalate the adopt-vs-build decision.** Three outcomes:

- **Adopt** a candidate as a published dependency of 3/4/5, if it meets the
  host-key and credential bars. Deliverable then is: an integration note in this
  repo plus a worked example and a live test proving 3/4/5 can call it.
- **Adopt the helper pattern:** write one shared transport helper this repo
  owns, copied into each consuming extension's `_lib/` (small, reviewed once).
- **Build** `@randybias/ssh-host` as a thin generic model, only if neither
  candidate nor the helper pattern is adequate.

The rest of this spec is the contract if we build (outcome 3) or shape the
shared helper (outcome 2).

## 3. Model contract (if built)

- **Type** `@randybias/ssh-host`. CalVer version == manifest version.
- **`globalArguments` empty.** Every method takes its SSH target as arguments,
  so one definition serves any host. State, if any, is keyed by `host`
  (the instance value), never by the definition name.
- **Factory with overridable deps** (process spawner, clock, sleep) so unit
  tests spawn no process and open no socket. Production export = factory with no
  overrides.

### Methods

| Method | Kind | Description |
|---|---|---|
| `exec` | action | Run one argv on the host over SSH; returns `{stdout, stderr, exit_code}`. Caller argv is passed as an argument vector, never interpolated into a shell string. |
| `upload` | action | Write bytes (from stdin or a vault value) to a path on the host, mode settable, atomic (temp + rename). Returns `{path, bytes, sha256}`. |
| `wait_connection` | action | READ-ONLY. Poll until the host answers SSH with the expected host keys, up to a timeout; returns `{reachable, host_keys}`. |

If a candidate is adopted instead, 3/4/5 consume *its* equivalents; map them in
the integration note.

### Inputs (every method)

- `host` — hostname or IP (string, required).
- `port` — 1–65535, default 22.
- `user` — remote username (string, required).
- `host_key_policy` — **required**, one of `strict` (pinned) or
  `insecure_tofu` (explicitly trust-on-first-use). No default. In `strict`,
  `host_keys` (a list of `ssh-keyscan`-format lines) is required and is the only
  accepted set.
- `private_key` — `.meta({ sensitive: true })`, delivered over stdin or a vault
  ref, never argv. (Or `password` via askpass; key preferred.)
- `connect_timeout_s` — 1–120, default 15.

Use strict `z.object`, no `.passthrough()`. Secrets marked sensitive.

### Outputs

Typed objects as above. `exec` surfaces a non-zero remote exit code as data
(`exit_code`), not a thrown error, so callers can branch; a transport failure
(unreachable, auth, host-key mismatch) is an error.

## 4. Failure modes (each gets a test and a live cell)

| Mode | Expected |
|---|---|
| Host unreachable / connect timeout | Clean typed error naming the host (no key material in the message). |
| Auth failure (wrong key) | Typed error, no secret leaked. |
| Host-key mismatch in `strict` | Refuse, do not connect, do not TOFU. |
| Remote command exits non-zero | `exec` returns `exit_code != 0`; not an exception. |
| Injection attempt in an argv element | Passed as a literal argv element; never splits into a second command. Tested with `; rm -rf /`, `$(...)`, backticks, newline. |
| `upload` to an unwritable path | Typed error; no partial file left (atomic temp+rename). |

## 5. Tests (offline, increasing risk)

1. Schema/secret/license defects (sensitive marking, strict object).
2. Pure mapping: argv assembly for `ssh`/`scp`, host-key file assembly — assert
   **no secret and no shell metacharacter interpolation** in the spawned argv.
3. Failure + adversarial: every row in §4, injection on every remote-bound
   input, in every language the value crosses.
4. Packaging.

Fixtures synthetic only: RFC 5737 IPs (`192.0.2.0/24`), `example.com`/`.test`
names, placeholder keys.

## 6. Live e2e matrix (throwaway host)

| Cell | Target | Expected |
|---|---|---|
| exec success | hourly VPS | exit 0, stdout captured |
| exec non-zero | VPS | `exit_code` set, no throw |
| upload + read back | VPS | sha256 of pushed file matches |
| wait_connection | VPS | reachable, host keys == `ssh-keyscan` |
| strict host-key match | VPS | connects |
| strict host-key mismatch | VPS (wrong pin) | refuses |
| unreachable host | 192.0.2.1 | typed timeout error |
| auth failure | VPS, wrong key | typed error |
| injection literal | VPS | metacharacters land as literal argv |
| idempotent re-run | VPS | `upload` same bytes = no-op/identical sha |

Every executed cell writes a receipt (content hash, cell, result) into
`ssh-host/LOGBOOK.md`. A skip or an absent failure is never a pass.

## 7. Notes carried from cherry-servers (apply here)

- A method literally named `delete` tombstones the whole model — use
  `kind: "action"` for any mutating verb; none of the three methods here is a
  model `delete`.
- `swamp model method run --json` echoes `methodArguments`, sensitive ones
  included (lab 3555). Deliver the key over `--stdin`; never capture that stdout.
- Ubuntu 24.04 socket-activates sshd; a cloud-init that changes the SSH port
  must restart `ssh.socket` (relevant to callers, note in README).

## Next version scope: next

Next `ssh-host` version (public, beta).

- This is the canonical transport: any finding in `_lib/ssh.ts` is High for
  every vendor, and triage treats it so.
- Residual Mediums: two concurrent first-use TOFU calls race on the pin write;
  argv has no allowlist grammar beyond the NUL check; `ssh-keyscan` output is
  not capped; a target with no `sha256sum` fails only after the rename; the
  post-rename check takes the first stdout token, so a printing forced-command
  wrapper fails the upload; `maxOutputBytes` caps stdout only.
- Add the typed pre-auth error kind that `cephadm` asked for.
- Live: the published options were exercised against a container sshd only;
  run the full VPS matrix (23 cells) on this head.
- The resulting blob becomes the canonical target for the following round of
  re-vendoring; the current round keeps `8f132c43`.
