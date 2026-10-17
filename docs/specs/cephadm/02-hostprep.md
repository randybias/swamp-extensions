# 02: Host preparation, package-source pre-flight, disk wiping

Status: draft for review · Part of the `@randybias/cephadm` behaviour
specification. Read `00-overview.md` first; its Decisions section wins over
this file.

Methods specified here:

| Method | Class | Description lead |
|---|---|---|
| `cephHostPrep` | M (idempotent converge) | none |
| `cephVerifyPackageSource` | RO | `READ-ONLY.` |
| `wipeDiskToRaw` | D | `DESTRUCTIVE.` |

`cephVerifyHostPrep` and `cephVerifyDisksRaw` are specified in
`05-verify.md`. They check what this file's mutating methods establish, so the
definitions of **ready host** (§1.6) and **raw disk** (§1.7) are stated here
and `05-verify.md` MUST use them unchanged.

## 1. Cross-cutting rules for this group

### 1.1 Connection arguments

Every method takes `host` plus the shared SSH argument family in
00-overview §3 (`sshUser`, `port`, `keyPath`, `privateKey`,
`strictHostKeyChecking`). Grammars, defaults and nullish handling are defined
there and in 01-transport.

- A method MUST NOT re-declare or narrow a shared field in its own schema.
  **Why:** a method that narrowed `port` rejected the explicit `null` that
  every workflow sends, while all other methods accepted it.
- The effective `strictHostKeyChecking` value MUST appear on the argv of every
  ssh call a method makes.
- When `port` is given, every ssh call MUST dial that port. **Why:** the
  control endpoint can differ from the cluster address (several nodes behind
  one gateway address, D57).

### 1.2 Input grammars used in this group

`host` and disk `serial` grammars are owned by 01-transport. Reminder, because
the serial selects disks on the destructive path: a serial is 1–40 letters,
digits or hyphens, and an injection-shaped serial (for example one containing
`;`, `$`, `/` or a space) MUST be rejected at schema time in both
`dataDevices` and `excludeDevices`, before any ssh call. The resolver
re-validates it (D3).

Grammars owned here:

- **`cephadmUrl`.** MUST parse as a URL whose scheme is `http` or `https`.
  The raw string as given (not a re-serialised parse) MUST NOT contain any of
  `;` `&` `|` backtick `$` `(` `)` `<` `>` or any whitespace.
  - Accept: `https://download.example.com/ceph/19.2.1/el9/noarch/cephadm`,
    `http://192.0.2.10:8080/cephadm`.
  - Reject: `file:///tmp/cephadm`, `ftp://example.com/cephadm`,
    `data:text/plain,x`, `//example.com/cephadm` (scheme-relative),
    `example.com/cephadm` (no scheme), `https://example.com/x;id`,
    `https://example.com/$(id)`.
  - Even after validation, the value MUST be single-quoted when placed in a
    remote command. Validation and quoting are both required; neither
    substitutes for the other.
- **Package names (D15).** Each item of `packages` MUST match the Debian
  package-name grammar: at least two characters, only lowercase letters,
  digits, `+`, `-` and `.`, and starting with a lowercase letter or digit.
  Architecture qualifiers and version pins are not part of the grammar.
  Names are still single-quoted on use.
  - Accept: `chrony`, `lvm2`, `podman`, `libstdc++6`, `python3.11`.
  - Reject: `Chrony`, `a`, `-y`, `.hidden`, `lvm2;reboot`, `lvm2 podman`,
    `chrony=4.3-2`, `chrony:amd64`.
- **`cephadmVersion` (D14).** A dotted release number of digits, as printed
  by `cephadm version`, for example `19.2.1`. Reject: empty, `19`, `v19.2.1`,
  `19.2.1;id`, `squid`.
- **`timeSyncService`.** A systemd unit name: letters, digits and `@ . _ : -`,
  optionally ending `.service`, at most 255 characters; single-quoted on use.
  Accept: `chrony`, `chrony.service`, `systemd-timesyncd.service`. Reject:
  empty, `chrony;id`, `../x`.
- **Every other free string** that reaches a remote command (volume-group
  names, md array paths, file paths, discovered mirror names) MUST be POSIX
  single-quoted: an embedded `'` closes the quote, is backslash-escaped and the
  quote is reopened.

### 1.3 Remote privilege rule

- Privileged commands run as `sudo -n -- <cmd>` passed to the remote login
  shell.
- Shell redirection is parsed by the unprivileged login shell. A root-owned
  file MUST therefore be written as `sudo -n -- tee <path> > /dev/null` with
  the content on stdin, never as a `sudo` command followed by `> path`.
  **Why:** the unprivileged shell opens the target path itself and fails on a
  root-owned file.
- LVM and mdadm discovery commands (`pvs`, `mdadm --examine`) MUST run as
  root. **Why:** run unprivileged, `pvs` prints a warning and reports nothing,
  and `mdadm --examine` cannot read a claimed disk, so teardown phases
  silently report "nothing to do".
- A tolerated non-zero exit tolerates only the command's own exit status. An
  ssh exit of 255, a connection-level failure or a timeout is always a typed
  transport error (D8) and is handled by the transport rules, never treated as
  "already done".

### 1.4 Serial-to-device resolution

Disks are always selected through the shared resolver in 01-transport
(D3–D6): it matches by-id links whose names end with `_<serial>` or
`-<serial>`, ignores partition links, proves that every match resolves to one
block device, and fails on zero or several devices. Callers in this file rely
on these properties:

- Resolution failures are configuration errors and always throw, attributed
  to the calling method's phase (for example `cephadm[wipe.resolve]:`), never
  to a shared label.
- The kernel name hint (`devHint`) is never used for selection. **Why:**
  kernel enumeration order is not stable across boots.
- A method that compares disks or looks them up in `lsblk` MUST use the single
  canonical block device the resolver proved (the `readlink -f` target), so
  that two serials aliasing one physical disk compare equal.

### 1.5 Records

- `cephHostPrep` writes resource `hostPrepResult`, key `cephHostPrep-<host>`.
- `wipeDiskToRaw` writes resource `wipeDiskResult`, key `wipeDiskToRaw-<host>`.
- `cephVerifyPackageSource` writes the shared verify-result record (D16),
  key `cephVerifyPackageSource-<host>`.
- The two mutating methods' keys MUST differ for the same host so neither
  overwrites the other.
- Lifetime, version retention and strict schemas follow 00-overview §4. Every
  field a method writes MUST be declared. **Why:** undeclared fields are
  silently stripped on write.

### 1.6 Definition: ready host

Shared by `cephHostPrep` (its goal) and `cephVerifyHostPrep` (its check, in
05-verify). A host is **ready** when all of the following hold:

1. Every requested package is installed according to `dpkg -s <pkg>` (exit 0).
2. `/usr/local/sbin/cephadm` exists and is executable.
3. `sudo -n -- /usr/local/sbin/cephadm version` exits 0 and the version token
   parsed from its output **equals** the pinned version (D13, D14).
   - The version token is the first whitespace-separated word after the word
     `version` in the output, for example `19.2.1` in
     `cephadm version 19.2.1 (<commit>) squid (stable)`.
   - Substring matching is forbidden. **Why:** a short label such as `19`
     would match the wrong release.
   - Output with no parsable token is "not the pinned version".
   - **[twin]** The parse MUST be tested against captured output of the
     pinned binary.
4. `systemctl is-active <unit>` prints exactly `active` after trimming.

Both methods MUST run the cephadm probe the same way, under sudo (D13).
**Why:** a binary that needs root would otherwise pass one check and fail the
other.

### 1.7 Definition: raw disk

Shared by `wipeDiskToRaw` (its post-check) and `cephVerifyDisksRaw` (in
05-verify). A disk is **raw** when its canonical device is present as a node
in one `lsblk -J -o NAME,PATH,MOUNTPOINT,TYPE,FSTYPE` read and:

1. its `fstype` is empty (this covers filesystems, `LVM2_member` and
   `linux_raid_member`);
2. it has no children of any type; each child is reported by its type
   (`part`, `lvm`, `raid1`, `md`, …), not all as "partitions" (D17);
3. no node in its subtree has a mountpoint.

A device absent from the `lsblk` read is **not observed** and MUST NOT be
reported raw. **Why:** "no children" on a device nobody saw certifies a disk
nobody looked at.

This is stricter than the wipe's in-use gate (§4 gate 3), which refuses only
mounted devices: an unmounted disk with signatures is exactly what the wipe
exists to clean.

---

## 2. Method: cephHostPrep

### Safety class
M: mutating, idempotent converge.

### Purpose
Make one host **ready** (§1.6) for cephadm: the named packages installed, the
pinned cephadm binary installed and reporting the pinned version, and the
named time-sync service active. Anything already true is left alone.

### Inputs

| Name | Type | Required | Default | Validation | Meaning |
|---|---|---|---|---|---|
| `host` + SSH family | – | as 00-overview §3 | – | §1.1 | Target host |
| `packages` | string[] | yes | none | ≥ 1 item; each matches the package grammar (D15) | Debian packages to ensure; the caller decides, there is no built-in list |
| `cephadmUrl` | string | yes | none | §1.2 URL grammar | Where to download the cephadm binary; the caller pins the release |
| `cephadmVersion` | string | yes | none | §1.2 version grammar | Pinned release; must equal the token parsed from `cephadm version` (D14) |
| `timeSyncService` | string | yes | none | §1.2 unit grammar | systemd unit that provides time sync; host policy, not assumed |
| `installRetryBudgetMs` | integer, nullish | no | none (absent, null or 0 means no retry) | integer ≥ 0; negative or fractional rejected | Total time the package phase may spend retrying |

### Preconditions
- Debian-family host with apt, dpkg and systemd.
- The SSH user has passwordless sudo.
- The host can reach its apt mirrors and `cephadmUrl`. `cephVerifyPackageSource`
  checks this in seconds and SHOULD run first.

### Behaviour

**Transport settings for this method.**
- The per-command time limit MUST be 15 minutes, well above the generic
  default in 01-transport. **Why:** a cold `apt-get install` of two packages
  took 15–60 s; a short limit killed working installs and reported them
  failed, after which they finished on their own. The limit only matters on
  failure, so a generous one costs nothing on a healthy run.
- The ssh connect timeout MUST stay at the transport's capped value and MUST
  NOT grow with the command limit. **Why:** otherwise an unreachable host
  takes 15 minutes to report.
- Connection multiplexing MUST be on: every call goes over one authenticated
  master per host (`-o ControlMaster=auto` with a `ControlPath` in a directory
  only the runner user can access) and carries a ServerAlive dead-master guard
  (for example `-o ServerAliveInterval=15 -o ServerAliveCountMax=3`, about
  45 s to detect a blackholed master; that then looks like an ordinary
  mid-session exit 255). **Why:** the method makes a dozen or more ssh starts
  per host and callers fan out over several hosts at once; sshd's
  `MaxStartups` throttling closed sessions during authentication and one
  host's install never started.
- The very last ssh call, on success and on failure, MUST be
  `ssh -O exit` for that master. It is best effort: it never throws and never
  masks the method's own error. Log `info` if the master closed, `warn` if not
  (a non-zero exit usually just means no master was listening).

**Steps.**
1. **Package phase** (rules below). Ends with every requested package present
   according to dpkg, or throws.
2. **cephadm.**
   1. `test -x /usr/local/sbin/cephadm`. The install path is fixed, not a
      parameter: it is where cephadm documentation and every later
      `cephadm shell` call expect it.
   2. If present, run the health probe of §1.6 item 3. Healthy only when it
      exits 0 and the parsed token equals `cephadmVersion`. If present but
      unhealthy (it crashes, for example a broken stub missing its Python
      dependencies, or it reports another version): log `warn`, treat it as
      absent, set `reinstalledBroken=true`.
   3. If absent or unhealthy:
      `sudo -n -- curl --fail --silent --show-error -o /usr/local/sbin/cephadm '<cephadmUrl>'`,
      then `sudo -n -- chmod +x /usr/local/sbin/cephadm`. Any failure throws
      `cephadm[hostprep.cephadm-install]:` with host, URL and cause.
   4. After installing, re-run the health probe. If it does not report the
      pinned version, throw `cephadm[hostprep.cephadm-verify]:` with expected
      and actual tokens. Success MUST NOT be reported on the download's exit
      code alone.
3. **Time sync.** `systemctl is-active '<unit>'`; active means trimmed stdout
   equals `active`.
   - Already active: no enable call.
   - Otherwise `sudo -n -- systemctl enable --now '<unit>'` (its own non-zero
     exit is tolerated), then re-check `is-active`. Still not active → throw
     `cephadm[hostprep.time-sync]:` naming the unit.
4. Write the record (§1.5).

**Package phase rules.**
- **The verdict comes from dpkg, never from the install command's exit
  status.**
- Each **entry** starts with one state read: a busy probe, then
  `dpkg -s '<pkg>'` for every package not yet confirmed. Present means
  `dpkg -s` exits 0; the version is its `Version:` field.
- **Busy probe**, run under sudo (an unprivileged `fuser` cannot see root's
  open files). The host is busy if `fuser` exists and finds a holder of
  `/var/lib/dpkg/lock-frontend` or `/var/lib/dpkg/lock`, or if `pgrep -x`
  matches `apt`, `apt-get`, `dpkg` or `unattended-upgr`. Fail-safe: only
  output that trims to exactly `idle` means idle; empty or any other output
  means busy.
- **Acting on the read:**
  - all requested packages present → the phase succeeds;
  - busy → count a busy wait, back off, re-enter. Never install over a running
    apt or dpkg;
  - idle with some missing → `sudo -n -- apt-get update`, then
    `sudo -n -- apt-get install -y <missing only, each quoted>`, then re-enter
    at once with no sleep. That re-entry's read is the verdict and does not
    consume budget.
- `alreadyPresent` per package is the answer from the first idle read. A
  package that becomes present is dropped from later reads and its dpkg
  version recorded.
- **apt exited 0 but the next idle read still shows a package missing** →
  throw `cephadm[hostprep.packages-absent]:` "apt reported success but dpkg
  does not show <pkgs>". Do not loop.
- **apt's own non-zero exit** (it ran and refused, for example "Unable to
  locate package") → fail fast with zero sleeps, after one `dpkg -s` read per
  pending package, as `cephadm[hostprep.apt-install]:` with `requested`,
  `stillAbsent`, `installedDespiteFailure` and apt's stderr. The message MUST
  say this is not a connectivity problem.
- **Exception, lock contention:** if apt's stderr says it could not get the
  dpkg lock or frontend lock, or that the lock "is held by process", the probe
  raced another apt. Treat it as busy (busy wait, back off, re-enter), not as
  an apt failure.
- **ssh transport failure** (D8) anywhere in an entry proves nothing about the
  packages. Record it (attempt number, kind, pre-session cause, message) and
  re-enter.
  - **Pre-session failure** (authentication refused, connection refused, name
    resolution failure, connect timeout, negotiation failure, or a session
    dropped during authentication): the command never ran.
  - **Anything else** (mid-session loss, including "connection reset by peer"
    after login): the command MAY HAVE RUN. The next entry's busy read is what
    prevents a re-send while that apt is still working; once idle, installing
    only what is still missing is safe. **Why:** misclassifying "connection
    reset by peer" as pre-authentication caused a blind re-send over a running
    apt.
- **Backoff.** Sleep before re-entry = min(30 s, 3 s × 2^n) + random jitter
  in [0, 3 s), clamped to the budget remaining; it never sleeps past the
  budget. Time comes from the injectable clock, jitter from the injectable
  randomness source, and sleeping from the injectable sleep (00-overview §2).
  There are no fixed settle windows or poll intervals.
- **Iteration bound.** Independently of the clock, entries are capped at
  ceil(budget / 3 s) + 2, so a frozen injected clock still terminates.
- **No budget (absent, null or 0).** Exactly one pass: read; install the
  missing ones if idle; re-read. A busy host or any ssh failure fails at once
  with zero sleeps, so a bad key fails in seconds, not minutes.
- **One extra verdict read after a mid-session loss.** If the budget or the
  iteration cap runs out and the last cause was a mid-session loss, perform
  exactly one more state read, never a wait or an install. If it finds the
  packages, succeed; if busy or still absent, give up.
- **Give-up classification**, naming the last blocking cause:
  - busy → `cephadm[hostprep.apt-busy]:` apt/dpkg still running after X ms of
    Y ms; nothing was installed over it.
  - pre-session → `cephadm[hostprep.ssh-pre-session]:` the install never
    started; the ssh cause in plain words ("authentication refused
    (publickey)", "connection refused", "host name could not be resolved",
    "connection timed out", "ssh negotiation failed"); points at ssh
    credentials or reachability, not apt or the mirror. If every recorded
    failure was a drop during authentication, the message instead says every
    session was dropped before it ran and to look at sshd (`MaxStartups` under
    concurrent fan-out) rather than apt or the mirror.
  - mid-session → `cephadm[hostprep.packages-absent]:` with one of two
    wordings. Host re-read after the loss: "still absent (confirmed by
    re-reading dpkg) and the last session MAY HAVE RUN". Host could not be
    re-read: "outcome UNKNOWN, not a confirmed absence; nothing was re-sent;
    re-run (idempotent) to re-read dpkg". A mid-session loss MUST NEVER be
    reported as "the install never started".
  - With no budget supplied, every give-up message adds that no retry budget
    was given, so nothing was retried.
- On success after any transport failure, log `warn`: the session failed but
  dpkg shows the packages, so success is reported on dpkg's evidence.

### Idempotency
On a ready host the second run issues no `apt-get` calls (every package reads
present on the first idle read), no download (cephadm present and healthy) and
no enable (time sync active); the record shows `alreadyPresent=true`
throughout. The method cannot tell a package this run installed from one an
earlier, partly failed run installed.

### Output / record
Resource `hostPrepResult`, key `cephHostPrep-<host>`:
- `host`
- `packages[]`: `name`, `alreadyPresent` (first idle read), `installedVersion`
  (dpkg `Version:`, when seen)
- `cephadm`: `alreadyPresent` (false if it was reinstalled), `path`,
  `version` (the parsed token observed after the final probe),
  `reinstalledBroken`
- `timeSync`: `service`, `wasActive`, `active`
- `packagePhase` (evidence, so a green run does not hide a retried one):
  `installAttempts` (install commands sent, re-sends included),
  `transportFailures`, `droppedPreauth`, `preSessionFailures`, `busyWaits`,
  `entries` (state reads), `elapsedMs`, `confirmedAfterTransportFailure`
  (packages were confirmed present only after a session had failed)
- Nothing sensitive.

### Post-verification
- Packages: the dpkg re-read is the verdict.
- cephadm: the health probe is re-run after install.
- Time sync: `is-active` is re-read after enable.
- **Not verified** (state in the description and README): that packages are
  the intended version or came from the intended mirror; that an installed
  package works; that another tool holds apt's lists lock (only apt, apt-get,
  dpkg and unattended-upgrades by process name, and the two dpkg locks, are
  seen).

### Failure modes

| Condition | Result |
|---|---|
| Missing required argument; package, URL, version, unit or host grammar violation; negative or fractional budget | Rejected at schema time, no ssh call |
| apt busy at give-up | `cephadm[hostprep.apt-busy]:` |
| Pre-session ssh failure at give-up | `cephadm[hostprep.ssh-pre-session]:`, cause in words |
| Mid-session loss at give-up | `cephadm[hostprep.packages-absent]:`, MAY HAVE RUN or UNKNOWN wording |
| apt exit 0 but dpkg still missing | `cephadm[hostprep.packages-absent]:` |
| apt non-zero, not lock contention | `cephadm[hostprep.apt-install]:`, fail fast |
| Download or chmod error | `cephadm[hostprep.cephadm-install]:` |
| Re-probe does not equal the pinned version | `cephadm[hostprep.cephadm-verify]:` |
| Time sync still inactive after enable | `cephadm[hostprep.time-sync]:` |

Every failure still closes the ssh master as the last call, and the error
thrown is the original one.

### Security
- `cephadmUrl` is fetched by root into a root-owned executable path, so it is
  both validated and single-quoted; a URL carrying `;` or `|` MUST NOT break
  out of the command.
- Package and unit names are validated and single-quoted.
- Host-key policy comes from `strictHostKeyChecking` (00-overview §3).
- No secret in records, logs or errors.

### Why
- Exit-status verdicts produced false failures: a session killed by its own
  timeout was reported as "install failed" while dpkg finished the install
  seconds later.
- Reporting a transport failure as an install failure sends operators to the
  mirror for a problem that does not exist; hence separate classifications
  for ssh pre-session, apt busy, apt install and packages absent.
- Concurrent fan-out triggers sshd's authentication throttling; one
  multiplexed master per host avoids it instead of retrying around it.
- A mid-session drop must never be re-sent blindly: the earlier apt may still
  be running.
- `test -x` is not health: a broken cephadm stub passed it and would have been
  reported "already present".

### Test obligations
- [ ] dpkg reports a package installed → no `apt-get` call for it;
      `alreadyPresent=true`.
- [ ] Some packages missing → `apt-get install -y` lists only the missing
      ones.
- [ ] Package name outside the Debian grammar (`Chrony`, `lvm2;reboot`,
      `chrony=4.3-2`) → rejected at schema time (D15).
- [ ] cephadm present and `cephadm version` prints the pinned token → no
      curl.
- [ ] `cephadm version` is invoked under `sudo -n --` (D13).
- [ ] cephadm present but `cephadm version` crashes → curl and chmod run;
      `reinstalledBroken=true`.
- [ ] cephadm present reporting another version → reinstalled.
- [ ] Pinned `19.2.1`, output reports `19.2.10` → not healthy (exact token,
      D14); pinned `19.2.1`, output reports `19.2.1` → healthy (D14).
- [ ] Fresh install whose re-probe still fails → throws
      `hostprep.cephadm-verify`, not success.
- [ ] cephadm missing → curl to `/usr/local/sbin/cephadm` and `chmod +x`,
      both under sudo.
- [ ] URL is single-quoted in the curl command; an injection-shaped URL is
      rejected at schema time; each rejected URL form in §1.2 is rejected.
- [ ] apt failure → error names `hostprep.apt-install`; curl failure → names
      `hostprep.cephadm-install`.
- [ ] Time sync already active → no `enable`; inactive → `enable --now` then
      re-check; never active → throws `hostprep.time-sync`.
- [ ] Record has per-package presence, cephadm presence and version, time-sync
      state and `packagePhase`; the schema accepts every field written.
- [ ] Required arguments have no default; injection host rejected;
      `strictHostKeyChecking` is on every ssh argv; explicit `port: null`
      accepted.
- [ ] Every remote call carries `ControlMaster=auto` and the ServerAlive
      options; exactly one `ssh -O exit`, and it is the last call, also when
      the run fails (the error is the original one).
- [ ] Command time limit > 60 s and > the generic default; `ConnectTimeout`
      on argv equals the capped connect value, not the raised limit.
- [ ] Install session fails mid-session but dpkg then shows the packages →
      success, `confirmedAfterTransportFailure=true`. Control: same failure,
      packages still absent → fails.
- [ ] Drop during authentication with a budget → retried with backoff; the
      second attempt lands.
- [ ] Budget 0 + mid-session failure → one install only; error is
      `hostprep.packages-absent` with "MAY HAVE RUN" wording, not "dropped
      before it ran".
- [ ] Pre-authentication drop then mid-session drop under budget → ≥ 2
      installs; final cause mid-session.
- [ ] Every session dropped during authentication → message names sshd and
      `MaxStartups`, "rather than apt".
- [ ] apt's own non-zero exit → fails fast, zero sleeps.
- [ ] Bad key (permission denied) with a 60 s budget →
      `hostprep.ssh-pre-session` naming authentication; no dpkg reads; total
      sleep ≤ budget; each sleep ≤ cap + jitter; sleeps grow until the cap.
- [ ] Bad key with no budget → one entry, zero sleeps.
- [ ] Connection refused on the first install, then success → success,
      1 pre-session failure, 2 installs.
- [ ] Busy for 3 reads then idle → no install before idle; exactly one
      install.
- [ ] Mid-session drop while apt keeps running → reads busy, then idle with
      the package present → installed once, confirmed after failure.
- [ ] Mid-session drop, apt died, package absent, idle → install re-sent once
      (2 installs).
- [ ] Host busy forever → `hostprep.apt-busy`; sleeps never exceed the
      budget; the last sleep is clamped to the remainder.
- [ ] Frozen clock → the iteration bound still terminates.
- [ ] Lock race (probe idle, apt exits 100 "lock held") → treated as busy;
      the next entry succeeds.
- [ ] "Unable to locate package" → `hostprep.apt-install`, zero sleeps.
- [ ] Budget schema: absent, null, 0 and 45000 accepted; negative and
      fractional rejected; no default.
- [ ] Busy probe runs under sudo and uses `fuser` and `pgrep`; `idle` → idle;
      `busy`, empty or garbage → busy.
- [ ] Mid-session drop with no budget → the one verdict read finds the
      packages → success, zero sleeps, nothing re-sent.
- [ ] Mid-session drop with no budget, host unreadable afterwards → error
      says outcome UNKNOWN, never a confirmed absence.
- [ ] Re-run on a ready host → no apt, curl or enable calls; all
      `alreadyPresent=true`.

---

## 3. Method: cephVerifyPackageSource

### Safety class
RO: read-only. Description starts with `READ-ONLY.`

### Purpose
A fast pre-flight for the network dependencies of `cephHostPrep`. For every
apt mirror the target itself is configured to use, plus the host of
`cephadmUrl`, report from the target whether the name resolves and whether
anything answers there. Each endpoint gets one of three outcomes, never a
boolean.

### Inputs

| Name | Type | Required | Default | Validation | Meaning |
|---|---|---|---|---|---|
| `host` + SSH family | – | as 00-overview §3 | – | §1.1 | Target host |
| `cephadmUrl` | string | yes | none | §1.2 URL grammar | The same pinned URL `cephHostPrep` will download |
| `throwOnFail` | boolean, nullish | no | `true` | – | Throw after recording a failing result (D16) |

There is no mirror-list argument. **Why:** the mirror is a fact about the
host; a passed-in mirror could be one the host does not use, and the check
would pass while the real one is broken.

### Preconditions
SSH access only. No sudo is needed or used.

### Behaviour
Two remote scripts, each sent over stdin in one round trip. No sudo, no
mutation.

1. **Discovery pass.** Print three sections separated by marker lines:
   - the contents of `/etc/apt/sources.list`,
     `/etc/apt/sources.list.d/*.list` and `/etc/apt/sources.list.d/*.sources`
     (missing files ignored);
   - `apt-config dump` filtered case-insensitively for `proxy`;
   - an empty probes section.

   Lines under an unknown marker are discarded, not filed under the previous
   section. Blank lines are ignored.
2. **Parse apt sources**, both formats:
   - skip blank lines and lines starting with `#`;
   - deb822: a `URIs:` line may list several space-separated URIs;
   - one-line format: `deb` or `deb-src`, an optional `[options]` group, then
     the URI;
   - only `http` and `https` URIs count (scheme compared case-insensitively,
     stored lowercase);
   - strip userinfo and port; the DNS name is what is probed;
   - deduplicate on scheme + name, keeping first-seen order;
   - a file with nothing usable yields an empty list.

   Examples: `deb [arch=amd64 signed-by=/usr/share/keyrings/k.gpg] http://deb.example.com/debian bookworm main`
   yields `http` + `deb.example.com`; `URIs: https://u:p@mirror.example.com:8443/ubuntu http://archive.example.com/ubuntu`
   yields `https` + `mirror.example.com` and `http` + `archive.example.com`;
   `deb file:/srv/repo ./` yields nothing.
3. **Probe pass.** For each discovered name (single-quoted) and for the host
   of `cephadmUrl` (scheme, userinfo, port and path stripped):
   - resolve with `getent hosts <name>` and join the addresses; none →
     record "no addresses";
   - otherwise run
     `curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -I <scheme>://<name>/`
     and record curl's exit code and the HTTP status.

   Resolution and reachability are measured separately, so "did not resolve"
   is observed, not inferred from a curl failure.
4. **Classify each probe line**, in this order:
   - no addresses → `cannot-resolve` (even though curl also failed; only the
     DNS answer counts);
   - curl exit ≠ 0, or status missing or `000` → `cannot-reach`, keeping
     curl's exit code so that refused and timed out stay distinguishable;
   - otherwise → `reached`, with the HTTP status. **Any** HTTP status counts
     (200, 301, 403, 404, 500): a server answering at the mirror root is
     reachable;
   - a malformed line (fewer than four fields) is ignored; no verdict is
     invented.
5. **Origin** per endpoint: `apt-source` if discovered from apt
   configuration, else `cephadm-url`. If the cephadm host is also an apt
   mirror, it appears once, as `apt-source`.
6. **Findings**, one per non-reached endpoint, each naming the system to go
   to:
   - `cannot-resolve` → DNS on the target (resolver, stub, search domain),
     not the mirror;
   - `cannot-reach` → resolved to <addresses> but nothing answered on
     <scheme>: routing, firewall or the mirror itself, not DNS (with curl's
     exit code when known).
7. Any expected endpoint (apt names plus the cephadm host) with no
   classifiable probe line gets the finding "NOT PROBED: nothing is known
   about it". A cut or empty probe output therefore fails every endpoint
   instead of passing.
8. No apt sources at all → `noSourcesFound=true` plus a finding. **Why:** a
   host with no sources cannot install, and an empty list must not pass
   vacuously.
9. `pass` = no findings.
10. A non-empty proxy section → log `warn` that apt's route is not the route
    this check probed.
11. Write the verify record (D16), then, if `pass=false` and `throwOnFail`,
    throw (D40).

### Idempotency
Pure read; a point-in-time measurement.

### Output / record
Verify-result record (00-overview §4), key `cephVerifyPackageSource-<host>`:
- `pass`
- `expected`: the endpoint list, each `{name, scheme, origin, outcome:
  "reached"}`
- `actual`: per endpoint `{name, scheme, outcome}`; null only if nothing was
  observed
- `detail`:
  - `endpoints[]`: `name`, `scheme`, `origin` (`apt-source` |
    `cephadm-url`), `outcome` (`reached` | `cannot-resolve` |
    `cannot-reach`), `addresses[]` (empty exactly when `cannot-resolve`),
    `httpStatus` (optional), `curlExit` (optional)
  - `findings[]`
  - `aptProxyConfig[]`: verbatim proxy lines; non-empty means the verdict may
    not match apt's path
  - `noSourcesFound`
- `capturedAt`

### Post-verification
None; it is a check. **Not verified** (state in the description and README):
that the mirror carries the packages and versions; that the repository
signing key is trusted; that apt via a proxy takes the same path; that
reachability lasts.

### Failure modes

| Condition | Result |
|---|---|
| Non-reached endpoint, unprobed endpoint, or no apt sources | `pass=false`; record written; with `throwOnFail` (default) then throws `cephadm[pkgsource.check]:` naming every finding (D16, D40) |
| Either remote script exits non-zero (shell failure) | Throws `cephadm[pkgsource.discover]:` or `cephadm[pkgsource.probe]:` |
| Transport failure | Typed transport error (D8, 01-transport) |
| Injection-shaped host or URL | Rejected at schema time |

### Security
- No sudo. Never `apt-get install` or `update`, `rm`, `mkdir`, `tee` or any
  other mutating verb.
- Discovered names and the cephadm URL host are single-quoted in the probe
  script. Discovered names come from host files and are treated as untrusted.

### Why
- A DNS stub that did not forward made every host fail its package install
  minutes into preparation; the answer was available in milliseconds.
- Collapsing "did not resolve" and "did not answer" into one boolean sends
  operators to the wrong system.
- deb822-only hosts (modern Ubuntu) would look like "no sources" to a
  one-line-only parser and pass vacuously.

### Test obligations
- [ ] Parser reads one-line (`deb`, `deb-src`, with `[options]`) and deb822
      multi-URI lines; ignores comments.
- [ ] Parser strips userinfo and port; ignores non-http schemes.
- [ ] Parser on all-comment or blank input → empty.
- [ ] Section splitter discards lines under unknown markers.
- [ ] No addresses + curl failed → `cannot-resolve`.
- [ ] Addresses + curl exit 7, status `000` → `cannot-reach`, `curlExit` 7.
- [ ] Statuses 200, 301, 403, 404 and 500 → `reached`.
- [ ] Malformed probe lines → no verdict.
- [ ] Findings text differs: DNS versus routing or mirror.
- [ ] All endpoints answer → pass; both origins recorded.
- [ ] Unresolved name → fail; the finding says DNS.
- [ ] Resolved but silent (curl 28, `000`) → fail; finding differs from the
      DNS one.
- [ ] Endpoint missing from probe output → NOT PROBED finding; empty probe
      output fails every endpoint.
- [ ] No apt sources → fail with `noSourcesFound=true`.
- [ ] Proxy configured → reported in `aptProxyConfig` and a `warn` logged.
- [ ] The probe list is built from the discovery pass output (the target's own
      mirrors); ssh dials the given port.
- [ ] No remote call uses sudo or a mutating verb.
- [ ] Failing check with default `throwOnFail` → record written first, then
      throws (D16, D40); with `throwOnFail=false` → returns and records the
      failing result (D16).
- [ ] Record schema accepts every field written.
- [ ] Shared SSH arguments declared from the shared family; explicit
      `port: null` accepted.

---

## 4. Method: wipeDiskToRaw

### Safety class
D: destructive and irreversible. Description starts with `DESTRUCTIVE.`
Wiping the wrong disk can leave a host unbootable; every rule below exists to
prevent that.

### Purpose
Remove all LVM, md-RAID, filesystem and partition-table state from the disks
named by serial, leaving them **raw** (§1.7) for use as Ceph OSD devices,
while keeping the host's boot RAID configuration intact.

### Inputs

| Name | Type | Required | Default | Validation | Meaning |
|---|---|---|---|---|---|
| `host` + SSH family | – | as 00-overview §3 | – | §1.1 | Target host |
| `dataDevices` | array of `{serial, sizeBytes?, devHint?}` | yes | – | ≥ 1 item; `serial` per §1.2; `sizeBytes` positive integer, informational; `devHint` informational, never used for selection | Disks to wipe |
| `excludeDevices` | array of `{serial, reason?}` | yes (may be empty) | – | `serial` per §1.2 | Never-touch list (boot disks) |
| `dryRun` | boolean, nullish | no | `false` | – | Run every gate and report the plan; nothing destructive |
| `multiplex` | boolean, nullish | no | `false` | – | Run all calls over one ssh control master per host (D18) |

- `excludeDevices` is required so that a caller must consciously state the
  exclusion, even when it is empty.
- `dryRun` absent or null behaves as `false`, also on direct calls that bypass
  schema parsing.

### Preconditions
- SSH user with passwordless sudo.
- The host has `lsblk` with JSON output, LVM tools, `mdadm`, `wipefs`,
  `sgdisk`, `partprobe`, `udevadm`, `dmsetup` and `update-initramfs`.
- `/etc/mdadm/mdadm.conf` MAY be absent (D11).

### Behaviour

**Logging.** Log `info` at start (host, device counts, `dryRun`) and at every
phase boundary on the destructive path. **Why:** a mid-teardown failure must
leave a record of how far it got.

**Transport (D18).**
- With `multiplex=true`, every call goes over one control master per host with
  the same options and the same guaranteed final `ssh -O exit` as
  `cephHostPrep`.
- Every step follows the shared retry rule in 01-transport. Safety reminder:
  a pre-session failure (the command never ran) MAY be retried; a
  mid-session loss on any destructive command MUST NOT be re-sent until the
  host state has been re-read, and where this file gives a step-specific rule
  (zero-superblock) that rule applies.

**Safety gates.** All run before anything destructive, in this order.
1. **Conflict.** A serial present in both lists → throw
   `cephadm[wipe.conflict]:`, with zero ssh calls.
2. **Resolve.** Resolve every data and exclude serial through the shared
   resolver (§1.4). Zero or several devices → throw `cephadm[wipe.resolve]:`.
3. **In use.** One `lsblk -J -o NAME,PATH,MOUNTPOINT,TYPE,FSTYPE`. Invalid
   JSON → throw `cephadm[wipe.lsblk-invalid]:`. For each data device:
   - not found in the tree → throw `cephadm[wipe.in-use]:` (its safety cannot
     be verified);
   - any mountpoint on the device or anywhere in its subtree (partitions, md
     arrays, LVM volumes) → throw `cephadm[wipe.in-use]:` listing the
     mountpoints.

   This is how a boot or root disk is caught, including through an active
   boot md array. Safety is verified positively, never assumed.
4. **Excluded path.** A data device whose canonical device equals an excluded
   device's canonical device → throw `cephadm[wipe.excluded-path]:`. This
   catches two serials that alias one physical disk.

**Dry run.** Stop after the gates. Write `{host, dryRun: true,
plannedDevices: [{serial, device}], excludedDevices: [{serial, device}]}`.
No destructive command is issued.

**Teardown** (`dryRun=false`).
0. **Recovery capture.**
   - If `/etc/mdadm/mdadm.conf` exists:
     `sudo -n -- cp -a /etc/mdadm/mdadm.conf /etc/mdadm/mdadm.conf.bak.<ISO timestamp with ":" and "." replaced by "-">`.
     A failed backup throws `cephadm[wipe.backup]:` before any teardown.
   - If it does not exist, record `mdadmConfPresent=false` and skip the
     backup and all md-config steps (6–9) (D11).
   - Capture `mdadm --detail --scan` and `cat /etc/fstab` (own non-zero exit
     tolerated). Both are returned in the record for human recovery.
1. **LVM teardown, as root, deduplicated.** Per data device
   `sudo -n -- pvs --noheadings -o vg_name <dev>`. If it names a volume group:
   record the device as a PV; if that VG was not yet handled, run
   `sudo -n -- vgchange -an '<vg>'`, `sudo -n -- lvremove -f '<vg>'`,
   `sudo -n -- vgremove -f '<vg>'` (own non-zero exits tolerated) and mark it
   removed. A VG spanning several targets is handled once. Then, for every
   recorded PV device, `sudo -n -- pvremove -ff -y <dev>` (own non-zero exit
   tolerated).
   - **Why `lvremove` before `vgremove`:** a Ceph OSD's `osd-block-*` volume is
     open while its device-mapper target is live, and a VG with an open LV
     will not deactivate.
   - **Why `pvremove -ff -y`:** the PV label survives `vgremove` and keeps
     LVM's claim; `-ff -y` because nobody is there to answer a prompt.
2. **LVM gate**, only if any PV was found. Re-read `lsblk -J` once and re-run
   `sudo -n -- pvs` per data device. Two independent reads, because they fail
   in different directions:
   - device absent from `lsblk` and `pvs` names no VG → throw
     `cephadm[wipe.lvm-unobservable]:` (cannot observe whether a
     device-mapper volume is still stacked; refuse to call the LVM teardown
     clean);
   - `pvs` still names a VG, or the device has any child of type `lvm` →
     throw `cephadm[wipe.lvm-held]:`. The message says this is LVM, not md,
     explains the Ceph OSD VG/LV shape, and includes the claiming VG, the
     `lvm` children and the VGs removed. If `pvs` named a VG, report this
     verdict with the VG even when the device is missing from `lsblk`.
   - Only `lvm`-type children are checked here. Partitions are still
     legitimately present before `wipefs` and `sgdisk`.
3. **md stop, deduplicated.** Per data device
   `sudo -n -- mdadm --examine --scan <dev>`; take the array path from the
   first line of the form `ARRAY <path> …`. For each new array:
   `sudo -n -- mdadm --stop '<array>'` (own non-zero tolerated), then read
   `cat /proc/mdstat` up to 10 times, 1 s apart (injectable sleep), until no
   line begins with `<array basename> :`. Still present → throw
   `cephadm[wipe.md-stop]:` (something holds it, for example a container bind
   mount invisible to `fuser` and `lsof`; refuse to touch its members).
   **Why:** a stop command's exit code is acceptance, not effect.
4. **Zero superblock**, per device, up to 5 attempts:
   `sudo -n -- mdadm --zero-superblock <dev>`.
   - Exit 0 → done.
   - The output says the device has no md superblock (for example
     "Unrecognised md component device") → done (D10). **[twin]** Capture the
     exact messages and exit codes of the pinned mdadm and test against them.
   - The device is busy (for example "Couldn't open … for write - not
     zeroing"), or the session was dropped during authentication → re-run
     `sudo -n -- mdadm --examine --scan <dev>`, `sudo -n -- mdadm --stop` any
     array it names, `sudo -n -- udevadm settle`, sleep 1 s, retry. **Why:**
     udev can re-assemble an array between a verified stop and the zero.
   - Any other non-zero exit → throw `cephadm[wipe.zero-superblock]:` with
     mdadm's output; it is not retried (D10).
   - A transport loss that is not a drop during authentication → throw
     `cephadm[wipe.zero-superblock-unknown]:` (the command may have run; it is
     not re-sent; re-read `/proc/mdstat` and `mdadm --examine` before
     deciding).
   - After the 5th busy failure, read holders before throwing:
     `lsblk -nro NAME,TYPE <dev>` and `sudo -n -- dmsetup ls`. Throw
     `cephadm[wipe.zero-superblock-held]:` saying the device is HELD (not
     "being re-formed" by an array), with the holders, the device-mapper
     targets and the last error. A holder of type `lvm` means a device-mapper
     LV still owns it.
5. **Signatures.** `sudo -n -- wipefs -a <dev>` per device; failure throws
   `cephadm[wipe.signatures]:`.
6. **Partition table.** Per device `sudo -n -- sgdisk --zap-all <dev>` (own
   non-zero tolerated: it exits non-zero on a disk with no GPT), then
   `sudo -n -- partprobe <dev>`, which MUST succeed; failure throws
   `cephadm[wipe.partprobe]:`. **Why:** `wipefs` erases on-disk signatures but
   not the kernel's in-memory partition table, and stale `-partN` links
   remained.
7. **md config edit** (skipped when the file is absent, D11). Read
   `cat /etc/mdadm/mdadm.conf`, then compute the new text:
   - For each stopped array, remove **only** lines that are `ARRAY`, then
     whitespace, then exactly that array path, then whitespace or end of line.
     The match is anchored and on the exact token, with the path's characters
     taken literally. Removing `/dev/md/data` keeps a line for
     `/dev/md/data-old`. A broad substring delete is forbidden.
   - **Restore boot safety:** run `sudo -n -- mdadm --detail --scan`. For
     every `ARRAY` line still reported (normally the boot array), append that
     scan line, trimmed, only if no anchored line for its path exists. No
     duplicates; trailing blank lines collapsed; the file ends with a newline.
     This also repairs a previously lost boot line.
8. **Write and rebuild, only if needed (D12).** If an array was stopped or the
   new text differs from the text read: write it as root with
   `sudo -n -- tee /etc/mdadm/mdadm.conf > /dev/null`, content on stdin, then
   `sudo -n -- update-initramfs -u`. Otherwise write nothing and do not
   rebuild. Record `mdConfigRewritten` and `initramfsRebuilt`.
9. **Boot-safety assertion** (whenever the file exists). Re-read the file
   **from the host**, not the in-memory text. Every still-active array MUST
   have its anchored line; otherwise throw `cephadm[wipe.boot-safety]:` (the
   restore did not land; refuse to report success).
10. **Raw check.** Re-read `lsblk -J`. Per wiped device: absent → throw
    `cephadm[wipe.raw-unobservable]:` (cannot observe its partition table;
    refuse to call it raw); any child of type `part` → throw
    `cephadm[wipe.raw-partitions]:` ("stale in-kernel partition table")
    listing them.
11. Write the record.

### Idempotency
- On an already-raw disk, `pvs` and `mdadm --examine` find nothing, so no LVM
  or `mdadm --stop` call is made; zero-superblock (succeeding on "no
  superblock", D10), `wipefs`, `sgdisk`, `partprobe`, the config read and the
  checks still run. With nothing stopped and the config unchanged, there is no
  rewrite and no initramfs rebuild (D12).
- A VG or md array shared by several targets is torn down once.
- Re-running after a partial failure is safe: every step is idempotent and
  every gate re-reads the host.

### Output / record
Resource `wipeDiskResult`, key `wipeDiskToRaw-<host>`:
- always: `host`, `dryRun`, `capturedAt`;
- dry run: `plannedDevices[]`, `excludedDevices[]` (each `{serial, device}`);
- real run: `wiped[]` (`{serial, device}`), `mdadmConfPresent`, `backupPath`
  (null when the file was absent), `removedVolumeGroups[]`, `stoppedArrays[]`,
  `mdConfigRewritten`, `initramfsRebuilt`, `preTeardownMdadmScan`,
  `preTeardownFstab`.
- No secrets; the fstab and mdadm scan are host configuration.

### Post-verification
LVM gate (`pvs` plus `lsblk`), `/proc/mdstat` poll after each stop, md config
read-back from the host, final `lsblk` partition check. `cephVerifyDisksRaw`
(05-verify) asserts full raw-ness (§1.7) independently.

### Failure modes
Every row throws, and every gate row throws before any destructive command.
The classifications MUST stay distinct.

| Phase token | Condition |
|---|---|
| schema rejection | Injection-shaped host or serial; missing `dataDevices` or `excludeDevices` |
| `wipe.conflict` | Serial in both lists; zero ssh calls |
| `wipe.resolve` | A serial resolves to zero or several devices |
| `wipe.lsblk-invalid` | `lsblk` output is not valid JSON |
| `wipe.in-use` | Data device missing from `lsblk`, or mounted anywhere in its subtree |
| `wipe.excluded-path` | Data device is the same disk as an excluded one |
| `wipe.backup` | `mdadm.conf` exists but the backup copy failed |
| `wipe.lvm-unobservable` | Device absent from the LVM-gate `lsblk` and `pvs` names no VG |
| `wipe.lvm-held` | A VG still claims the disk, or an `lvm` child is still mapped |
| `wipe.md-stop` | Array still in `/proc/mdstat` after the poll |
| `wipe.zero-superblock` | mdadm non-zero that is neither "no superblock" nor busy |
| `wipe.zero-superblock-unknown` | Mid-session loss during zero-superblock |
| `wipe.zero-superblock-held` | Still busy after 5 attempts; holders reported |
| `wipe.signatures` | `wipefs -a` failed |
| `wipe.partprobe` | `partprobe` failed |
| `wipe.boot-safety` | A still-active array lacks its line in the re-read config |
| `wipe.raw-unobservable` | Wiped device absent from the final `lsblk` |
| `wipe.raw-partitions` | Wiped device still has `part` children |

### Security
- Serials are validated strictly at schema time and re-validated by the
  resolver (D3).
- Device paths are interpolated unquoted into root commands such as
  `wipefs -a`, so they MUST come only from the resolver, whose device-path
  character guard (01-transport, D6) every caller inherits.
- VG names, array paths and config paths are single-quoted.
- Root-owned files are written only via `tee` on stdin (§1.3).

### Why
- A broad mdadm.conf delete pattern matched `metadata=1.2` on the root array's
  line and nearly made a host unbootable; hence anchored exact-path removal,
  re-emitting surviving arrays, and a read-back assertion.
- Unprivileged `pvs` and `mdadm --examine` silently report nothing; LVM
  teardown and md discovery became no-ops while reporting success, and every
  OSD disk kept an active `ceph-*` VG.
- Tolerating non-zero exits is right for already-raw disks, but only with an
  effect gate afterwards; without one, a later phase failed on a busy device
  and blamed md for an LVM cause.
- A "could not open for write" error must report measured holders, not an md
  story, because the real holder was an LVM device-mapper volume.
- udev can re-assemble an array between a verified stop and the zero, so the
  zero is retried after re-stop and settle, with a bound.
- "No children" on a device missing from `lsblk` certifies a disk nobody
  looked at; absence is failure.
- Rewriting the md config and rebuilding initramfs on every wipe costs time
  and touches boot state for no reason (D12).

### Test obligations
- [ ] Serial in both lists → throws `wipe.conflict` with zero ssh calls.
- [ ] Serial resolving to zero or several devices → throws `wipe.resolve`; no
      destructive command.
- [ ] Target mounted, or backing root through an md array → throws
      `wipe.in-use`; no destructive command.
- [ ] Data device equals an excluded device (two serials, one disk) → throws
      `wipe.excluded-path`; no destructive command.
- [ ] `dryRun` → passes gates, nothing destructive, plan reported.
- [ ] Already-raw target → no `vgchange`/`vgremove`, no `mdadm --stop`;
      zero-superblock and `wipefs` run.
- [ ] Zero-superblock reports "no md superblock" with non-zero exit → success,
      not retried (D10).
- [ ] Zero-superblock fails with another non-busy error → throws
      `wipe.zero-superblock`, not retried (D10).
- [ ] Mid-session drop during zero-superblock → not re-sent;
      `wipe.zero-superblock-unknown`.
- [ ] Drop during authentication during zero-superblock → retried.
- [ ] Busy zero → re-stop, settle, retry; bounded at 5, then
      `wipe.zero-superblock-held` with holders, never "array being re-formed".
- [ ] Shared VG across two devices → torn down once; shared md array →
      stopped once.
- [ ] Anchored config-line removal: removes only the exact array; no-op when
      absent; `/dev/md/data` removal keeps `/dev/md/data-old`; a line with
      `metadata=1.2` for another array survives.
- [ ] Scan-line path extraction; nothing returned without an `ARRAY` line.
- [ ] Ensure-present appends a missing boot line and never duplicates it.
- [ ] Boot array line missing on read-back → throws `wipe.boot-safety`.
- [ ] Happy-path order: backup → LVM → LVM gate → md stop → zero-superblock →
      wipefs → sgdisk/partprobe → config edit → initramfs → read-back → raw
      check; recovery captures returned; `removedVolumeGroups` lists the VG.
- [ ] `wipefs` followed per device by `sudo -n -- sgdisk --zap-all` then
      `sudo -n -- partprobe`.
- [ ] Partitions visible at the gate but gone after zap → completes.
- [ ] `sgdisk` non-zero tolerated, but partitions still visible after → throws
      `wipe.raw-partitions`.
- [ ] md discovery and `pvs` run with sudo.
- [ ] `mdadm --stop` verified against `/proc/mdstat`; still active → throws
      `wipe.md-stop` before any zero.
- [ ] `info` logged at each phase boundary on the destructive path.
- [ ] `dataDevices` and `excludeDevices` both required; injection-shaped host
      and serials rejected in both lists.
- [ ] Ceph OSD VG: `pvs` as root; `lvremove` before `vgremove`; `pvremove -ff
      -y` run.
- [ ] VG still claims the disk after teardown → `wipe.lvm-held`; VG gone but
      an `lvm` child still mapped → `wipe.lvm-held`.
- [ ] Device absent from the final `lsblk` → `wipe.raw-unobservable`; absent
      from the LVM-gate `lsblk` with no VG → `wipe.lvm-unobservable`; absent
      with `pvs` still naming the VG → `wipe.lvm-held` including the VG name.
- [ ] No `/etc/mdadm/mdadm.conf` → no backup, md-config steps skipped,
      `mdadmConfPresent=false` recorded, teardown completes (D11).
- [ ] No array stopped and config unchanged → no `tee`, no
      `update-initramfs` (D12); array stopped → both run (D12); config
      changed only by restoring a lost boot line → both run (D12).
- [ ] A tolerated step (`sgdisk`, `vgremove`) returning ssh exit 255 →
      typed transport error, not tolerated (D8).
- [ ] `multiplex=true` → every call carries `ControlMaster=auto` and the
      ServerAlive options, and `ssh -O exit` is the last call, also on failure
      (D18); `multiplex` absent → no control master (D18).
- [ ] Pre-session failure on a teardown step → retried per the 01-transport
      rule; mid-session loss on `wipefs` → not re-sent without a re-read
      (D18).
- [ ] Record keys for `cephHostPrep` and `wipeDiskToRaw` differ for the same
      host.

---

## 5. Methods specified elsewhere

- `cephVerifyHostPrep`: see `05-verify.md`. Uses the ready-host definition
  in §1.6, including sudo for `cephadm version` (D13) and the exact token
  comparison (D14).
- `cephVerifyDisksRaw`: see `05-verify.md`. Uses the raw-disk definition in
  §1.7, including reporting children by type (D17).
- Serial-to-device resolver: see `01-transport.md` (D3–D6).

## Unresolved

1. **D18 argument name.** D18 says multiplexing applies "when the caller
   enables it" but names no argument. This file uses `multiplex` (boolean,
   nullish, default `false`). Confirm the name, or move it into the shared SSH
   family if 01-transport defines one.
2. **Resolver output under D5.** D5 says the resolver returns the by-id link
   path. `wipeDiskToRaw` also needs the single canonical device it proved,
   for `lsblk` lookups and the excluded-path comparison (§1.4). 01-transport
   should expose both.
3. **Package grammar scope (D15).** This file rejects architecture qualifiers
   (`pkg:amd64`) and version pins (`pkg=1.0`). Confirm that is intended.
