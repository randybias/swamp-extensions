# Maintainer logbook

Not packaged. Notes for whoever maintains this extension.

- 2026-10-16: initial models (servers, projects, ssh-keys, plans) and two
  workflows. Layout mirrors the first-party Hetzner Cloud extension. Server GET
  responses include root and BMC passwords, so stored state is an explicit
  allowlist built by `toState`. The API's `active` state was observed to lag a
  reachable SSH daemon by several minutes on bare metal, hence `wait_ready`.
  Non-hourly billing cycles are charged upfront from the account balance.
- 2026-10-16: first live order, with 2026.10.16.1, kept (a long-running server,
  not a test). A new project, VPS `B2-6-6gb-100s-shared` in `LT-Siauliai`,
  Ubuntu 24.04, monthly cycle, no user data. Live cells:
  - `projects create`: created a new project. `ssh-keys create`: uploaded a key.
  - `servers create`: order accepted in 7s, state `pending`, no IP yet.
  - `servers wait_ready` (accept-new, cloud-init `boot-finished` marker, key
    over stdin): ready after 83s. The API still said `provisioning`, which again
    shows it lags the server.
  - `servers create` re-run: adopted the recorded id; the project list showed
    exactly one server, so no second order.
  - Not yet live: `delete` (servers and ssh-keys). Run it on a throwaway hourly
    server, never on this one.
  - Observed: the API reports a monthly cycle as pricing unit `1 month`, so
    stored `cycle` is `1 month` rather than `monthly`. `termination_date` comes
    back as the string `None`.
  - Swamp CLI: `swamp model method run --json` echoes `methodArguments` in
    stdout, including arguments marked sensitive. Nothing under `.swamp/` kept
    it. Pass private keys with `--stdin` and don't capture that stdout.
- 2026-10-16: live end-to-end pass for 2026.10.16.3 (CONVENTIONS §8), in a
  throwaway swamp repo and a scratch project, with hourly servers: VPS
  `B2-1-1gb-20s-shared`, bare metal `e3-1240v3` (one disk) and `e3-1240v5` (two
  disks), and spot `e5-1620v4`. Both workflows were run from their entry points.
  What it found, all fixed in 16.3:
  - Both shipped workflows were broken in 16.1 and 16.2: the wait-ready and
    delete steps failed with "Unresolved expression in globalArguments" because
    swamp fails a method that reads a global argument whose definition input was
    not given. Optional arguments now accept null and are read lazily,
    definitions give optional inputs `default: null`, and delete guards on the
    recorded project instead of `project_id`.
  - Swamp treats a method named `delete` as deleting the whole model and
    tombstones every record it holds. With one definition per kind holding many
    servers, deleting one server tombstoned the others and swamp then refused
    `get` on that model. The deletes are now `kind: "action"`.
  - Cherry's API returned 521 and 500 during the run. One 500 ended a
    `wait_ready` at 3.5 minutes. Reads and deletes now retry transient errors,
    and `wait_ready` keeps polling through them; orders are never retried.
  - Strict host keys failed when only some key types were pinned.
  - `get` and `list` dropped the stored user-data hash; `sync` turned `deleted`
    into `not_found`.
  - Projects had no delete, so a scratch project could not be cleaned up.
  - Readiness could record the wrong address and host keys on bare metal. During
    deploy, port 22 first answers from Cherry's provisioning environment
    (OpenSSH 8.9 on Ubuntu 22.04, its own host keys). With `os_partition_size`
    on a two-disk plan, the marker check passed on the installed system at one
    public IP while the API still said deploying; the server then moved to
    another IP, rebooted with new host keys and kept its disk. metal-2 changed
    IP mid-deploy as well. `wait_ready` now needs the API at deployed/active
    too, and records the address and keys from that poll; live, the recorded
    keys equal an `ssh-keyscan` of the final IP (bare metal and VPS).
  - `os_partition_size` works on a two-disk plan (40 GB RAID1 root, the rest
    unallocated) and is silently ignored on the one-disk `e3-1240v3`.
  - Secrets: a key given with `--stdin` is printed in `--json` output (swamp lab
    3555); a vault reference in `--input` resolves and is never printed.
  - Observed: VPS ready about 2.5 min after the order. Bare metal reached
    deployed/active in about 15 min on one disk and about 27 min with a custom
    partition on two; spot about 9 min to a booted system. Deletes take about 2
    s and the API returns 404 at once. Cherry reuses a deleted server's IP for
    the next order. Ubuntu 24.04 socket-activates sshd, so cloud-init that adds
    a port must restart `ssh.socket`. The image's vendor cloud-config makes
    `cloud-init status` report "degraded" (a deprecated `user` key); that is not
    the user data failing.
