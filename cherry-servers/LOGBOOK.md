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
