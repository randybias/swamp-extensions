/**
 * Phase planning and execution: turns validated inputs into an ordered stream
 * of remote steps, then runs that stream through the SSH transport.
 *
 * Every step is a {@link RemoteCall}: a fixed script streamed over the SSH
 * session's stdin. Caller values reach it only as positional parameters, and
 * file content as the base64 `bw_data` bytes, so nothing is interpolated into
 * a shell string. File writes create the parent directory, write a
 * same-directory temp file and `mv` it into place atomically, so they work for
 * a non-root login and are idempotent by content.
 *
 * The firewall and lockdown plans write the revert script (kind `stage`) and
 * then activate the timer (kind `arm`) before they apply (kind `apply`).
 * {@link assertArmedBeforeApply} proves that the timer activation, not merely
 * the upload, precedes the change.
 *
 * @module
 */

import type { ExecResult, SshDeps, SshTarget } from "./ssh.ts";
import {
  armCall,
  commitCall,
  disarmCall,
  guardedApplyCall,
  isTimerActive,
  markerCall,
  parseMarker,
  PROBE_DEADLINE_S,
  probeCall,
  renderRevertScript,
  scriptPath,
  STATE_DIR,
} from "./armed_revert.ts";
import { DEADLINE_EXITS, type RemoteCall, runRemote } from "./remote.ts";
import { listingSha256, managedSha256, normalizeListing } from "./nftables.ts";
import { HostConfigError, ifacePatternMatches } from "./validate.ts";

/** The risk class of a step, used to assert ordering. */
export type StepKind =
  | "stage"
  | "arm"
  | "precheck"
  | "apply"
  | "verify"
  | "cleanup"
  | "base";

/** One remote action in a plan. */
export interface Step {
  /** Risk class of the step. */
  kind: StepKind;
  /** Human-readable label. */
  label: string;
  /** The script to run and its deadline. */
  call: RemoteCall;
  /** When true, a remote exit outside `okExit` stops the plan. */
  check?: boolean;
  /** Exit codes that count as success for a checked step; default `[0]`. */
  okExit?: number[];
}

/** A step after execution, with its result summarised for logging and tests. */
export interface EmittedStep {
  /** Risk class of the step. */
  kind: StepKind;
  /** Human-readable label. */
  label: string;
  /** The script the step ran. */
  script: string;
  /** The remote exit code. */
  exit_code: number;
}

const enc = new TextEncoder();

/** Deadline of a package install, which may fetch and unpack a lot. */
const PACKAGES_DEADLINE_S = 900;
/** Deadline of every other base step. */
const BASE_DEADLINE_S = 120;

/**
 * True when the timer-activation step (`arm`) precedes the first mutating
 * `apply` step in `steps`. A `stage` step (writing the revert script) does not
 * count: the invariant is that the timer is armed, not merely prepared.
 */
export function isArmedBeforeApply(steps: Step[]): boolean {
  const arm = steps.findIndex((s) => s.kind === "arm");
  const apply = steps.findIndex((s) => s.kind === "apply");
  return arm >= 0 && apply >= 0 && arm < apply;
}

/** Throws unless the plan arms a revert before it applies a change. */
export function assertArmedBeforeApply(steps: Step[]): void {
  if (!isArmedBeforeApply(steps)) {
    throw new Error("Plan violates the armed-revert invariant");
  }
}

const PKG_SCRIPT = `for p in "$@"; do
  if dpkg-query -W -f='\${Status}' "$p" 2>/dev/null | grep -q "install ok installed"; then
    continue
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends "$p"
  printf 'changed %s\\n' "$p"
done
`;

const USER_SCRIPT = `if ! id -u "$1" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$1"
  printf 'created %s\\n' "$1"
fi
if ! id -nG "$1" | tr ' ' '\\n' | grep -qx sudo; then
  if usermod -aG sudo "$1" 2>/dev/null; then
    install -d -m 0755 "${STATE_DIR}"
    : > "${STATE_DIR}/sudo-granted-$1"
  fi
fi
`;

/**
 * Takes back what an earlier run granted a previous managed account: the sudo
 * membership only if this tool added it (a marker on the host records that),
 * then the managed authorized_keys file. The account itself stays. Sudo goes
 * first, so a keys file that cannot be removed leaves the account without its
 * privilege, and the marker is already gone, so a rerun retries only the keys.
 *
 * Exit 0: revoked. Exit 3: the keys file was left alone because `~/.ssh` is a
 * symlink or not the account's own directory (removing through it could delete
 * another account's keys); the sudo part is still done. Any other non-zero
 * exit: part of the revoke failed, and a rerun retries it.
 *
 * `getent` exits 2 for "no such entry", but a failing name-service backend can
 * answer the same way, so an account counts as gone only when `id` and the
 * local passwd file agree and no network source is configured for passwd.
 */
export const REVOKE_SKIPPED = 3;
const REVOKE_SCRIPT = `user=$1
rc=0
set +e
entry=$(getent passwd "$user" 2>/dev/null)
found=$?
set -e
case $found in
  0) exists=1 ;;
  2)
    if id -u "$user" >/dev/null 2>&1 || grep -q "^$user:" /etc/passwd ||
      grep -Eq '^passwd:.*(ldap|sss|nis|winbind)' /etc/nsswitch.conf; then
      echo "cannot confirm $user is gone" >&2
      exit 1
    fi
    exists=0 ;;
  *) echo "cannot look up $user" >&2; exit 1 ;;
esac
m="${STATE_DIR}/sudo-granted-$user"
if [ -e "$m" ]; then
  if [ "$exists" = 1 ]; then
    gpasswd -d "$user" sudo >/dev/null 2>&1 || true
    if ! groups=$(id -nG "$user"); then
      echo "cannot read the groups of $user" >&2
      exit 1
    fi
    if printf '%s\\n' "$groups" | tr ' ' '\\n' | grep -qx sudo; then
      echo "could not remove $user from sudo" >&2
      exit 1
    fi
  fi
  rm -f "$m"
fi
if [ "$exists" = 1 ]; then
  home=$(printf '%s\\n' "$entry" | cut -d: -f6)
  d="$home/.ssh"
  if [ -L "$d" ] || [ ! -d "$d" ] || [ "$(stat -c %U "$d")" != "$user" ]; then
    if [ -e "$d" ] || [ -L "$d" ]; then
      echo "left $d alone: not the account's own directory" >&2
      rc=${REVOKE_SKIPPED}
    fi
  else
    # Removed as the account itself, so a swap of its own ~/.ssh for a symlink
    # between the checks above and this line cannot make root delete a file
    # that belongs to someone else.
    runuser -u "$user" -- rm -f "$d/authorized_keys"
  fi
fi
exit $rc
`;

const KEYS_SCRIPT = `user=$1
home=$(getent passwd "$user" | cut -d: -f6)
[ -n "$home" ] || { printf 'no home directory for %s\\n' "$user" >&2; exit 1; }
install -d -m 700 "$home/.ssh"
chown "$user" "$home/.ssh" 2>/dev/null || true
tmp=$(mktemp "$home/.ssh/authorized_keys.XXXXXX")
bw_data > "$tmp"
chmod 600 "$tmp"
chown "$user" "$tmp" 2>/dev/null || true
if [ -f "$home/.ssh/authorized_keys" ] && cmp -s "$tmp" "$home/.ssh/authorized_keys"; then
  rm -f "$tmp"
else
  mv -f "$tmp" "$home/.ssh/authorized_keys"
  printf 'updated authorized_keys\\n'
fi
`;

/** Inputs to the base phase. All strings are already grammar-validated. */
export interface BaseInput {
  /** Wrap privileged commands in `sudo -n`. */
  sudo: boolean;
  /** Packages to ensure installed. */
  packages: string[];
  /** Administrative account to ensure exists. */
  adminUser: string;
  /** Public keys to authorize for the account, verbatim lines. */
  authorizedKeys: string[];
  /** Sysctl keys and values to write. */
  sysctl: Record<string, string>;
  /** Time zone to set. */
  timezone: string;
  /** Previous managed accounts whose grants are revoked first. */
  revoke?: string[];
}

/** Renders the managed sysctl drop-in with sorted keys. */
export function renderSysctlConf(sysctl: Record<string, string>): string {
  const keys = Object.keys(sysctl).sort();
  return `# Managed by @randybias/server-host. Generated; do not edit.\n${
    keys.map((k) => `${k} = ${sysctl[k]}`).join("\n")
  }\n`;
}

/** Renders the fixed journald hardening drop-in. */
export function renderJournaldConf(): string {
  return `# Managed by @randybias/server-host. Generated; do not edit.\n[Journal]\nStorage=persistent\nCompress=yes\nSystemMaxUse=200M\nForwardToSyslog=no\n`;
}

/**
 * A step that writes `content` to an absolute path. The parent directory is
 * created, the temp file lives in the destination directory and is removed on
 * any exit, and `mv` replaces the destination atomically. `path` and `mode`
 * are constants chosen by this module, never a caller value.
 */
export function writeFileStep(
  kind: StepKind,
  label: string,
  path: string,
  content: Uint8Array,
  mode: string,
  sudo: boolean,
): Step {
  const script = `dir=$(dirname "${path}")
install -d -m 0755 "$dir"
tmp=$(mktemp "${path}.XXXXXX")
bw_data > "$tmp"
chmod ${mode} "$tmp"
if [ -f "${path}" ] && cmp -s "$tmp" "${path}"; then
  chmod ${mode} "${path}"
  exit 0
fi
mv -f "$tmp" "${path}"
`;
  return {
    kind,
    label,
    call: {
      sudo,
      script,
      data: content,
      deadlineS: BASE_DEADLINE_S,
      cleanup: 'rm -f "${tmp:-}"',
    },
    check: true,
  };
}

/**
 * Builds the base-phase step stream for exactly the components named in
 * `changed`. An unchanged re-run passes an empty list and emits no steps, so
 * nothing is installed, restarted or reset.
 */
export function planApplyBase(
  input: BaseInput,
  changed: readonly string[],
): Step[] {
  const steps: Step[] = [];
  const want = (name: string) => changed.includes(name);
  const base = (
    label: string,
    call: Omit<RemoteCall, "sudo" | "deadlineS"> & { deadlineS?: number },
    okExit?: number[],
  ): Step => ({
    kind: "base",
    label,
    call: { sudo: input.sudo, deadlineS: BASE_DEADLINE_S, ...call },
    check: true,
    ...(okExit ? { okExit } : {}),
  });
  if (want("revoke_previous")) {
    for (const user of input.revoke ?? []) {
      // 0 = revoked, 3 = keys left alone (the caller reads it); anything else
      // stops the plan before the new account is granted anything.
      steps.push(
        base(`revoke grants of ${user}`, {
          script: REVOKE_SCRIPT,
          args: [user],
        }, [0, REVOKE_SKIPPED]),
      );
    }
  }
  if (want("packages") && input.packages.length > 0) {
    steps.push(base("install packages", {
      script: PKG_SCRIPT,
      args: input.packages,
      deadlineS: PACKAGES_DEADLINE_S,
    }));
  }
  if (want("admin_user")) {
    steps.push(base("create admin user", {
      script: USER_SCRIPT,
      args: [input.adminUser],
    }));
  }
  if (want("authorized_keys")) {
    steps.push(base("authorize admin keys", {
      script: KEYS_SCRIPT,
      args: [input.adminUser],
      data: enc.encode(
        input.authorizedKeys.length > 0
          ? `${input.authorizedKeys.join("\n")}\n`
          : "",
      ),
      cleanup: 'rm -f "${tmp:-}"',
    }));
  }
  if (want("sysctl")) {
    steps.push(
      writeFileStep(
        "base",
        "write sysctl drop-in",
        "/etc/sysctl.d/99-server-host.conf",
        enc.encode(renderSysctlConf(input.sysctl)),
        "0644",
        input.sudo,
      ),
      base("apply sysctl", { script: "sysctl --system\n" }),
    );
  }
  if (want("journald")) {
    steps.push(
      writeFileStep(
        "base",
        "write journald drop-in",
        "/etc/systemd/journald.conf.d/99-server-host.conf",
        enc.encode(renderJournaldConf()),
        "0644",
        input.sudo,
      ),
      base("restart journald", {
        script: "systemctl restart systemd-journald\n",
      }),
    );
  }
  if (want("timezone")) {
    steps.push(base("set time zone", {
      script: 'timedatectl set-timezone "$1"\n',
      args: [input.timezone],
    }));
  }
  if (want("time_sync")) {
    steps.push(base("enable time sync", {
      script: "timedatectl set-ntp true\n",
    }));
  }
  return steps;
}

/** Options shared by the two reverting firewall plans. */
export interface FirewallChangeInput {
  /** Random token embedded in the revert unit and file names. */
  token: string;
  /** Seconds until the host reverts itself. */
  revertAfterS: number;
  /** Wrap privileged commands in `sudo -n`. */
  sudo: boolean;
  /** Rendered nftables script to apply. */
  rulesText: string;
  /** SHA-256 of the managed table the apply installs; recorded on the host. */
  managedSha256: string;
}

/**
 * Builds the ordered firewall-change stream: `nft -c` syntax check (no side
 * effects, so it runs before anything is armed), write the revert script
 * (stage), arm (which snapshots and starts the timer under the host lock),
 * apply under the same lock only while the revert still guards the change,
 * then read the table back.
 */
export function planFirewallChange(input: FirewallChangeInput): Step[] {
  const rules = enc.encode(input.rulesText);
  const steps: Step[] = [
    {
      kind: "precheck",
      label: "nft syntax check",
      call: {
        sudo: input.sudo,
        data: rules,
        deadlineS: PROBE_DEADLINE_S,
        script: "bw_data | nft -c -f -\n",
      },
      check: true,
    },
    writeFileStep(
      "stage",
      "write revert script",
      scriptPath(input.token),
      enc.encode(renderRevertScript(input.token)),
      "0700",
      input.sudo,
    ),
    {
      kind: "arm",
      label: "arm revert timer",
      call: armCall(
        input.token,
        input.revertAfterS,
        input.sudo,
        input.managedSha256,
      ),
      check: true,
    },
    {
      kind: "apply",
      label: "apply ruleset",
      call: guardedApplyCall(input.token, input.sudo, rules),
      check: true,
    },
    {
      kind: "verify",
      label: "read table back",
      call: {
        sudo: input.sudo,
        deadlineS: PROBE_DEADLINE_S,
        script: "nft -j list table inet server_host\n",
      },
      check: true,
    },
  ];
  assertArmedBeforeApply(steps);
  return steps;
}

/** Builds the ordered stream that cancels an armed revert. */
export function planCommit(token: string, sudo: boolean): Step[] {
  return [{
    kind: "cleanup",
    label: "cancel revert timer",
    call: commitCall(token, sudo),
    check: true,
  }];
}

/**
 * The step that abandons a revert after a change that definitely did not
 * happen. Tolerant and idempotent; see {@link disarmCall}.
 */
export function planDisarm(token: string, sudo: boolean): Step[] {
  return [{
    kind: "cleanup",
    label: "disarm revert timer",
    call: disarmCall(token, sudo),
    check: true,
  }];
}

/** Inputs to the READ-ONLY probe. */
export interface ReadInput {
  /** Wrap privileged commands in `sudo -n`. */
  sudo: boolean;
  /** The revert token to check, when the caller recorded one. */
  token?: string;
}

/** The READ-ONLY result of probing a host's current firewall state. */
export interface ProbeResult {
  /** SHA-256 of the full `nft -j list ruleset` output without handles. */
  ruleset_sha256: string;
  /** SHA-256 of the canonical managed table. */
  managed_sha256: string;
  /** True when the managed table is present. */
  managed_table: boolean;
  /** The managed input chain's rules, normalized; empty when the table is absent. */
  managed_input_rules: string[];
  /** True when the revert timer (the recorded one, else the host's) is active. */
  armed: boolean;
  /** Token of the revert the host itself records as current, if any. */
  current_token?: string;
  /** ISO-8601 expiry of that revert, if any. */
  current_expires_at?: string;
  /** Managed-table hash the host recorded for that revert, if any. */
  current_managed_sha256?: string;
  /** ISO-8601 time of the probe. */
  observed_at: string;
}

/**
 * Runs READ-ONLY probes and returns the host's current firewall state. A probe
 * that fails throws {@link HostOpsError} (and one whose output overruns the
 * transport's capture cap throws the transport's own error); a caller must not
 * persist an observation it did not obtain.
 */
export async function probeState(
  deps: SshDeps,
  target: SshTarget,
  input: ReadInput,
): Promise<ProbeResult> {
  const listed = await runRemote(deps, target, {
    sudo: input.sudo,
    deadlineS: LIST_DEADLINE_S,
    script: "nft -j list ruleset\n",
  });
  if (listed.exit_code !== 0) {
    throw new HostOpsError(
      `nft -j list ruleset on ${target.host} failed with exit code ${listed.exit_code}; refusing to record firewall state`,
    );
  }
  let table;
  try {
    table = normalizeListing(listed.stdout);
  } catch {
    throw new HostOpsError(
      `nft -j list ruleset on ${target.host} did not return JSON; refusing to record firewall state`,
    );
  }
  const managed = table !== null;
  const marked = await runRemote(deps, target, markerCall(input.sudo));
  if (marked.exit_code !== 0) {
    throw new HostOpsError(
      `Reading the revert marker on ${target.host} failed with exit code ${marked.exit_code}; refusing to record firewall state`,
    );
  }
  const marker = parseMarker(marked.stdout);
  if (marker === null && marked.stdout.trim() !== "") {
    throw new HostOpsError(
      `The revert marker on ${target.host} is not readable; refusing to record firewall state`,
    );
  }
  const token = input.token ?? marker?.token;
  let armed = false;
  if (token) {
    const probe = await runRemote(
      deps,
      target,
      probeCall(token, input.sudo),
    );
    if (probe.exit_code === 0) {
      armed = isTimerActive(probe.stdout);
    } else if (probe.exit_code === 3 || probe.exit_code === 4) {
      armed = false;
    } else {
      throw new HostOpsError(
        `Revert timer probe on ${target.host} failed with exit code ${probe.exit_code}; refusing to record firewall state`,
      );
    }
  }
  return {
    ruleset_sha256: await listingSha256(listed.stdout),
    managed_sha256: await managedSha256(table),
    managed_input_rules: table?.chains.find((c) => c.name === "input")?.rules ??
      [],
    managed_table: managed,
    armed,
    ...(marker
      ? {
        current_token: marker.token,
        current_expires_at: new Date(marker.expires_at_s * 1000).toISOString(),
        ...(marker.managed_sha256
          ? { current_managed_sha256: marker.managed_sha256 }
          : {}),
      }
      : {}),
    observed_at: new Date(deps.now()).toISOString(),
  };
}

/** Deadline of the full-ruleset listing, which can be large. */
const LIST_DEADLINE_S = 60;

/**
 * Runs `steps` through the transport in order and returns what was emitted. A
 * step marked `check` throws {@link HostOpsError} on a non-zero remote exit,
 * so a failed `nft -c` pre-check stops the plan before anything is armed. A
 * step that outlives its remote deadline always throws, checked or not, and
 * the error says the outcome is unknown.
 * `after` runs once each step has succeeded, before the next one starts; the
 * model uses it to persist the armed revert before the change is applied.
 */
export async function executePlan(
  deps: SshDeps,
  target: SshTarget,
  steps: Step[],
  after?: (step: Step, result: ExecResult) => Promise<void>,
): Promise<EmittedStep[]> {
  const emitted: EmittedStep[] = [];
  for (const step of steps) {
    const res = await runRemote(deps, target, step.call);
    if (DEADLINE_EXITS.includes(res.exit_code)) {
      throw new HostOpsError(
        `Remote step "${step.label}" outlived its ${step.call.deadlineS}s deadline on the host; its outcome is unknown`,
        step.kind,
        res.exit_code,
        true,
      );
    }
    if (step.check && !(step.okExit ?? [0]).includes(res.exit_code)) {
      throw new HostOpsError(
        `Remote step "${step.label}" failed with exit code ${res.exit_code}`,
        step.kind,
        res.exit_code,
      );
    }
    emitted.push({
      kind: step.kind,
      label: step.label,
      script: step.call.script,
      exit_code: res.exit_code,
    });
    if (after) await after(step, res);
  }
  return emitted;
}

/** A remote step failed or a plan violated an invariant. */
export class HostOpsError extends Error {
  /** The kind of step that failed, when the failure was a remote exit. */
  readonly stepKind?: StepKind;
  /** The remote exit code, when the failure was a remote exit. */
  readonly exitCode?: number;
  /** True when the step hit its remote deadline, so what it did is unknown. */
  readonly deadline: boolean;
  /** Creates a host-operations error. */
  constructor(
    message: string,
    stepKind?: StepKind,
    exitCode?: number,
    deadline = false,
  ) {
    super(message);
    this.name = "HostOpsError";
    this.stepKind = stepKind;
    this.exitCode = exitCode;
    this.deadline = deadline;
  }
}

/** Re-exported so callers depend on one error family for host operations. */
export { HostConfigError, STATE_DIR };

/**
 * A READ-ONLY script printing, separated by `---` lines, the JSON of the IPv4
 * default routes, the IPv6 default routes, and the route to the address this SSH
 * session comes from. It fails closed: a missing `ip`, any failing `ip`
 * command, or an empty `SSH_CLIENT` is a non-zero exit. It must NOT run under
 * sudo, whose env_reset strips `SSH_CLIENT`; `ip route` needs no privilege.
 */
export const UPLINK_SCRIPT = `c="\${SSH_CLIENT:-}"
c="\${c%% *}"
if [ -z "$c" ]; then echo "SSH_CLIENT is empty" >&2; exit 3; fi
command -v ip >/dev/null
ip -4 -j route show default
echo ---
ip -6 -j route show default
echo ---
ip -j route get "$c"
`;

/** The call of {@link UPLINK_SCRIPT}; deliberately not run through sudo. */
export const UPLINK_CALL: RemoteCall = {
  sudo: false,
  script: UPLINK_SCRIPT,
  deadlineS: PROBE_DEADLINE_S,
};

/** The interfaces the probe found, by role. */
export interface UplinkDevs {
  /** Interfaces of the IPv4 and IPv6 default routes, including ECMP next hops. */
  defaults: string[];
  /** Interfaces of the route to the SSH client. */
  session: string[];
}

function devsOf(routes: unknown[]): string[] {
  const out: string[] = [];
  for (const r of routes) {
    const o = r as { dev?: unknown; nexthops?: { dev?: unknown }[] };
    if (typeof o.dev === "string" && o.dev !== "") out.push(o.dev);
    for (const n of o.nexthops ?? []) {
      if (typeof n.dev === "string" && n.dev !== "") out.push(n.dev);
    }
  }
  return out;
}

/** Parses the output of {@link UPLINK_SCRIPT}. */
export function parseUplinkDevs(stdout: string): UplinkDevs {
  const parts = stdout.split(/^---$/m).map((p) => p.trim());
  if (parts.length !== 3) {
    throw new HostOpsError("The route probe output was not in three parts");
  }
  const lists = parts.map((text) => {
    if (text === "") return [] as unknown[];
    let routes: unknown;
    try {
      routes = JSON.parse(text);
    } catch {
      throw new HostOpsError("The route probe did not return JSON");
    }
    if (!Array.isArray(routes)) {
      throw new HostOpsError("The route probe did not return a list of routes");
    }
    return routes;
  });
  return {
    defaults: [...new Set([...devsOf(lists[0]), ...devsOf(lists[1])])].sort(),
    session: [...new Set(devsOf(lists[2]))].sort(),
  };
}

/**
 * Refuses trusted interfaces that carry the management session or the default
 * route: trusting them would accept every port from the internet and bypass
 * `management_cidrs`. READ-ONLY; runs before anything is armed. It checks once,
 * in TypeScript: the apply script does not repeat it, so an interface that
 * starts carrying the session between the check and the apply is not caught.
 */
export async function assertTrustedNotUplink(
  deps: SshDeps,
  target: SshTarget,
  trusted: readonly string[],
): Promise<void> {
  if (trusted.length === 0) return;
  const res = await runRemote(deps, target, UPLINK_CALL);
  if (res.exit_code !== 0) {
    throw new HostOpsError(
      `The route probe on ${target.host} failed (exit ${res.exit_code}); refusing trusted_interfaces it could not check`,
    );
  }
  const { defaults, session } = parseUplinkDevs(res.stdout);
  // A host that shows neither a default route nor a session route cannot be
  // checked, and an unchecked trust of an interface is refused.
  if (defaults.length === 0 || session.length === 0) {
    throw new HostOpsError(
      `The route probe on ${target.host} found no ${
        defaults.length === 0 ? "default route" : "route to the SSH client"
      }; refusing trusted_interfaces it could not check`,
    );
  }
  const devs = [...new Set([...defaults, ...session])];
  for (const p of trusted) {
    const hit = devs.find((d) => ifacePatternMatches(p, d));
    if (hit !== undefined) {
      throw new HostConfigError(
        `trusted_interfaces entry ${p} matches ${hit}, which carries the SSH session or the default route; trusting it would accept every port from there`,
      );
    }
  }
}
