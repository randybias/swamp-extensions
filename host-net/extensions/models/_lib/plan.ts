/**
 * The ordered step plan for `apply` and `remove`, and the MTU ordering derived
 * from the device graph. The plan is data: tests assert the arm step precedes
 * every mutation, and that the golden ordering is stable.
 *
 * @module
 */

import { deviceGraph, type DeviceNode, type NetConfig } from "./validate.ts";

/** The kinds of step a plan emits. */
export type StepKind =
  | "probe"
  | "precheck"
  | "snapshot"
  | "stage"
  | "arm"
  | "mtu"
  | "write"
  | "apply"
  | "delete"
  | "verify";

/** One ordered step. */
export interface Step {
  /** Step kind. */
  kind: StepKind;
  /** Stable step id. */
  id: string;
  /** Human description. */
  description: string;
  /** Argv, when the step runs a local command through the transport. */
  argv?: string[];
  /** Remote script text, when the step is a host script. */
  script?: string;
}

/**
 * Existing parent devices whose MTU this change raises, before the backend
 * applies. Created VLANs and bridges get their MTU from the renderer, so a
 * raise step is emitted only for a physical NIC that already exists.
 */
export function mtuRaiseOrder(cfg: NetConfig): DeviceNode[] {
  return deviceGraph(cfg).filter((n) => n.kind === "ethernet" && n.mtu > 0);
}

/** Devices whose MTU is lowered, child-first. */
export function mtuLowerOrder(cfg: NetConfig): DeviceNode[] {
  return mtuRaiseOrder(cfg).reverse();
}

/** The argv that activates the host-side revert timer. */
export function armArgv(token: string, revertAfterS: number): string[] {
  return [
    "systemd-run",
    `--unit=host-net-revert-${token}`,
    `--on-active=${revertAfterS}`,
    "--timer-property=AccuracySec=1s",
    "/var/lib/host-net/restore.sh",
    token,
  ];
}

/** The argv that fires the armed revert immediately. */
export function revertNowArgv(token: string): string[] {
  return ["/var/lib/host-net/restore.sh", token];
}

/** The argv that stops and clears the revert timer for a token. */
export function disarmArgv(token: string): string[] {
  return [
    "systemctl",
    "stop",
    `host-net-revert-${token}.timer`,
    `host-net-revert-${token}.service`,
  ];
}

function mtuStep(node: DeviceNode, direction: "raise" | "lower"): Step {
  return {
    kind: "mtu",
    id: `mtu-${direction}-${node.name}`,
    description: `${direction} MTU on ${node.name} to ${node.mtu}`,
    argv: ["ip", "link", "set", "dev", node.name, "mtu", String(node.mtu)],
  };
}

/** Builds the ordered steps for an apply. */
export function planApply(
  cfg: NetConfig,
  opts: { token: string; revertAfterS: number; writtenPaths: string[] },
): Step[] {
  const steps: Step[] = [
    { kind: "probe", id: "probe", description: "probe live link/addr/route" },
    {
      kind: "precheck",
      id: "precheck",
      description: "render and syntax-check the staged config",
    },
    {
      kind: "snapshot",
      id: "snapshot",
      description: "snapshot the managed config and live state under the lock",
    },
    {
      kind: "stage",
      id: "stage-marker",
      description: "write the revert marker and restore script",
    },
    {
      kind: "arm",
      id: "arm",
      description: "activate the host-side revert timer",
      argv: armArgv(opts.token, opts.revertAfterS),
    },
  ];
  for (const node of mtuRaiseOrder(cfg)) steps.push(mtuStep(node, "raise"));
  steps.push({
    kind: "write",
    id: "write-config",
    description: `write ${opts.writtenPaths.join(", ")} atomically`,
  });
  steps.push({
    kind: "apply",
    id: "apply-config",
    description: "apply the configuration",
  });
  steps.push({
    kind: "verify",
    id: "verify",
    description: "verify management, default route, links and jumbo",
  });
  return steps;
}

/** Builds the ordered steps for a remove. */
export function planRemove(
  cfg: NetConfig,
  opts: { token: string; revertAfterS: number },
): Step[] {
  const steps: Step[] = [
    { kind: "probe", id: "probe", description: "probe live link/addr/route" },
    {
      kind: "snapshot",
      id: "snapshot",
      description: "snapshot the managed config and live state under the lock",
    },
    {
      kind: "stage",
      id: "stage-marker",
      description: "write the revert marker and restore script",
    },
    {
      kind: "arm",
      id: "arm",
      description: "activate the host-side revert timer",
      argv: armArgv(opts.token, opts.revertAfterS),
    },
    {
      kind: "delete",
      id: "delete-created",
      description: "delete only the devices this config created",
    },
  ];
  for (const node of mtuLowerOrder(cfg)) steps.push(mtuStep(node, "lower"));
  steps.push({
    kind: "apply",
    id: "apply-config",
    description: "apply the configuration",
  });
  steps.push({
    kind: "verify",
    id: "verify",
    description: "verify the removal",
  });
  return steps;
}

/**
 * Asserts the invariant that the arm step precedes every mutating step. A
 * reordering (or treating the stage step as the arm) is a hard failure.
 */
export function assertArmBeforeApply(steps: Step[]): void {
  const armAt = steps.findIndex((s) => s.kind === "arm");
  if (armAt < 0) throw new Error("plan has no arm step");
  for (let i = 0; i < steps.length; i++) {
    const kind = steps[i].kind;
    if (
      kind === "mtu" || kind === "write" || kind === "apply" ||
      kind === "delete"
    ) {
      if (i < armAt) {
        throw new Error(
          `step ${steps[i].id} (${kind}) precedes the arm step`,
        );
      }
    }
  }
  const stageAt = steps.findIndex((s) => s.kind === "stage");
  if (stageAt >= 0 && steps[stageAt].id === steps[armAt].id) {
    throw new Error("the stage step was treated as the arm");
  }
}
