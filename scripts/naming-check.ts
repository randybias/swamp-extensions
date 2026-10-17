/**
 * Naming check (gate 9): visibility, audience and names, per the naming and
 * visibility convention (shared-docs 2026-10-17, sections 2 to 4).
 * Usage: naming-check.ts <extension-dir>   one extension
 *        naming-check.ts --all             every top-level dir holding manifest.yaml
 * Run from the repo root. Exit 0 clean, 1 findings, 2 cannot run.
 * Denylist terms are never printed, only their index.
 */
import { loadDenylist, redact } from "./leak-scan.ts";

// ---- Policy. Every exception below is temporary and listed in STATUS. ----

/** This repo is the public monorepo: a private extension here fails. */
export const REPO_VISIBILITY: "public" | "private" =
  (Deno.env.get("NAMING_REPO_VISIBILITY") as "public" | "private" | undefined) ?? "public";

/** Expected manifest collective per visibility. Both @randybias until the @bogworks move. */
export const COLLECTIVE: Record<string, string> = {
  public: Deno.env.get("NAMING_COLLECTIVE_PUBLIC") ?? "@randybias",
  private: Deno.env.get("NAMING_COLLECTIVE_PRIVATE") ?? "@randybias",
};

export const VISIBILITY_AUDIENCE: Record<string, string> = {
  public: "general",
  private: "personal",
};

export const BANNED_NOUNS = new Set([
  "stack",
  "tools",
  "utils",
  "helpers",
  "misc",
  "common",
  "core",
  "base",
  "manager",
  "service",
  "system",
  "host",
  "server",
  "infra",
  "platform",
  "ops",
]);

/**
 * Public names that use a banned noun, judged qualified by a concrete system noun.
 * A new name with a banned noun fails until a reviewer adds it here.
 */
export const QUALIFIED_NAMES = new Set([
  "ssh-host", // ssh is the system
  "artifact-server", // under audit, see STATUS
  "k8s-secret", // under audit, see STATUS
  "secret-file", // under audit, see STATUS
  "host-net", // under audit, see STATUS
  "server-host", // under audit, see STATUS
]);

export const VERBS = new Set([
  "create",
  "delete",
  "bootstrap",
  "join",
  "rotate",
  "upgrade",
  "restore",
  "verify",
  "apply",
  "drain",
]);

/** Existing workflow names (collective stripped) that break the workflow rule. Under audit, see STATUS. */
export const WORKFLOW_EXCEPTIONS = new Set([
  "cephadm-add-host",
  "cephadm-distribute-key",
  "cephadm-fetch-csi-key",
  "cephadm-get-conn-bundle",
  "cephadm-inventory-rgw-buckets",
  "cephadm-prep-host",
  "cephadm-remove-osds",
  "cephadm-wipe-disks",
  // moving to the private repo, see STATUS
  "server-stack-provision-host",
  "server-stack-teardown-host",
]);

/** Extensions whose LOGBOOK predates the visibility:/audience: lines. Under audit, see STATUS. */
export const LOGBOOK_EXCEPTIONS = new Set([
  "apt-cache",
  "artifact-server",
  "azure-nsg",
  "azure-vm",
  "cephadm",
  "cherry-servers",
  "host-net",
  "k0s-cluster",
  "k8s-secret",
  "kea-dhcp",
  "knot-dns",
  "kubevirt",
  "libvirt",
  "redfish",
  "secret-file",
  "server-host",
  "server-stack",
  "ssh-host",
  "syncthing-peer",
  "ubuntu-autoinstall",
  "wireguard-mesh",
  "zfs",
]);

/**
 * Per-extension waivers of named rules. server-stack only: it is private and
 * personal, published publicly by mistake, and is moving to the private repo,
 * see STATUS. Waived findings are still printed.
 */
export const WAIVERS: Record<string, Set<string>> = {
  "server-stack": new Set(["private-in-public-repo", "manifest-visibility"]),
};

// ---- Checks ----

export interface ExtInfo {
  ext: string;
  release: { visibility?: unknown; audience?: unknown } | undefined;
  manifestName: string;
  manifestVisibility?: string;
  workflows: string[]; // full names, e.g. "@randybias/cephadm-add-host"
  logbook?: string; // LOGBOOK.md text, undefined when absent
}

export interface Finding {
  rule: string;
  detail: string;
  waived: boolean;
}

const CHARSET = /^[a-z0-9]+(-[a-z0-9]+)*$/;
/** A segment that is a number, a version or a date: 2026, v2, 20261017. */
const VERSIONISH = /^v?\d+$/;

/** Charset, hyphen, version and date findings for one bare name. */
export function lintName(name: string): string[] {
  const out: string[] = [];
  if (!CHARSET.test(name)) out.push("lowercase letters, digits and single hyphens only");
  const bad = name.split("-").filter((s) => VERSIONISH.test(s));
  if (bad.length) out.push(`version or date segment: ${bad.join(",")}`);
  return out;
}

function splitCollective(full: string): [string, string] {
  const m = /^(@[^/]+)\/(.+)$/.exec(full);
  return m ? [m[1], m[2]] : ["", full];
}

/** Every naming finding for one extension, waivers applied but kept. */
export function checkExtension(info: ExtInfo, deny: string[]): Finding[] {
  const raw: [string, string][] = [];
  const add = (rule: string, detail: string) => raw.push([rule, detail]);
  const { ext } = info;

  // (a) release.yaml declarations
  const vis = info.release?.visibility;
  const aud = info.release?.audience;
  if (!info.release) add("release", `no ${ext} stanza in release.yaml`);
  if (vis !== "public" && vis !== "private") {
    add("visibility", `release.yaml ${ext}.visibility must be public or private`);
  }
  if (aud !== "general" && aud !== "personal") {
    add("audience", `release.yaml ${ext}.audience must be general or personal`);
  }
  const visibility = vis === "private" ? "private" : "public";
  if (
    typeof vis === "string" && typeof aud === "string" && VISIBILITY_AUDIENCE[vis] !== undefined
  ) {
    if (VISIBILITY_AUDIENCE[vis] !== aud) {
      add("audience", `${vis} requires audience ${VISIBILITY_AUDIENCE[vis]}, got ${aud}`);
    }
  }
  const manVis = info.manifestVisibility ?? "public";
  if ((vis === "public" || vis === "private") && manVis !== vis) {
    add("manifest-visibility", `manifest visibility ${manVis} != release.yaml ${vis}`);
  }

  // (b) a private extension in the public repo
  if (vis === "private" && REPO_VISIBILITY === "public") {
    add(
      "private-in-public-repo",
      "private extension in the public repo: move it to the private repo",
    );
  }

  // (c) name lint, (d) denylist, (e) collective
  const [collective, pkg] = splitCollective(info.manifestName);
  if (pkg !== ext) add("name", `manifest name ${info.manifestName} does not match dir ${ext}`);
  for (const f of lintName(pkg)) add("name", `${pkg}: ${f}`);
  const segs = pkg.split("-");
  if (visibility === "public") {
    if (segs.length > 3) add("name", `${pkg}: ${segs.length} segments, public names allow 3`);
    const banned = segs.filter((s) => BANNED_NOUNS.has(s));
    if (banned.length && !QUALIFIED_NAMES.has(pkg)) {
      add(
        "name",
        `${pkg}: banned noun ${banned.join(",")} needs a concrete system qualifier ` +
          "and a reviewed QUALIFIED_NAMES entry",
      );
    }
  }
  const expected = COLLECTIVE[visibility];
  if (collective !== expected) {
    add("collective", `${info.manifestName}: ${visibility} expects collective ${expected}`);
  }
  const deniedIn = (name: string) => {
    const low = name.toLowerCase();
    deny.forEach((t, n) => {
      if (low.includes(t)) add("denylist", `name ${name} <denylisted:${n}>`);
    });
  };
  deniedIn(info.manifestName);

  // (f) workflows
  for (const full of info.workflows) {
    const [wc, wf] = splitCollective(full);
    deniedIn(full);
    for (const f of lintName(wf)) add("workflow", `${wf}: ${f}`);
    if (wc !== expected) add("workflow", `${full}: ${visibility} expects collective ${expected}`);
    if (WORKFLOW_EXCEPTIONS.has(wf)) continue;
    const wsegs = wf.split("-");
    if (visibility === "public") {
      if (!wf.startsWith(`${ext}-`)) add("workflow", `${wf}: must start with ${ext}-`);
      const verb = wf.startsWith(`${ext}-`) ? wf.slice(ext.length + 1).split("-")[0] : "";
      if (!VERBS.has(verb)) add("workflow", `${wf}: verb ${verb || "(none)"} not in the verb list`);
      if (wsegs.length > 5) add("workflow", `${wf}: ${wsegs.length} segments, at most 5`);
    } else if (!wsegs.some((s) => VERBS.has(s))) {
      add("workflow", `${wf}: no verb from the verb list`);
    }
  }

  // (g) LOGBOOK carries the declarations
  if (!LOGBOOK_EXCEPTIONS.has(ext)) {
    const text = info.logbook;
    if (text === undefined) add("logbook", `${ext}/LOGBOOK.md missing`);
    else {
      const lv = /^visibility:[ \t]*(\S+)[ \t]*$/m.exec(text)?.[1];
      const la = /^audience:[ \t]*(\S+)[ \t]*$/m.exec(text)?.[1];
      if (!lv) add("logbook", "LOGBOOK.md has no literal visibility: line");
      else if (lv !== vis) add("logbook", `LOGBOOK visibility ${lv} != release.yaml ${vis}`);
      if (!la) add("logbook", "LOGBOOK.md has no literal audience: line");
      else if (la !== aud) add("logbook", `LOGBOOK audience ${la} != release.yaml ${aud}`);
    }
  }

  const waived = WAIVERS[ext] ?? new Set<string>();
  return raw.map(([rule, detail]) => ({ rule, detail, waived: waived.has(rule) }));
}

// ---- CLI ----

async function yqJson(path: string): Promise<unknown> {
  const r = await new Deno.Command("yq", { args: ["-o=json", ".", path], stderr: "null" }).output();
  if (!r.success) throw new Error(`yq cannot read ${path}`);
  return JSON.parse(new TextDecoder().decode(r.stdout));
}

async function gather(ext: string, release: Record<string, unknown>): Promise<ExtInfo> {
  // deno-lint-ignore no-explicit-any
  const man = await yqJson(`${ext}/manifest.yaml`) as any;
  const workflows: string[] = [];
  for (const w of (man?.workflows ?? []) as string[]) {
    // deno-lint-ignore no-explicit-any
    const wy = await yqJson(`${ext}/extensions/workflows/${w}`) as any;
    workflows.push(String(wy?.name ?? w));
  }
  let logbook: string | undefined;
  try {
    logbook = await Deno.readTextFile(`${ext}/LOGBOOK.md`);
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
  }
  return {
    ext,
    release: release[ext] as ExtInfo["release"],
    manifestName: String(man?.name ?? ""),
    manifestVisibility: man?.visibility,
    workflows,
    logbook,
  };
}

if (import.meta.main) {
  const arg = Deno.args[0];
  let exts: string[] = [];
  let deny: string[];
  let release: Record<string, unknown>;
  const infos: ExtInfo[] = [];
  try {
    if (arg === "--all") {
      for await (const e of Deno.readDir(".")) {
        if (!e.isDirectory) continue;
        try {
          if ((await Deno.stat(`${e.name}/manifest.yaml`)).isFile) exts.push(e.name);
        } catch { /* not an extension */ }
      }
      exts.sort();
    } else if (arg && (await Deno.stat(`${arg}/manifest.yaml`)).isFile) {
      exts = [arg.replace(/\/$/, "")];
    } else throw new Error("usage: naming-check.ts <extension-dir> | --all");
    deny = await loadDenylist(
      Deno.env.get("LEAK_DENYLIST"),
      `${Deno.env.get("HOME")}/.config/swamp-extensions/denylist`,
    );
    release = (await yqJson("release.yaml") ?? {}) as Record<string, unknown>;
    for (const ext of exts) infos.push(await gather(ext, release));
  } catch (e) {
    console.error(`naming-check: cannot run: ${(e as Error).message}`);
    Deno.exit(2);
  }
  let failed = false;
  for (const info of infos) {
    for (const f of checkExtension(info, deny)) {
      if (!f.waived) failed = true;
      console.log(
        redact(`${f.waived ? "WAIVED" : "FAIL"} ${info.ext} ${f.rule}: ${f.detail}`, deny),
      );
    }
  }
  Deno.exit(failed ? 1 : 0);
}
