/**
 * Leak scan: denylisted names, private addresses, foreign emails and
 * unresolvable references. The denylist is never committed: it comes from
 * $LEAK_DENYLIST or ~/.config/swamp-extensions/denylist.
 * Usage: leak-scan.ts <extension-dir>. Exit 0 clean, 1 findings, 2 cannot run.
 */
import { findAddresses, isPrivateIpv4, isPrivateIpv6 } from "./lib/addresses.ts";
import { allowReason } from "./lib/allow.ts";

const EMAIL = /[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b/g;
const SAFE_EMAIL_DOMAIN = /^(example\.(com|org|net)|.+\.example|.+\.test)$/i;
const REFERENCE = [
  /per the spec/i,
  /see section/i,
  /§\s*\d/,
  /\bTODO\b/,
  /\bFIXME\b/,
  /\bTBD\b/,
  /\bD\d{1,3}\b/,
];

/** Load the denylist from `env` (preferred) or `path`; throws when missing or empty. */
export async function loadDenylist(env: string | undefined, path: string): Promise<string[]> {
  const raw = env ?? await Deno.readTextFile(path);
  const terms = raw.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
    .map((l) => l.toLowerCase());
  if (!terms.length) throw new Error("denylist is empty");
  return terms;
}

/** Scan one file's text and return `rel:line class detail` findings; `packaged` enables the reference class. */
export function scanText(rel: string, text: string, deny: string[], packaged: boolean): string[] {
  const out: string[] = [];
  const lowRel = rel.toLowerCase();
  deny.forEach((t, n) => {
    if (lowRel.includes(t)) out.push(`${rel}:0 denylist-path <denylisted:${n}>`);
  });
  text.split("\n").forEach((src, i) => {
    const at = `${rel}:${i + 1}`;
    const low = src.toLowerCase();
    deny.forEach((t, n) => {
      if (low.includes(t)) out.push(`${at} denylist <denylisted:${n}>`);
    });
    if (allowReason(src)) return;
    for (const h of findAddresses(src)) {
      if (
        (h.kind === "ipv4" && isPrivateIpv4(h.value)) ||
        (h.kind === "ipv6" && isPrivateIpv6(h.value))
      ) out.push(`${at} private-address ${h.value}`);
    }
    for (const m of src.matchAll(EMAIL)) {
      if (m[0].toLowerCase() === "noreply@anthropic.com" || SAFE_EMAIL_DOMAIN.test(m[1])) continue;
      out.push(`${at} email ${m[0]}`);
    }
    // Report the rule, never the line: the line may hold a denylisted term.
    const rule = packaged ? REFERENCE.findIndex((r) => r.test(src)) : -1;
    if (rule >= 0) out.push(`${at} reference rule:${rule}`);
  });
  return out.map((l) => redact(l, deny));
}

/** Replace every denylisted term in a diagnostic line with its index. */
function redact(line: string, deny: string[]): string {
  let shown = line;
  deny.forEach((t, n) => {
    shown = shown.replace(
      new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"),
      `<denylisted:${n}>`,
    );
  });
  return shown;
}

function isPackaged(rel: string): boolean {
  return rel === "README.md" || rel === "manifest.yaml" || rel.startsWith("extensions/");
}

if (import.meta.main) {
  const dir = Deno.args[0]?.replace(/\/$/, "");
  let deny: string[];
  try {
    if (!dir || !(await Deno.stat(`${dir}/manifest.yaml`)).isFile) {
      throw new Error("usage: leak-scan.ts <extension-dir>");
    }
    deny = await loadDenylist(
      Deno.env.get("LEAK_DENYLIST"),
      `${Deno.env.get("HOME")}/.config/swamp-extensions/denylist`,
    );
  } catch (e) {
    console.error(`leak-scan: cannot run: ${(e as Error).message}`);
    Deno.exit(2);
  }
  const ls = new Deno.Command("git", {
    args: ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."],
    cwd: dir,
  }).outputSync();
  if (!ls.success) {
    console.error("leak-scan: cannot run: git ls-files failed");
    Deno.exit(2);
  }
  const files = new TextDecoder().decode(ls.stdout).split("\0")
    .filter((f) => f && !f.endsWith("deno.lock"));
  const findings: string[] = [];
  for (const rel of files) {
    let text: string;
    try {
      text = await Deno.readTextFile(`${dir}/${rel}`);
    } catch (e) {
      if (e instanceof Deno.errors.NotFound) continue; // deleted in the working tree
      console.error(`leak-scan: cannot run: cannot read ${rel}: ${(e as Error).name}`);
      Deno.exit(2);
    }
    if (text.includes("\0")) continue; // binary
    findings.push(...scanText(rel, text, deny, isPackaged(rel)));
  }
  findings.forEach((l) => console.log(l));
  Deno.exit(findings.length ? 1 : 0);
}
