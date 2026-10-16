/**
 * Fixture guard: test and fixture files may contain only documentation
 * addresses (RFC 5737, RFC 3849, RFC 7042, loopback) or synthetic MACs.
 * Usage: fixture-guard.ts <extension-dir>. Exit 0 clean, 1 findings, 2 cannot run.
 */
import { findAddresses } from "./lib/addresses.ts";
import { allowReason } from "./lib/allow.ts";

async function* walk(dir: string): AsyncGenerator<string> {
  for await (const e of Deno.readDir(dir)) {
    if (e.name === ".swamp" || e.name === "node_modules") continue;
    const p = `${dir}/${e.name}`;
    // Follow symlinks so a linked fixtures dir cannot hide from the guard.
    const info = e.isSymlink ? await Deno.stat(p) : e;
    if (info.isDirectory) yield* walk(p);
    else if (info.isFile) yield p;
  }
}

const TEST_FILE = /([._]test\.[cm]?[jt]sx?|\.snap)$/i;
const TEST_DIR = /(^|\/)(fixtures?|testdata|tests?|__snapshots__)\//i;

/** Every test file (`*_test.ts`, `*.test.js`, `*.snap`) plus every file under a fixture or test dir, sorted. */
export async function fixtureFiles(extDir: string): Promise<string[]> {
  const out: string[] = [];
  for await (const p of walk(extDir)) {
    const rel = p.slice(extDir.length + 1);
    if (TEST_FILE.test(rel) || TEST_DIR.test(rel)) out.push(p);
  }
  return out.sort();
}

/** Return `path:line kind value` for every non-documentation address in fixtures. */
export async function guard(extDir: string): Promise<string[]> {
  const findings: string[] = [];
  for (const f of await fixtureFiles(extDir)) {
    const text = await Deno.readTextFile(f);
    if (text.includes("\0")) continue;
    const lines = text.split("\n");
    for (const h of findAddresses(text)) {
      if (h.documentation || allowReason(lines[h.line - 1])) continue;
      findings.push(
        `${f.slice(extDir.length + 1)}:${h.line} ${h.kind} ${h.value}`,
      );
    }
  }
  return findings;
}

if (import.meta.main) {
  const dir = Deno.args[0]?.replace(/\/$/, "");
  try {
    if (!dir || !(await Deno.stat(`${dir}/manifest.yaml`)).isFile) {
      throw new Error();
    }
  } catch {
    console.error(
      "fixture-guard: usage: fixture-guard.ts <extension-dir with manifest.yaml>",
    );
    Deno.exit(2);
  }
  const findings = await guard(dir);
  findings.forEach((l) => console.log(l));
  Deno.exit(findings.length ? 1 : 0);
}
