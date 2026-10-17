// Test fixtures for the first-sector (MBR) probe; synthetic bytes only.
import { mbrTargets, type ProbeInputs } from "./protected_devices.ts";

/** A sector 0 as `od` prints it: 512 bytes, boot code optional. */
export function sector0(
  opts: { code?: boolean; sig?: boolean; bytes?: Record<number, number> } = {},
): string {
  const b = new Array(512).fill(0);
  for (const [i, v] of Object.entries(opts.bytes ?? {})) b[Number(i)] = v;
  if (opts.code) { for (let i = 0; i < 446; i++) b[i] = i % 251 + 1; }
  if (opts.sig ?? true) {
    b[510] = 0x55;
    b[511] = 0xaa;
  }
  const rows: string[] = [];
  for (let i = 0; i < 512; i += 16) {
    rows.push(
      " " +
        b.slice(i, i + 16).map((x: number) => x.toString(16).padStart(2, "0"))
          .join(" "),
    );
  }
  return rows.join("\n") + "\n";
}

/** Answers "zeros plus the 55aa signature" for every unscripted disk. */
export function withMbr(input: ProbeInputs, candidates: string[]): ProbeInputs {
  const mbr = { ...input.mbr };
  for (const path of mbrTargets(input, candidates)) {
    mbr[path] ??= { code: 0, stdout: sector0() };
  }
  return { ...input, mbr };
}
