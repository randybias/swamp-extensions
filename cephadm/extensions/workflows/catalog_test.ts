/**
 * Catalog tests for every cephadm workflow.
 *
 * These read the manifest and the on-disk workflows and check the catalog's
 * structural rules: manifest-vs-disk agreement, naming and descriptions,
 * the single model instance or per-item instance names, the required
 * SSH block with no defaulted port, the exact host-key enum, the
 * gate shape of a mutating workflow (approval, separate prove job, report on
 * failed or skipped), and that no approval prompt embeds a record read.
 *
 * The workflows are a small, regular YAML subset, so this file carries a
 * purpose-built parser rather than a dependency, keeping the extension's
 * `deno.lock` untouched.
 *
 * @module
 */

import { assert, assertEquals } from "jsr:@std/assert@1.0.19";

/** A JSON-like parsed YAML object. */
type Json = Record<string, unknown>;

/** One significant line of YAML. */
interface Line {
  /** Leading-space count. */
  indent: number;
  /** Trailing-space-stripped content. */
  text: string;
}

/** Drops blank and comment lines and records each line's indent. */
function tokenize(text: string): Line[] {
  const lines: Line[] = [];
  for (const raw of text.split("\n")) {
    const trimmed = raw.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    lines.push({
      indent: raw.length - raw.trimStart().length,
      text: raw.trim(),
    });
  }
  return lines;
}

/** Parses one scalar: quotes, booleans, integers and inline arrays. */
function scalar(value: string): unknown {
  const v = value.trim();
  if (v === "") return null;
  if (v.startsWith("[")) {
    const inner = v.slice(1, v.endsWith("]") ? -1 : undefined);
    return inner.trim() === "" ? [] : inner.split(",").map((s) => scalar(s));
  }
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^-?\d+$/.test(v)) return Number(v);
  if (
    (v.startsWith("'") && v.endsWith("'")) ||
    (v.startsWith('"') && v.endsWith('"'))
  ) {
    return v.slice(1, -1);
  }
  return v;
}

/** Parses the YAML subset used by these workflow files. */
function parseYaml(text: string): Json {
  const lines = tokenize(text);
  let pos = 0;

  const parseList = (indent: number): unknown[] => {
    const out: unknown[] = [];
    while (
      pos < lines.length && lines[pos].indent === indent &&
      lines[pos].text.startsWith("- ")
    ) {
      const rest = lines[pos].text.slice(2).trim();
      if (/^[^:]+:/.test(rest)) {
        lines[pos] = { indent: indent + 2, text: rest };
        out.push(parseMap(indent + 2));
      } else {
        out.push(scalar(rest));
        pos++;
      }
    }
    return out;
  };

  const parseMap = (indent: number): Json => {
    const obj: Json = {};
    while (
      pos < lines.length && lines[pos].indent === indent &&
      !lines[pos].text.startsWith("- ")
    ) {
      const line = lines[pos];
      const colon = line.text.indexOf(":");
      if (colon < 0) {
        pos++;
        continue;
      }
      const key = line.text.slice(0, colon).trim();
      const rest = line.text.slice(colon + 1).trim();
      pos++;
      if (rest === ">-" || rest === ">" || rest === "|" || rest === "|-") {
        const parts: string[] = [];
        while (pos < lines.length && lines[pos].indent > line.indent) {
          parts.push(lines[pos].text.trim());
          pos++;
        }
        obj[key] = parts.join(" ");
      } else if (rest === "") {
        obj[key] = parseNode(indent + 2);
      } else {
        obj[key] = scalar(rest);
      }
    }
    return obj;
  };

  const parseNode = (indent: number): unknown => {
    if (pos >= lines.length || lines[pos].indent < indent) return null;
    if (lines[pos].text.startsWith("- ")) return parseList(indent);
    return parseMap(indent);
  };

  return parseNode(lines[0]?.indent ?? 0) as Json;
}

/** Coerces a value to an object. */
function asObj(value: unknown): Json {
  return (value ?? {}) as Json;
}

/** Coerces a value to an array. */
function asArr(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** Coerces a value to a string. */
function asStr(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** Every step across every job, with its job name. */
function steps(doc: Json): { job: string; name: string; step: Json }[] {
  const out: { job: string; name: string; step: Json }[] = [];
  for (const rawJob of asArr(doc.jobs)) {
    const job = asObj(rawJob);
    for (const rawStep of asArr(job.steps)) {
      const step = asObj(rawStep);
      out.push({ job: asStr(job.name), name: asStr(step.name), step });
    }
  }
  return out;
}

/** The task of a step. */
function task(step: Json): Json {
  return asObj(step.task);
}

const here = import.meta.dirname ?? "extensions/workflows";
const root = `${here}/../..`;
const manifest = parseYaml(
  await Deno.readTextFile(`${root}/manifest.yaml`),
);
const listed = asArr(manifest.workflows).map(asStr).sort();
const onDisk = [...Deno.readDirSync(here)]
  .filter((entry) => entry.isDirectory)
  .map((entry) => `${entry.name}/workflow.yaml`)
  .sort();

const catalog = await Promise.all(
  onDisk.map(async (rel) => ({
    rel,
    doc: parseYaml(await Deno.readTextFile(`${here}/${rel}`)),
  })),
);

Deno.test("manifest workflows list and the workflow directory agree ", () => {
  assertEquals(listed, onDisk);
});

for (const { rel, doc } of catalog) {
  const name = asStr(doc.name);
  const label = name || rel;

  const shortName = name.replace(/^@[^/]+\//, "");
  Deno.test(`${label}: name, and one-line description of 40-90 characters`, () => {
    assert(
      /^(?:@randybias\/)?cephadm-[a-z0-9]+(?:-[a-z0-9]+)+$/.test(name),
      `bad workflow name: ${name}`,
    );
    assertEquals(name.includes("--"), false, "double hyphen in name");
    assert(!shortName.startsWith("ceph-"), `ceph- prefix in name: ${name}`);
    assertEquals(`${shortName}/workflow.yaml`, rel);
    const description = asStr(doc.description);
    assert(
      description.length >= 40 && description.length <= 90,
      `description length ${description.length}: ${description}`,
    );
    assertEquals(description.includes("${{"), false, "template in description");
    assertEquals(description.includes("\n"), false, "newline in description");
  });

  Deno.test(`${label}: required SSH block with no defaulted port`, () => {
    const inputs = asObj(doc.inputs);
    const props = asObj(inputs.properties);
    const required = asArr(inputs.required).map(asStr);
    const hostKey = required.includes("host")
      ? "host"
      : required.includes("adminHost")
      ? "adminHost"
      : "";
    assert(hostKey !== "", "no host or adminHost input required");
    assert("port" in props, "port input missing");
    assert(!("default" in asObj(props.port)), "port must have no default");
    assert(required.includes("port"), "port must be required");
    assert(required.includes("sshUser"), "sshUser must be required");
    assert(
      required.includes("strictHostKeyChecking"),
      "strictHostKeyChecking must be required",
    );
    assertEquals(
      asObj(props.strictHostKeyChecking).enum,
      ["yes", "no"],
      "strictHostKeyChecking enum must be exactly yes/no",
    );
  });

  Deno.test(`${label}: every instance is cephadm or a per-item cephadm-* `, () => {
    const instances: string[] = [];
    for (const { step } of steps(doc)) {
      const t = task(step);
      if (asStr(t.type) === "model_method") {
        const instance = asStr(t.modelIdOrName);
        instances.push(instance);
        assert(
          instance === "cephadm" || instance.startsWith("cephadm-"),
          `bad model instance: ${instance}`,
        );
      }
    }
    for (const { step } of steps(doc)) {
      const t = task(step);
      for (const field of [asStr(t.expr), asStr(t.message), asStr(t.prompt)]) {
        for (const match of field.matchAll(/data\.latest\("([^"]+)"/g)) {
          const read = match[1];
          assert(
            read === "cephadm" || read.startsWith("cephadm-"),
            `data.latest reads a non-cephadm instance: ${read}`,
          );
          if (read !== "cephadm") {
            assert(
              instances.some((i) => i.startsWith(read)),
              `data.latest "${read}" has no producing step instance `,
            );
          }
        }
      }
    }
  });

  Deno.test(`${label}: every job and step is described`, () => {
    for (const rawJob of asArr(doc.jobs)) {
      const job = asObj(rawJob);
      assert(
        asStr(job.description).length > 0,
        `job ${asStr(job.name)} undescribed`,
      );
      for (const { step } of steps({ jobs: [job] })) {
        assert(
          asStr(step.description).length > 0,
          `step ${asStr(step.name)} undescribed`,
        );
      }
    }
  });

  Deno.test(`${label}: approval prompts name inputs and never read records`, () => {
    for (const { step } of steps(doc)) {
      const t = task(step);
      if (asStr(t.type) === "manual_approval") {
        const prompt = asStr(t.prompt);
        assert(prompt.length > 0, "empty approval prompt");
        assertEquals(
          prompt.includes("data.latest"),
          false,
          "approval prompt contains data.latest",
        );
        assertEquals(t.timeout, 3600, "approval timeout must be 3600");
      }
    }
  });

  Deno.test(`${label}: mutating workflows have pre-approval, prove and report jobs`, () => {
    const all = steps(doc);
    const mutating = all.some(({ step }) =>
      asStr(task(step).type) === "manual_approval"
    );
    if (!mutating) return;
    const jobs = asArr(doc.jobs).map(asObj);
    const approvalJob = jobs.find((job) =>
      asArr(job.steps).some((s) =>
        asStr(task(asObj(s)).type) === "manual_approval"
      )
    );
    const proveJob = jobs.find((job) => {
      if (job === approvalJob) return false;
      const jobSteps = asArr(job.steps).map(asObj);
      const read = jobSteps.some((s) => asStr(task(s).type) === "model_method");
      const asserts = jobSteps.some((s) => asStr(task(s).type) === "assert");
      return read && asserts;
    });
    assert(
      proveJob !== undefined,
      "no separate prove job with a read-back and assert",
    );
    assert(
      jobs.some((job) =>
        JSON.stringify(job.dependsOn ?? []).includes('"skipped"')
      ),
      "no report-failure job triggered on skipped",
    );
    for (const { step } of all) {
      const t = task(step);
      if (
        asStr(t.type) === "model_method" &&
        asStr(t.methodName).startsWith("cephVerify")
      ) {
        assertEquals(
          asObj(t.inputs).throwOnFail,
          false,
          `${asStr(t.methodName)} in ${label} must pass throwOnFail false`,
        );
      }
    }
  });
}
