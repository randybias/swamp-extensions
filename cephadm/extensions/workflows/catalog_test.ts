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
import { Environment } from "npm:@marcbachmann/cel-js@7.6.1";
import { model } from "../models/cephadm.ts";

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

/** Methods that only read; anything else in a step is a mutation. */
const READ_ONLY_METHODS = new Set([
  "cephVerifyHostPrep",
  "cephVerifyMonQuorum",
  "cephVerifyMgr",
  "cephVerifyOsd",
  "cephVerifyCsiUsers",
  "cephVerifyHealth",
  "cephVerifyDisksRaw",
  "cephVerifyMonPlacement",
  "cephVerifyMgrPlacement",
  "cephVerifyOsdClaimable",
  "cephVerifyKeyDistributed",
  "cephVerifyPool",
  "cephVerifyClusterFsid",
  "cephVerifyHostNoout",
  "cephVerifyHostTornDown",
  "cephVerifyPackageSource",
  "cephVerifyRbdSmoke",
  "cephHostClusterState",
  "cephHostMaintenanceState",
  "cephCephadmCheckHost",
  "cephOsdOkToStop",
  "cephGetConnBundle",
  "cephFetchCsiKey",
  "cephCapacityReport",
  "cephRgwBucketInventory",
]);

/** The step names a step depends on, within its job. */
function dependsOnSteps(step: Json): string[] {
  return asArr(step.dependsOn).map((entry) => asStr(asObj(entry).step)).filter(
    (name) => name !== "",
  );
}

/** Every step name reachable from `name` through `dependsOn` in one job. */
function ancestors(jobSteps: Json[], name: string): Set<string> {
  const byName = new Map(jobSteps.map((step) => [asStr(step.name), step]));
  const seen = new Set<string>();
  const start = byName.get(name);
  const stack = start ? dependsOnSteps(start) : [];
  while (stack.length > 0) {
    const next = stack.pop() as string;
    if (seen.has(next)) continue;
    seen.add(next);
    const step = byName.get(next);
    if (step) stack.push(...dependsOnSteps(step));
  }
  return seen;
}

/** Recursively collects every string in a parsed document. */
function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
  } else if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) collectStrings(item, out);
  }
}

/** Every `${{ ... }}` expression in one string. */
function expressions(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split("${{").slice(1)) {
    const end = part.indexOf("}}");
    out.push((end >= 0 ? part.slice(0, end) : part).trim());
  }
  return out;
}

/** Inputs that are neither required nor defaulted, so they may be absent. */
function optionalNames(inputs: Json): Set<string> {
  const props = asObj(inputs.properties);
  const required = new Set(asArr(inputs.required).map(asStr));
  return new Set(
    Object.keys(props).filter((name) =>
      !required.has(name) && !("default" in asObj(props[name]))
    ),
  );
}

/** Builds a value for one declared input. */
function synthValue(name: string, schema: Json): unknown {
  if (Array.isArray(schema.enum) && schema.enum.length > 0) {
    return schema.enum[0];
  }
  const type = asStr(schema.type);
  if (type === "boolean") return true;
  if (type === "integer" || type === "number") {
    if (name === "port") return 22;
    if (name === "priority") return 100;
    return 1;
  }
  if (type === "array") {
    const items = asObj(schema.items);
    if (asStr(items.type) === "object") return [synthObject(items)];
    if (name === "placement") return ["web-1.example.com"];
    return ["example"];
  }
  if (type === "object") return synthObject(schema);
  if (name === "host" || name === "adminHost" || name === "targetHost") {
    return "192.0.2.10";
  }
  if (name === "targetAddr") return "192.0.2.11";
  if (name === "monIp" || name === "addr") return "192.0.2.10";
  if (name === "publicNet" || name === "clusterNet") return "192.0.2.0/24";
  if (name === "sshUser" || name === "adminUsername") return "root";
  if (name === "host_key_policy") return "strict";
  if (name === "host_keys") {
    return ["192.0.2.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey"];
  }
  if (name === "scheme") return "replicated";
  if (name === "cephImage") return "registry.example.com/ceph/ceph:v19.2.1";
  return "example";
}

/** Builds an object from a schema's properties. */
function synthObject(schema: Json): Record<string, unknown> {
  const props = asObj(schema.properties);
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(props)) {
    out[key] = synthValue(key, asObj(value));
  }
  return out;
}

/** Required and defaulted inputs, with the optional ones omitted. */
function buildInputs(inputs: Json): Record<string, unknown> {
  const props = asObj(inputs.properties);
  const required = new Set(asArr(inputs.required).map(asStr));
  const out: Record<string, unknown> = {};
  for (const [name, rawSchema] of Object.entries(props)) {
    const schema = asObj(rawSchema);
    if (required.has(name)) out[name] = synthValue(name, schema);
    else if ("default" in schema) out[name] = schema.default;
  }
  return out;
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
      required.includes("host_key_policy"),
      "host_key_policy must be required",
    );
    assertEquals(
      asObj(props.host_key_policy).enum,
      ["strict", "insecure_tofu"],
      "host_key_policy enum must be exactly strict/insecure_tofu",
    );
    assert("host_keys" in props, "host_keys input missing");
    assertEquals(
      asObj(props.host_keys).type,
      "array",
      "host_keys must be an array",
    );
  });

  Deno.test(`${label}: every step input key is a method argument`, () => {
    const methods = model.methods as unknown as Record<
      string,
      {
        arguments: {
          shape: Record<
            string,
            { safeParse: (v: unknown) => { success: boolean } }
          >;
        };
      }
    >;
    for (const { step } of steps(doc)) {
      const t = task(step);
      if (asStr(t.type) !== "model_method") continue;
      const methodName = asStr(t.methodName);
      const method = methods[methodName];
      assert(method !== undefined, `unknown method ${methodName}`);
      const shape = method.arguments.shape;
      const inputs = asObj(t.inputs);
      for (const key of Object.keys(inputs)) {
        assert(
          key in shape,
          `${name}: step ${
            asStr(step.name)
          } passes unknown input ${key} to ${methodName}`,
        );
      }
      for (const [key, field] of Object.entries(shape)) {
        if (field.safeParse(undefined).success) continue; // optional or defaulted
        assert(
          key in inputs,
          `${name}: step ${
            asStr(step.name)
          } omits required ${key} for ${methodName}`,
        );
      }
    }
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

  Deno.test(`${label}: every mutating method sits behind an approval, with a prove job`, () => {
    const all = steps(doc);
    const mutating = all.filter(({ step }) => {
      const t = task(step);
      const method = asStr(t.methodName);
      return asStr(t.type) === "model_method" && method !== "" &&
        !READ_ONLY_METHODS.has(method);
    });
    if (mutating.length === 0) return;
    const jobs = asArr(doc.jobs).map(asObj);
    const approvals = new Set(
      all.filter(({ step }) => asStr(task(step).type) === "manual_approval")
        .map(({ name }) => name),
    );
    assert(approvals.size > 0, "mutating workflow has no manual_approval step");
    for (const { job, name, step } of mutating) {
      const jobRecord = jobs.find((entry) => asStr(entry.name) === job);
      const jobSteps = asArr(asObj(jobRecord).steps).map(asObj);
      const reached = ancestors(jobSteps, name);
      const approved = [...approvals].some((approval) => reached.has(approval));
      assert(
        approved,
        `${label}: ${name} (${
          asStr(task(step).methodName)
        }) is not behind an approval`,
      );
    }
    const approvalJobs = jobs.filter((job) =>
      asArr(job.steps).some((s) =>
        asStr(task(asObj(s)).type) === "manual_approval"
      )
    );
    const proveJob = jobs.find((job) => {
      if (approvalJobs.includes(job)) return false;
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

Deno.test("every gated mutating step directly depends on each gate and the approval", () => {
  const failures: string[] = [];
  for (const { rel, doc } of catalog) {
    for (const jobRaw of asArr(doc.jobs)) {
      const job = asObj(jobRaw);
      const jobSteps = asArr(job.steps).map(asObj);
      const approvals = jobSteps.filter((s) =>
        asStr(task(s).type) === "manual_approval"
      ).map((s) => asStr(s.name));
      if (approvals.length === 0) continue;
      const assertSteps = jobSteps.filter((s) =>
        asStr(task(s).type) === "assert"
      ).map((s) => asStr(s.name));
      // Gate asserts that run before approval, and re-gate asserts whose own
      // ancestors include an approval. The latter must exist and be a direct
      // edge regardless of the mutation's own dependency list.
      const preGates = assertSteps.filter((a) =>
        approvals.some((ap) => ancestors(jobSteps, ap).has(a))
      );
      const postGates = assertSteps.filter((a) =>
        approvals.some((ap) => ancestors(jobSteps, a).has(ap))
      );
      const mutating = jobSteps.filter((s) => {
        const t = task(s);
        return asStr(t.type) === "model_method" &&
          !READ_ONLY_METHODS.has(asStr(t.methodName));
      });
      for (const m of mutating) {
        const name = asStr(m.name);
        const anc = ancestors(jobSteps, name);
        const approvalAnc = approvals.filter((a) => anc.has(a));
        if (approvalAnc.length === 0) continue;
        if (preGates.length > 0 && postGates.length === 0) {
          failures.push(
            `${rel}: ${name} has a pre-gate but no post-approval re-gate assert`,
          );
        }
        const direct = asArr(m.dependsOn).map(asObj);
        const directByName = new Map(
          direct.map((d) => [asStr(d.step), asStr(asObj(d.condition).type)]),
        );
        for (const required of [...approvalAnc, ...preGates, ...postGates]) {
          if (!directByName.has(required)) {
            failures.push(
              `${rel}: ${name} lacks a direct dependency on ${required}`,
            );
          } else if (directByName.get(required) !== "succeeded") {
            failures.push(
              `${rel}: ${name} -> ${required} is not succeeded-only (${
                directByName.get(required)
              })`,
            );
          }
        }
      }
    }
  }
  assertEquals(failures, [], failures.join("\n"));
});

Deno.test("optional inputs are referenced only inside has() ternaries", () => {
  const failures: string[] = [];
  for (const { rel, doc } of catalog) {
    const optional = optionalNames(asObj(doc.inputs));
    if (optional.size === 0) continue;
    const strings: string[] = [];
    collectStrings(doc, strings);
    for (const text of strings) {
      for (const expr of expressions(text)) {
        for (const name of optional) {
          if (!new RegExp(`\\binputs\\.${name}\\b`).test(expr)) continue;
          if (new RegExp(`has\\(\\s*inputs\\.${name}\\s*\\)`).test(expr)) {
            continue;
          }
          failures.push(`${rel}: inputs.${name} unguarded in: ${expr}`);
        }
      }
    }
  }
  assertEquals(failures, [], failures.join("\n"));
});

Deno.test("every workflow expression evaluates with optional inputs absent", () => {
  const cel = new Environment({ unlistedVariablesAreDyn: true });
  const failures: string[] = [];
  for (const { rel, doc } of catalog) {
    const optional = optionalNames(asObj(doc.inputs));
    if (optional.size === 0) continue;
    const inputs = buildInputs(asObj(doc.inputs));
    const strings: string[] = [];
    collectStrings(doc, strings);
    for (const text of strings) {
      for (const expr of expressions(text)) {
        try {
          cel.evaluate(expr, {
            inputs,
            run: { startedAt: "2000-01-01T00:00:00.000Z" },
            self: {},
          });
        } catch (error) {
          const message = error instanceof Error
            ? error.message
            : String(error);
          const match = /No such key: ([A-Za-z_][A-Za-z0-9_]*)/.exec(message);
          if (match && optional.has(match[1])) {
            failures.push(`${rel}: ${expr} -> ${message.split("\n")[0]}`);
          }
        }
      }
    }
  }
  assertEquals(failures, [], failures.join("\n"));
});
