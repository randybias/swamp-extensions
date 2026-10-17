# Conventions for `@randybias` swamp extensions

These rules apply to every extension in this repo. They combine the practice
of swamp's first-party extensions with Randy's own publishing standard. Where
the two differ, the choice is noted. The gates in `scripts/gates.sh` enforce
whatever can be checked mechanically.

## 1. The audience test

Every description, README line, doc comment and example must pass one test:
**would this make sense to someone with no access to anything of ours?**

Never publish any of the following:

- **Identifying details:** org, lab, host, domain or user names, real
  addresses, serials or MACs.
- **References the reader cannot follow:** "per the spec", "see section 6",
  internal ticket numbers.
- **Private idioms:** tier codes, phase names, process jargon.
- **Provenance:** history and incident stories belong in git and `LOGBOOK.md`.
- **Stale claims.**

Keep the hard-won lesson and drop the identifying instance. For example, write
"a host whose bare name does not resolve from the control host", not the
specific host that taught you this.

## 2. Naming

- Name the package and model type for the **kind of resource**, as
  `@randybias/<kind>`, e.g. `@randybias/cephadm`. Never name one after a
  particular deployment, cluster or site.
- Build one generic model per kind, using the factory pattern. Supply targets
  (hosts, clusters, zones) as method arguments or data, never baked into the
  type.
- **The same goes for model definitions, ours and in every example.** One
  definition per kind, with an `inputs` schema; its globalArguments are
  `${{ inputs.<name> }}` and secrets are vault references. Instance values
  (hostname, project, plan, region) arrive at run time with `--input`, so
  nothing in a definition names a particular host or deployment. A
  definition called `db-1-server` with `hostname: db-1` inside it is the
  anti-pattern. Write `cherry-server` with `--input hostname=db-1`.
  - The extension's state must be keyed by an instance value (e.g. the
    hostname), never by the definition name, so one definition can serve many
    instances.
- Use single hyphens only. Never use `--` as a separator.
- Name workflows `<kind>-<verb>-<object>`, e.g. `cephadm-apply-osds`.

## 3. Layout

This follows the first-party `@swamp` layout. Each extension directory
contains:

```
<ext>/
├── manifest.yaml
├── deno.json, deno.lock          exact-pinned npm versions
├── README.md, LICENSE.txt        both listed in additionalFiles
├── LOGBOOK.md                    maintainer notes; NOT in additionalFiles
├── extensions/models/<kind>.ts   model entry point (plain `export const model = {...}`)
├── extensions/models/_lib/*.ts   helpers, one concern per file
└── extensions/workflows/<name>/workflow.yaml
```

- Every `.ts` file has a sibling `_test.ts`.
- Imports use inline `npm:`/`jsr:` specifiers, e.g. `npm:zod@4.x.y`. Bare
  specifiers are forbidden, because the registry scorer runs without an import
  map.
- Static imports only.

## 4. Manifest

```yaml
manifestVersion: 1
name: "@randybias/<kind>"
version: "YYYY.MM.DD.MICRO"      # from `swamp extension version`
description: "<two sentences>"
license: Apache-2.0
repository: https://github.com/randybias/swamp-extensions
platforms: []
labels: [5-10 lowercase keywords]
additionalFiles: [README.md, LICENSE.txt]
models: [...]
workflows: [...]
```

The **description is two sentences**: what it does, and the one structural
fact a user needs. First-party extensions often use long markdown descriptions,
but we deliberately don't. The README is where detail belongs.

## 5. Descriptions in source and workflows

**Model types, methods and resources** get one to three sentences:

- what it does;
- whether it is idempotent;
- what it returns;
- the one caveat that would trip up a caller.

Then stop. Additional rules:

- A read-only method's description starts with `READ-ONLY.`
- A destructive method's description starts with `DESTRUCTIVE.`
- Check how it renders with `swamp model type describe <type> --json`.

**Workflow descriptions** are one line of 40–90 characters, verb first, e.g.
`Apply OSDs on named disks, one service per host`. Not allowed:

- markdown;
- YAML block scalars;
- multiple sentences;
- template syntax.

**Step and input descriptions:**

- A step is `<Verb> <what> [via <mechanism>]`.
- An input is a noun phrase plus its unit or format.
- Every step in a destructive workflow has a description.

**JSDoc** covers at least 80% of exported symbols, which is the registry
`symbols-docs` factor.

## 6. README

```markdown
# @randybias/<kind>

[Swamp](https://github.com/swamp-club/swamp) extension for <subject>.
Built and tested against <target system> <exact version>.

## Models
### `<kind>`
<one line>

| Method | Description |
|---|---|
| ... | one line, imperative, no trailing full stop |

## Workflows
## Dependencies
## Install
## Example
## How it works
## License
```

- Leave out any section that doesn't apply. If one applies but is empty,
  answer it in a single line.
- Generate the method tables from the source, never from memory.
- Every example must be checked against real syntax and the real schema.
- Examples use the factory form from §2: one definition with `inputs`, run
  for at least two instances. Never one definition per host. Users copy the
  example, so the example sets the pattern.
- Credentials always appear as vault references. Never show a literal secret,
  not even an obviously fake one.
- No status, roadmap or TODO language.
- Length: about 25–35 lines for one model, and under 150 in general.
- The tested-version line names only versions that were actually exercised on
  the twin (see §10).

## 7. Schemas and security

- Use strict `z.object` and never `.passthrough()` on anything exposed to CEL.
  Inputs are explicit and bounded.
- Mark every secret field `.meta({ sensitive: true })`. Secrets arrive only
  through vault references or ephemeral process environment. Never put one in
  source, command-line arguments, logs, data, fixtures or examples.
  - Deliver them over stdin, a header or an askpass helper.
- **Host-key policy** is a required input (strict, or explicitly insecure). It
  is never a silent default.
- **Remote commands.** Every caller-supplied value that reaches a remote shell
  is validated against an allowlist grammar and quoted. The grammar is enforced
  in every language the value passes through.
- **Data lifetime.** Declare a lifetime and GC policy for every resource. Plan
  for upgrades: a breaking schema change ships with a tested `upgrades[]`
  migration.

## 8. Tests and fixtures

- **Increasing-risk order:**
  1. schema, secret and license defects;
  2. pure mapping and contract tests;
  3. failure and adversarial tests;
  4. packaging;
  5. only then live tests.
- **Every public method has tests for:**
  - success;
  - idempotent re-run;
  - each documented failure mode;
  - injection attempts on every remote-bound input.
- **Fixtures are synthetic only:**
  - RFC 5737 addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`);
  - `example.com` or `.test` names;
  - placeholder serials, MACs and usernames.
- `scripts/fixture-guard.ts` fails the build on any other address range. A
  line that must keep one carries `leak-allow(<reason>)`.
- Recorded command output used as a fixture must be sanitized and should keep
  the real *shape* of the output.

### Live end-to-end testing

Unit tests are never a substitute for actual use. An extension is not
finished, and is never promoted to `stable`, until every model method and
every workflow it ships has run live, end to end:

- **The whole lifecycle,** in order, on a throwaway resource:
  1. create;
  2. read, get and sync;
  3. update, where the model has it;
  4. re-run, which must adopt the existing resource without creating a second;
  5. delete;
  6. delete again, which must be a clean no-op.
- **Every workflow** runs from its real entry point, with the inputs a
  consumer would pass, not just the model methods underneath it.
- **Failure paths that can be triggered for real** also run live. Examples are
  a wrong ID, a bad credential and an unreachable host.
- **Afterwards,** confirm with the provider's own API that nothing is left
  behind.

Throwaway resources, such as an hourly server or a scratch DNS record, are the
default target. The spend is part of the job, not a reason to skip the test.

## 9. Gates and review

A change is ready to merge only when `scripts/gates.sh <ext>` passes. The
script is the authority on gate order. In short:

- deno gates;
- swamp fmt;
- quality score;
- leak scan;
- gitleaks;
- fixture guard;
- dry-run push;
- adversarial-review report;
- naming check (gate 9, `scripts/naming-check.ts`): `visibility:` and
  `audience:` in `release.yaml` and the LOGBOOK, no private extension in this
  repo, package and workflow name lint; its temporary exceptions are listed in
  the script and in STATUS;
- code review.

Review rules:

- Review the final **committed** diff (`--from/--to` or a commit), never the
  working tree.
- **Use a multi-model panel**, with seats from different model families:
  1. the built-in Claude Code review; `ocr delegate preview|rule` picks the
     files and rules;
  2. `ocr review` on OpenRouter, using the providers in the local ocr config;
  3. a `codex` CLI seat, run read-only from an empty scratch directory, given
     only the diff and the rubric.
- Rank findings by convergence: a finding raised by two or more seats comes
  first, and a finding from one seat is a lead to check, not a verdict. Verify
  each finding at HEAD, then fix it or refute it with a reason. A clean result
  from weak models alone is weak evidence.
- Model credentials come only from `api_key_cmd` (vault) or the CLI's own login.
  Never put them on argv or in the repo.
- Use only the maintainer's own model accounts (OpenRouter, OpenAI via
  codex, Gemini).
- Send reviewers only this repo's code.
- An errored or empty seat is not a passing review. Name the seat and the cause,
  and never count it as a pass. Record the seats run, the failures and the
  dispositions in the PR or commit message.

## 10. Evidence and versions

- Recording evidence: each cell in a live test matrix is `pass`, `fail`,
  `blocked`, `skip` or `untested`.
  - A skip, or the absence of a failure, is never a pass.
  - Live tests run only on targets the maintainer owns.
- What we claim:
  - The README states only the exact versions tested there.
  - A version that hasn't been tested live is published to the `beta` channel
    and promoted later.
  - Promotion to `stable` needs a `pass` for every method and workflow in the
    live end-to-end matrix (§8). A `skip` or `untested` cell blocks it.

## 11. Publishing

- **Order of steps:**
  1. `swamp extension version`;
  2. bump the manifest and model version;
  3. `swamp extension fmt`;
  4. `swamp extension quality`;
  5. `swamp extension push --dry-run --json`;
  6. adversarial-review report;
  7. every gate green (the approval);
  8. push.
- **Who pushes:**
  - Claude pushes the first version of an extension once every gate passes,
    including the review report for its exact contentHash. Randy delegated
    this on 2026-10-16. Pushes are public, and beta until tested live.
  - After that, CI publishes when a manifest version changes on `main`
    (`ci: true` in `release.yaml`).
- Versions are immutable. Fix forward with a MICRO bump. Use `swamp extension
  deprecate` to retire a version, never deletion.
