/**
 * An in-memory SSH target for tests.
 *
 * It is a drop-in {@link SshDeps} whose `run` never spawns a process: it
 * recovers the remote script from the quoted ssh argv and serves it from a
 * small fake filesystem. It exists only for the test files, is imported by no
 * model, and is therefore not packaged.
 *
 * @module
 */

import {
  type CommandResult,
  type RunOptions,
  sha256Hex,
  type SshDeps,
} from "./ssh.ts";
import { renderSha256Sums } from "./layout.ts";
import { normalizeMode } from "./remote.ts";

/** One file in the fake remote filesystem. */
export interface FakeFile {
  /** File text. */
  content: string;
  /** Octal mode without a leading zero, e.g. `644`. */
  mode: string;
  /** Owner user name. */
  owner: string;
  /** Owner group name. */
  group: string;
}

/** A fake remote host with a tiny filesystem. */
export interface FakeRemote {
  /** Path to file. */
  files: Map<string, FakeFile>;
  /** Paths that are directories. */
  dirs: Set<string>;
  /** Paths that are symlinks. */
  symlinks: Set<string>;
  /** Raw target of each symlink. */
  symlinkTarget: Map<string, string>;
  /** Every recovered remote script or argv, in order. */
  commands: string[];
  /** Every argv run under `sudo -n --`, in order. */
  sudoArgv: string[][];
  /** Injectable transport dependencies. */
  deps: SshDeps;
  /** `systemctl is-active nginx` output; default `active`. */
  nginxActive: string;
  /** When true, `nginx -t` exits non-zero. */
  failNginxTest: boolean;
  /** Supplies a body for a fetched URL, or null for a 404. */
  curl: (url: string) => string | null;
  /** Certificate `notBefore` line returned by the fake openssl. */
  certNotBefore: string;
  /** Certificate `notAfter` line returned by the fake openssl. */
  certNotAfter: string;
  /** PEM returned by both `x509 -pubkey` and `pkey -pubout`. */
  publicPem: string;
  /** Adds or replaces a file. */
  setFile: (
    path: string,
    content: string,
    mode?: string,
    owner?: string,
    group?: string,
  ) => void;
}

/** Recovers the argv from a `quoteArgv`-produced command string. */
function unquoteRemote(command: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < command.length) {
    while (command[i] === " ") i++;
    if (i >= command.length) break;
    if (command[i] === "'") {
      i++;
      let buf = "";
      while (i < command.length) {
        if (command[i] === "'") {
          if (
            command[i + 1] === "\\" && command[i + 2] === "'" &&
            command[i + 3] === "'"
          ) {
            buf += "'";
            i += 4;
            continue;
          }
          i++;
          break;
        }
        buf += command[i];
        i++;
      }
      out.push(buf);
    } else {
      let buf = "";
      while (i < command.length && command[i] !== " ") {
        buf += command[i];
        i++;
      }
      out.push(buf);
    }
  }
  return out;
}

/** Extracts the value of a `name='...'` assignment. */
function assign(script: string, name: string): string | null {
  const m = script.match(new RegExp(`(?:^|\\n)${name}='((?:[^']|'\\\\'')*)'`));
  return m ? m[1].replace(/'\\''/g, "'") : null;
}

/** Builds a fake remote. Starts empty; seed it with {@link FakeRemote.setFile}. */
export function makeFakeRemote(): FakeRemote {
  const files = new Map<string, FakeFile>();
  const dirs = new Set<string>(["/"]);
  const symlinks = new Set<string>();
  const symlinkTarget = new Map<string, string>();
  const commands: string[] = [];
  const sudoArgv: string[][] = [];
  const self: FakeRemote = {
    files,
    dirs,
    symlinks,
    symlinkTarget,
    commands,
    sudoArgv,
    nginxActive: "active",
    failNginxTest: false,
    curl: () => null,
    certNotBefore: "notBefore=Jan  1 00:00:00 2020 GMT",
    certNotAfter: "notAfter=Jan  1 00:00:00 2100 GMT",
    publicPem:
      "-----BEGIN PUBLIC KEY-----\nRkFLRQ==\n-----END PUBLIC KEY-----\n",
    setFile: (path, content, mode = "644", owner = "root", group = "root") => {
      files.set(path, { content, mode, owner, group });
      dirs.add(path.slice(0, path.lastIndexOf("/")) || "/");
    },
    deps: {
      now: () => 1_700_000_000_000,
      sleep: () => Promise.resolve(),
      run: (
        cmd: string,
        args: string[],
        options?: RunOptions,
      ): Promise<CommandResult> => {
        if (cmd === "openssl") return Promise.resolve(fakeOpenssl(self, args));
        if (cmd !== "ssh") {
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        }
        const raw = args.at(-1) ?? "";
        const tokens = raw.trimStart().startsWith("'")
          ? unquoteRemote(raw)
          : [raw];
        const stdin = options?.stdin == null
          ? ""
          : typeof options.stdin === "string"
          ? options.stdin
          : new TextDecoder().decode(options.stdin);
        let script = "";
        let argv: string[] | null = null;
        if (tokens[0] === "bash") script = tokens.at(-1) ?? "";
        else if (tokens[0] === "sudo") {
          if (tokens.includes("bash")) {
            script = tokens.at(-1) ?? "";
            sudoArgv.push(tokens.slice(3));
          } else {
            argv = tokens.slice(3);
            sudoArgv.push(argv);
          }
        } else if (tokens.length === 1) script = tokens[0];
        else argv = tokens;
        return handle(self, script, argv, stdin);
      },
    },
  };
  return self;
}

/** Canned openssl output, enough for the validator. */
function fakeOpenssl(host: FakeRemote, args: string[]): CommandResult {
  if (args.includes("-startdate") || args.includes("-enddate")) {
    return {
      code: 0,
      stdout: `${host.certNotBefore}\n${host.certNotAfter}\n`,
      stderr: "",
    };
  }
  if (
    args.includes("-pubkey") || (args[0] === "pkey" && args.includes("-pubout"))
  ) {
    return { code: 0, stdout: host.publicPem, stderr: "" };
  }
  return { code: 0, stdout: "", stderr: "" };
}

/** Runs one recovered remote script or argv against the fake host. */
async function handle(
  host: FakeRemote,
  script: string,
  argv: string[] | null,
  stdin: string,
): Promise<CommandResult> {
  host.commands.push(argv ? `argv:${argv.join(" ")}` : script);
  const ok = (stdout = ""): CommandResult => ({ code: 0, stdout, stderr: "" });

  if (argv) {
    if (argv[0] === "nginx" && argv[1] === "-t") {
      return host.failNginxTest
        ? { code: 1, stdout: "", stderr: "nginx: configuration test failed" }
        : ok("nginx: configuration test is successful\n");
    }
    if (argv[0] === "systemctl" && argv[1] === "reload") {
      host.nginxActive = "active";
      return ok();
    }
    if (argv[0] === "install" && argv[1] === "-o") {
      const stage = argv.at(-2)!;
      const dest = argv.at(-1)!;
      const file = host.files.get(stage);
      if (!file) return { code: 1, stdout: "", stderr: "no stage" };
      host.files.set(dest, {
        content: file.content,
        mode: normalizeMode(argv[argv.indexOf("-m") + 1]) ?? "600",
        owner: argv[argv.indexOf("-o") + 1],
        group: argv[argv.indexOf("-g") + 1],
      });
      host.files.delete(stage);
      return ok();
    }
    if (argv[0] === "install" && argv[1] === "-d") {
      for (const p of argv.slice(argv.indexOf("-m") + 2)) host.dirs.add(p);
      return ok();
    }
    if (argv[0] === "rm") {
      for (const p of argv.filter((a) => a.startsWith("/"))) {
        for (const key of [...host.files.keys()]) {
          if (key === p || key.startsWith(`${p}/`)) host.files.delete(key);
        }
        for (const key of [...host.symlinks]) {
          if (key === p || key.startsWith(`${p}/`)) host.symlinks.delete(key);
        }
        for (const key of [...host.dirs]) {
          if (key === p || key.startsWith(`${p}/`)) host.dirs.delete(key);
        }
      }
      return ok();
    }
    if (argv[0] === "ln") {
      const dest = argv.at(-1)!;
      host.symlinks.add(dest);
      host.symlinkTarget.set(dest, argv.at(-2)!);
      return ok();
    }
    return ok();
  }

  if (/echo symlink/.test(script)) {
    const f = assign(script, "f")!;
    if (host.symlinks.has(f)) return ok("symlink\n");
    if (host.dirs.has(f)) return ok("dir\n");
    const file = host.files.get(f);
    if (!file) return ok("missing\n");
    const h = await sha256Hex(file.content);
    return ok(
      `${h} ${file.mode} ${file.owner} ${file.group} ${
        new TextEncoder().encode(file.content).length
      }\n`,
    );
  }
  if (/echo SYMLINK/.test(script)) {
    const f = assign(script, "f")!;
    if (host.symlinks.has(f)) return ok("SYMLINK\n");
    if (host.dirs.has(f)) return ok("DIRECTORY\n");
    const file = host.files.get(f);
    if (!file) return ok("MISSING\n");
    const h = await sha256Hex(file.content);
    return ok(`${h} ${file.mode}\n`);
  }
  if (/mktemp "\$d\/\.ssh-host-upload/.test(script)) {
    const f = assign(script, "f")!;
    const mode = normalizeMode(
      (script.match(/chmod '([^']+)' "\$t"/) ?? [])[1] ?? "600",
    ) ?? "600";
    host.files.set(f, { content: stdin, mode, owner: "user", group: "user" });
    return ok(`${await sha256Hex(stdin)} ${mode}\n`);
  }
  if (script.includes("##VERSION")) return ok(renderLayout(host, script));
  if (script.includes("##ACTIVE")) return ok(renderNginx(host, script));
  if (script.includes("flock 9")) {
    regenerate(host, assign(script, "r")!);
    return ok();
  }
  if (script.includes('mv -T "$tmp"') && script.includes("/refs/")) {
    const r = assign(script, "r")!;
    const name = script.match(/\/refs\/([A-Za-z0-9._-]+)'/)![1];
    const kind = script.match(/printf '%s\s+%s\\n' '([a-z]+)'/)![1];
    const hash = script.match(/'([0-9a-f]{64})'/)![1];
    host.files.set(`${r}/refs/${name}`, {
      content: `${kind}  ${hash}\n`,
      mode: "644",
      owner: "user",
      group: "user",
    });
    return ok();
  }
  if (
    /^if \[ -e '.*' \]; then rm -rf '.*'; else mv -T '.*' '.*'; fi$/.test(
      script,
    )
  ) {
    const final = script.match(/^if \[ -e '([^']+)' \]/)![1];
    const stage = script.match(/mv -T '([^']+)'/)![1];
    const exists = host.dirs.has(final) ||
      [...host.files.keys()].some((k) =>
        k === final || k.startsWith(`${final}/`)
      );
    for (const k of [...host.files.keys()]) {
      if (k === stage || k.startsWith(`${stage}/`)) {
        if (!exists) {
          host.files.set(final + k.slice(stage.length), host.files.get(k)!);
        }
        host.files.delete(k);
      }
    }
    for (const k of [...host.dirs]) {
      if (k === stage || k.startsWith(`${stage}/`)) {
        if (!exists) host.dirs.add(final + k.slice(stage.length));
        host.dirs.delete(k);
      }
    }
    if (!exists) host.dirs.add(final);
    return ok();
  }
  if (/^set -eu\nr=/.test(script) && script.includes("for p in ")) {
    const r = assign(script, "r")!;
    const list = (script.match(/rm -rf -- (.*)$/m) ?? [])[1] ?? "";
    const paths = [...list.matchAll(/'([^']+)'/g)].map((m) => m[1]);
    for (const d of [`${r}/sha256`, `${r}/bundles`]) {
      if (host.symlinks.has(d)) {
        return { code: 3, stdout: "", stderr: "symlink" };
      }
    }
    for (const p of paths) {
      const seg = p.split("/");
      const dir = p.startsWith("sha256/")
        ? `${r}/sha256/${seg[1]}`
        : `${r}/bundles/${seg[1]}`;
      if (host.symlinks.has(dir)) {
        return { code: 3, stdout: "", stderr: "symlink" };
      }
    }
    for (const p of paths) {
      for (const k of [...host.files.keys()]) {
        if (k === `${r}/${p}` || k.startsWith(`${r}/${p}/`)) {
          host.files.delete(k);
        }
      }
      for (const k of [...host.dirs]) {
        if (k === `${r}/${p}` || k.startsWith(`${r}/${p}/`)) {
          host.dirs.delete(k);
        }
      }
    }
    return ok();
  }
  if (/rm -f '.*\/refs\//.test(script)) {
    host.files.delete(script.match(/rm -f '([^']+)'/)![1]);
    return ok();
  }
  if (/^rm -f '/.test(script)) {
    host.files.delete(script.match(/^rm -f '([^']+)'/)![1]);
    return ok();
  }
  if (/mkdir -p '.*' && mv -T '/.test(script)) {
    const [dir, temp, dest] = [
      script.match(/mkdir -p '([^']+)'/)![1],
      script.match(/mv -T '([^']+)'/)![1],
      script.match(/mv -T '[^']+' '([^']+)'/)![1],
    ];
    host.dirs.add(dir);
    const file = host.files.get(temp);
    if (file) {
      host.files.set(dest, file);
      host.files.delete(temp);
    }
    return ok();
  }
  if (/^cd '.*' && rm -rf -- /.test(script)) {
    const root = script.match(/^cd '([^']+)'/)![1];
    const rest = script.replace(/^cd '[^']+' && rm -rf -- /, "");
    for (const p of rest.split(" ")) {
      host.files.delete(`${root}/${p.replace(/^'|'$/g, "")}`);
    }
    return ok();
  }
  if (/^if \[ -L '([^']+)' \]; then readlink/.test(script)) {
    const p = script.match(/^if \[ -L '([^']+)' \]/)![1];
    return ok(host.symlinkTarget.get(p) ?? "");
  }
  if (/^if \[ -L /.test(script)) return ok();
  if (/^mkdir -p /.test(script)) {
    host.dirs.add(script.replace(/^mkdir -p '?/, "").replace(/'$/, ""));
    return ok();
  }
  if (/^cat '/.test(script)) {
    const p = script.match(/^cat '([^']+)'/)![1];
    const file = host.files.get(p);
    return file ? ok(file.content) : { code: 1, stdout: "", stderr: "missing" };
  }
  if (/curl -fsS/.test(script)) {
    const [, temp, url] = script.match(/-o '([^']+)' '([^']+)'/)!;
    const body = host.curl(url);
    if (body == null) return { code: 22, stdout: "", stderr: "curl: 404" };
    host.files.set(temp, {
      content: body,
      mode: "600",
      owner: "user",
      group: "user",
    });
    return ok(`${await sha256Hex(body)}\n`);
  }
  if (/printf 'BLOB/.test(script)) {
    const r = assign(script, "r")!;
    const out: string[] = [];
    for (const [p, f] of host.files) {
      if (p.startsWith(`${r}/sha256/`)) {
        out.push(
          `BLOB\t${p.slice(r.length + 1)}\t${await sha256Hex(f.content)}`,
        );
      }
    }
    for (const dir of new Set(host.dirs)) {
      const prefix = `${r}/bundles/`;
      if (!dir.startsWith(prefix)) continue;
      const rest = dir.slice(prefix.length);
      if (rest === "" || rest.includes("/")) continue;
      const rows: string[] = [];
      for (const [p, f] of host.files) {
        if (p.startsWith(`${dir}/`)) {
          rows.push(`${await sha256Hex(f.content)}  ${p.split("/").at(-1)}`);
        }
      }
      rows.sort();
      out.push(`BUNDLE\t${rest}\t${await sha256Hex(`${rows.join("\n")}\n`)}`);
    }
    return ok(`${out.join("\n")}\n`);
  }
  return ok();
}

/** Renders the `##VERSION`-delimited layout script response. */
function renderLayout(host: FakeRemote, script: string): string {
  const r = assign(script, "r")!;
  const lines: string[] = [];
  const read = (p: string) => host.files.get(p)?.content ?? "";
  lines.push("##VERSION", read(`${r}/.layout-version`).trim());
  lines.push("##SUMS", read(`${r}/SHA256SUMS`).trim());
  lines.push("##REFS");
  for (const [p, f] of host.files) {
    if (p.startsWith(`${r}/refs/`)) {
      lines.push(`${p.slice(r.length + 6)}\t${f.content.trim()}`);
    }
  }
  lines.push("##BLOBS");
  const blobs: string[] = [];
  for (const [p, f] of host.files) {
    if (p.startsWith(`${r}/sha256/`)) {
      blobs.push(
        `${p.slice(r.length + 8)}\t${
          new TextEncoder().encode(f.content).length
        }\t${(host.deps.now() / 1000).toFixed(6)}`,
      );
    }
  }
  lines.push(...blobs.sort());
  lines.push("##BUNDLES");
  const bundles = [...host.dirs]
    .filter((d) => d.startsWith(`${r}/bundles/`))
    .map((d) => d.split("/").at(-1)!);
  lines.push(...[...new Set(bundles)].sort());
  lines.push("##END");
  return lines.join("\n");
}

/** Renders the `##ACTIVE`-delimited nginx-state script response. */
function renderNginx(host: FakeRemote, script: string): string {
  const sitePath = script.match(/if \[ -f '([^']+)' \]/)![1];
  const file = host.files.get(sitePath);
  const lines = ["##ACTIVE", host.nginxActive, "##CFG"];
  lines.push(file ? "0".repeat(64) : "");
  lines.push("##TLS");
  lines.push(file && /ssl/.test(file.content) ? "yes" : "no");
  lines.push("##AUTH");
  lines.push(file && /auth_basic/.test(file.content) ? "yes" : "no");
  lines.push("##END");
  return lines.join("\n");
}

/** Rebuilds `SHA256SUMS` in the fake host from the blobs present. */
function regenerate(host: FakeRemote, r: string): void {
  const blobs = [];
  for (const p of host.files.keys()) {
    if (p.startsWith(`${r}/sha256/`)) {
      const parts = p.slice(r.length + 1).split("/");
      blobs.push({
        sha256: parts[1] ?? "",
        filename: parts.slice(2).join("/"),
      });
    }
  }
  host.files.set(`${r}/SHA256SUMS`, {
    content: renderSha256Sums(blobs),
    mode: "644",
    owner: "user",
    group: "user",
  });
}
