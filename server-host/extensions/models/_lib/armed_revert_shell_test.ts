// Runs the generated host scripts under a real POSIX shell, in a scratch state
// directory, against stub `nft`, `systemctl` and `systemd-run`, to prove the
// lock/marker protocol: a superseded or fired revert can never overwrite newer
// rules, and an apply is refused once its revert no longer guards it.
import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  APPLY_REFUSED,
  renderArmArgv,
  renderCommitArgv,
  renderDisarmArgv,
  renderGuardedApplyArgv,
  renderRevertScript,
  STATE_DIR,
} from "./armed_revert.ts";

const A = "a".repeat(16);
const SHA = "c".repeat(64);
const B = "b".repeat(16);

interface Box {
  dir: string;
  state: string;
  bin: string;
  /** Unit states the `systemctl` stub reports, by unit name. */
  setUnit(unit: string, state: string): Promise<void>;
  run(script: string, stdin?: string, now?: number): Promise<number>;
  file(name: string): Promise<string | null>;
  put(name: string, text: string): Promise<void>;
}

async function box(): Promise<Box> {
  const dir = await Deno.makeTempDir({ prefix: "wgbox-" });
  const state = `${dir}/state`;
  const bin = `${dir}/bin`;
  await Deno.mkdir(state);
  await Deno.mkdir(bin);
  const stub = async (name: string, body: string) => {
    await Deno.writeTextFile(`${bin}/${name}`, `#!/bin/sh\n${body}\n`);
    await Deno.chmod(`${bin}/${name}`, 0o755);
  };
  // nft: the live ruleset is a file with one line per table, `table inet NAME
  // BODY`. `-f -` applies `add table`, `delete table inet NAME` and `table inet NAME BODY`
  // lines; `flush ruleset` empties everything (which the code must never send).
  await stub(
    "nft",
    `live="${dir}/live"; touch "$live"
case "$1" in
  list)
    case "$2" in
      ruleset) cat "$live" ;;
      tables) [ ! -e "${dir}/nft-fail" ] || exit 1; awk '{print $1, $2, $3}' "$live" ;;
      table) grep "^table $3 $4\\( \\|$\\)" "$live" ;;
    esac ;;
  -f)
    cat > "$live.in"
    if grep -q '^flush ruleset' "$live.in"; then : > "$live"; fi
    while IFS= read -r line; do
      case "$line" in
        "add table "*) ;;
        "delete table "*) n="$(echo "$line" | awk '{print $3, $4}')"; grep -v "^table $n\\( \\|$\\)" "$live" > "$live.t" || true; mv "$live.t" "$live" ;;
        "table "*) echo "$line" >> "$live" ;;
      esac
    done < "$live.in" ;;
esac`,
  );
  await stub(
    "systemctl",
    `case "$1" in
  is-active) cat "${dir}/unit-$2" 2>/dev/null || echo inactive ;;
  stop) echo inactive > "${dir}/unit-$2" ;;
esac`,
  );
  await stub(
    "systemd-run",
    `for a in "$@"; do case "$a" in --unit=*) u="\${a#--unit=}" ;; esac; done
echo active > "${dir}/unit-$u.timer"`,
  );
  const sub = (s: string) => s.replaceAll(STATE_DIR, state);
  return {
    dir,
    state,
    bin,
    setUnit: (unit, st) => Deno.writeTextFile(`${dir}/unit-${unit}`, st + "\n"),
    async run(script, stdin = "", now) {
      // `date` is stubbed only when a fixed clock is requested.
      if (now !== undefined) {
        await Deno.writeTextFile(`${bin}/date`, `#!/bin/sh\necho ${now}\n`);
        await Deno.chmod(`${bin}/date`, 0o755);
      }
      const child = new Deno.Command("sh", {
        args: ["-c", sub(script)],
        stdin: "piped",
        stdout: "null",
        stderr: "null",
        env: { PATH: `${bin}:/usr/bin:/bin` },
      }).spawn();
      const w = child.stdin.getWriter();
      await w.write(new TextEncoder().encode(stdin));
      await w.close();
      return (await child.output()).code;
    },
    async file(name) {
      try {
        return await Deno.readTextFile(`${dir}/${name}`);
      } catch {
        return null;
      }
    },
    put: (name, text) => Deno.writeTextFile(`${dir}/${name}`, text),
  };
}

const scriptOf = (argv: string[]) => argv[2];

/** Stages the revert script for `token` and arms it; returns the exit code. */
async function arm(b: Box, token: string, secs = 300, now = 1000) {
  await Deno.writeTextFile(
    `${b.state}/revert-${token}.sh`,
    renderRevertScript(token).replaceAll(STATE_DIR, b.state),
  );
  return await b.run(scriptOf(renderArmArgv(token, secs, false, SHA)), "", now);
}

Deno.test("shell: arm snapshots, records the marker, starts the timer; apply then succeeds", async () => {
  const b = await box();
  try {
    await b.put("live", "table inet server_host original\n");
    assertEquals(await arm(b, A), 0);
    assertEquals(await b.file("state/current"), `${A} 1300 ${SHA}\n`);
    assertEquals(
      await b.file(`state/revert-${A}.nft`),
      "table inet server_host original\n",
    );
    const code = await b.run(
      scriptOf(renderGuardedApplyArgv(A, false)),
      "add table inet server_host\ndelete table inet server_host\ntable inet server_host new\n",
      1100,
    );
    assertEquals(code, 0);
    assertEquals(await b.file("live"), "table inet server_host new\n");
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("shell: a second arm is refused while the first timer is active, and while its service is running", async () => {
  const b = await box();
  try {
    assertEquals(await arm(b, A), 0);
    assertEquals(await arm(b, B, 300, 1100), 75);
    // Timer elapsed (inactive) but the restore SERVICE is active: still refused.
    await b.setUnit(`server-host-revert-${A}.timer`, "inactive");
    await b.setUnit(`server-host-revert-${A}.service`, "active");
    assertEquals(await arm(b, B, 300, 1400), 75);
    assertEquals((await b.file("state/current"))?.startsWith(A), true);
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("shell: inactive units but leftover files inside the firing window are refused; a long-dead revert is replaced", async () => {
  const b = await box();
  try {
    assertEquals(await arm(b, A), 0); // expires at 1300
    await b.setUnit(`server-host-revert-${A}.timer`, "inactive");
    // Just after expiry: the restore has not run yet, so wait.
    assertEquals(await arm(b, B, 300, 1310), 75);
    // Well past the grace window: the timer was lost (reboot); replace it.
    assertEquals(await arm(b, B, 300, 1300 + 121), 0);
    assertEquals((await b.file("state/current"))?.startsWith(B), true);
    assertEquals(await b.file(`state/revert-${A}.nft`), null);
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("shell: once the restore has run, an apply under the old token is refused and rules are untouched", async () => {
  const b = await box();
  try {
    await b.put("live", "table inet server_host original\n");
    assertEquals(await arm(b, A), 0);
    // The timer fires: the restore script runs.
    await b.put("live", "table inet server_host mid-change\n");
    assertEquals(
      await b.run(`sh ${b.state}/revert-${A}.sh`),
      0,
    );
    assertEquals(await b.file("live"), "table inet server_host original\n");
    const code = await b.run(
      scriptOf(renderGuardedApplyArgv(A, false)),
      "add table inet server_host\ndelete table inet server_host\ntable inet server_host late\n",
      1100,
    );
    assertEquals(code, APPLY_REFUSED.superseded);
    assertEquals(await b.file("live"), "table inet server_host original\n");
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("shell: an apply after the revert expired is refused", async () => {
  const b = await box();
  try {
    await b.put("live", "table inet server_host original\n");
    assertEquals(await arm(b, A), 0); // expires at 1300
    const code = await b.run(
      scriptOf(renderGuardedApplyArgv(A, false)),
      "add table inet server_host\ndelete table inet server_host\ntable inet server_host late\n",
      1300,
    );
    assertEquals(code, APPLY_REFUSED.expired);
    assertEquals(await b.file("live"), "table inet server_host original\n");
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("shell: a superseded restore never overwrites the newer rules", async () => {
  const b = await box();
  try {
    await b.put("live", "table inet server_host original\n");
    assertEquals(await arm(b, A), 0);
    // A is gone (committed away); B becomes current and applies new rules.
    assertEquals(await b.run(scriptOf(renderCommitArgv(A, false))), 0);
    assertEquals(await arm(b, B, 300, 1100), 0);
    assertEquals(
      await b.run(
        scriptOf(renderGuardedApplyArgv(B, false)),
        "add table inet server_host\ndelete table inet server_host\ntable inet server_host b\n",
        1150,
      ),
      0,
    );
    // A's stale restore script (resurrected) must do nothing.
    await Deno.writeTextFile(
      `${b.state}/revert-${A}.sh`,
      renderRevertScript(A).replaceAll(STATE_DIR, b.state),
    );
    await Deno.writeTextFile(
      `${b.state}/revert-${A}.nft`,
      "table inet server_host stale\n",
    );
    assertEquals(await b.run(`sh ${b.state}/revert-${A}.sh`), 0);
    assertEquals(await b.file("live"), "table inet server_host b\n");
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("shell: commit removes the marker; disarm is idempotent and leaves another revert's marker alone", async () => {
  const b = await box();
  try {
    assertEquals(await arm(b, A), 0);
    assertEquals(await b.run(scriptOf(renderDisarmArgv(B, false))), 0);
    assertEquals((await b.file("state/current"))?.startsWith(A), true);
    assertEquals(await b.run(scriptOf(renderDisarmArgv(A, false))), 0);
    assertEquals(await b.file("state/current"), null);
    assertEquals(await b.run(scriptOf(renderDisarmArgv(A, false))), 0);
    assertEquals(await arm(b, B, 300, 1100), 0);
    // Commit fails when the timer is gone.
    await b.setUnit(`server-host-revert-${B}.timer`, "inactive");
    assertEquals(await b.run(scriptOf(renderCommitArgv(B, false))), 1);
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("shell: the snapshot and the restore touch only the managed table; other tables survive both", async () => {
  const b = await box();
  try {
    const foreign = "table inet k0s kube-proxy-and-cni-rules\n" +
      "table ip nat docker-rules\n";
    await b.put("live", foreign + "table inet server_host original\n");
    assertEquals(await arm(b, A), 0);
    // The snapshot holds the managed table and nothing else.
    assertEquals(
      await b.file(`state/revert-${A}.nft`),
      "table inet server_host original\n",
    );
    // The apply replaces the managed table and leaves the others alone.
    assertEquals(
      await b.run(
        scriptOf(renderGuardedApplyArgv(A, false)),
        "add table inet server_host\ndelete table inet server_host\ntable inet server_host new\n",
        1100,
      ),
      0,
    );
    // Something else installs more rules meanwhile (k0s, after the apply).
    await b.put(
      "live",
      (await b.file("live"))! + "table inet kube-later more-rules\n",
    );
    assertEquals(await b.run(`sh ${b.state}/revert-${A}.sh`), 0);
    const live = (await b.file("live"))!;
    assertEquals(live.includes("table inet server_host original"), true);
    assertEquals(live.includes("table inet server_host new"), false);
    for (const t of ["k0s", "nat", "kube-later"]) {
      assertEquals(live.includes(t), true, t);
    }
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("shell: when no managed table existed, the restore removes it and still leaves the others", async () => {
  const b = await box();
  try {
    await b.put("live", "table inet k0s kube-proxy-and-cni-rules\n");
    assertEquals(await arm(b, A), 0);
    assertEquals(await b.file(`state/revert-${A}.nft`), "");
    assertEquals(
      await b.run(
        scriptOf(renderGuardedApplyArgv(A, false)),
        "add table inet server_host\ndelete table inet server_host\ntable inet server_host new\n",
        1100,
      ),
      0,
    );
    assertEquals(await b.run(`sh ${b.state}/revert-${A}.sh`), 0);
    assertEquals(
      await b.file("live"),
      "table inet k0s kube-proxy-and-cni-rules\n",
    );
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});

Deno.test("shell: if nft cannot list the tables, arm fails and arms nothing, so a restore can never drop the managed table", async () => {
  const b = await box();
  try {
    await b.put("live", "table inet server_host original\n");
    await b.put("nft-fail", "");
    assertEquals((await arm(b, A)) !== 0, true);
    assertEquals(await b.file("state/current"), null);
    assertEquals(await b.file(`unit-server-host-revert-${A}.timer`), null);
    assertEquals(await b.file("live"), "table inet server_host original\n");
  } finally {
    await Deno.remove(b.dir, { recursive: true });
  }
});
