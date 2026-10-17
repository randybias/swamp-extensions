import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { PhaseError } from "./errors.ts";
import type { CommandResult, RunOptions, SshSession } from "./ssh.ts";
import {
  bucketInventory,
  classifyUserInfo,
  INVENTORY_PAGE_SIZE,
  parseBucketListPage,
  parseUserView,
  redactSecrets,
  sumUsage,
} from "./rgw.ts";

const deps = {
  now: () => 0,
  sleep: () => Promise.resolve(),
  random: () => 0.5,
};

function rgwSession(route: (body: string) => CommandResult): SshSession {
  let dir = 0;
  let scriptBody = "";
  return {
    target: { host: "192.0.2.10", user: "admin", strictHostKeyChecking: "yes" },
    controlPath: null,
    run: (opts: RunOptions) => {
      if (opts.command.startsWith("mktemp -d")) {
        dir++;
        return Promise.resolve({
          code: 0,
          stdout: `/tmp/cephadm-shell.ABCDE${dir}\n`,
          stderr: "",
        });
      }
      if (opts.command.startsWith("umask 022")) {
        scriptBody = opts.stdin ?? "";
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      if (opts.command.startsWith("cephadm shell")) {
        return Promise.resolve(route(scriptBody));
      }
      if (opts.command.startsWith("rm -rf")) {
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      return Promise.resolve({ code: 1, stdout: "", stderr: "unrouted" });
    },
    close: () => Promise.resolve({ closed: false, detail: "not multiplexed" }),
  };
}

Deno.test(
  "the redactor covers JSON, flags and literal secrets before truncation", // leak-allow(decision D48)
  () => {
    const out = redactSecrets(
      '{"keys":[{"access_key":"AK","secret_key":"S3CR3T"}]}',
    );
    assertEquals(out.includes("S3CR3T"), false);
    assertEquals(out.includes("AK"), true);
    assertEquals(JSON.parse(out).keys[0].secret_key, "<redacted>");
    assertEquals(
      redactSecrets("run --secret=S3CR3T --secret-key S3CR3T now", ["S3CR3T"]),
      "run --secret=<redacted> --secret-key <redacted> now",
    );
    assertEquals(
      redactSecrets("a secret_key value S3CR3T here", ["S3CR3T"]),
      "a secret_key value <redacted> here",
    );
    // Negative control: text without a secret is unchanged.
    assertEquals(redactSecrets("nothing to hide"), "nothing to hide");
  },
);

Deno.test("the parsed user view omits the secret and keeps the access key", () => {
  const view = parseUserView({
    user_id: "app-user",
    display_name: "App User",
    email: "ops@example.test",
    keys: [{
      user: "app-user",
      access_key: "AKIAEXAMPLE",
      secret_key: "S3CR3T",
    }],
    max_buckets: 0,
    suspended: 1,
  });
  assertEquals(view?.maxBuckets, 0);
  assertEquals(view?.suspended, true);
  assertEquals(view?.accessKeys, ["AKIAEXAMPLE"]);
  assertEquals(JSON.stringify(view).includes("S3CR3T"), false);
  assertEquals(parseUserView({ no: "user_id" }), null);
});

Deno.test(
  "user-info classification keeps absence distinct from unreadable", // leak-allow(decision D50)
  () => {
    assertEquals(classifyUserInfo(0, '{"user_id":"u"}', "").state, "present");
    assertEquals(classifyUserInfo(0, "garbage", "").state, "unreadable");
    assertEquals(
      classifyUserInfo(2, "could not fetch user info: (2) No such file", "")
        .state,
      "absent",
    );
    assertEquals(
      classifyUserInfo(
        22,
        "banner\ncould not fetch user info: no user info saved",
        "",
      ).state,
      "absent",
    );
    assertEquals(
      classifyUserInfo(1, "No such user exists", "").state,
      "absent",
    );
    assertEquals(
      classifyUserInfo(
        1,
        "could not fetch user info: (13) Permission denied",
        "",
      ).state,
      "unreadable",
    );
    assertEquals(
      classifyUserInfo(5, "could not fetch user info: (5) I/O error", "").state,
      "unreadable",
    );
  },
);

Deno.test("bucket list pages and usage stats parse defensively", () => {
  assertEquals(parseBucketListPage(["a", "b"]), ["a", "b"]);
  assertEquals(parseBucketListPage([{ bucket: "a" }, "b"]), ["a", "b"]);
  assertEquals(parseBucketListPage([]), []);
  assertEquals(parseBucketListPage("nope"), null);
  assertEquals(parseBucketListPage([1]), null);
  assertEquals(
    sumUsage({
      usage: {
        "rgw.main": { num_objects: 3, size: 1000, size_actual: 1024 },
        "rgw.multimeta": { num_objects: 1 },
      },
    }),
    { objects: 4, size: 1000, actual: 1024 },
  );
  assertEquals(sumUsage({ usage: {} }), { objects: 0, size: 0, actual: 0 });
  assertEquals(sumUsage({ usage: { x: { num_objects: "many" } } }), {
    objects: 0,
    size: 0,
    actual: 0,
  });
});

Deno.test("the inventory lists buckets, stats them and marks unsafe names", async () => {
  const s = rgwSession((body) => {
    if (body.includes("bucket list")) {
      return {
        code: 0,
        stdout: JSON.stringify(["data-01", "x; rm -rf /"]),
        stderr: "",
      };
    }
    if (body.includes("bucket stats")) {
      return {
        code: 0,
        stdout: JSON.stringify({
          owner: "app-user",
          placement_rule: "default-placement",
          usage: {
            "rgw.main": { num_objects: 3, size: 1000, size_actual: 1024 },
          },
        }),
        stderr: "",
      };
    }
    return { code: 1, stdout: "", stderr: "unrouted" };
  });
  const record = await bucketInventory(deps, s, "192.0.2.10", "");
  assertEquals(record.bucketCount, 1);
  assertEquals(record.unstattable, ["x; rm -rf /"]);
  assertEquals(record.buckets[0].bucket, "data-01");
  assertEquals(record.buckets[0].placementRule, "default-placement");
  assertEquals(record.totalObjects, 3);
  assertEquals(record.totalSizeActualBytes, 1024);
  assertEquals(record.pagesRead, 1);
  assertEquals(record.rgwRealm, "");
});

Deno.test("the inventory pages with the last name of a full page", async () => {
  const names = Array.from(
    { length: INVENTORY_PAGE_SIZE + 2 },
    (_, i) => `b${String(i).padStart(5, "0")}`,
  );
  const markers: (string | null)[] = [];
  const s = rgwSession((body) => {
    if (body.includes("bucket list")) {
      const m = body.match(/--marker='([^']+)'/);
      const marker = m ? m[1] : null;
      markers.push(marker);
      const page = marker === null
        ? names.slice(0, INVENTORY_PAGE_SIZE)
        : names.slice(INVENTORY_PAGE_SIZE);
      return { code: 0, stdout: JSON.stringify(page), stderr: "" };
    }
    if (body.includes("bucket stats")) {
      return {
        code: 0,
        stdout: JSON.stringify({ owner: "o", usage: {} }),
        stderr: "",
      };
    }
    return { code: 1, stdout: "", stderr: "unrouted" };
  });
  const record = await bucketInventory(deps, s, "192.0.2.10", "");
  assertEquals(record.bucketCount, INVENTORY_PAGE_SIZE + 2);
  assertEquals(record.pagesRead, 2);
  assertEquals(markers[0], null);
  assertEquals(markers[1], names[INVENTORY_PAGE_SIZE - 1]);
});

Deno.test("the inventory refuses a no-progress or unsafe page", async () => {
  const full = Array.from({ length: INVENTORY_PAGE_SIZE }, (_, i) => `b${i}`);
  const repeat = rgwSession((body) =>
    body.includes("bucket list")
      ? { code: 0, stdout: JSON.stringify(full), stderr: "" }
      : { code: 0, stdout: "{}", stderr: "" }
  );
  await assertRejects(
    () => bucketInventory(deps, repeat, "192.0.2.10", ""),
    PhaseError,
    "no progress",
  );

  const unsafe = Array.from(
    { length: INVENTORY_PAGE_SIZE - 1 },
    (_, i) => `b${i}`,
  ).concat(["bad name"]);
  const unsafeSession = rgwSession((body) =>
    body.includes("bucket list")
      ? { code: 0, stdout: JSON.stringify(unsafe), stderr: "" }
      : { code: 0, stdout: "{}", stderr: "" }
  );
  await assertRejects(
    () => bucketInventory(deps, unsafeSession, "192.0.2.10", ""),
    PhaseError,
    "unsafe name",
  );
});
