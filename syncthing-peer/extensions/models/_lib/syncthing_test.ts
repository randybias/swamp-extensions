import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  assertApiKey,
  assertApiUrl,
  assertDeviceId,
  assertFolderId,
  assertRemoteFolderPath,
  buildDeviceSpec,
  buildFolderSpec,
  createClient,
  curlConfigValue,
  curlRequestConfig,
  deviceBody,
  deviceMatches,
  type FetchFn,
  folderBody,
  folderDevices,
  folderMatches,
  folderSpecOf,
  isDeviceAddress,
  isSafeLabel,
  normalizeApiUrl,
  parseCurlOutput,
  type SyncthingDeps,
  SyncthingError,
} from "./syncthing.ts";
import {
  type CommandResult,
  type CommandRunner,
  type RunOptions,
} from "./ssh.ts";

const HEADER_VALUE = "placeholder-header-value";
const DEVICE =
  "AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD-EEEEEEE-FFFFFFF-GGGGGGG-HHHHHHH";

const DEPS: SyncthingDeps = {
  fetch: () => Promise.resolve(new Response("{}", { status: 200 })),
  run: () => Promise.resolve({ code: 0, stdout: "", stderr: "" }),
  now: () => 0,
  sleep: () => Promise.resolve(),
};

Deno.test("api URL policy allows loopback HTTP and any HTTPS", () => {
  assertApiUrl("http://127.0.0.1:8384");
  assertApiUrl("http://localhost:8384");
  assertApiUrl("http://[::1]:8384");
  assertApiUrl("https://syncthing.example.com");
  for (
    const bad of [
      "http://syncthing.example.com:8384",
      "http://user:pass@127.0.0.1:8384",
      "http://127.0.0.1:8384/?x=1",
      "ftp://127.0.0.1",
      "not a url",
    ]
  ) {
    assertThrows(() => assertApiUrl(bad), Error, undefined, bad);
  }
});

Deno.test("api key, device id, folder id and path grammars", () => {
  assertApiKey(HEADER_VALUE);
  for (const bad of ["short", "has space", "bad;key", "a".repeat(129)]) {
    assertThrows(() => assertApiKey(bad), Error, undefined, bad);
  }
  assertDeviceId(DEVICE);
  for (const bad of ["AAAAAAA", DEVICE.toLowerCase(), "AAAAAAA-BBBBBBB"]) {
    assertThrows(() => assertDeviceId(bad), Error, undefined, bad);
  }
  assertFolderId("media");
  assertFolderId("photos-2026");
  for (const bad of [".", "..", ".hidden", "a/b", "", "a".repeat(256)]) {
    assertThrows(() => assertFolderId(bad), Error, undefined, bad);
  }
  assertRemoteFolderPath("/srv/data");
  for (const bad of ["relative", "/a/../b", "/a/./b", ""]) {
    assertThrows(() => assertRemoteFolderPath(bad), Error, undefined, bad);
  }
  for (
    const good of ["dynamic", "tcp://192.0.2.10:22000", "quic://[::1]:22000"]
  ) {
    assertEquals(isDeviceAddress(good), true, good);
  }
  for (
    const bad of ["tcp", "dynamic://x", "tcp://host", "ftp://h:1", "tcp://h:p"]
  ) {
    assertEquals(isDeviceAddress(bad), false, bad);
  }
  assert(isSafeLabel("edge-2"));
  assert(!isSafeLabel("  "));
  assert(!isSafeLabel("bad\u0007name"));
  assert(!isSafeLabel("caf\u00e9"), "non-ASCII is outside the allowlist");
  assertEquals(
    normalizeApiUrl("http://127.0.0.1:8384/"),
    "http://127.0.0.1:8384",
  );
  assertEquals(
    normalizeApiUrl("HTTPS://Syncthing.Example.com/"),
    "https://syncthing.example.com",
  );
});

Deno.test("curl config carries the key over stdin and escapes quotes", () => {
  const config = curlRequestConfig(
    "PUT",
    "http://127.0.0.1:8384/rest/config/devices/x",
    HEADER_VALUE,
    { a: 'say "hi"', b: "back\\slash" },
  );
  assert(config.includes(`header = "X-API-Key: ${HEADER_VALUE}"`));
  assert(config.includes("say"));
  assert(config.includes("hi"));
  assert(config.includes("back"));
  assert(config.includes('request = "PUT"'));
  assert(config.includes('max-time = "30"'));
  assert(config.includes('connect-timeout = "10"'));
  assert(config.includes('proto = "=http,https"'));
  assertEquals(curlConfigValue('a"b'), '"a\\"b"');
  assertThrows(() => curlConfigValue("a\nb"), Error, "newline");
});

Deno.test("parseCurlOutput splits body and status", () => {
  assertEquals(parseCurlOutput('{"ok":true}\n__SYNCTHING_STATUS__200\n'), {
    status: 200,
    body: { ok: true },
  });
  assertEquals(parseCurlOutput("nope\n__SYNCTHING_STATUS__500\n"), {
    status: 500,
    body: "nope",
  });
  assertThrows(() => parseCurlOutput("no marker"), Error, "status");
});

Deno.test("the local client sends the key only as a header and refuses redirects", async () => {
  const calls: {
    url: string;
    headers: Record<string, string>;
    redirect?: string;
  }[] = [];
  const fetch: FetchFn = (input, init) => {
    calls.push({
      url: String(input),
      headers: (init?.headers ?? {}) as Record<string, string>,
      redirect: init?.redirect,
    });
    return Promise.resolve(
      new Response(JSON.stringify({ myID: "NODE" }), { status: 200 }),
    );
  };
  const client = createClient({ ...DEPS, fetch }, "local", {
    apiUrl: "http://127.0.0.1:8384",
    apiKey: HEADER_VALUE,
  });
  const result = await client.request("GET", "/rest/system/status");
  assertEquals(result.status, 200);
  assertEquals((result.body as { myID: string }).myID, "NODE");
  assertEquals(calls[0].headers["X-API-Key"], HEADER_VALUE);
  assertEquals(calls[0].url.includes(HEADER_VALUE), false, "key in URL");
  assertEquals(calls[0].redirect, "manual");

  const redirecting = createClient(
    {
      ...DEPS,
      fetch: () =>
        Promise.resolve(
          new Response("", {
            status: 302,
            headers: { location: "https://evil.test" },
          }),
        ),
    },
    "local",
    { apiUrl: "http://127.0.0.1:8384", apiKey: HEADER_VALUE },
  );
  await assertRejects(
    () => redirecting.request("GET", "/rest/system/status"),
    SyncthingError,
    "redirect",
  );
});

Deno.test("the ssh client streams the config on stdin and never writes a remote file", async () => {
  const calls: { args: string[]; stdin?: string; timeoutMs?: number }[] = [];
  const run: CommandRunner = (
    cmd: string,
    args: string[],
    options: RunOptions = {},
  ): Promise<CommandResult> => {
    const stdin = typeof options.stdin === "string"
      ? options.stdin
      : options.stdin
      ? new TextDecoder().decode(options.stdin)
      : undefined;
    calls.push({ args: [cmd, ...args], stdin, timeoutMs: options.timeoutMs });
    if ((args.at(-1) ?? "").includes("curl")) {
      return Promise.resolve({
        code: 0,
        stdout: '{"ok":true}__SYNCTHING_STATUS__201',
        stderr: "",
      });
    }
    return Promise.resolve({ code: 0, stdout: "MISSING\n", stderr: "" });
  };
  const client = createClient({ ...DEPS, run }, "ssh", {
    apiUrl: "http://127.0.0.1:8384",
    apiKey: HEADER_VALUE,
  }, {
    host: "192.0.2.10",
    port: 22,
    user: "root",
    host_key_policy: "strict",
    host_keys: ["192.0.2.10 ssh-ed25519 AAAA"],
    connect_timeout_s: 15,
  });
  const result = await client.request("PUT", "/rest/config/devices/x", {
    deviceID: "x",
  });
  assertEquals(result.status, 201);
  // The whole remote command is curl reading its config from stdin.
  const curl = calls.find((call) => (call.args.at(-1) ?? "").includes("curl"));
  assert(curl, "curl must read its config from stdin");
  assert(
    (curl.stdin ?? "").includes(`header = "X-API-Key: ${HEADER_VALUE}"`),
    "the key must travel in the streamed config",
  );
  // A remote step carries a timeout, and no secret or temp path is on argv.
  assert(typeof curl.timeoutMs === "number" && curl.timeoutMs >= 30_000);
  for (const call of calls) {
    const text = call.args.join(" ");
    assertEquals(text.includes(HEADER_VALUE), false, "key on argv");
    assertEquals(text.includes("mktemp"), false, "no remote temp file");
    assertEquals(text.includes("curlrc"), false, "no remote config file");
    assertEquals(text.includes("umask 077"), false, "no secret dir");
    assertEquals(text.includes(".cache/syncthing-peer"), false, "no cache dir");
    assertEquals(text.includes("rm -f"), false, "no cleanup path");
  }
});

Deno.test("a failed remote curl is a typed error and leaks no key", async () => {
  const run: CommandRunner = (
    _cmd: string,
    args: string[],
  ): Promise<CommandResult> => {
    if ((args.at(-1) ?? "").includes("curl")) {
      return Promise.resolve({
        code: 60,
        stdout: "",
        stderr: "SSL certificate problem",
      });
    }
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  const client = createClient({ ...DEPS, run }, "ssh", {
    apiUrl: "http://127.0.0.1:8384",
    apiKey: HEADER_VALUE,
  }, {
    host: "192.0.2.10",
    port: 22,
    user: "root",
    host_key_policy: "strict",
    host_keys: ["192.0.2.10 ssh-ed25519 AAAA"],
    connect_timeout_s: 15,
  });
  const error = await assertRejects(
    () => client.request("GET", "/rest/system/status"),
    Error,
  ) as Error;
  assert(error.message.includes("exit 60"));
  assertEquals(error.message.includes(HEADER_VALUE), false);
});

Deno.test("device and folder specs validate and match", () => {
  const device = buildDeviceSpec({
    deviceId: DEVICE,
    name: "edge-2",
    addresses: ["dynamic", "tcp://192.0.2.10:22000"],
  });
  assertEquals(device.addresses.length, 2);
  assertEquals((deviceBody(device) as { deviceID: string }).deviceID, DEVICE);
  assert(
    deviceMatches(
      {
        deviceID: DEVICE,
        name: "edge-2",
        addresses: ["tcp://192.0.2.10:22000", "dynamic"],
        introducer: false,
        paused: false,
      },
      device,
    ),
  );
  assert(!deviceMatches({ name: "other" }, device));
  assertThrows(
    () => buildDeviceSpec({ deviceId: DEVICE, name: "x", addresses: ["tcp"] }),
    Error,
  );
  assertThrows(
    () => buildDeviceSpec({ deviceId: DEVICE, name: "bad\u0007" }),
    Error,
  );

  const folder = buildFolderSpec({
    folderId: "media",
    label: "Media",
    path: "/srv/media",
    devices: [DEVICE],
  });
  assertEquals(folder.type, "sendreceive");
  assertEquals(
    (folderBody(folder) as { devices: { deviceID: string }[] }).devices,
    [{ deviceID: DEVICE }],
  );
  assertEquals(
    folderDevices({ devices: [{ deviceID: DEVICE }, "PLAINID"] }),
    [DEVICE, "PLAINID"],
  );
  // Syncthing adds the node's own device and extra fields to the read-back.
  const live = {
    id: "media",
    label: "Media",
    path: "/srv/media",
    type: "sendreceive",
    paused: false,
    devices: [
      { deviceID: "OWN-ID", encryptionPassword: "" },
      { deviceID: DEVICE, introducedBy: "" },
    ],
  };
  assert(folderMatches(live, folder, "OWN-ID"));
  assert(!folderMatches(live, folder), "own device is part of the raw list");
  assertEquals(folderSpecOf(live, folder, "OWN-ID").devices, [DEVICE]);
  assertThrows(
    () => buildFolderSpec({ folderId: "media", label: "M", path: "/a/../b" }),
    Error,
  );
  assertThrows(
    () => buildFolderSpec({ folderId: "..", label: "M", path: "/a" }),
    Error,
  );
});
