import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import type { CommandResult, CommandRunner, RunOptions } from "./ssh.ts";
import { normalizePem, parseOpenSslDate, validateTls } from "./tls.ts";

const PEM = "-----BEGIN PUBLIC KEY-----\nRkFLRQ==\n-----END PUBLIC KEY-----\n";

/** An openssl stand-in; `overrides` replaces individual outputs. */
function openssl(
  overrides: Partial<
    Record<"cert" | "key" | "dates" | "certPub" | "keyPub", CommandResult>
  > = {},
): CommandRunner {
  return (
    _cmd: string,
    args: string[],
    _options?: RunOptions,
  ): Promise<CommandResult> => {
    const ok = (stdout: string): CommandResult => ({
      code: 0,
      stdout,
      stderr: "",
    });
    if (args.includes("-startdate") || args.includes("-enddate")) {
      return Promise.resolve(
        overrides.dates ??
          ok(
            "notBefore=Jan  1 00:00:00 2020 GMT\nnotAfter=Jan  1 00:00:00 2100 GMT\n",
          ),
      );
    }
    if (args.includes("-pubkey")) {
      return Promise.resolve(overrides.certPub ?? ok(PEM));
    }
    if (args[0] === "pkey" && args.includes("-pubout")) {
      return Promise.resolve(overrides.keyPub ?? ok(PEM));
    }
    if (args[0] === "pkey") return Promise.resolve(overrides.key ?? ok(""));
    return Promise.resolve(overrides.cert ?? ok(""));
  };
}

const DEPS = (run: CommandRunner) => ({
  run,
  now: () => Date.parse("2030-01-01T00:00:00Z"),
});
const CERT = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";
const KEY = "opaque-private-key-placeholder\n";

Deno.test("parseOpenSslDate reads an openssl date and rejects junk", () => {
  const at = parseOpenSslDate(
    "notBefore=Jan  1 00:00:00 2020 GMT",
    "notBefore",
  );
  assertEquals(at, Date.parse("Jan  1 00:00:00 2020 GMT"));
  assertEquals(parseOpenSslDate("garbage", "notBefore"), null);
});

Deno.test("normalizePem strips headers and whitespace", () => {
  assertEquals(normalizePem(PEM), "RkFLRQ==");
});

Deno.test("validateTls accepts a matching, currently valid pair", async () => {
  await validateTls(DEPS(openssl()), CERT, KEY);
});

Deno.test("validateTls refuses an unparseable certificate", async () => {
  await assertRejects(
    () =>
      validateTls(
        DEPS(openssl({ cert: { code: 1, stdout: "", stderr: "bad" } })),
        CERT,
        KEY,
      ),
    Error,
    "not a valid X.509",
  );
});

Deno.test("validateTls refuses an expired certificate", async () => {
  await assertRejects(
    () =>
      validateTls(
        DEPS(
          openssl({
            dates: {
              code: 0,
              stdout:
                "notBefore=Jan  1 00:00:00 2010 GMT\nnotAfter=Jan  1 00:00:00 2019 GMT\n",
              stderr: "",
            },
          }),
        ),
        CERT,
        KEY,
      ),
    Error,
    "expired",
  );
});

Deno.test("validateTls refuses a not-yet-valid certificate", async () => {
  await assertRejects(
    () =>
      validateTls(
        DEPS(
          openssl({
            dates: {
              code: 0,
              stdout:
                "notBefore=Jan  1 00:00:00 2099 GMT\nnotAfter=Jan  1 00:00:00 2100 GMT\n",
              stderr: "",
            },
          }),
        ),
        CERT,
        KEY,
      ),
    Error,
    "not yet valid",
  );
});

Deno.test("validateTls refuses a mismatched key", async () => {
  await assertRejects(
    () =>
      validateTls(
        DEPS(
          openssl({
            keyPub: {
              code: 0,
              stdout:
                "-----BEGIN PUBLIC KEY-----\nT1RIRVI=\n-----END PUBLIC KEY-----\n",
              stderr: "",
            },
          }),
        ),
        CERT,
        KEY,
      ),
    Error,
    "does not match",
  );
});

Deno.test("validateTls refuses missing validity dates", async () => {
  await assertRejects(
    () =>
      validateTls(
        DEPS(openssl({ dates: { code: 0, stdout: "nope", stderr: "" } })),
        CERT,
        KEY,
      ),
    Error,
    "validity dates",
  );
});
