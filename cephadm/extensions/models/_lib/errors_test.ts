import { assertEquals, assertThrows } from "jsr:@std/assert@1.0.19";
import {
  fail,
  isTransportLike,
  LocalRefusalError,
  PhaseError,
  RemoteExitError,
  SudoPolicyError,
  TransportError,
} from "./errors.ts";

Deno.test("a phase error renders phase, message and no parentheses without detail", () => {
  const e = new PhaseError("bootstrap", "fsid missing");
  assertEquals(e.message, "cephadm[bootstrap]: fsid missing");
  assertEquals(e instanceof Error, true);
  assertEquals(e.phase, "bootstrap");
  assertThrows(
    () => fail("bootstrap", "fsid missing"),
    PhaseError,
    "fsid missing",
  );
});

Deno.test("detail renders strings raw and other values as JSON, in order", () => {
  const e = new PhaseError("x", "boom", {
    host: "node1.test",
    expected: 6,
    observed: 5,
    up: true,
    devices: ["/dev/nvme0n1", "/dev/sda"],
  });
  assertEquals(
    e.message,
    'cephadm[x]: boom (host=node1.test, expected=6, observed=5, up=true, devices=["/dev/nvme0n1","/dev/sda"])',
  );
});

Deno.test("undefined detail fields are omitted and none leaves no parentheses", () => {
  const e = new PhaseError("x", "boom", { a: undefined, b: 1 });
  assertEquals(e.message, "cephadm[x]: boom (b=1)");
  assertEquals(
    new PhaseError("x", "boom", { a: undefined, b: undefined }).message,
    "cephadm[x]: boom",
  );
});

Deno.test(
  "a transport error is a distinct type carrying kind and cause", // leak-allow(decision D8)
  () => {
    const e = new TransportError({
      host: "192.0.2.10",
      port: 2202,
      user: "admin",
      kind: "dropped-before-auth",
      cause: "auth",
      message: "authentication failed",
    });
    assertEquals(e instanceof TransportError, true);
    assertEquals(e instanceof PhaseError, false);
    assertEquals(e.kind, "dropped-before-auth");
    assertEquals(e.sessionCause, "auth");
    assertEquals(e.preSession, true);
    assertEquals(e.message.includes("admin@192.0.2.10:2202"), true);
    assertEquals(isTransportLike(e), true);
    assertEquals(isTransportLike(new Error("x")), false);
  },
);

Deno.test("transport errors default the port to 22 in the message", () => {
  const e = new TransportError({
    host: "node1.test",
    port: 22,
    user: "admin",
    kind: "other",
    cause: null,
    message: "connection refused",
  });
  assertEquals(e.message.includes("admin@node1.test:22"), true);
  assertEquals(e.preSession, false);
});

Deno.test("sudo policy, remote exit and local refusal are distinct types", () => {
  assertEquals(isTransportLike(new SudoPolicyError("x")), true);
  assertEquals(isTransportLike(new LocalRefusalError("x")), true);
  const remote = new RemoteExitError(1, "out", "err", "admin@h:22: false");
  assertEquals(remote.code, 1);
  assertEquals(remote.stdout, "out");
  assertEquals(remote.stderr, "err");
  assertEquals(isTransportLike(remote), false);
});
