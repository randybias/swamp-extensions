import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  assertListenAcceptable,
  hostListens,
  listenFragment,
  otherZoneListens,
} from "./listen.ts";

/** A recorded zone as `readModelData` returns it. */
function recorded(
  apex: string,
  requested: string[],
  over: Record<string, unknown> = {},
) {
  return {
    attributes: {
      host: "h1",
      apex,
      status: "applied",
      requested_listen: requested,
      ...over,
    },
  };
}

/** A plain-object method context, as the runtime hands to a model. */
function store(rows: unknown[] | Error) {
  return {
    definition: { name: "dns" },
    readModelData: (_model: string | undefined, _spec: string) =>
      rows instanceof Error ? Promise.reject(rows) : Promise.resolve(rows),
  };
}

Deno.test("another zone's listens are kept, this zone's own record is not", async () => {
  const ctx = store([
    recorded("a.example.", ["192.0.2.1"]),
    recorded("b.example.", ["192.0.2.2"]),
  ]);
  assertEquals(await otherZoneListens(ctx, "h1", "a.example."), ["192.0.2.2"]);
});

Deno.test("removed zones, other hosts and render rows do not hold a listen", async () => {
  const ctx = store([
    recorded("a.example.", ["192.0.2.1"], { status: "removed" }),
    recorded("b.example.", ["192.0.2.2"], { host: "h2" }),
    { attributes: { host: "h1", apex: "c.example.", status: "rendered" } },
  ]);
  assertEquals(await otherZoneListens(ctx, "h1", "z.example."), []);
});

Deno.test("an unreadable store fails closed instead of dropping listeners", async () => {
  await assertRejects(
    () => otherZoneListens(store(new Error("boom")), "h1", "a.example."),
    Error,
    "boom",
  );
});

Deno.test("a context without a store contributes no other listens", async () => {
  assertEquals(await otherZoneListens({}, "h1", "a.example."), []);
});

Deno.test("the host set is the sorted union and renders as one fragment", () => {
  const set = hostListens(["192.0.2.2@5353"], ["192.0.2.1", "192.0.2.2@5353"]);
  assertEquals(set, ["192.0.2.1", "192.0.2.2@5353"]);
  assertEquals(
    listenFragment(set),
    'server:\n  listen: ["192.0.2.1", "192.0.2.2@5353"]\n',
  );
  assertEquals(listenFragment([]), "");
});

Deno.test("a wildcard needs the ack and may not overlap the resolver", () => {
  assertThrows(
    () =>
      assertListenAcceptable(
        { listen: ["0.0.0.0"], listen_any_ack: false },
        undefined,
      ),
    Error,
    "listen_any_ack",
  );
  assertThrows(
    () =>
      assertListenAcceptable(
        { listen: ["192.0.2.1"], listen_any_ack: false },
        ["192.0.2.1"],
      ),
    Error,
    "overlap",
  );
});
