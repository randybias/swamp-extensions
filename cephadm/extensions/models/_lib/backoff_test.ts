import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { cappedBackoff, poll, type WaitDeps } from "./backoff.ts";
import { TransportError } from "./errors.ts";

Deno.test("capped backoff rises from near ceiling/16 to the ceiling", () => {
  assertEquals(cappedBackoff(0, 1600, 0), 50);
  assertEquals(cappedBackoff(0, 1600, 0.999999), 100);
  assertEquals(cappedBackoff(1, 1600, 0), 100);
  assertEquals(cappedBackoff(2, 1600, 0), 200);
  // Large n saturates at the ceiling.
  assertEquals(cappedBackoff(31, 1600, 0), 800);
  assertEquals(cappedBackoff(0, 1, 0), 1);
});

function waitDeps(nowRef: { t: number }, sleeps: number[]): WaitDeps {
  return {
    now: () => nowRef.t,
    sleep: (ms) => {
      sleeps.push(ms);
      nowRef.t += ms;
      return Promise.resolve();
    },
    random: () => 0,
  };
}

Deno.test("poll retries transport errors but stops at a non-transport error", async () => {
  let reads = 0;
  const deps = waitDeps({ t: 0 }, []);
  const ok = await poll(deps, {
    deadlineMs: 10_000,
    ceilingMs: 100,
    read: () => {
      reads++;
      if (reads < 3) {
        return Promise.reject(
          new TransportError({
            host: "192.0.2.10",
            port: 22,
            user: "admin",
            kind: "dropped-before-auth",
            cause: "auth",
            message: "dropped",
          }),
        );
      }
      return Promise.resolve(1);
    },
    done: () => true,
  });
  assertEquals(ok.value, 1);
  assertEquals(ok.attempts, 3);

  const stopDeps = waitDeps({ t: 0 }, []);
  let stopReads = 0;
  await assertRejects(() =>
    poll(stopDeps, {
      deadlineMs: 10_000,
      ceilingMs: 100,
      read: () => {
        stopReads++;
        return Promise.resolve(1);
      },
      done: () => {
        throw new Error("state not observed");
      },
    })
  );
  assertEquals(stopReads, 1);
});

Deno.test("poll clamps every sleep to the deadline and reads once more", async () => {
  const sleeps: number[] = [];
  const deps = waitDeps({ t: 0 }, sleeps);
  const result = await poll(deps, {
    deadlineMs: 50,
    ceilingMs: 400,
    read: () => Promise.resolve(false),
    done: (v) => v,
  });
  assertEquals(result.value, null);
  assertEquals(sleeps.every((s) => s <= 50 && s >= 1), true);
  // The final read runs after the deadline, so at least two reads happened.
  assertEquals(result.attempts >= 2, true);
});

Deno.test("a frozen clock still terminates at the iteration bound", async () => {
  const deps: WaitDeps = {
    now: () => 0,
    sleep: () => Promise.resolve(),
    random: () => 0,
  };
  const result = await poll(deps, {
    deadlineMs: 10_000,
    ceilingMs: 100,
    maxIterations: 5,
    read: () => Promise.resolve(false),
    done: (v) => v,
  });
  assertEquals(result.value, null);
  // Five loop reads plus exactly one final read.
  assertEquals(result.attempts, 6);
});
