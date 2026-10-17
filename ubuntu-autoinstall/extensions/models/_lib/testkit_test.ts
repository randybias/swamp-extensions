import { assert, assertEquals } from "jsr:@std/assert@1.0.19";
import { fakeRemote, HASH, KEY, renderArgs, SSH_TARGET } from "./testkit.ts";

Deno.test("the fake remote records calls and stores uploaded bytes", async () => {
  const fake = fakeRemote();
  // The upload write script is answered with the stored hash and mode.
  const result = await fake.deps.run("ssh", ["-p", "22", "h", "script"], {
    stdin: "hello",
  });
  assertEquals(result.code, 0);
  assert(fake.calls.length === 1);
});

Deno.test("the fixtures are synthetic and consistent", () => {
  assertEquals(SSH_TARGET.host_key_policy, "strict");
  assert(HASH.startsWith("$6$"));
  assert(KEY.startsWith("ssh-ed25519 "));
  assertEquals(renderArgs().identity.hostname, "web-1");
});
