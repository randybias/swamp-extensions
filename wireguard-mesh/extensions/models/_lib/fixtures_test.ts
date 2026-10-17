import { assertEquals } from "jsr:@std/assert@1.0.19";
import {
  fullMesh,
  HUB,
  hubSelf,
  hubSpoke,
  key,
  S1,
  S2,
  S3,
} from "./fixtures.ts";
import { MeshSchema } from "./render.ts";

Deno.test("every synthetic fixture parses against the mesh schema", () => {
  for (const mesh of [hubSpoke(), hubSelf(), fullMesh()]) {
    assertEquals(MeshSchema.safeParse(mesh).success, true);
  }
});

Deno.test("fixtures use only clearly-fake keys and RFC 5737 addresses", () => {
  for (const p of [HUB, S1, S2, S3]) {
    assertEquals(/^(.)\1{41}A=$/.test(p.public_key), true, p.name);
    for (const ip of p.allowed_ips) {
      assertEquals(ip.startsWith("192.0.2."), true, ip);
    }
  }
  assertEquals(key("Z").length, 44);
});
