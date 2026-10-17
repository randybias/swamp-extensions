import { assertEquals } from "jsr:@std/assert@1.0.19";
import { overlaps, parseCidr } from "./cidr.ts";

Deno.test("cidr parsing and overlap", () => {
  const c = (s: string) => parseCidr(s)!;
  assertEquals(overlaps(c("192.0.2.0/24"), c("192.0.2.9/32")), true);
  assertEquals(overlaps(c("192.0.2.0/25"), c("192.0.2.128/25")), false);
  assertEquals(overlaps(c("0.0.0.0/0"), c("2001:db8::/32")), false);
  assertEquals(overlaps(c("2001:db8::/32"), c("2001:db8:1::/48")), true);
  assertEquals(overlaps(c("2001:db8::/33"), c("2001:db8:8000::/33")), false);
  assertEquals(parseCidr("2001:db8::1/129"), null);
  assertEquals(parseCidr("::/0")?.prefix, 0);
  assertEquals(parseCidr("1:2:3:4:5:6:7:8:9/64"), null);
  assertEquals(parseCidr("192.0.02.1/24"), null);
});
