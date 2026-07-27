import { describe, expect, it } from "vitest";
import { looksLikeIpOrIce, sanitizeRoutingHints } from "../privacy";

describe("network privacy routing hints", () => {
  it("detects repeated IP and ICE checks without stateful regex misses", () => {
    expect(looksLikeIpOrIce("candidate:1 1 UDP 1 192.168.1.2 5000 typ host")).toBe(true);
    expect(looksLikeIpOrIce("candidate:1 1 UDP 1 192.168.1.2 5000 typ host")).toBe(true);
  });

  it("accepts only canonical anonymous-network hostnames", () => {
    const onionAddr = `${"a".repeat(56)}.onion`;
    expect(
      sanitizeRoutingHints({
        onionAddr: ` ${onionAddr.toUpperCase()} `,
      })
    ).toEqual({ onionAddr });
    expect(
      sanitizeRoutingHints({
        onionAddr: "127.0.0.1.onion",
      })
    ).toBeUndefined();
  });

  it("accepts only 256-bit base64url mailbox capabilities", () => {
    const inboxWriteToken = "A".repeat(43);
    expect(sanitizeRoutingHints({ inboxWriteToken })).toEqual({ inboxWriteToken });
    expect(sanitizeRoutingHints({ inboxWriteToken: "too-short" })).toBeUndefined();
  });
});
