import { describe, expect, it } from "vitest";
import { decodeFriendCodeV1, encodeFriendCodeV1 } from "../friendCode";
import { encodeBase64Url } from "../base64url";
import { canonicalBytes } from "../../crypto/canonicalJson";

const makeBytes = (seed: number) => {
  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i += 1) out[i] = (seed + i) % 256;
  return out;
};

const makeCode = () =>
  encodeFriendCodeV1({
    v: 1,
    identityPub: encodeBase64Url(makeBytes(11)),
    dhPub: encodeBase64Url(makeBytes(33)),
    deviceId: "123e4567-e89b-42d3-a456-426614174000",
  });

const makeCodeWithDashInBody = () => {
  for (let seed = 1; seed < 300; seed += 1) {
    const code = encodeFriendCodeV1({
      v: 1,
      identityPub: encodeBase64Url(makeBytes(seed)),
      dhPub: encodeBase64Url(makeBytes(seed + 91)),
      deviceId: "123e4567-e89b-42d3-a456-426614174000",
    });
    if (code.slice("NKC1-".length).includes("-")) {
      return code;
    }
  }
  throw new Error("failed to build test code with '-' in body");
};

const toStandardBase64Code = (code: string) => {
  const body = code.slice("NKC1-".length);
  const standard = body.replace(/-/g, "+").replace(/_/g, "/");
  return `NKC1-${standard}`;
};

const legacyHash32Bytes = (bytes: Uint8Array) => {
  const seeds = [
    0x811c9dc5, 0x01000193, 0x1234567, 0x9e3779b9, 0x85ebca6b, 0xc2b2ae35,
    0x27d4eb2f, 0x165667b1,
  ];
  const out = new Uint8Array(seeds.length * 4);
  seeds.forEach((seed, idx) => {
    let hash = seed >>> 0;
    for (const byte of bytes) {
      hash ^= byte;
      hash = Math.imul(hash, 0x01000193);
    }
    const offset = idx * 4;
    out[offset] = (hash >>> 24) & 0xff;
    out[offset + 1] = (hash >>> 16) & 0xff;
    out[offset + 2] = (hash >>> 8) & 0xff;
    out[offset + 3] = hash & 0xff;
  });
  return out;
};


describe("friendCode", () => {
  it("decodes valid code", () => {
    const decoded = decodeFriendCodeV1(makeCode());
    expect("error" in decoded ? decoded.error : "").toBe("");
  });

  it("round-trips a mailbox write capability", () => {
    const inboxWriteToken = encodeBase64Url(makeBytes(71));
    const code = encodeFriendCodeV1({
      v: 1,
      identityPub: encodeBase64Url(makeBytes(11)),
      dhPub: encodeBase64Url(makeBytes(33)),
      deviceId: "123e4567-e89b-42d3-a456-426614174000",
      inboxWriteToken,
    });
    const decoded = decodeFriendCodeV1(code);
    expect("error" in decoded ? undefined : decoded.inboxWriteToken).toBe(inboxWriteToken);
  });

  it("decodes code with common paste noise", () => {
    const noisy = `"${makeCode()}:"`;
    const decoded = decodeFriendCodeV1(noisy);
    expect("error" in decoded ? decoded.error : "").toBe("");
  });

  it("decodes code with zero-width separators", () => {
    const code = makeCode();
    const withZeroWidth = `${code.slice(0, 8)}\u200b${code.slice(8)}`;
    const decoded = decodeFriendCodeV1(withZeroWidth);
    expect("error" in decoded ? decoded.error : "").toBe("");
  });

  it("decodes code when base64url body includes '-'", () => {
    const decoded = decodeFriendCodeV1(makeCodeWithDashInBody());
    expect("error" in decoded ? decoded.error : "").toBe("");
  });

  it("decodes code when body uses standard base64 characters", () => {
    const code = toStandardBase64Code(makeCode());
    const decoded = decodeFriendCodeV1(code);
    expect("error" in decoded ? decoded.error : "").toBe("");
  });

  it("ignores invalid deviceId instead of rejecting the whole code", () => {
    const raw = encodeBase64Url(makeBytes(11));
    const payload = {
      v: 1 as const,
      identityPub: raw,
      dhPub: encodeBase64Url(makeBytes(33)),
      deviceId: "not-a-uuid",
    };
    const code = encodeFriendCodeV1(payload);
    const decoded = decodeFriendCodeV1(code);
    expect("error" in decoded ? decoded.error : "").toBe("");
    if (!("error" in decoded)) {
      expect(decoded.deviceId).toBeUndefined();
    }
  });

  it("accepts legacy checksum friend code", () => {
    const payload = {
      v: 1 as const,
      identityPub: encodeBase64Url(makeBytes(21)),
      dhPub: encodeBase64Url(makeBytes(61)),
      deviceId: "123e4567-e89b-42d3-a456-426614174000",
    };
    const payloadBytes = canonicalBytes(payload);
    const checksum = legacyHash32Bytes(payloadBytes).slice(0, 4);
    const combined = new Uint8Array(payloadBytes.length + checksum.length);
    combined.set(payloadBytes, 0);
    combined.set(checksum, payloadBytes.length);
    const code = `NKC1-${encodeBase64Url(combined)}`;
    const decoded = decodeFriendCodeV1(code);
    expect("error" in decoded ? decoded.error : "").toBe("");
  });
});
