import { canonicalBytes } from "../crypto/canonicalJson";
import { decodeBase64Url, encodeBase64Url } from "./base64url";
import { sha256 } from "./sha256";

export type FriendCodeV1 = {
  v: 1;
  identityPub: string;
  dhPub: string;
  deviceId?: string;
  onionAddr?: string;
  inboxWriteToken?: string;
};

const PREFIX = "NKC1-";
const ZERO_WIDTH_OR_BOM = /[\u200B-\u200D\uFEFF]/g;
const BASE64_BODY_ALLOWED = /[^A-Za-z0-9_+\-/=]/g;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const sanitizeScannedCode = (value: string) => {
  let next = value.replace(ZERO_WIDTH_OR_BOM, "").trim();
  next = next.replace(/^[\s"'`([{<]+/, "");
  next = next.replace(/[\s"'`)\]}>:;,.!?]+$/, "");
  return next;
};

const extractCodeBody = (value: string, prefix: string) => {
  const compact = sanitizeScannedCode(value).replace(/\s+/g, "");
  const prefixCompact = prefix.replace("-", "");
  if (!compact.toUpperCase().startsWith(prefixCompact)) return null;
  let raw = compact.slice(prefixCompact.length);
  raw = raw.replace(/^[-:]/, "");
  raw = raw.replace(BASE64_BODY_ALLOWED, "");
  return raw;
};

const hash32Bytes = (bytes: Uint8Array) => {
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

const checksum4Bytes = (payloadBytes: Uint8Array) => sha256(payloadBytes).slice(0, 4);
const legacyChecksum4Bytes = (payloadBytes: Uint8Array) => hash32Bytes(payloadBytes).slice(0, 4);

export const encodeFriendCodeV1 = (data: FriendCodeV1) => {
  const payload: FriendCodeV1 = {
    v: 1,
    identityPub: data.identityPub,
    dhPub: data.dhPub,
    deviceId: data.deviceId,
    onionAddr: data.onionAddr,
    inboxWriteToken: data.inboxWriteToken,
  };
  const payloadBytes = canonicalBytes(payload);
  const checksum = checksum4Bytes(payloadBytes);
  const combined = new Uint8Array(payloadBytes.length + checksum.length);
  combined.set(payloadBytes, 0);
  combined.set(checksum, payloadBytes.length);
  return `${PREFIX}${encodeBase64Url(combined)}`;
};

export const decodeFriendCodeV1 = (
  code: string
): FriendCodeV1 | { error: string } => {
  const raw = extractCodeBody(code, PREFIX);
  if (!raw) {
    return { error: "Invalid friend code prefix." };
  }

  let decoded: Uint8Array;
  try {
    decoded = decodeBase64Url(raw);
  } catch {
    return { error: "Invalid friend code encoding." };
  }

  if (decoded.length <= 4) {
    return { error: "Friend code is too short." };
  }

  const payloadBytes = decoded.slice(0, decoded.length - 4);
  const checksum = decoded.slice(decoded.length - 4);
  const expected = checksum4Bytes(payloadBytes);
  const expectedLegacy = legacyChecksum4Bytes(payloadBytes);
  const matches = (candidate: Uint8Array) => {
    if (candidate.length !== checksum.length) return false;
    for (let i = 0; i < checksum.length; i += 1) {
      if (checksum[i] !== candidate[i]) return false;
    }
    return true;
  };
  const checksumOk = matches(expected) || matches(expectedLegacy);
  if (!checksumOk) {
    return { error: "Friend code checksum mismatch." };
  }

  let payload: Partial<FriendCodeV1>;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as Partial<FriendCodeV1>;
  } catch {
    return { error: "Invalid friend code payload encoding." };
  }

  if (payload?.v !== 1 || typeof payload.identityPub !== "string" || typeof payload.dhPub !== "string") {
    return { error: "Invalid friend code payload." };
  }

  try {
    const identityBytes = decodeBase64Url(payload.identityPub);
    const dhBytes = decodeBase64Url(payload.dhPub);
    if (identityBytes.length !== 32 || dhBytes.length !== 32) {
      return { error: "Invalid key lengths in friend code." };
    }
  } catch {
    return { error: "Invalid public keys in friend code." };
  }

  const deviceIdCandidate = typeof payload.deviceId === "string" ? payload.deviceId.trim() : "";
  const deviceId = deviceIdCandidate && UUID_PATTERN.test(deviceIdCandidate)
    ? deviceIdCandidate
    : undefined;
  const inboxWriteToken =
    typeof payload.inboxWriteToken === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(payload.inboxWriteToken)
      ? payload.inboxWriteToken
      : undefined;

  return {
    v: 1,
    identityPub: payload.identityPub,
    dhPub: payload.dhPub,
    deviceId,
    onionAddr: typeof payload.onionAddr === "string" ? payload.onionAddr : undefined,
    inboxWriteToken,
  };
};

export const computeFriendId = (identityPubBytes: Uint8Array) =>
  encodeBase64Url(hash32Bytes(identityPubBytes)).slice(0, 16);
