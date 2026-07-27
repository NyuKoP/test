const ipv4Pattern =
  /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const ipv6Pattern = /\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/g;
const icePattern = /(candidate:|a=candidate)/gi;
const ipv4TestPattern = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/;
const ipv6TestPattern = /\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/;
const iceTestPattern = /(candidate:|a=candidate)/i;
const onionV3Pattern = /^[a-z2-7]{56}\.onion$/;

export const redactIPs = (value: string) => {
  if (!value) return value;
  return value
    .replace(ipv4Pattern, "[redacted-ip]")
    .replace(ipv6Pattern, "[redacted-ip]")
    .replace(icePattern, "candidate:[redacted]");
};

export const looksLikeIpOrIce = (value: string) =>
  ipv4TestPattern.test(value) || ipv6TestPattern.test(value) || iceTestPattern.test(value);

export const sanitizeRoutingHints = (
  hints?: { onionAddr?: string; deviceId?: string; inboxWriteToken?: string }
) => {
  if (!hints) return undefined;
  const next: { onionAddr?: string; deviceId?: string; inboxWriteToken?: string } = {};
  const onionAddr = hints.onionAddr?.trim().toLowerCase();
  if (onionAddr && onionV3Pattern.test(onionAddr) && !looksLikeIpOrIce(onionAddr)) {
    next.onionAddr = onionAddr;
  }
  if (typeof hints.deviceId === "string") {
    const uuidPattern =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (uuidPattern.test(hints.deviceId)) {
      next.deviceId = hints.deviceId;
    }
  }
  if (
    typeof hints.inboxWriteToken === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(hints.inboxWriteToken)
  ) {
    next.inboxWriteToken = hints.inboxWriteToken;
  }
  return Object.keys(next).length ? next : undefined;
};
