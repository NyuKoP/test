import { getPublicStore } from "./publicStore";

export type PrivacyPreferences = {
  readReceipts: boolean;
  typingIndicator: boolean;
  linkPreviews: boolean;
  autoRejectUnknownRequests: boolean;
};

const PREF_KEY = "nkc_privacy_prefs_v1";
const CONV_DIRECT_ALLOW_PREFIX = "nkc_conv_allow_direct_v1:";
const RENDEZVOUS_BASE_URL_KEY = "rendezvous_base_url_v1";
const RENDEZVOUS_USE_ONION_KEY = "rendezvous_use_onion_v1";
const ONION_CONTROLLER_URL_KEY = "onion_controller_url_v1";
const ROUTE_POLICY_KEY = "default_route_mode_v1";
const LEGACY_ROUTE_POLICY_KEY = "route_policy_v1";
const GROUP_AVATAR_OVERRIDE_PREFIX = "nkc_group_avatar_override_v1:";
export const PRIVACY_PREFS_CHANGED_EVENT = "nkc:privacy-prefs-changed";

export const defaultPrivacyPrefs: PrivacyPreferences = {
  readReceipts: false,
  typingIndicator: true,
  linkPreviews: true,
  autoRejectUnknownRequests: false,
};

export const getPrivacyPrefs = async () => {
  const store = getPublicStore();
  const raw = await store.get(PREF_KEY);
  if (!raw) return defaultPrivacyPrefs;
  try {
    const parsed = JSON.parse(raw) as Partial<PrivacyPreferences>;
    return { ...defaultPrivacyPrefs, ...parsed };
  } catch (error) {
    console.error("Failed to read privacy prefs", error);
    await store.remove(PREF_KEY);
    return defaultPrivacyPrefs;
  }
};

export const setPrivacyPrefs = async (prefs: PrivacyPreferences) => {
  const store = getPublicStore();
  await store.set(PREF_KEY, JSON.stringify({ ...prefs, updatedAt: Date.now() }));
  if (typeof window !== "undefined") {
    window.dispatchEvent(
      new CustomEvent<PrivacyPreferences>(PRIVACY_PREFS_CHANGED_EVENT, { detail: prefs })
    );
  }
};

export const getConvAllowDirect = async (convId: string) => {
  const store = getPublicStore();
  const raw = await store.get(`${CONV_DIRECT_ALLOW_PREFIX}${convId}`);
  return raw !== "false";
};

export const setConvAllowDirect = async (convId: string, value: boolean) => {
  const store = getPublicStore();
  await store.set(`${CONV_DIRECT_ALLOW_PREFIX}${convId}`, value ? "true" : "false");
};

export const getRendezvousBaseUrl = async () => {
  const store = getPublicStore();
  return (await store.get(RENDEZVOUS_BASE_URL_KEY)) ?? "";
};

export const setRendezvousBaseUrl = async (value: string) => {
  const trimmed = value.trim();
  if (trimmed) {
    const bridge = (
      globalThis as {
        nkc?: {
          authorizeOnionFetchOrigin?: (
            url: string
          ) => Promise<{ ok: boolean; error?: string }>;
        };
      }
    ).nkc;
    if (!bridge?.authorizeOnionFetchOrigin) {
      throw new Error("Network origin approval is unavailable");
    }
    const approval = await bridge.authorizeOnionFetchOrigin(trimmed);
    if (!approval.ok) throw new Error(approval.error ?? "Network origin was not approved");
  }
  const store = getPublicStore();
  await store.set(RENDEZVOUS_BASE_URL_KEY, trimmed);
};

export const getRendezvousUseOnion = async () => {
  const store = getPublicStore();
  const raw = await store.get(RENDEZVOUS_USE_ONION_KEY);
  return raw === "true";
};

export const setRendezvousUseOnion = async (value: boolean) => {
  const store = getPublicStore();
  await store.set(RENDEZVOUS_USE_ONION_KEY, value ? "true" : "false");
};

export const getOnionControllerUrlOverride = async () => {
  const store = getPublicStore();
  return (await store.get(ONION_CONTROLLER_URL_KEY)) ?? "";
};

export const setOnionControllerUrlOverride = async (value: string) => {
  const store = getPublicStore();
  const trimmed = value.trim();
  if (!trimmed) {
    await store.remove(ONION_CONTROLLER_URL_KEY);
    return;
  }
  await store.set(ONION_CONTROLLER_URL_KEY, trimmed);
};

export const getRoutePolicy = async () => {
  const store = getPublicStore();
  const raw = (await store.get(ROUTE_POLICY_KEY)) ?? (await store.get(LEGACY_ROUTE_POLICY_KEY));
  if (!raw) return "auto";
  if (raw === "auto" || raw === "preferTor" || raw === "manual") {
    return raw;
  }
  return "auto";
};

export const setRoutePolicy = async (value: string) => {
  const store = getPublicStore();
  await store.set(ROUTE_POLICY_KEY, value);
  await store.remove(LEGACY_ROUTE_POLICY_KEY);
};

export const getGroupAvatarOverride = async (convId: string) => {
  const store = getPublicStore();
  const raw = await store.get(`${GROUP_AVATAR_OVERRIDE_PREFIX}${convId}`);
  return raw ?? null;
};

export const setGroupAvatarOverride = async (convId: string, ref: string | null) => {
  const store = getPublicStore();
  const key = `${GROUP_AVATAR_OVERRIDE_PREFIX}${convId}`;
  if (!ref) {
    await store.remove(key);
    return;
  }
  await store.set(key, ref);
};
