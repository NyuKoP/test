import {
  computeEnvelopeHash,
  decryptEnvelope,
  deriveConversationKey,
  encryptEnvelope,
  type Envelope,
  type EnvelopeHeader,
  verifyEnvelopeSignature,
} from "../crypto/box";
import { canonicalBytes } from "../crypto/canonicalJson";
import { nextSendDhKey, nextSendKey, tryRecvDhKey, tryRecvKey } from "../crypto/ratchet";
import {
  getEvent,
  getLastEventHash,
  listConversations,
  listEventsByConv,
  listProfiles,
  saveMessage,
  saveReceivedMessageMediaChunk,
  saveConversation,
  saveEvent,
  saveProfile,
  type Conversation,
  type Message,
  type UserProfile,
} from "../db/repo";
import { parseIncomingMediaRef } from "../security/mediaPolicy";
import { decodeBase64Url, encodeBase64Url } from "../security/base64url";
import { getDhPrivateKey, getIdentityPrivateKey, getIdentityPublicKey } from "../security/identityKeys";
import { getFriendPsk } from "../security/pskStore";
import { getOrCreateDeviceId } from "../security/deviceRole";
import { applyTOFU } from "../security/trust";
import { computeFriendId, decodeFriendCodeV1 } from "../security/friendCode";
import { getPrivacyPrefs } from "../security/preferences";
import { emitFlowTraceLog } from "../diagnostics/infoCollectionLogs";
import { createSafeConsole } from "../diagnostics/safeConsole";
import { updateFromRoleEvent, type RoleChangeEvent } from "../devices/deviceRegistry";
import { getDeviceApproval } from "../devices/deviceApprovals";
import { createId } from "../utils/ids";
import {
  connectConversation as connectTransport,
  disconnectConversation as disconnectTransport,
  onConversationMessage,
  sendToConversation,
} from "../net/transportManager";
import type { PeerHint } from "../net/transport";
import { sanitizeRoutingHints } from "../net/privacy";
import { putReadCursor } from "../storage/receiptStore";
import { applyGroupEvent, isGroupEventPayload } from "./groupSync";
import { getSodium } from "../security/sodium";
import {
  isFriendControlFrame,
  isFriendControlFrameFresh,
  verifyFriendControlFrameSignature,
  verifyFriendControlFrameProtocol,
  type FriendControlFrame,
  type FriendRequestFrame,
  type FriendResponseFrame,
} from "../friends/friendControlFrame";

const console = createSafeConsole(globalThis.console);

type EnvelopeEvent = {
  eventId: string;
  convId: string;
  authorDeviceId: string;
  lamport: number;
  ts: number;
  envelopeJson: string;
};

type PeerCaps = {
  proto: number;
  sync: { v: number };
  ratchet?: { v: number };
  media?: { chunks?: boolean; v?: number };
  devices?: { roles?: boolean; v?: number };
};

type NormalizedPeerCaps = {
  proto: number;
  sync: { v: number };
  ratchet: { v: number };
  media: { chunks: boolean; v: number };
  devices: { roles: boolean; v: number };
};

const LEGACY_PEER_CAPS: NormalizedPeerCaps = {
  proto: 1,
  sync: { v: 1 },
  ratchet: { v: 0 },
  media: { chunks: false, v: 0 },
  devices: { roles: false, v: 0 },
};

const LOCAL_CAPS: PeerCaps = {
  proto: 1,
  sync: { v: 2 },
  ratchet: { v: 2 },
  media: { chunks: true, v: 2 },
  devices: { roles: true, v: 1 },
};

type HelloFrame = {
  type: "HELLO";
  deviceId: string;
  identityPub: string;
  nonce: string;
  sig: string;
  caps?: PeerCaps;
  profile?: { displayName?: string; status?: string; avatarRef?: UserProfile["avatarRef"] };
};

type AckFrame = {
  type: "ACK";
  deviceId: string;
  identityPub: string;
  nonce: string;
  sig: string;
  caps?: PeerCaps;
};

type SyncReqFrame = {
  type: "SYNC_REQ";
  scope: "conv" | "contacts" | "conversations" | "global";
  convId?: string;
  since: Record<string, number>;
};

type SyncResFrame = {
  type: "SYNC_RES";
  scope: "conv" | "contacts" | "conversations" | "global";
  convId?: string;
  events: EnvelopeEvent[];
  next: Record<string, number>;
  flow?: {
    sessionId: string;
    chunkIndex: number;
    totalChunks: number;
    final: boolean;
  };
};

type SyncFlowAckFrame = {
  type: "SYNC_FLOW_ACK";
  sessionId: string;
  chunkIndex: number;
  receivedEvents: number;
};

type Frame = HelloFrame | AckFrame | SyncReqFrame | SyncResFrame | SyncFlowAckFrame;

export type PeerContext = PeerHint & {
  friendKeyId?: string;
  identityPub?: string;
  dhPub?: string;
  kind?: "friend" | "device";
  peerDeviceId?: string;
  peerCaps?: NormalizedPeerCaps;
};

const contactsLogId = (convId: string) => `contacts:${convId}`;
const conversationsLogId = (convId: string) => `convs:${convId}`;
const globalLogId = (convId: string) => `global:${convId}`;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
type SyncTransportOverride = {
  send: (convId: string, bytes: Uint8Array) => Promise<void> | void;
};
let syncTransportOverride: SyncTransportOverride | null = null;
const MAX_SYNC_CHUNK_EVENTS = 16;
const MAX_SYNC_CHUNK_BYTES = 96 * 1024;
const SYNC_FLOW_WINDOW = 2;
const SYNC_FLOW_ACK_TIMEOUT_MS = 5_000;
const SYNC_FLOW_MAX_RETRIES = 3;

const normalizeCapVersion = (value: unknown, fallback: number) =>
  typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.trunc(value)
    : fallback;

const normalizePeerCaps = (caps?: PeerCaps): NormalizedPeerCaps => ({
  proto: normalizeCapVersion(caps?.proto, LEGACY_PEER_CAPS.proto),
  sync: { v: normalizeCapVersion(caps?.sync?.v, LEGACY_PEER_CAPS.sync.v) },
  ratchet: { v: normalizeCapVersion(caps?.ratchet?.v, LEGACY_PEER_CAPS.ratchet.v) },
  media: {
    chunks: Boolean(caps?.media?.chunks),
    v: normalizeCapVersion(caps?.media?.v, LEGACY_PEER_CAPS.media.v),
  },
  devices: {
    roles: Boolean(caps?.devices?.roles),
    v: normalizeCapVersion(caps?.devices?.v, LEGACY_PEER_CAPS.devices.v),
  },
});

const getPeerCaps = (convId: string): NormalizedPeerCaps =>
  peerContexts.get(convId)?.peerCaps ?? LEGACY_PEER_CAPS;

export const canUseBinaryMediaTransport = (convId: string) =>
  getPeerCaps(convId).media.chunks && getPeerCaps(convId).media.v >= 2;

const hasKnownPeerCaps = (convId: string) => Boolean(peerContexts.get(convId)?.peerCaps);

const getPeerCapsForEvent = (convKeyId: string, eventConvId: string) => {
  const eventCaps = peerContexts.get(eventConvId)?.peerCaps;
  if (eventCaps) return eventCaps;
  const contextCaps = peerContexts.get(convKeyId)?.peerCaps;
  if (contextCaps) return contextCaps;
  return LEGACY_PEER_CAPS;
};

const getPeerRatchetVersion = (caps: NormalizedPeerCaps) => {
  if (caps.ratchet.v >= 2) return 2;
  if (caps.ratchet.v >= 1) return 1;
  return 0;
};

const canUseRoleEvents = (caps: NormalizedPeerCaps) => caps.devices.roles && caps.devices.v >= 1;

const resolveSendEnvelopeKey = async (
  convId: string,
  logId: string,
  ratchetBaseKey: Uint8Array,
  legacyKey: Uint8Array
) => {
  const ratchetVersion = getPeerRatchetVersion(getPeerCaps(convId));
  if (ratchetVersion >= 2) {
    try {
      const ratchet = await nextSendDhKey(logId, ratchetBaseKey);
      return { msgKey: ratchet.msgKey, headerRk: ratchet.headerRk };
    } catch (error) {
      console.warn("[ratchet] send v2 fallback", { convId, logId, error });
    }
  }
  if (ratchetVersion >= 1) {
    try {
      const ratchet = await nextSendKey(logId, ratchetBaseKey);
      return { msgKey: ratchet.msgKey, headerRk: ratchet.headerRk };
    } catch (error) {
      console.warn("[ratchet] send v1 fallback", { convId, logId, error });
    }
  }
  return { msgKey: legacyKey };
};

const logPeerCaps = (convId: string, caps: NormalizedPeerCaps) => {
  console.debug("[sync] peer caps", {
    convId,
    proto: caps.proto,
    ratchet: caps.ratchet.v,
    mediaChunks: caps.media.chunks,
    roles: caps.devices.roles,
  });
};

const logDecrypt = (label: string, meta: { convId: string; eventId: string; mode: string }) => {
  console.debug(`[sync] ${label}`, meta);
};

const isDeviceSyncAllowed = async (convId: string, reason: string) => {
  const peer = peerContexts.get(convId);
  if (!peer || peer.kind !== "device") return true;
  const peerDeviceId = peer.peerDeviceId ?? peer.friendKeyId;
  if (!peerDeviceId) {
    console.warn("[sync] device sync blocked: missing peer device id", {
      convId,
      reason,
    });
    return false;
  }
  const localDeviceId = getOrCreateDeviceId();
  const [localApproval, peerApproval] = await Promise.all([
    getDeviceApproval(localDeviceId),
    getDeviceApproval(peerDeviceId),
  ]);
  const hasPeerApproval = Boolean(peerApproval);
  const isBoundToPeer = localApproval?.approvedBy === peerDeviceId;
  if (hasPeerApproval || isBoundToPeer) return true;
  console.warn("[sync] device sync blocked: approval not bound to peer", {
    convId,
    reason,
    localDeviceId,
    peerDeviceId,
    localApprovedBy: localApproval?.approvedBy ?? null,
    hasPeerApproval,
  });
  return false;
};

const perAuthorLamportSeen = new Map<string, number>();
const perConvLamportSeen = new Map<string, Map<string, number>>();
const peerContexts = new Map<string, PeerContext>();
const pendingHelloNonces = new Map<string, { nonce: string; createdAt: number }>();
const seenHelloNonces = new Map<string, number>();
const HANDSHAKE_NONCE_TTL_MS = 5 * 60 * 1000;
const MAX_SEEN_HELLO_NONCES = 2048;
const deferredRoleEvents = new Map<string, Map<string, RoleChangeEvent>>();
const convSubscriptions = new Map<string, () => void>();
type OutgoingFlowSession = {
  convId: string;
  frames: SyncResFrame[];
  nextToSend: number;
  inFlight: Map<number, { attempts: number; timer: ReturnType<typeof setTimeout> }>;
};
const outgoingFlowSessions = new Map<string, OutgoingFlowSession>();
let localUserIdCache: string | null | undefined;

const deferRoleChangeEvent = (convId: string, eventId: string, event: RoleChangeEvent) => {
  let pending = deferredRoleEvents.get(convId);
  if (!pending) {
    pending = new Map();
    deferredRoleEvents.set(convId, pending);
  }
  pending.set(eventId, event);
};

const flushDeferredRoleEvents = async (convId: string) => {
  const pending = deferredRoleEvents.get(convId);
  if (!pending || pending.size === 0) return;
  if (!hasKnownPeerCaps(convId)) return;
  if (!canUseRoleEvents(getPeerCaps(convId))) {
    console.warn("[sync] deferred role changes dropped: peer capability missing", {
      convId,
      capsState: "known_unsupported",
      count: pending.size,
    });
    deferredRoleEvents.delete(convId);
    return;
  }
  const entries = Array.from(pending.entries()).sort((lhs, rhs) => lhs[1].ts - rhs[1].ts);
  for (const [eventId, roleEvent] of entries) {
    try {
      await updateFromRoleEvent(roleEvent);
      pending.delete(eventId);
    } catch (error) {
      console.warn("[sync] deferred role change apply failed", { convId, eventId, error });
    }
  }
  if (pending.size === 0) deferredRoleEvents.delete(convId);
};

const resolveLocalUserId = async () => {
  if (localUserIdCache !== undefined) return localUserIdCache;
  const profiles = await listProfiles();
  const user = profiles.find((profile) => profile.kind === "user") || null;
  localUserIdCache = user?.id ?? null;
  return localUserIdCache;
};

const resolveSenderProfileId = async (peerConvId: string) => {
  const peer = peerContexts.get(peerConvId);
  if (!peer) return null;
  const profiles = await listProfiles();
  const friends = profiles.filter((profile) => profile.kind === "friend");
  const match =
    friends.find((friend) => peer.friendKeyId && friend.id === peer.friendKeyId) ||
    friends.find((friend) => peer.friendKeyId && friend.friendId === peer.friendKeyId) ||
    friends.find((friend) => peer.identityPub && friend.identityPub === peer.identityPub) ||
    null;
  return match?.id ?? null;
};

const createNonce = () => {
  const bytes = new Uint8Array(16);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  }
  return encodeBase64Url(bytes);
};

const signHandshake = async (payload: Record<string, unknown>) => {
  const sodium = await getSodium();
  const identityPriv = await getIdentityPrivateKey();
  const sig = sodium.crypto_sign_detached(canonicalBytes(payload), identityPriv);
  return encodeBase64Url(sig);
};

const verifyHandshake = async (
  payload: Record<string, unknown>,
  sigB64: string,
  identityPubB64: string
) => {
  try {
    const sodium = await getSodium();
    const sig = decodeBase64Url(sigB64);
    const verifyKey = decodeBase64Url(identityPubB64);
    return sodium.crypto_sign_verify_detached(sig, canonicalBytes(payload), verifyKey);
  } catch {
    return false;
  }
};

const formatSafetyNumber = (encoded: string) => {
  const compact = encoded.replace(/[^a-zA-Z0-9]/g, "");
  const a = compact.slice(0, 6);
  const b = compact.slice(6, 11);
  const c = compact.slice(11, 17);
  return [a, b, c].filter(Boolean).join("-");
};

const emitFriendLifecycleTrace = (
  event: string,
  payload: {
    traceId?: string;
    frameType: "friend_req" | "friend_accept" | "friend_decline";
    convId?: string;
    friendId?: string;
    profileId?: string;
    stage?: string;
    [key: string]: unknown;
  }
) => {
  emitFlowTraceLog({
    event,
    source: "sync:friendLifecycle",
    ...payload,
    traceId: payload.traceId,
    frameType: payload.frameType,
    convId: payload.convId ?? null,
    friendId: payload.friendId ?? null,
    profileId: payload.profileId ?? null,
  });
};

const computeSafetyNumber = async (identityA: string, identityB: string) => {
  const sodium = await getSodium();
  const a = decodeBase64Url(identityA);
  const b = decodeBase64Url(identityB);
  const pair = [a, b].sort((lhs, rhs) => {
    const la = lhs.length;
    const lb = rhs.length;
    const min = Math.min(la, lb);
    for (let i = 0; i < min; i += 1) {
      if (lhs[i] !== rhs[i]) return lhs[i] - rhs[i];
    }
    return la - lb;
  });
  const hash = sodium.crypto_generichash(16, new Uint8Array([...pair[0], ...pair[1]]));
  return formatSafetyNumber(encodeBase64Url(hash));
};

const resolveFriendByIdentity = async (identityPub?: string) => {
  if (!identityPub) return null;
  const profiles = await listProfiles();
  const exact = profiles.find((profile) => profile.identityPub === identityPub);
  if (exact) return exact;
  try {
    const friendId = computeFriendId(decodeBase64Url(identityPub));
    return profiles.find((profile) => profile.friendId === friendId) ?? null;
  } catch {
    return null;
  }
};

const upsertFriendFromRequest = async (
  convId: string,
  payload: FriendRequestFrame
) => {
  if (!payload.from?.identityPub || !payload.from?.dhPub) return;
  emitFriendLifecycleTrace("friendLifecycle:incoming-request:start", {
    traceId: payload.traceId,
    frameType: payload.type,
    convId,
    stage: "upsertFriendFromRequest:start",
    hasDeviceId: Boolean(payload.from.deviceId),
    hasFriendCode: Boolean(payload.from.friendCode),
  });
  const privacyPrefs = await getPrivacyPrefs();
  const profiles = await listProfiles();
  const existing = profiles.find(
    (profile) =>
      profile.identityPub === payload.from.identityPub ||
      (profile.friendId &&
        profile.identityPub &&
        profile.identityPub === payload.from.identityPub)
  );
  if (!existing && privacyPrefs.autoRejectUnknownRequests) {
    console.info("[friend] auto-rejected unknown friend request");
    emitFriendLifecycleTrace("friendLifecycle:incoming-request:auto-rejected", {
      traceId: payload.traceId,
      frameType: payload.type,
      convId,
      stage: "upsertFriendFromRequest:auto-reject-unknown",
    });
    return;
  }

  const identityBytes = decodeBase64Url(payload.from.identityPub);
  const friendId = computeFriendId(identityBytes);
  const now = Date.now();
  const decodedFriendCode =
    typeof payload.from.friendCode === "string" && payload.from.friendCode.trim()
      ? decodeFriendCodeV1(payload.from.friendCode)
      : null;
  const codeHints =
    decodedFriendCode && !("error" in decodedFriendCode)
      ? sanitizeRoutingHints({
          deviceId: decodedFriendCode.deviceId,
          onionAddr: decodedFriendCode.onionAddr,
          inboxWriteToken: decodedFriendCode.inboxWriteToken,
        })
      : undefined;
  const resolvedDeviceId =
    payload.from.deviceId ??
    (decodedFriendCode && !("error" in decodedFriendCode) ? decodedFriendCode.deviceId : undefined) ??
    existing?.primaryDeviceId;
  const routingHints = sanitizeRoutingHints({
    deviceId: resolvedDeviceId,
    onionAddr: codeHints?.onionAddr ?? existing?.routingHints?.onionAddr,
    inboxWriteToken:
      codeHints?.inboxWriteToken ?? existing?.routingHints?.inboxWriteToken,
  });
  const reachability = resolvedDeviceId
    ? { status: "ok" as const }
    : {
        status: "unreachable" as const,
        lastError: "Missing deviceId in friend request",
      };

  const incomingTs = payload.ts ?? now;
  const existingVcard = existing?.profileVcard;
  const shouldUpdateVcard =
    !existingVcard?.updatedAt || existingVcard.updatedAt <= incomingTs;
  const nextVcard = (() => {
    if (!shouldUpdateVcard && existingVcard) return existingVcard;
    const next: UserProfile["profileVcard"] = {
      ...(existingVcard ?? {}),
      updatedAt: incomingTs,
    };
    if (payload.profile?.displayName !== undefined) {
      next.displayName = payload.profile.displayName;
    }
    if (payload.profile?.status !== undefined) {
      next.status = payload.profile.status;
    }
    if (payload.profile?.avatarRef !== undefined) {
      next.avatarRef = payload.profile.avatarRef;
    }
    if (payload.from?.friendCode !== undefined) {
      next.friendCode = payload.from.friendCode;
    }
    return next;
  })();

  const existingStatus = existing?.friendStatus;
  const isMutualRequest = existingStatus === "request_out";
  const preserveExistingStatus =
    existingStatus === "normal" || existingStatus === "hidden" || existingStatus === "blocked";
  const nextFriendStatus = isMutualRequest ? "normal" : preserveExistingStatus ? existingStatus : "request_in";
  const shouldMarkPending = nextFriendStatus === "request_in";
  const forceHidden = nextFriendStatus === "blocked" || nextFriendStatus === "hidden";

  const profile: UserProfile = {
    id: existing?.id ?? createId(),
    friendId,
    displayName: payload.profile?.displayName ?? existing?.displayName ?? "Friend",
    status: payload.profile?.status ?? existing?.status ?? "",
    theme: existing?.theme ?? "dark",
    kind: "friend",
    friendStatus: nextFriendStatus,
    friendControlTs: Math.max(existing?.friendControlTs ?? 0, incomingTs),
    isFavorite: existing?.isFavorite ?? false,
    identityPub: payload.from.identityPub,
    dhPub: payload.from.dhPub,
    routingHints: routingHints ?? existing?.routingHints,
    primaryDeviceId: resolvedDeviceId,
    trust: existing?.trust ?? { pinnedAt: now, status: "trusted" },
    verification: existing?.verification ?? { status: "unverified" },
    reachability,
    profileVcard: nextVcard,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  await saveProfile(profile);
  emitFriendLifecycleTrace("friendLifecycle:incoming-request:profile-saved", {
    traceId: payload.traceId,
    frameType: payload.type,
    convId,
    friendId,
    profileId: profile.id,
    stage: "upsertFriendFromRequest:profile-saved",
    nextFriendStatus,
    shouldMarkPending,
    primaryDeviceId: resolvedDeviceId ?? null,
    hasOnionAddr: Boolean(routingHints?.onionAddr),
  });

  const requestConvId = payload.convId ?? convId;
  const currentUserId = await resolveLocalUserId();
  if (!currentUserId) return;
  const convs = await listConversations();
  const existingConv =
    convs.find((conv) => conv.id === requestConvId) ??
    convs.find(
      (conv) =>
        !(conv.type === "group" || conv.participants.length > 2) &&
        conv.participants.includes(profile.id)
    ) ??
    null;

  if (existingConv) {
    const updated: Conversation = {
      ...existingConv,
      pendingAcceptance: shouldMarkPending ? true : false,
      pendingOutgoing: shouldMarkPending ? false : false,
      pendingFriendResponse: undefined,
      hidden: forceHidden ? true : shouldMarkPending ? false : existingConv.hidden,
    };
    await saveConversation(updated);
    emitFriendLifecycleTrace("friendLifecycle:incoming-request:conversation-updated", {
      traceId: payload.traceId,
      frameType: payload.type,
      convId: requestConvId,
      friendId,
      profileId: profile.id,
      stage: "upsertFriendFromRequest:conversation-updated",
      pendingAcceptance: updated.pendingAcceptance,
      pendingOutgoing: updated.pendingOutgoing,
      hidden: updated.hidden,
    });
    return;
  }

  if (!shouldMarkPending) {
    emitFriendLifecycleTrace("friendLifecycle:incoming-request:no-conversation-created", {
      traceId: payload.traceId,
      frameType: payload.type,
      convId: requestConvId,
      friendId,
      profileId: profile.id,
      stage: "upsertFriendFromRequest:no-conversation-created",
      reason: "no-pending-acceptance",
    });
    return;
  }

  const newConv: Conversation = {
    id: requestConvId,
    type: "direct",
    name: profile.displayName ?? "Friend",
    pinned: false,
    unread: 0,
    hidden: false,
    muted: false,
    blocked: false,
    pendingAcceptance: true,
    pendingOutgoing: false,
    pendingFriendResponse: undefined,
    lastTs: payload.ts ?? now,
    lastMessage: "친구 요청",
    participants: [currentUserId, profile.id],
  };
  await saveConversation(newConv);
  emitFriendLifecycleTrace("friendLifecycle:incoming-request:conversation-created", {
    traceId: payload.traceId,
    frameType: payload.type,
    convId: newConv.id,
    friendId,
    profileId: profile.id,
    stage: "upsertFriendFromRequest:conversation-created",
    pendingAcceptance: newConv.pendingAcceptance,
    pendingOutgoing: newConv.pendingOutgoing,
  });
};

const applyFriendResponse = async (convId: string, payload: FriendResponseFrame) => {
  if (!payload.from?.identityPub || !payload.from?.dhPub) return false;
  const existing = await resolveFriendByIdentity(payload.from.identityPub);
  if (!existing) {
    emitFriendLifecycleTrace("friendLifecycle:incoming-response:friend-not-found", {
      traceId: payload.traceId,
      frameType: payload.type,
      convId,
      stage: "applyFriendResponse:friend-not-found",
    });
    return false;
  }
  emitFriendLifecycleTrace("friendLifecycle:incoming-response:start", {
    traceId: payload.traceId,
    frameType: payload.type,
    convId,
    friendId: existing.friendId,
    profileId: existing.id,
    stage: "applyFriendResponse:start",
  });
  const now = Date.now();
  const friendStatus = payload.type === "friend_accept" ? "normal" : "blocked";
  const decodedFriendCode =
    typeof payload.from.friendCode === "string" && payload.from.friendCode.trim()
      ? decodeFriendCodeV1(payload.from.friendCode)
      : null;
  const codeHints =
    decodedFriendCode && !("error" in decodedFriendCode)
      ? sanitizeRoutingHints({
          deviceId: decodedFriendCode.deviceId,
          onionAddr: decodedFriendCode.onionAddr,
          inboxWriteToken: decodedFriendCode.inboxWriteToken,
        })
      : undefined;
  const resolvedDeviceId =
    payload.from.deviceId ??
    (decodedFriendCode && !("error" in decodedFriendCode) ? decodedFriendCode.deviceId : undefined) ??
    existing.primaryDeviceId;
  await saveProfile({
    ...existing,
    displayName: payload.profile?.displayName ?? existing.displayName,
    status: payload.profile?.status ?? existing.status,
    avatarRef: payload.profile?.avatarRef ?? existing.avatarRef,
    friendStatus,
    friendControlTs: Math.max(existing.friendControlTs ?? 0, payload.ts ?? now),
    primaryDeviceId: resolvedDeviceId,
    routingHints: sanitizeRoutingHints({
      deviceId: resolvedDeviceId,
      onionAddr: codeHints?.onionAddr ?? existing.routingHints?.onionAddr,
      inboxWriteToken:
        codeHints?.inboxWriteToken ?? existing.routingHints?.inboxWriteToken,
    }),
    profileVcard: payload.profile
      ? {
          displayName: payload.profile.displayName,
          status: payload.profile.status,
          avatarRef: payload.profile.avatarRef,
          friendCode: payload.from.friendCode ?? existing.profileVcard?.friendCode,
          updatedAt: payload.ts ?? now,
        }
      : existing.profileVcard,
    updatedAt: now,
  });
  emitFriendLifecycleTrace("friendLifecycle:incoming-response:profile-saved", {
    traceId: payload.traceId,
    frameType: payload.type,
    convId,
    friendId: existing.friendId,
    profileId: existing.id,
    stage: "applyFriendResponse:profile-saved",
    friendStatus,
    primaryDeviceId: resolvedDeviceId ?? null,
    hasOnionAddr: Boolean(codeHints?.onionAddr ?? existing.routingHints?.onionAddr),
  });

  const convs = await listConversations();
  const conv =
    convs.find((item) => item.id === convId) ??
    convs.find(
      (item) =>
        !(item.type === "group" || item.participants.length > 2) &&
        item.participants.includes(existing.id)
    ) ??
    null;
  if (!conv) return true;
  await saveConversation({
    ...conv,
    pendingAcceptance: false,
    pendingOutgoing: false,
    pendingFriendResponse: undefined,
    hidden: friendStatus === "blocked" ? true : conv.hidden,
  });
  emitFriendLifecycleTrace("friendLifecycle:incoming-response:conversation-updated", {
    traceId: payload.traceId,
    frameType: payload.type,
    convId: conv.id,
    friendId: existing.friendId,
    profileId: existing.id,
    stage: "applyFriendResponse:conversation-updated",
    friendStatus,
    hidden: friendStatus === "blocked" ? true : conv.hidden,
  });
  return true;
};

export const handleIncomingFriendFrame = async (
  payload: FriendControlFrame,
  options: { trustedEnvelope?: boolean; localFriendCode?: string } = {}
) => {
  if (!isFriendControlFrame(payload)) return false;
  if (!options.trustedEnvelope) {
    if (!isFriendControlFrameFresh(payload)) {
      console.warn("[friend] dropped control frame: stale timestamp", { type: payload.type });
      emitFriendLifecycleTrace("friendLifecycle:dropped", {
        traceId: payload.traceId,
        frameType: payload.type,
        convId: payload.convId,
        stage: "handleIncomingFriendFrame:stale-timestamp",
      });
      return false;
    }
    const verified = await verifyFriendControlFrameSignature(payload);
    if (!verified) {
      console.warn("[friend] dropped control frame: invalid signature", { type: payload.type });
      emitFriendLifecycleTrace("friendLifecycle:dropped", {
        traceId: payload.traceId,
        frameType: payload.type,
        convId: payload.convId,
        stage: "handleIncomingFriendFrame:invalid-signature",
      });
      return false;
    }
  }
  const protocolCheck = await verifyFriendControlFrameProtocol(payload, {
    localFriendCode: options.localFriendCode,
  });
  if (!protocolCheck.ok) {
    console.warn("[friend] dropped control frame: invalid protocol", {
      type: payload.type,
      reason: protocolCheck.reason,
    });
    emitFriendLifecycleTrace("friendLifecycle:dropped", {
      traceId: payload.traceId,
      frameType: payload.type,
      convId: payload.convId,
      stage: "handleIncomingFriendFrame:invalid-protocol",
      reason: protocolCheck.reason ?? null,
    });
    return false;
  }
  const existing = await resolveFriendByIdentity(payload.from.identityPub);
  if (
    Number.isFinite(payload.ts) &&
    Number.isFinite(existing?.friendControlTs) &&
    Number(existing?.friendControlTs) >= Number(payload.ts)
  ) {
    console.warn("[friend] dropped control frame: replayed timestamp", { type: payload.type });
    emitFriendLifecycleTrace("friendLifecycle:dropped", {
      traceId: payload.traceId,
      frameType: payload.type,
      convId: payload.convId,
      stage: "handleIncomingFriendFrame:replayed-timestamp",
    });
    return false;
  }
  if (payload.type === "friend_req") {
    const convId = payload.convId ?? createId();
    await upsertFriendFromRequest(convId, payload);
    return true;
  }
  if (payload.type === "friend_accept" || payload.type === "friend_decline") {
    const convId = payload.convId ?? "";
    return applyFriendResponse(convId, payload);
  }
  return false;
};

const verifyHandshakeCompat = async (
  payloadWithCaps: Record<string, unknown>,
  legacyPayload: Record<string, unknown>,
  sigB64: string,
  identityPubB64: string,
  hasCaps: boolean
) => {
  const withCaps = await verifyHandshake(payloadWithCaps, sigB64, identityPubB64);
  if (withCaps) return true;
  if (hasCaps) return false;
  return verifyHandshake(legacyPayload, sigB64, identityPubB64);
};

const toBytes = (frame: Frame) => textEncoder.encode(JSON.stringify(frame));

const tryParseFrame = (bytes: Uint8Array): Frame | null => {
  try {
    const raw = textDecoder.decode(bytes);
    const parsed = JSON.parse(raw) as Frame;
    if (!parsed || typeof parsed !== "object" || !("type" in parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
};

const getSinceMap = (convId?: string) => {
  if (!convId) {
    const since: Record<string, number> = {};
    perAuthorLamportSeen.forEach((value, key) => {
      since[key] = value;
    });
    return since;
  }
  const perConv = perConvLamportSeen.get(convId);
  if (!perConv) return {};
  const since: Record<string, number> = {};
  perConv.forEach((value, key) => {
    since[key] = value;
  });
  return since;
};

const updateLamportSeen = (convId: string, authorDeviceId: string, lamport: number) => {
  const prevAuthor = perAuthorLamportSeen.get(authorDeviceId) ?? 0;
  if (lamport > prevAuthor) perAuthorLamportSeen.set(authorDeviceId, lamport);

  let perConv = perConvLamportSeen.get(convId);
  if (!perConv) {
    perConv = new Map();
    perConvLamportSeen.set(convId, perConv);
  }
  const prevConv = perConv.get(authorDeviceId) ?? 0;
  if (lamport > prevConv) perConv.set(authorDeviceId, lamport);
};

const getLamportSeen = (convId: string, authorDeviceId: string) => {
  const perConv = perConvLamportSeen.get(convId);
  return perConv?.get(authorDeviceId) ?? 0;
};

const buildNextMap = (events: EnvelopeEvent[]) => {
  const next: Record<string, number> = {};
  for (const event of events) {
    const prev = next[event.authorDeviceId] ?? 0;
    if (event.lamport > prev) {
      next[event.authorDeviceId] = event.lamport;
    }
  }
  return next;
};

const toEnvelopeEvent = (event: EnvelopeEvent) => ({
  eventId: event.eventId,
  convId: event.convId,
  authorDeviceId: event.authorDeviceId,
  lamport: event.lamport,
  ts: event.ts,
  envelopeJson: event.envelopeJson,
});

const sortEventsDeterministic = (events: EnvelopeEvent[]) =>
  events.sort((a, b) => {
    if (a.ts !== b.ts) return a.ts - b.ts;
    if (a.authorDeviceId !== b.authorDeviceId) {
      return a.authorDeviceId.localeCompare(b.authorDeviceId);
    }
    return a.lamport - b.lamport;
  });

const resolveLegacyKey = async (convId: string) => {
  const peer = peerContexts.get(convId);
  if (!peer?.dhPub) return null;
  const dhPriv = await getDhPrivateKey();
  const theirDhPub = decodeBase64Url(peer.dhPub);
  const friendKeyId = peer.friendKeyId ?? peer.directAddr ?? convId;
  const pskBytes = await getFriendPsk(friendKeyId);
  const legacyContextBytes = textEncoder.encode(`direct:${friendKeyId}`);
  return deriveConversationKey(dhPriv, theirDhPub, pskBytes, legacyContextBytes);
};

const resolveRatchetBaseKey = async (peerConvId: string, contextConvId: string) => {
  const peer = peerContexts.get(peerConvId);
  if (!peer?.dhPub) return null;
  const dhPriv = await getDhPrivateKey();
  const theirDhPub = decodeBase64Url(peer.dhPub);
  const friendKeyId = peer.friendKeyId ?? peer.directAddr ?? peerConvId;
  const pskBytes = await getFriendPsk(friendKeyId);
  const contextBytes = textEncoder.encode(`conv:${contextConvId}`);
  return deriveConversationKey(dhPriv, theirDhPub, pskBytes, contextBytes);
};

const getPeerVerifyKey = async (convId: string, authorDeviceId: string) => {
  const localDeviceId = getOrCreateDeviceId();
  if (authorDeviceId === localDeviceId) {
    return getIdentityPublicKey();
  }
  const peer = peerContexts.get(convId);
  if (!peer?.identityPub) return null;
  return decodeBase64Url(peer.identityPub);
};

const applyDecryptedBody = async (
  peerConvId: string,
  conv: Conversation | null,
  envelope: Envelope,
  body: unknown
) => {
  if (!body || typeof body !== "object") return;

  const [senderId, currentUserId] = await Promise.all([
    resolveSenderProfileId(peerConvId),
    resolveLocalUserId(),
  ]);

  if (isGroupEventPayload(body)) {
    await applyGroupEvent(body, senderId, currentUserId);
    return;
  }

  const typed = body as {
    type?: string;
    phase?: string;
    ownerId?: string;
    idx?: number;
    total?: number;
    chunkSize?: number;
    size?: number;
    mime?: string;
    b64?: string;
    kind?: string;
    convId?: string;
    cursorTs?: number;
    anchorMsgId?: string;
    msgId?: string;
    ts?: number;
    clientBatchId?: string;
  };

  if (typed.type === "media" && typed.phase === "chunk") {
    if (
      typeof typed.ownerId !== "string" ||
      typeof typed.b64 !== "string" ||
      typeof typed.mime !== "string" ||
      !Number.isInteger(typed.idx) ||
      !Number.isInteger(typed.total) ||
      !Number.isInteger(typed.chunkSize) ||
      !Number.isFinite(typed.size)
    ) {
      console.warn("[sync] invalid media chunk metadata");
      return;
    }
    try {
      const bytes = decodeBase64Url(typed.b64);
      await saveReceivedMessageMediaChunk({
        ownerId: typed.ownerId,
        idx: typed.idx as number,
        total: typed.total as number,
        chunkSize: typed.chunkSize as number,
        size: typed.size as number,
        mime: typed.mime,
        bytes,
      });
    } catch (error) {
      console.warn("[sync] media chunk rejected", error);
    }
    return;
  }

  if (typed.type === "rcpt" && typed.kind === "read_cursor") {
    if (!senderId || typeof typed.convId !== "string") return;
    const cursorTsCandidate = Number.isFinite(typed.cursorTs)
      ? Number(typed.cursorTs)
      : typed.ts ?? envelope.header.ts;
    if (!Number.isFinite(cursorTsCandidate)) return;
    const cursorTs = cursorTsCandidate;
    await putReadCursor({
      convId: typed.convId,
      actorId: senderId,
      cursorTs,
      anchorMsgId: typed.anchorMsgId ?? typed.msgId,
    });
    return;
  }

  if (typed.type === "msg") {
    await applyMessageEvent(
      conv,
      envelope,
      body as { type: "msg"; text: string; media?: unknown; clientBatchId?: string },
      senderId ?? currentUserId ?? envelope.header.authorDeviceId
    );
    return;
  }
  if (typed.type === "friend_req") {
    const authenticatedPeerIdentity = peerContexts.get(peerConvId)?.identityPub;
    const claimedIdentity = (body as FriendControlFrame).from?.identityPub;
    if (!authenticatedPeerIdentity || claimedIdentity !== authenticatedPeerIdentity) {
      console.warn("[friend] dropped control frame: envelope identity mismatch", { peerConvId });
      return;
    }
    await handleIncomingFriendFrame(
      { ...(body as FriendControlFrame), ts: typed.ts ?? envelope.header.ts },
      { trustedEnvelope: true }
    );
    return;
  }
  if (typed.type === "friend_accept" || typed.type === "friend_decline") {
    const authenticatedPeerIdentity = peerContexts.get(peerConvId)?.identityPub;
    const claimedIdentity = (body as FriendControlFrame).from?.identityPub;
    if (!authenticatedPeerIdentity || claimedIdentity !== authenticatedPeerIdentity) {
      console.warn("[friend] dropped control frame: envelope identity mismatch", { peerConvId });
      return;
    }
    await handleIncomingFriendFrame(
      { ...(body as FriendControlFrame), ts: typed.ts ?? envelope.header.ts },
      { trustedEnvelope: true }
    );
    return;
  }
  if (typed.type === "contact") {
    await applyContactEvent(body as { type: "contact"; profile: Partial<UserProfile> });
    return;
  }
  if (typed.type === "conv") {
    await applyConversationEvent(body as { type: "conv"; conv: Conversation });
    return;
  }
  if (typed.kind === "ROLE_CHANGE") {
    const roleEvent = body as RoleChangeEvent;
    if (canUseRoleEvents(getPeerCaps(peerConvId))) {
      await updateFromRoleEvent(roleEvent);
      return;
    }
    if (!hasKnownPeerCaps(peerConvId)) {
      deferRoleChangeEvent(peerConvId, envelope.header.eventId, roleEvent);
      console.info("[sync] role change deferred: peer caps unconfirmed", {
        convId: peerConvId,
        eventId: envelope.header.eventId,
      });
      return;
    }
    if (!canUseRoleEvents(getPeerCaps(peerConvId))) {
      console.warn("[sync] role change dropped: peer capability missing", {
        convId: peerConvId,
        capsState: "known_unsupported",
      });
      return;
    }
  }
};

const applyMessageEvent = async (
  conv: Conversation | null,
  envelope: Envelope,
  body: { type: "msg"; text: string; media?: unknown; clientBatchId?: string },
  senderId: string
) => {
  if (!conv) return;
  const lastMessage = typeof body.text === "string" ? body.text : "";
  const updated: Conversation = {
    ...conv,
    lastMessage,
    lastTs: envelope.header.ts,
  };
  const media = body.media === undefined
    ? undefined
    : parseIncomingMediaRef(body.media, envelope.header.eventId) ?? undefined;
  const message: Message = {
    id: envelope.header.eventId,
    convId: conv.id,
    senderId,
    text: lastMessage,
    ts: envelope.header.ts,
    media,
    clientBatchId: body.clientBatchId,
  };
  await saveMessage(message);
  await saveConversation(updated);
};

const applyContactEvent = async (body: { type: "contact"; profile: Partial<UserProfile> }) => {
  const profile = body.profile;
  if (!profile || !profile.friendId) return;
  const profiles = await listProfiles();
  const existing = profiles.find((item) => item.friendId === profile.friendId) || null;

  if (existing?.identityPub && existing.dhPub && profile.identityPub && profile.dhPub) {
    const tofu = applyTOFU(
      { identityPub: existing.identityPub, dhPub: existing.dhPub },
      { identityPub: profile.identityPub, dhPub: profile.dhPub }
    );
    if (!tofu.ok) {
      await saveProfile({
        ...existing,
        trust: {
          pinnedAt: existing.trust?.pinnedAt ?? Date.now(),
          status: "blocked",
          reason: tofu.reason,
        },
        friendStatus: "blocked",
        updatedAt: Date.now(),
      });
      return;
    }
  }

  const now = Date.now();
  const sanitizedHints = sanitizeRoutingHints(
    profile.routingHints ?? existing?.routingHints
  );
  const next: UserProfile = {
    id: existing?.id ?? createId(),
    friendId: profile.friendId,
    displayName: profile.displayName ?? existing?.displayName ?? "Friend",
    status: profile.status ?? existing?.status ?? "",
    theme: (profile.theme as UserProfile["theme"]) ?? existing?.theme ?? "dark",
    kind: "friend",
    friendStatus: profile.friendStatus ?? existing?.friendStatus ?? "normal",
    isFavorite: profile.isFavorite ?? existing?.isFavorite ?? false,
    identityPub: profile.identityPub ?? existing?.identityPub,
    dhPub: profile.dhPub ?? existing?.dhPub,
    routingHints: sanitizedHints,
    primaryDeviceId:
      profile.primaryDeviceId ??
      (profile.routingHints as UserProfile["routingHints"] | undefined)?.deviceId ??
      existing?.primaryDeviceId,
    trust: existing?.trust ?? { pinnedAt: now, status: "trusted" },
    verification: existing?.verification,
    reachability: existing?.reachability,
    profileVcard: profile.profileVcard ?? existing?.profileVcard,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  await saveProfile(next);
};

const applyConversationEvent = async (body: { type: "conv"; conv: Conversation }) => {
  const incoming = body.conv;
  if (!incoming?.id) return;
  const existing = (await listConversations()).find((item) => item.id === incoming.id) || null;
  const merged: Conversation = {
    id: incoming.id,
    type: incoming.type ?? existing?.type ?? "direct",
    name: incoming.name ?? existing?.name ?? "Chat",
    pinned: incoming.pinned ?? existing?.pinned ?? false,
    unread: incoming.unread ?? existing?.unread ?? 0,
    hidden: incoming.hidden ?? existing?.hidden ?? false,
    muted: incoming.muted ?? existing?.muted ?? false,
    blocked: incoming.blocked ?? existing?.blocked ?? false,
    pendingAcceptance: incoming.pendingAcceptance ?? existing?.pendingAcceptance,
    pendingOutgoing: incoming.pendingOutgoing ?? existing?.pendingOutgoing,
    pendingFriendResponse: incoming.pendingFriendResponse ?? existing?.pendingFriendResponse,
    lastTs: incoming.lastTs ?? existing?.lastTs ?? Date.now(),
    lastMessage: incoming.lastMessage ?? existing?.lastMessage ?? "",
    participants: incoming.participants ?? existing?.participants ?? [],
    sharedAvatarRef: incoming.sharedAvatarRef ?? existing?.sharedAvatarRef,
  };
  await saveConversation(merged);
};

const isEnvelopeLike = (value: unknown): value is Envelope => {
  if (!value || typeof value !== "object") return false;
  const envelope = value as Partial<Envelope>;
  const header = envelope.header as Partial<EnvelopeHeader> | undefined;
  if (!header || typeof header !== "object") return false;
  return (
    typeof header.convId === "string" &&
    typeof header.eventId === "string" &&
    typeof header.authorDeviceId === "string" &&
    Number.isFinite(header.ts) &&
    Number.isFinite(header.lamport) &&
    typeof envelope.ciphertext === "string" &&
    typeof envelope.nonce === "string" &&
    typeof envelope.sig === "string"
  );
};

const isEphemeralMediaChunk = (body: unknown) => {
  if (!body || typeof body !== "object") return false;
  const value = body as { type?: unknown; phase?: unknown };
  return value.type === "media" && value.phase === "chunk";
};

const persistAppliedEnvelope = async (envelope: Envelope, body: unknown) => {
  if (isEphemeralMediaChunk(body)) return;
  const eventHash = await computeEnvelopeHash(envelope);
  const expectedPrev = await getLastEventHash(envelope.header.convId);
  const mismatch = envelope.header.prev !== expectedPrev;
  if (mismatch) console.warn("[sync] event chain mismatch");
  await saveEvent({
    eventId: envelope.header.eventId,
    convId: envelope.header.convId,
    authorDeviceId: envelope.header.authorDeviceId,
    lamport: envelope.header.lamport,
    ts: envelope.header.ts,
    envelopeJson: JSON.stringify(envelope),
    prevHash: envelope.header.prev,
    eventHash,
    conflict: mismatch || undefined,
  });
};

const ensurePeerContextFromConversation = async (convId: string) => {
  const existing = peerContexts.get(convId);
  if (existing?.identityPub && existing?.dhPub) return true;

  const [conversations, profiles, localUserId] = await Promise.all([
    listConversations(),
    listProfiles(),
    resolveLocalUserId(),
  ]);
  if (!localUserId) return false;

  const conv = conversations.find((item) => item.id === convId) ?? null;
  if (!conv) return false;
  const isDirect =
    !(conv.type === "group" || conv.participants.length > 2) &&
    conv.participants.length === 2;
  if (!isDirect) return false;

  const partnerId = conv.participants.find((id) => id && id !== localUserId) ?? null;
  if (!partnerId) return false;
  const partner =
    profiles.find((profile) => profile.id === partnerId && profile.kind === "friend") ?? null;
  if (!partner?.identityPub || !partner.dhPub) return false;

  peerContexts.set(conv.id, {
    ...existing,
    kind: "friend",
    friendKeyId: existing?.friendKeyId ?? partner.friendId ?? partner.id,
    identityPub: existing?.identityPub ?? partner.identityPub,
    dhPub: existing?.dhPub ?? partner.dhPub,
    onionAddr: existing?.onionAddr ?? partner.routingHints?.onionAddr,
    peerDeviceId:
      existing?.peerDeviceId ??
      partner.routingHints?.deviceId ??
      partner.primaryDeviceId ??
      partner.deviceId,
  });
  return true;
};

const resolveFallbackConversationId = async (envelope: Envelope) => {
  const [conversations, profiles, localUserId] = await Promise.all([
    listConversations(),
    listProfiles(),
    resolveLocalUserId(),
  ]);
  if (!localUserId) return null;

  const directCandidates = conversations.filter((conv) => {
    const isDirect =
      !(conv.type === "group" || conv.participants.length > 2) &&
      conv.participants.length === 2;
    return isDirect && conv.participants.includes(localUserId);
  });

  for (const conv of directCandidates) {
    const partnerId = conv.participants.find((id) => id && id !== localUserId) ?? null;
    if (!partnerId) continue;
    const partner =
      profiles.find((profile) => profile.id === partnerId && profile.kind === "friend") ?? null;
    if (!partner?.identityPub) continue;
    try {
      const verifyKey = decodeBase64Url(partner.identityPub);
      const verified = await verifyEnvelopeSignature(envelope, verifyKey);
      if (verified) {
        return conv.id;
      }
    } catch {
      // keep scanning candidates
    }
  }

  return null;
};

export const ingestIncomingEnvelopeText = async (payloadText: string) => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payloadText);
  } catch {
    return false;
  }
  if (!isEnvelopeLike(parsed)) return false;

  const envelope = parsed as Envelope;
  const convId = envelope.header.convId;
  if (!convId) return false;
  let targetConvId = convId;
  let hasPeer = await ensurePeerContextFromConversation(targetConvId);
  if (!hasPeer) {
    const fallbackConvId = await resolveFallbackConversationId(envelope);
    if (fallbackConvId) {
      targetConvId = fallbackConvId;
      hasPeer = await ensurePeerContextFromConversation(targetConvId);
      if (hasPeer && fallbackConvId !== convId) {
        console.info("[sync] incoming envelope mapped to local conversation", {
          incomingConvId: convId,
          targetConvId: fallbackConvId,
          eventId: envelope.header.eventId,
        });
      }
    }
  }
  if (!hasPeer) {
    console.warn("[sync] incoming envelope dropped: peer context unavailable", { convId });
    return false;
  }

  const event: EnvelopeEvent = {
    eventId: envelope.header.eventId,
    convId: envelope.header.convId,
    authorDeviceId: envelope.header.authorDeviceId,
    lamport: envelope.header.lamport,
    ts: envelope.header.ts,
    envelopeJson: payloadText,
  };
  await applyEnvelopeEvents(targetConvId, [event]);
  return true;
};

const applyEnvelopeEvents = async (convKeyId: string, events: EnvelopeEvent[]) => {
  const unique = new Map<string, EnvelopeEvent>();
  for (const event of events) {
    if (!event?.eventId) continue;
    unique.set(event.eventId, event);
  }

  const sorted = sortEventsDeterministic(Array.from(unique.values()));
  const convs = await listConversations();
  const conv = convs.find((item) => item.id === convKeyId) || null;

  for (const event of sorted) {
    if (!Number.isFinite(event.lamport)) {
      console.warn("[sync] invalid lamport", { convId: event.convId });
      continue;
    }
    const seenLamport = getLamportSeen(event.convId, event.authorDeviceId);
    if (event.lamport <= seenLamport) {
      console.warn("[sync] replay event dropped", {
        convId: event.convId,
        authorDeviceId: event.authorDeviceId,
        lamport: event.lamport,
      });
      continue;
    }
    const existing = await getEvent(event.eventId);
    if (existing) {
      updateLamportSeen(event.convId, event.authorDeviceId, event.lamport);
      continue;
    }

    let envelope: Envelope;
    try {
      envelope = JSON.parse(event.envelopeJson) as Envelope;
    } catch (error) {
      console.warn("[sync] invalid envelope json", error);
      continue;
    }

    if (!envelope?.header || envelope.header.eventId !== event.eventId) {
      console.warn("[sync] invalid envelope header", envelope?.header);
      continue;
    }

    try {
      const verifyKey = await getPeerVerifyKey(convKeyId, envelope.header.authorDeviceId);
      if (!verifyKey) {
        console.warn("[sync] missing verify key");
        continue;
      }

      const verified = await verifyEnvelopeSignature(envelope, verifyKey);
      if (!verified) {
        console.warn("[sync] signature invalid");
        continue;
      }

      const rk = envelope.header.rk;
      const peerRatchetVersion = getPeerRatchetVersion(
        getPeerCapsForEvent(convKeyId, event.convId)
      );
      if (rk && rk.v === 2 && Number.isFinite(rk.i) && typeof rk.dh === "string") {
        if (peerRatchetVersion < 2) {
          console.warn("[sync] rk v2 received with caps mismatch; trying decrypt anyway", {
            convId: event.convId,
            eventId: event.eventId,
          });
        }
        logDecrypt("path", { convId: event.convId, eventId: event.eventId, mode: "v2" });
        const ratchetBaseKey = await resolveRatchetBaseKey(convKeyId, envelope.header.convId);
        if (!ratchetBaseKey) {
          console.warn("[sync] missing conversation key");
          continue;
        }
        const recv = await tryRecvDhKey(envelope.header.convId, ratchetBaseKey, rk);
        if ("deferred" in recv) {
          logDecrypt("deferred", { convId: event.convId, eventId: event.eventId, mode: "v2" });
          continue;
        }
        const body = await decryptEnvelope<{ type: string }>(
          recv.msgKey,
          envelope,
          verifyKey
        );

        logDecrypt("commit", { convId: event.convId, eventId: event.eventId, mode: "v2" });
        await recv.commit();
        await persistAppliedEnvelope(envelope, body);
        updateLamportSeen(event.convId, event.authorDeviceId, event.lamport);
        await applyDecryptedBody(convKeyId, conv, envelope, body);
        continue;
      }

      if (rk && rk.v === 1 && Number.isFinite(rk.i)) {
        if (peerRatchetVersion < 1) {
          console.warn("[sync] rk v1 received with caps mismatch; trying decrypt anyway", {
            convId: event.convId,
            eventId: event.eventId,
          });
        }
        logDecrypt("path", { convId: event.convId, eventId: event.eventId, mode: "v1" });
        const ratchetBaseKey = await resolveRatchetBaseKey(convKeyId, envelope.header.convId);
        if (!ratchetBaseKey) {
          console.warn("[sync] missing conversation key");
          continue;
        }
        const recv = await tryRecvKey(envelope.header.convId, ratchetBaseKey, rk.i);
        if ("deferred" in recv) {
          logDecrypt("deferred", { convId: event.convId, eventId: event.eventId, mode: "v1" });
          continue;
        }
        const body = await decryptEnvelope<{ type: string }>(
          recv.msgKey,
          envelope,
          verifyKey
        );

        logDecrypt("ok", { convId: event.convId, eventId: event.eventId, mode: "v1" });
        await persistAppliedEnvelope(envelope, body);
        updateLamportSeen(event.convId, event.authorDeviceId, event.lamport);
        await applyDecryptedBody(convKeyId, conv, envelope, body);
        continue;
      }

      const conversationKey = await resolveLegacyKey(convKeyId);
      if (!conversationKey) {
        console.warn("[sync] missing conversation key");
        continue;
      }
      logDecrypt("path", { convId: event.convId, eventId: event.eventId, mode: "legacy" });
      const body = await decryptEnvelope<{ type: string }>(
        conversationKey,
        envelope,
        verifyKey
      );

      logDecrypt("ok", { convId: event.convId, eventId: event.eventId, mode: "legacy" });
      await persistAppliedEnvelope(envelope, body);
      updateLamportSeen(event.convId, event.authorDeviceId, event.lamport);
      await applyDecryptedBody(convKeyId, conv, envelope, body);
    } catch (error) {
      console.warn("[sync] decrypt/apply failed", error);
    }
  }
};

const sendFrame = async (convId: string, frame: Frame) => {
  try {
    const bytes = toBytes(frame);
    if (syncTransportOverride) {
      await syncTransportOverride.send(convId, bytes);
      return;
    }
    await sendToConversation(convId, bytes);
  } catch (error) {
    console.warn("[sync] send failed", error);
  }
};

const canUseFlowControl = (convId: string) => getPeerCaps(convId).sync.v >= 2;

const createSyncResponseFrames = (
  base: Omit<SyncResFrame, "events" | "next" | "flow">,
  events: EnvelopeEvent[],
  next: Record<string, number>,
  flowControl: boolean
): SyncResFrame[] => {
  if (!flowControl || events.length <= MAX_SYNC_CHUNK_EVENTS) {
    return [{ ...base, events, next }];
  }

  const sessionId = createId();
  const chunks: EnvelopeEvent[][] = [];
  let current: EnvelopeEvent[] = [];

  for (const event of events) {
    const candidate = [...current, event];
    const candidateFrame: SyncResFrame = {
      ...base,
      events: candidate,
      next: {},
      flow: { sessionId, chunkIndex: chunks.length, totalChunks: 1, final: false },
    };
    const candidateTooLarge =
      current.length > 0 &&
      (candidate.length > MAX_SYNC_CHUNK_EVENTS ||
        toBytes(candidateFrame).byteLength > MAX_SYNC_CHUNK_BYTES);
    if (candidateTooLarge) {
      chunks.push(current);
      current = [event];
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) chunks.push(current);

  const totalChunks = chunks.length;
  return chunks.map((chunk, chunkIndex) => {
    const final = chunkIndex === totalChunks - 1;
    return {
      ...base,
      events: chunk,
      next: final ? next : {},
      flow: { sessionId, chunkIndex, totalChunks, final },
    };
  });
};

const clearFlowSession = (sessionId: string) => {
  const session = outgoingFlowSessions.get(sessionId);
  if (!session) return;
  session.inFlight.forEach((entry) => clearTimeout(entry.timer));
  outgoingFlowSessions.delete(sessionId);
};

const scheduleFlowRetry = (sessionId: string, chunkIndex: number) => {
  const session = outgoingFlowSessions.get(sessionId);
  if (!session) return;
  const entry = session.inFlight.get(chunkIndex);
  if (!entry) return;
  entry.timer = setTimeout(() => {
    const current = outgoingFlowSessions.get(sessionId);
    const currentEntry = current?.inFlight.get(chunkIndex);
    if (!current || !currentEntry) return;
    if (currentEntry.attempts >= SYNC_FLOW_MAX_RETRIES) {
      clearFlowSession(sessionId);
      return;
    }
    const frame = current.frames[chunkIndex];
    if (!frame) {
      current.inFlight.delete(chunkIndex);
      pumpFlowSession(sessionId);
      return;
    }
    currentEntry.attempts += 1;
    void sendFrame(current.convId, frame).then(() => {
      scheduleFlowRetry(sessionId, chunkIndex);
    });
  }, SYNC_FLOW_ACK_TIMEOUT_MS);
};

const pumpFlowSession = (sessionId: string) => {
  const session = outgoingFlowSessions.get(sessionId);
  if (!session) return;
  while (
    session.nextToSend < session.frames.length &&
    session.inFlight.size < SYNC_FLOW_WINDOW
  ) {
    const chunkIndex = session.nextToSend;
    session.nextToSend += 1;
    const timer = setTimeout(() => undefined, 0);
    clearTimeout(timer);
    session.inFlight.set(chunkIndex, { attempts: 1, timer });
    const frame = session.frames[chunkIndex];
    if (!frame) {
      session.inFlight.delete(chunkIndex);
      continue;
    }
    void sendFrame(session.convId, frame).then(() => {
      scheduleFlowRetry(sessionId, chunkIndex);
    });
  }
  if (session.nextToSend >= session.frames.length && session.inFlight.size === 0) {
    outgoingFlowSessions.delete(sessionId);
  }
};

const sendSyncResponseFrames = async (convId: string, frames: SyncResFrame[]) => {
  if (frames.length === 0) return;
  if (frames.length === 1 || !frames[0].flow) {
    await sendFrame(convId, frames[0]);
    return;
  }
  const sessionId = frames[0].flow.sessionId;
  clearFlowSession(sessionId);
  outgoingFlowSessions.set(sessionId, {
    convId,
    frames,
    nextToSend: 0,
    inFlight: new Map(),
  });
  pumpFlowSession(sessionId);
};

const handleSyncFlowAck = (frame: SyncFlowAckFrame) => {
  const session = outgoingFlowSessions.get(frame.sessionId);
  if (!session) return;
  const entry = session.inFlight.get(frame.chunkIndex);
  if (entry) clearTimeout(entry.timer);
  session.inFlight.delete(frame.chunkIndex);
  pumpFlowSession(frame.sessionId);
};

const handleSyncReq = async (convId: string, frame: SyncReqFrame) => {
  const allowed = await isDeviceSyncAllowed(convId, "sync_req");
  if (!allowed) return;

  const scopeConvId =
    frame.scope === "contacts"
      ? contactsLogId(frame.convId ?? convId)
      : frame.scope === "conversations"
        ? conversationsLogId(frame.convId ?? convId)
        : frame.scope === "global"
          ? globalLogId(frame.convId ?? convId)
          : frame.convId ?? convId;
  const all = await listEventsByConv(scopeConvId);
  const since = frame.since ?? {};
  const events = all.filter((event) => {
    const lastSeen = since[event.authorDeviceId] ?? 0;
    return event.lamport > lastSeen;
  });
  const next = buildNextMap(all as EnvelopeEvent[]);
  const responseFrames = createSyncResponseFrames(
    {
      type: "SYNC_RES",
      scope: frame.scope,
      convId: frame.convId,
    },
    sortEventsDeterministic(events.map((event) => toEnvelopeEvent(event as EnvelopeEvent))),
    next,
    canUseFlowControl(convId)
  );
  await sendSyncResponseFrames(convId, responseFrames);
};

const handleSyncRes = async (convId: string, frame: SyncResFrame) => {
  const allowed = await isDeviceSyncAllowed(convId, "sync_res");
  if (!allowed) return;

  const targetConvId =
    frame.scope === "contacts"
      ? contactsLogId(frame.convId ?? convId)
      : frame.scope === "conversations"
        ? conversationsLogId(frame.convId ?? convId)
        : frame.scope === "global"
          ? globalLogId(frame.convId ?? convId)
          : frame.convId ?? convId;
  const events = Array.isArray(frame.events) ? frame.events : [];
  await applyEnvelopeEvents(convId, events);
  if (frame.flow) {
    await sendFrame(convId, {
      type: "SYNC_FLOW_ACK",
      sessionId: frame.flow.sessionId,
      chunkIndex: frame.flow.chunkIndex,
      receivedEvents: events.length,
    });
  }
  if (frame.flow && !frame.flow.final) return;
  Object.entries(frame.next ?? {}).forEach(([deviceId, lamport]) => {
    if (!Number.isFinite(lamport)) return;
    updateLamportSeen(targetConvId, deviceId, lamport);
  });
};

const applyVerification = async (identityPub: string, deviceId?: string, profile?: HelloFrame["profile"]) => {
  const friend = await resolveFriendByIdentity(identityPub);
  if (!friend) return;
  if (friend.identityPub && friend.identityPub !== identityPub) {
    await saveProfile({
      ...friend,
      verification: {
        status: "key_changed",
        safetyNumber: friend.verification?.safetyNumber,
        verifiedAt: friend.verification?.verifiedAt,
      },
      friendStatus: "blocked",
      updatedAt: Date.now(),
    });
    return;
  }
  const localIdentityPub = encodeBase64Url(await getIdentityPublicKey());
  const safetyNumber = await computeSafetyNumber(localIdentityPub, identityPub);
  const now = Date.now();
  await saveProfile({
    ...friend,
    identityPub,
    primaryDeviceId: deviceId ?? friend.primaryDeviceId,
    routingHints: sanitizeRoutingHints({
      onionAddr: friend.routingHints?.onionAddr,
      deviceId: deviceId ?? friend.routingHints?.deviceId,
      inboxWriteToken: friend.routingHints?.inboxWriteToken,
    }),
    verification: {
      status: "verified",
      safetyNumber,
      verifiedAt: now,
    },
    reachability: deviceId
      ? { status: "ok", lastAttemptAt: now }
      : friend.reachability ?? { status: "unreachable", lastError: "Missing deviceId" },
    profileVcard: profile
      ? {
          displayName: profile.displayName,
          status: profile.status,
          avatarRef: profile.avatarRef,
          updatedAt: now,
        }
      : friend.profileVcard,
    updatedAt: now,
  });
};

const handleHello = async (convId: string, frame: HelloFrame) => {
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(frame.nonce)) {
    console.warn("[sync] invalid HELLO nonce", { convId });
    return;
  }
  const pinnedPeerIdentity = peerContexts.get(convId)?.identityPub;
  if (pinnedPeerIdentity && pinnedPeerIdentity !== frame.identityPub) {
    console.warn("[sync] dropped HELLO with pinned identity mismatch", { convId });
    return;
  }
  const payload = {
    type: "HELLO",
    identityPub: frame.identityPub,
    deviceId: frame.deviceId,
    nonce: frame.nonce,
    caps: frame.caps ?? null,
  };
  const legacyPayload = {
    type: "HELLO",
    identityPub: frame.identityPub,
    deviceId: frame.deviceId,
    nonce: frame.nonce,
  };
  const ok = await verifyHandshakeCompat(
    payload,
    legacyPayload,
    frame.sig,
    frame.identityPub,
    Boolean(frame.caps)
  );
  if (!ok) {
    console.warn("[sync] invalid HELLO signature", { convId });
    return;
  }
  const now = Date.now();
  for (const [key, seenAt] of seenHelloNonces) {
    if (now - seenAt > HANDSHAKE_NONCE_TTL_MS) seenHelloNonces.delete(key);
  }
  const replayKey = `${frame.identityPub}:${frame.nonce}`;
  if (seenHelloNonces.has(replayKey)) {
    console.warn("[sync] dropped replayed HELLO", { convId });
    return;
  }
  seenHelloNonces.set(replayKey, now);
  if (seenHelloNonces.size > MAX_SEEN_HELLO_NONCES) {
    const oldestKey = seenHelloNonces.keys().next().value as string | undefined;
    if (oldestKey) seenHelloNonces.delete(oldestKey);
  }
  const peerCaps = normalizePeerCaps(frame.caps);
  const existing = peerContexts.get(convId) ?? {};
  peerContexts.set(convId, {
    ...existing,
    identityPub: frame.identityPub,
    peerDeviceId: frame.deviceId,
    peerCaps,
  });
  logPeerCaps(convId, peerCaps);
  await flushDeferredRoleEvents(convId);
  await applyVerification(frame.identityPub, frame.deviceId, frame.profile);
  const ackPayload = {
    type: "ACK",
    identityPub: encodeBase64Url(await getIdentityPublicKey()),
    deviceId: getOrCreateDeviceId(),
    nonce: frame.nonce,
    caps: LOCAL_CAPS,
  } as const;
  const sig = await signHandshake(ackPayload);
  await sendFrame(convId, { ...ackPayload, sig });
};

const handleAck = async (convId: string, frame: AckFrame) => {
  const pending = pendingHelloNonces.get(convId);
  if (
    !pending ||
    pending.nonce !== frame.nonce ||
    Date.now() - pending.createdAt > HANDSHAKE_NONCE_TTL_MS
  ) {
    console.warn("[sync] dropped unsolicited or stale ACK", { convId });
    return;
  }
  const pinnedPeerIdentity = peerContexts.get(convId)?.identityPub;
  if (pinnedPeerIdentity && pinnedPeerIdentity !== frame.identityPub) {
    console.warn("[sync] dropped ACK with pinned identity mismatch", { convId });
    return;
  }
  const payload = {
    type: "ACK",
    identityPub: frame.identityPub,
    deviceId: frame.deviceId,
    nonce: frame.nonce,
    caps: frame.caps ?? null,
  };
  const legacyPayload = {
    type: "ACK",
    identityPub: frame.identityPub,
    deviceId: frame.deviceId,
    nonce: frame.nonce,
  };
  const ok = await verifyHandshakeCompat(
    payload,
    legacyPayload,
    frame.sig,
    frame.identityPub,
    Boolean(frame.caps)
  );
  if (!ok) {
    console.warn("[sync] invalid ACK signature", { convId });
    return;
  }
  pendingHelloNonces.delete(convId);
  const peerCaps = normalizePeerCaps(frame.caps);
  const existing = peerContexts.get(convId) ?? {};
  peerContexts.set(convId, {
    ...existing,
    identityPub: frame.identityPub,
    peerDeviceId: frame.deviceId,
    peerCaps,
  });
  logPeerCaps(convId, peerCaps);
  await flushDeferredRoleEvents(convId);
  await applyVerification(frame.identityPub, frame.deviceId);
};

const handleIncoming = async (convId: string, bytes: Uint8Array) => {
  const frame = tryParseFrame(bytes);
  if (!frame) return;
  if (frame.type === "HELLO") {
    await handleHello(convId, frame);
    return;
  }
  if (frame.type === "ACK") {
    await handleAck(convId, frame);
    return;
  }
  if (frame.type === "SYNC_REQ") {
    await handleSyncReq(convId, frame);
    return;
  }
  if (frame.type === "SYNC_RES") {
    await handleSyncRes(convId, frame);
    return;
  }
  if (frame.type === "SYNC_FLOW_ACK") {
    handleSyncFlowAck(frame);
  }
};

export const handleIncomingSyncFrame = handleIncoming;

export const setSyncTransportOverride = (transport: SyncTransportOverride | null) => {
  syncTransportOverride = transport;
  return () => {
    if (syncTransportOverride === transport) {
      syncTransportOverride = null;
    }
  };
};

export const connectConversation = async (convId: string, peerHint: PeerContext) => {
  peerContexts.set(convId, peerHint);
  const allowed = await isDeviceSyncAllowed(convId, "connect");
  if (!allowed) return;
  if (!convSubscriptions.has(convId)) {
    const unsubscribe = onConversationMessage(convId, (bytes) => {
      void handleIncoming(convId, bytes);
    });
    convSubscriptions.set(convId, unsubscribe);
  }
  await connectTransport(convId, peerHint);
  const identityPub = await getIdentityPublicKey();
  const helloPayload = {
    type: "HELLO",
    deviceId: getOrCreateDeviceId(),
    identityPub: encodeBase64Url(identityPub),
    nonce: createNonce(),
    caps: LOCAL_CAPS,
  } as const;
  pendingHelloNonces.set(convId, { nonce: helloPayload.nonce, createdAt: Date.now() });
  const sig = await signHandshake(helloPayload);
  const localUserId = await resolveLocalUserId();
  let profile: HelloFrame["profile"] | undefined;
  if (localUserId) {
    const profiles = await listProfiles();
    const me = profiles.find((item) => item.id === localUserId) || null;
    if (me) {
      profile = { displayName: me.displayName, status: me.status, avatarRef: me.avatarRef };
    }
  }
  const hello: HelloFrame = { ...helloPayload, sig, profile };
  await sendFrame(convId, hello);
  await syncConversation(convId);
  await syncGlobal(convId);
};

export const disconnectConversation = async (convId: string) => {
  pendingHelloNonces.delete(convId);
  const unsubscribe = convSubscriptions.get(convId);
  if (unsubscribe) {
    unsubscribe();
    convSubscriptions.delete(convId);
  }
  await disconnectTransport(convId);
};

export const syncConversation = async (convId: string) => {
  const allowed = await isDeviceSyncAllowed(convId, "sync_conversation");
  if (!allowed) return;
  const since = getSinceMap(convId);
  const frame: SyncReqFrame = {
    type: "SYNC_REQ",
    scope: "conv",
    convId,
    since,
  };
  await sendFrame(convId, frame);
};

export const syncGlobal = async (convId: string) => {
  const allowed = await isDeviceSyncAllowed(convId, "sync_global");
  if (!allowed) return;
  const since = getSinceMap(globalLogId(convId));
  const frame: SyncReqFrame = {
    type: "SYNC_REQ",
    scope: "global",
    convId,
    since,
  };
  await sendFrame(convId, frame);
};

const buildRoleChangeEvent = async (
  convId: string,
  payload: RoleChangeEvent,
  identityPriv: Uint8Array
) => {
  const logId = globalLogId(convId);
  const ratchetBaseKey = await resolveRatchetBaseKey(convId, logId);
  const legacyKey = await resolveLegacyKey(convId);
  if (!ratchetBaseKey || !legacyKey) return null;
  const deviceId = getOrCreateDeviceId();
  let nextLamport = perAuthorLamportSeen.get(deviceId) ?? 0;
  nextLamport += 1;

  const header: EnvelopeHeader = {
    v: 1 as const,
    eventId: createId(),
    convId: logId,
    ts: payload.ts,
    lamport: nextLamport,
    authorDeviceId: deviceId,
  };
  header.prev = await getLastEventHash(logId);
  const keyForEnvelope = await resolveSendEnvelopeKey(convId, logId, ratchetBaseKey, legacyKey);
  if (keyForEnvelope.headerRk) header.rk = keyForEnvelope.headerRk;

  const envelope = await encryptEnvelope(keyForEnvelope.msgKey, header, payload, identityPriv);
  const eventHash = await computeEnvelopeHash(envelope);
  const event: EnvelopeEvent = {
    eventId: header.eventId,
    convId: logId,
    authorDeviceId: header.authorDeviceId,
    lamport: header.lamport,
    ts: header.ts,
    envelopeJson: JSON.stringify(envelope),
  };
  await saveEvent({
    ...event,
    prevHash: header.prev,
    eventHash,
  });
  updateLamportSeen(logId, header.authorDeviceId, header.lamport);
  return event;
};

export const emitRoleChangeEvent = async (payload: RoleChangeEvent) => {
  const identityPriv = await getIdentityPrivateKey();
  const activeConvs = Array.from(peerContexts.keys());
  for (const convId of activeConvs) {
    try {
      const capsKnown = hasKnownPeerCaps(convId);
      if (capsKnown && !canUseRoleEvents(getPeerCaps(convId))) continue;
      const event = await buildRoleChangeEvent(convId, payload, identityPriv);
      if (!event) continue;
      const frame: SyncResFrame = {
        type: "SYNC_RES",
        scope: "global",
        convId,
        events: [event],
        next: buildNextMap([event]),
      };
      await sendFrame(convId, frame);
    } catch (error) {
      console.warn("[sync] role change emit failed", error);
    }
  }
};

const buildContactEvents = async (convId: string) => {
  const peer = peerContexts.get(convId);
  if (!peer?.friendKeyId || !peer.dhPub) return [];
  const logId = contactsLogId(convId);
  const ratchetBaseKey = await resolveRatchetBaseKey(convId, logId);
  const legacyKey = await resolveLegacyKey(convId);
  if (!ratchetBaseKey || !legacyKey) return [];
  const identityPriv = await getIdentityPrivateKey();
  const deviceId = getOrCreateDeviceId();
  let nextLamport = perAuthorLamportSeen.get(deviceId) ?? 0;

  const profiles = await listProfiles();
  const contacts = profiles.filter((profile) => profile.kind === "friend");
  const events: EnvelopeEvent[] = [];

  let prevHash = await getLastEventHash(logId);
  for (const contact of contacts) {
    nextLamport += 1;
    const header: EnvelopeHeader = {
      v: 1 as const,
      eventId: createId(),
      convId: logId,
      ts: Date.now(),
      lamport: nextLamport,
      authorDeviceId: deviceId,
    };
    header.prev = prevHash;
    const keyForEnvelope = await resolveSendEnvelopeKey(convId, logId, ratchetBaseKey, legacyKey);
    if (keyForEnvelope.headerRk) header.rk = keyForEnvelope.headerRk;
    const envelope = await encryptEnvelope(
      keyForEnvelope.msgKey,
      header,
      {
        type: "contact",
        profile: {
          friendId: contact.friendId,
          displayName: contact.displayName,
          status: contact.status,
          theme: contact.theme,
          friendStatus: contact.friendStatus,
          isFavorite: contact.isFavorite,
          identityPub: contact.identityPub,
          dhPub: contact.dhPub,
          routingHints: sanitizeRoutingHints(contact.routingHints),
          primaryDeviceId: contact.primaryDeviceId,
          profileVcard: contact.profileVcard,
        },
      },
      identityPriv
    );
    const eventHash = await computeEnvelopeHash(envelope);
    events.push({
      eventId: header.eventId,
      convId: logId,
      authorDeviceId: header.authorDeviceId,
      lamport: header.lamport,
      ts: header.ts,
      envelopeJson: JSON.stringify(envelope),
    });
    prevHash = eventHash;
    updateLamportSeen(logId, header.authorDeviceId, header.lamport);
    await saveEvent({
      eventId: header.eventId,
      convId: logId,
      authorDeviceId: header.authorDeviceId,
      lamport: header.lamport,
      ts: header.ts,
      envelopeJson: JSON.stringify(envelope),
      prevHash: header.prev,
      eventHash,
    });
  }
  return events;
};

const buildConversationEvents = async (convId: string) => {
  const peer = peerContexts.get(convId);
  if (!peer?.friendKeyId || !peer.dhPub) return [];
  const logId = conversationsLogId(convId);
  const ratchetBaseKey = await resolveRatchetBaseKey(convId, logId);
  const legacyKey = await resolveLegacyKey(convId);
  if (!ratchetBaseKey || !legacyKey) return [];
  const identityPriv = await getIdentityPrivateKey();
  const deviceId = getOrCreateDeviceId();
  let nextLamport = perAuthorLamportSeen.get(deviceId) ?? 0;

  const conversations = await listConversations();
  const events: EnvelopeEvent[] = [];

  let prevHash = await getLastEventHash(logId);
  for (const conversation of conversations) {
    nextLamport += 1;
    const header: EnvelopeHeader = {
      v: 1 as const,
      eventId: createId(),
      convId: logId,
      ts: Date.now(),
      lamport: nextLamport,
      authorDeviceId: deviceId,
    };
    header.prev = prevHash;
    const keyForEnvelope = await resolveSendEnvelopeKey(convId, logId, ratchetBaseKey, legacyKey);
    if (keyForEnvelope.headerRk) header.rk = keyForEnvelope.headerRk;

    const envelope = await encryptEnvelope(
      keyForEnvelope.msgKey,
      header,
      {
        type: "conv",
        conv: {
          id: conversation.id,
          type: conversation.type,
          name: conversation.name,
          pinned: conversation.pinned,
          unread: conversation.unread,
          hidden: conversation.hidden,
          muted: conversation.muted,
          blocked: conversation.blocked,
          pendingAcceptance: conversation.pendingAcceptance,
          pendingOutgoing: conversation.pendingOutgoing,
          pendingFriendResponse: conversation.pendingFriendResponse,
          lastTs: conversation.lastTs,
          lastMessage: conversation.lastMessage,
          participants: conversation.participants,
          sharedAvatarRef: conversation.sharedAvatarRef,
        },
      },
      identityPriv
    );
    const eventHash = await computeEnvelopeHash(envelope);
    events.push({
      eventId: header.eventId,
      convId: logId,
      authorDeviceId: header.authorDeviceId,
      lamport: header.lamport,
      ts: header.ts,
      envelopeJson: JSON.stringify(envelope),
    });
    prevHash = eventHash;
    updateLamportSeen(logId, header.authorDeviceId, header.lamport);
    await saveEvent({
      eventId: header.eventId,
      convId: logId,
      authorDeviceId: header.authorDeviceId,
      lamport: header.lamport,
      ts: header.ts,
      envelopeJson: JSON.stringify(envelope),
      prevHash: header.prev,
      eventHash,
    });
  }
  return events;
};

export const syncContactsNow = async () => {
  const activeConvs = Array.from(peerContexts.keys());
  for (const convId of activeConvs) {
    try {
      const peer = peerContexts.get(convId);
      if (peer?.kind !== "device") continue;
      const allowed = await isDeviceSyncAllowed(convId, "sync_contacts");
      if (!allowed) continue;
      const since = getSinceMap(contactsLogId(convId));
      const req: SyncReqFrame = {
        type: "SYNC_REQ",
        scope: "contacts",
        convId,
        since,
      };
      await sendFrame(convId, req);

      const events = await buildContactEvents(convId);
      if (!events.length) continue;
      const next = buildNextMap(events);
      const frame: SyncResFrame = {
        type: "SYNC_RES",
        scope: "contacts",
        convId,
        events,
        next,
      };
      await sendFrame(convId, frame);
    } catch (error) {
      console.warn("[sync] contacts sync failed", error);
    }
  }
};

export const syncConversationsNow = async () => {
  const activeConvs = Array.from(peerContexts.keys());
  for (const convId of activeConvs) {
    try {
      const peer = peerContexts.get(convId);
      if (peer?.kind !== "device") continue;
      const allowed = await isDeviceSyncAllowed(convId, "sync_conversations");
      if (!allowed) continue;
      const since = getSinceMap(conversationsLogId(convId));
      const req: SyncReqFrame = {
        type: "SYNC_REQ",
        scope: "conversations",
        convId,
        since,
      };
      await sendFrame(convId, req);

      const events = await buildConversationEvents(convId);
      if (!events.length) continue;
      const next = buildNextMap(events);
      const frame: SyncResFrame = {
        type: "SYNC_RES",
        scope: "conversations",
        convId,
        events,
        next,
      };
      await sendFrame(convId, frame);
    } catch (error) {
      console.warn("[sync] conversations sync failed", error);
    }
  }
};

export const __testApplyEnvelopeEvents = applyEnvelopeEvents;
export const __testHandleAck = handleAck;
export const __testHandleHello = handleHello;
export const __testGetPeerContext = (convId: string) => peerContexts.get(convId);
export const __testSetPeerContext = (convId: string, peer: PeerContext) => {
  peerContexts.set(convId, peer);
};
export const __testCreateSyncResponseFrames = (input: {
  scope: SyncReqFrame["scope"];
  convId?: string;
  events: EnvelopeEvent[];
  next: Record<string, number>;
  flowControl: boolean;
}) =>
  createSyncResponseFrames(
    {
      type: "SYNC_RES",
      scope: input.scope,
      convId: input.convId,
    },
    input.events,
    input.next,
    input.flowControl
  );
export const __testResetSyncState = () => {
  perAuthorLamportSeen.clear();
  perConvLamportSeen.clear();
  peerContexts.clear();
  pendingHelloNonces.clear();
  seenHelloNonces.clear();
  deferredRoleEvents.clear();
  Array.from(outgoingFlowSessions.keys()).forEach(clearFlowSession);
  syncTransportOverride = null;
};
