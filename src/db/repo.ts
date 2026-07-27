import Dexie from "dexie";
import { db, ensureDbOpen, resetDb } from "./schema";
import type {
  EncryptedRecord,
  EventRecord,
  MediaChunkRecord,
  MessageRecord,
  OutboxRecord,
} from "./schema";
import type { Envelope } from "../crypto/box";
import {
  chunkBuffer,
  createVaultHeader,
  decodeBinaryEnvelope,
  decryptJsonRecord,
  deriveMkm,
  deriveVk,
  encodeBinaryEnvelope,
  encryptJsonRecord,
  type VaultHeader,
} from "../crypto/vault";
import { clearVaultKey, getVaultKey, setVaultKey } from "../crypto/sessionKeyring";
import { createId } from "../utils/ids";
import { mapLimit } from "../utils/async";
import { parseAvatarRef, serializeAvatarRef } from "../utils/avatarRefs";
import { decodeBase64Url, encodeBase64Url } from "../security/base64url";
import {
  hasValidPreviewSignature,
  inspectAvatarImageFile,
  inspectOutgoingMediaFile,
  isPreviewMediaClaim,
  isSafePreviewMime,
  isValidMediaOwnerId,
  normalizeMediaMime,
  parseIncomingMediaRef,
  sanitizeMediaFilename,
  type PreparedMediaMetadata,
} from "../security/mediaPolicy";

export type AvatarRef = {
  ownerType: "profile" | "group";
  ownerId: string;
  mime: string;
  total: number;
  chunkSize: number;
};

export type MediaRef = {
  ownerType: "message";
  ownerId: string;
  mime: string;
  total: number;
  chunkSize: number;
  name: string;
  size: number;
};

export type MessageMediaChunk = {
  idx: number;
  total: number;
  bytes: Uint8Array;
};

export const createMessageMediaRef = (
  messageId: string,
  file: File,
  chunkSize = MEDIA_CHUNK_SIZE,
  metadata?: PreparedMediaMetadata
): MediaRef => {
  if (!Number.isFinite(chunkSize) || chunkSize <= 0 || chunkSize > MAX_MEDIA_CHUNK_SIZE) {
    throw new Error("Invalid media chunk size");
  }
  if (file.size <= 0 || file.size > MAX_MEDIA_BYTES) {
    throw new Error("Invalid media size");
  }
  return {
    ownerType: "message",
    ownerId: messageId,
    mime: metadata?.mime ?? normalizeMediaMime(file.type),
    total: Math.ceil(file.size / chunkSize),
    chunkSize,
    name: metadata?.name ?? sanitizeMediaFilename(file.name),
    size: file.size,
  };
};

export type UserProfile = {
  id: string;
  displayName: string;
  status: string;
  theme: "dark" | "light";
  avatarRef?: AvatarRef;
  kind: "user" | "friend";
  friendId?: string;
  deviceId?: string;
  primaryDeviceId?: string;
  identityPub?: string;
  dhPub?: string;
  routingHints?: { onionAddr?: string; deviceId?: string; inboxWriteToken?: string };
  trust?: { pinnedAt: number; status: "trusted" | "blocked" | "changed"; reason?: string };
  verification?: {
    status: "unverified" | "verified" | "key_changed" | "blocked";
    safetyNumber?: string;
    verifiedAt?: number;
  };
  reachability?: {
    status: "ok" | "unreachable" | "expired";
    lastError?: string;
    attempts?: number;
    nextAttemptAt?: number;
    lastAttemptAt?: number;
  };
  profileVcard?: {
    displayName?: string;
    status?: string;
    avatarRef?: AvatarRef;
    friendCode?: string;
    updatedAt?: number;
  };
  pskHint?: boolean;
  friendStatus?: "request_in" | "request_out" | "normal" | "hidden" | "blocked";
  friendControlTs?: number;
  isFavorite?: boolean;
  createdAt?: number;
  updatedAt?: number;
};

export type Conversation = {
  id: string;
  type?: "direct" | "group";
  name: string;
  pinned: boolean;
  unread: number;
  hidden: boolean;
  muted: boolean;
  blocked: boolean;
  pendingAcceptance?: boolean;
  pendingOutgoing?: boolean;
  pendingFriendResponse?: "accept" | "decline";
  lastTs: number;
  lastMessage: string;
  participants: string[];
  sharedAvatarRef?: string;
};

export type Message = {
  id: string;
  convId: string;
  senderId: string;
  text: string;
  ts: number;
  media?: MediaRef;
  clientBatchId?: string;
};

export type MessageEnvelopeRecord = {
  id: string;
  convId: string;
  ts: number;
  envelope: Envelope;
};

export type Event = EventRecord;

export type StoredMessageRecord =
  | { kind: "envelope"; record: MessageEnvelopeRecord }
  | { kind: "legacy"; record: Message };

export type OutboxPayload = { payloadB64u: string };
export type OutboxItem = {
  id: string;
  convId: string;
  createdAt: number;
  ttlMs: number;
  attempt: number;
  nextAttemptAt: number;
  lastError?: string;
};

const VAULT_META_KEY = "vault_header_v2";
const VAULT_KEY_ID_KEY = "vault_key_id_v1";
const TEXT_ENCODING_FIX_KEY = "text_encoding_fix_v1";
const MEDIA_CHUNK_SIZE = 192 * 1024;
const MAX_MEDIA_CHUNK_SIZE = 1024 * 1024;
const MEDIA_DECRYPT_CONCURRENCY = 6;
const MAX_MEDIA_BYTES = 500 * 1024 * 1024;
const MEDIA_YIELD_MIN_CHUNKS = 24;
const MEDIA_YIELD_EVERY = 6;
const MEDIA_DECRYPT_LARGE_CHUNKS = 32;
const MEDIA_DECRYPT_LARGE_CONCURRENCY = 3;
const MEDIA_DECRYPT_BATCH_MULTIPLIER = 4;
const MEDIA_WRITE_BATCH_SIZE = 8;
const OUTBOX_BACKOFF = [1000, 5000, 30_000, 2 * 60_000, 10 * 60_000, 60 * 60_000] as const;

const yieldToEventLoop = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const shouldYieldMedia = (index: number, total: number) =>
  total >= MEDIA_YIELD_MIN_CHUNKS && (index + 1) % MEDIA_YIELD_EVERY === 0;

const resolveMediaDecryptConcurrency = (totalChunks: number) =>
  totalChunks >= MEDIA_DECRYPT_LARGE_CHUNKS
    ? Math.min(MEDIA_DECRYPT_LARGE_CONCURRENCY, MEDIA_DECRYPT_CONCURRENCY)
    : MEDIA_DECRYPT_CONCURRENCY;

const nextOutboxAttemptAt = (attempt: number, now: number) =>
  now + OUTBOX_BACKOFF[Math.min(OUTBOX_BACKOFF.length - 1, Math.max(0, attempt))];

const decryptMediaChunks = async (vk: Uint8Array, chunks: MediaChunkRecord[]) => {
  const total = chunks.length;
  const concurrency = resolveMediaDecryptConcurrency(total);
  const batchSize = Math.max(concurrency * MEDIA_DECRYPT_BATCH_MULTIPLIER, concurrency);
  const decrypted: Uint8Array[] = [];

  for (let start = 0; start < total; start += batchSize) {
    const batch = chunks.slice(start, start + batchSize);
    const batchResult = await mapLimit(batch, concurrency, (chunk) =>
      decodeBinaryEnvelope(vk, chunk.id, "mediaChunk", chunk.enc_b64)
    );
    decrypted.push(...batchResult);
    if (total >= MEDIA_YIELD_MIN_CHUNKS && start + batchSize < total) {
      await yieldToEventLoop();
    }
  }

  return decrypted;
};

const decryptMediaToBlob = async (
  vk: Uint8Array,
  chunks: MediaChunkRecord[],
  mime: string,
  maxBytes: number
) => {
  const total = chunks.length;
  const concurrency = resolveMediaDecryptConcurrency(total);
  const batchSize = Math.max(concurrency * MEDIA_DECRYPT_BATCH_MULTIPLIER, concurrency);
  const blobParts: Blob[] = [];
  let totalBytes = 0;

  for (let start = 0; start < total; start += batchSize) {
    const batch = chunks.slice(start, start + batchSize);
    const batchResult = await mapLimit(batch, concurrency, (chunk) =>
      decodeBinaryEnvelope(vk, chunk.id, "mediaChunk", chunk.enc_b64)
    );
    if (start === 0) {
      const firstChunk = batchResult[0];
      if (
        !firstChunk ||
        (isPreviewMediaClaim(mime) && !hasValidPreviewSignature(mime, firstChunk))
      ) return null;
    }
    for (const bytes of batchResult) {
      totalBytes += bytes.byteLength;
      if (totalBytes > maxBytes) return null;
    }
    // Move decrypted batches into immutable Blob storage so the JS heap only retains
    // one decryption batch instead of every chunk of a large attachment.
    blobParts.push(new Blob(batchResult as unknown as BlobPart[]));
    if (total >= MEDIA_YIELD_MIN_CHUNKS && start + batchSize < total) {
      await yieldToEventLoop();
    }
  }

  return { blob: new Blob(blobParts, { type: mime }), totalBytes };
};

const requireVaultKey = () => {
  const vk = getVaultKey();
  if (!vk) throw new Error("Vault is locked");
  return vk;
};

const toB64 = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...Array.from(bytes)));

const computeVaultKeyId = async (vk: Uint8Array) => {
  if (!globalThis.crypto?.subtle) return null;
  const vkBytes = new Uint8Array(vk);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", vkBytes);
  return toB64(new Uint8Array(digest).slice(0, 16));
};

export const getVaultKeyId = async () => {
  await ensureDbOpen();
  const record = await db.meta.get(VAULT_KEY_ID_KEY);
  return record?.value || null;
};

export const setVaultKeyId = async (vk: Uint8Array) => {
  await ensureDbOpen();
  const keyId = await computeVaultKeyId(vk);
  if (!keyId) return null;
  await db.meta.put({ key: VAULT_KEY_ID_KEY, value: keyId });
  return keyId;
};

export const verifyVaultKeyId = async (vk: Uint8Array) => {
  await ensureDbOpen();
  const stored = await getVaultKeyId();
  if (!stored) return true;
  const current = await computeVaultKeyId(vk);
  if (!current) return true;
  return stored === current;
};

export const getVaultHeader = async (): Promise<VaultHeader | null> => {
  await ensureDbOpen();
  const record = await db.meta.get(VAULT_META_KEY);
  if (!record) return null;
  try {
    return JSON.parse(record.value) as VaultHeader;
  } catch {
    await db.meta.delete(VAULT_META_KEY);
    return null;
  }
};

const mojibakeMarker = /[ÃÂâêëìíîïðñòóôõöùúûüýþÿ�]/;

const countHangul = (value: string) => (value.match(/[가-힣]/g) ?? []).length;

const repairMojibake = (value: string) => {
  if (!value || !mojibakeMarker.test(value)) return value;
  try {
    const bytes = Uint8Array.from(value, (char) => char.charCodeAt(0));
    const repaired = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (repaired === value) return value;
    return countHangul(repaired) > countHangul(value) ? repaired : value;
  } catch {
    return value;
  }
};

export const repairVaultTextEncoding = async () => {
  await ensureDbOpen();
  const meta = await db.meta.get(TEXT_ENCODING_FIX_KEY);
  if (meta?.value === "1") return;

  const vk = requireVaultKey();
  const profileRecords = await db.profiles.toArray();
  for (const record of profileRecords) {
    const profile = await decryptJsonRecord<UserProfile>(vk, record.id, "profile", record.enc_b64);
    const displayName = repairMojibake(profile.displayName);
    const status = repairMojibake(profile.status);
    if (displayName !== profile.displayName || status !== profile.status) {
      await saveProfile({ ...profile, displayName, status });
    }
  }

  const conversationRecords = await db.conversations.toArray();
  for (const record of conversationRecords) {
    const conversation = await decryptJsonRecord<Conversation>(
      vk,
      record.id,
      "conv",
      record.enc_b64
    );
    const name = repairMojibake(conversation.name);
    const lastMessage = repairMojibake(conversation.lastMessage);
    if (name !== conversation.name || lastMessage !== conversation.lastMessage) {
      await saveConversation({ ...conversation, name, lastMessage });
    }
  }

  await db.meta.put({ key: TEXT_ENCODING_FIX_KEY, value: "1" });
};

export const ensureVaultHeader = async (): Promise<VaultHeader> => {
  await ensureDbOpen();
  const existing = await getVaultHeader();
  if (existing) return existing;
  const header = await createVaultHeader();
  await db.meta.put({ key: VAULT_META_KEY, value: JSON.stringify(header) });
  return header;
};

export const unlockVault = async (startKey: string) => {
  const header = await ensureVaultHeader();
  const mkm = await deriveMkm(startKey, header);
  const vk = await deriveVk(mkm);
  setVaultKey(vk);
  await setVaultKeyId(vk);
  return header;
};

export const bootstrapVault = async () => {
  await ensureVaultHeader();
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Secure random generator is unavailable.");
  }
  const vk = new Uint8Array(32);
  globalThis.crypto.getRandomValues(vk);
  setVaultKey(vk);
  await setVaultKeyId(vk);
};

export const lockVault = () => {
  clearVaultKey();
};

export const saveProfile = async (profile: UserProfile) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const enc_b64 = await encryptJsonRecord(vk, profile.id, "profile", profile);
  const record: EncryptedRecord = {
    id: profile.id,
    enc_b64,
    updatedAt: Date.now(),
  };
  await db.profiles.put(record);
};

export const deleteProfile = async (profileId: string) => {
  await ensureDbOpen();
  requireVaultKey();
  await db.profiles.delete(profileId);
};

export const listProfiles = async () => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const records = await db.profiles.toArray();
  const profiles = await Promise.all(
    records.map((record) =>
      decryptJsonRecord<UserProfile>(vk, record.id, "profile", record.enc_b64)
    )
  );
  return profiles;
};

export const saveConversation = async (conversation: Conversation) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const enc_b64 = await encryptJsonRecord(
    vk,
    conversation.id,
    "conv",
    conversation
  );
  await db.conversations.put({
    id: conversation.id,
    enc_b64,
    updatedAt: Date.now(),
  });
};

export const listConversations = async () => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const records = await db.conversations.toArray();
  const conversations = await Promise.all(
    records.map((record) =>
      decryptJsonRecord<Conversation>(vk, record.id, "conv", record.enc_b64)
    )
  );
  return conversations;
};

export const saveMessage = async (message: Message) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const enc_b64 = await encryptJsonRecord(vk, message.id, "message", message);
  const record: MessageRecord = {
    id: message.id,
    convId: message.convId,
    ts: message.ts,
    enc_b64,
  };
  await db.messages.put(record);
};

export const listMessagesByConv = async (convId: string) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const records = await db.messages.where("convId").equals(convId).sortBy("ts");
  const messages = await Promise.all(
    records.map((record) =>
      decryptJsonRecord<Message>(vk, record.id, "message", record.enc_b64)
    )
  );
  return messages;
};

export const saveMessageEnvelope = async (record: MessageEnvelopeRecord) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const enc_b64 = await encryptJsonRecord(vk, record.id, "message", record);
  const dbRecord: MessageRecord = {
    id: record.id,
    convId: record.convId,
    ts: record.ts,
    enc_b64,
  };
  await db.messages.put(dbRecord);
};

export const listMessageRecordsByConv = async (convId: string) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const records = await db.messages.where("convId").equals(convId).sortBy("ts");
  const decoded = await Promise.all(
    records.map((record) =>
      decryptJsonRecord<unknown>(vk, record.id, "message", record.enc_b64)
    )
  );
  return decoded.map((value) => {
    if (
      value &&
      typeof value === "object" &&
      "envelope" in value &&
      "convId" in value &&
      "ts" in value
    ) {
      return { kind: "envelope", record: value as MessageEnvelopeRecord } as const;
    }
    return { kind: "legacy", record: value as Message } as const;
  });
};

const LAMPORT_PREFIX = "lamport_v1:";

export const nextLamportForConv = async (convId: string) => {
  await ensureDbOpen();
  const key = `${LAMPORT_PREFIX}${convId}`;
  return db.transaction("rw", db.meta, async () => {
    const current = await db.meta.get(key);
    const parsed = current?.value ? Number.parseInt(current.value, 10) : 0;
    const value = Number.isFinite(parsed) ? parsed : 0;
    const next = value + 1;
    await db.meta.put({ key, value: String(next) });
    return next;
  });
};

export const saveEvent = async (record: EventRecord) => {
  await ensureDbOpen();
  await db.events.put(record);
};

export const getEvent = async (eventId: string) => {
  await ensureDbOpen();
  return db.events.get(eventId);
};

export const listEventsByConv = async (convId: string) => {
  await ensureDbOpen();
  return db.events.where("convId").equals(convId).sortBy("lamport");
};

export const getLastEventHash = async (convId: string) => {
  await ensureDbOpen();
  const record = await db.events
    .where("[convId+lamport]")
    .between([convId, Dexie.minKey], [convId, Dexie.maxKey])
    .reverse()
    .first();
  return record?.eventHash;
};

export const saveProfilePhoto = async (ownerId: string, file: File) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const metadata = await inspectAvatarImageFile(file);
  await db.mediaChunks
    .where("ownerId")
    .equals(ownerId)
    .and((chunk) => chunk.ownerType === "profile")
    .delete();

  const buffer = await file.arrayBuffer();
  const chunks = chunkBuffer(buffer, MEDIA_CHUNK_SIZE);
  const total = chunks.length;
  const now = Date.now();
  const records: MediaChunkRecord[] = [];

  for (let idx = 0; idx < chunks.length; idx += 1) {
    const chunkId = `${ownerId}:${idx}`;
    const enc_b64 = await encodeBinaryEnvelope(
      vk,
      chunkId,
      "mediaChunk",
      chunks[idx]
    );
    records.push({
      id: chunkId,
      ownerType: "profile",
      ownerId,
      idx,
      enc_b64,
      mime: metadata.mime,
      total,
      updatedAt: now,
    });
    if (shouldYieldMedia(idx, total)) {
      await yieldToEventLoop();
    }
  }

  await db.mediaChunks.bulkPut(records);

  const avatarRef: AvatarRef = {
    ownerType: "profile",
    ownerId,
    mime: metadata.mime,
    total,
    chunkSize: MEDIA_CHUNK_SIZE,
  };

  return avatarRef;
};

const saveAvatarPhoto = async (ownerType: AvatarRef["ownerType"], ownerId: string, file: File) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const metadata = await inspectAvatarImageFile(file);
  await db.mediaChunks
    .where("ownerId")
    .equals(ownerId)
    .and((chunk) => chunk.ownerType === ownerType)
    .delete();

  const buffer = await file.arrayBuffer();
  const chunks = chunkBuffer(buffer, MEDIA_CHUNK_SIZE);
  const total = chunks.length;
  const now = Date.now();
  const records: MediaChunkRecord[] = [];

  for (let idx = 0; idx < chunks.length; idx += 1) {
    const chunkId = `${ownerId}:${idx}`;
    const enc_b64 = await encodeBinaryEnvelope(vk, chunkId, "mediaChunk", chunks[idx]);
    records.push({
      id: chunkId,
      ownerType,
      ownerId,
      idx,
      enc_b64,
      mime: metadata.mime,
      total,
      updatedAt: now,
    });
    if (shouldYieldMedia(idx, total)) {
      await yieldToEventLoop();
    }
  }

  await db.mediaChunks.bulkPut(records);

  const avatarRef: AvatarRef = {
    ownerType,
    ownerId,
    mime: metadata.mime,
    total,
    chunkSize: MEDIA_CHUNK_SIZE,
  };

  return avatarRef;
};

export const saveGroupPhotoRef = async (ownerId: string, file: File) => {
  const avatarRef = await saveAvatarPhoto("group", ownerId, file);
  return serializeAvatarRef(avatarRef);
};

export const loadProfilePhoto = async (avatarRef?: AvatarRef) => {
  try {
    await ensureDbOpen();
    if (!avatarRef) return null;
    const vk = requireVaultKey();
    const ownerType = avatarRef.ownerType === "group" ? "group" : "profile";
    const chunks = await db.mediaChunks
      .where("ownerId")
      .equals(avatarRef.ownerId)
      .and((chunk) => chunk.ownerType === ownerType)
      .sortBy("idx");

    if (!chunks.length) return null;
    if (!Number.isFinite(avatarRef.total) || avatarRef.total <= 0) return null;
    if (!Number.isFinite(avatarRef.chunkSize) || avatarRef.chunkSize <= 0) return null;
    if (chunks.length !== avatarRef.total) return null;
    if (avatarRef.total * avatarRef.chunkSize > MAX_MEDIA_BYTES) return null;

    const decrypted = await decryptMediaChunks(vk, chunks);
    if (decrypted.length !== chunks.length) return null;
    const totalBytes = decrypted.reduce((sum, part) => sum + part.length, 0);
    if (totalBytes > MAX_MEDIA_BYTES) return null;
    const blob = new Blob(decrypted as unknown as BlobPart[], { type: avatarRef.mime });
    return blob;
  } catch {
    return null;
  }
};

export const loadAvatarFromRef = async (ref?: string | null) => {
  const parsed = parseAvatarRef(ref);
  if (!parsed) return null;
  return loadProfilePhoto(parsed);
};

export const saveMessageMedia = async (
  messageId: string,
  file: File,
  chunkSize = MEDIA_CHUNK_SIZE,
  onStoredChunk?: (chunk: MessageMediaChunk) => Promise<void>,
  preparedMetadata?: PreparedMediaMetadata
) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  if (!Number.isFinite(chunkSize) || chunkSize <= 0 || chunkSize > MAX_MEDIA_CHUNK_SIZE) {
    throw new Error("Invalid media chunk size");
  }
  if (file.size <= 0 || file.size > MAX_MEDIA_BYTES) {
    throw new Error("Invalid media size");
  }
  const metadata = preparedMetadata ?? await inspectOutgoingMediaFile(file);
  const mediaRef = createMessageMediaRef(messageId, file, chunkSize, metadata);
  await db.mediaChunks
    .where("ownerId")
    .equals(messageId)
    .and((chunk) => chunk.ownerType === "message")
    .delete();
  const total = mediaRef.total;
  const now = Date.now();
  const records: MediaChunkRecord[] = [];
  const pendingChunks: MessageMediaChunk[] = [];

  const flushRecords = async () => {
    if (!records.length) return;
    await db.mediaChunks.bulkPut(records.splice(0));
    if (!onStoredChunk) {
      pendingChunks.length = 0;
      return;
    }
    for (const chunk of pendingChunks.splice(0)) {
      await onStoredChunk(chunk);
    }
  };

  for (let idx = 0; idx < total; idx += 1) {
    const start = idx * chunkSize;
    const bytes = new Uint8Array(
      await file.slice(start, Math.min(file.size, start + chunkSize)).arrayBuffer()
    );
    const chunkId = `${messageId}:${idx}`;
    const enc_b64 = await encodeBinaryEnvelope(
      vk,
      chunkId,
      "mediaChunk",
      bytes
    );
    records.push({
      id: chunkId,
      ownerType: "message",
      ownerId: messageId,
      idx,
      enc_b64,
      mime: mediaRef.mime,
      total,
      updatedAt: now,
    });
    pendingChunks.push({ idx, total, bytes });
    if (records.length >= MEDIA_WRITE_BATCH_SIZE) {
      await flushRecords();
    }
    if (shouldYieldMedia(idx, total)) {
      await yieldToEventLoop();
    }
  }

  await flushRecords();

  return mediaRef;
};

export const saveReceivedMessageMediaChunk = async (input: {
  ownerId: string;
  idx: number;
  total: number;
  chunkSize: number;
  size: number;
  mime: string;
  bytes: Uint8Array;
}) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const ownerId = input.ownerId.trim();
  if (!isValidMediaOwnerId(ownerId)) throw new Error("Invalid media owner");
  if (!Number.isInteger(input.idx) || input.idx < 0) throw new Error("Invalid media chunk index");
  if (!Number.isInteger(input.total) || input.total <= 0) throw new Error("Invalid media chunk total");
  if (input.idx >= input.total) throw new Error("Invalid media chunk index");
  if (!Number.isInteger(input.chunkSize) || input.chunkSize <= 0 || input.chunkSize > MAX_MEDIA_CHUNK_SIZE) {
    throw new Error("Invalid media chunk size");
  }
  if (!Number.isFinite(input.size) || input.size <= 0 || input.size > MAX_MEDIA_BYTES) {
    throw new Error("Invalid media size");
  }
  if (input.total * input.chunkSize > MAX_MEDIA_BYTES + input.chunkSize) {
    throw new Error("Media exceeds size limit");
  }
  if (input.bytes.byteLength <= 0 || input.bytes.byteLength > input.chunkSize) {
    throw new Error("Invalid media chunk payload");
  }
  if (input.total !== Math.ceil(input.size / input.chunkSize)) {
    throw new Error("Invalid media chunk total");
  }
  const expectedChunkBytes = input.idx === input.total - 1
    ? input.size - input.chunkSize * (input.total - 1)
    : input.chunkSize;
  if (input.bytes.byteLength !== expectedChunkBytes) {
    throw new Error("Invalid media chunk payload length");
  }
  const mime = normalizeMediaMime(input.mime);
  if (isPreviewMediaClaim(input.mime) && !isSafePreviewMime(mime)) {
    throw new Error("Unsupported media preview type");
  }
  if (input.idx === 0 && isSafePreviewMime(mime) && !hasValidPreviewSignature(mime, input.bytes)) {
    throw new Error("Media content does not match its declared type");
  }

  const messageRecord = await db.messages.get(ownerId);
  if (!messageRecord) throw new Error("Media manifest is missing");
  const message = await decryptJsonRecord<Message>(
    vk,
    messageRecord.id,
    "message",
    messageRecord.enc_b64
  );
  const manifest = parseIncomingMediaRef(message.media, ownerId);
  if (
    !manifest ||
    manifest.total !== input.total ||
    manifest.chunkSize !== input.chunkSize ||
    manifest.size !== input.size ||
    manifest.mime !== mime
  ) {
    throw new Error("Media chunk does not match its authenticated manifest");
  }

  const existing = await db.mediaChunks
    .where("ownerId")
    .equals(ownerId)
    .and((chunk) => chunk.ownerType === "message")
    .first();
  if (existing && (existing.total !== input.total || normalizeMediaMime(existing.mime) !== mime)) {
    throw new Error("Inconsistent media metadata");
  }

  const chunkId = `${ownerId}:${input.idx}`;
  const enc_b64 = await encodeBinaryEnvelope(vk, chunkId, "mediaChunk", input.bytes);
  await db.mediaChunks.put({
    id: chunkId,
    ownerType: "message",
    ownerId,
    idx: input.idx,
    enc_b64,
    mime,
    total: input.total,
    updatedAt: Date.now(),
  });
  const received = await db.mediaChunks
    .where("ownerId")
    .equals(ownerId)
    .and((chunk) => chunk.ownerType === "message")
    .count();
  return { received, total: input.total, complete: received === input.total };
};

export const loadMessageMedia = async (mediaRef?: MediaRef) => {
  try {
    await ensureDbOpen();
    if (!mediaRef) return null;
    const validatedRef = parseIncomingMediaRef(mediaRef, mediaRef.ownerId);
    if (!validatedRef) return null;
    const vk = requireVaultKey();
    const chunks = await db.mediaChunks
      .where("ownerId")
      .equals(mediaRef.ownerId)
      .and((chunk) => chunk.ownerType === "message")
      .sortBy("idx");

    if (!chunks.length) return null;
    if (chunks.length !== validatedRef.total) return null;
    if (chunks.some((chunk, index) =>
      chunk.idx !== index ||
      chunk.total !== validatedRef.total ||
      normalizeMediaMime(chunk.mime) !== validatedRef.mime
    )) return null;

    const decrypted = await decryptMediaToBlob(vk, chunks, validatedRef.mime, MAX_MEDIA_BYTES);
    if (!decrypted) return null;
    if (decrypted.totalBytes !== validatedRef.size) return null;
    return decrypted.blob;
  } catch {
    return null;
  }
};

export const seedVaultData = async (user: UserProfile) => {
  await ensureDbOpen();
  const now = Date.now();
  const friends: UserProfile[] = [
    {
      id: createId(),
      displayName: "테스트 친구",
      status: "NKC 테스트 중",
      theme: "dark",
      kind: "friend",
      friendStatus: "normal",
      isFavorite: false,
      createdAt: now,
      updatedAt: now,
    },
    {
      id: createId(),
      displayName: "민지",
      status: "온라인",
      theme: "dark",
      kind: "friend",
      friendStatus: "normal",
      isFavorite: false,
      createdAt: now,
      updatedAt: now,
    },
    {
      id: createId(),
      displayName: "리드",
      status: "업무 중",
      theme: "dark",
      kind: "friend",
      friendStatus: "normal",
      isFavorite: false,
      createdAt: now,
      updatedAt: now,
    },
    {
      id: createId(),
      displayName: "진아",
      status: "자리 비움",
      theme: "dark",
      kind: "friend",
      friendStatus: "normal",
      isFavorite: false,
      createdAt: now,
      updatedAt: now,
    },
  ];

  await saveProfile(user);
  for (const friend of friends) {
    await saveProfile(friend);
  }

  const conversationEntries = Array.from({ length: 10 }).map((_, idx) => {
    const friend = friends[idx % friends.length];
    const isTestFriend = friend.displayName === "테스트 친구";
    const isPinned = idx < 2 || isTestFriend;
    const id = createId();
    return {
      conv: {
        id,
        name: `${friend.displayName} 대화 ${idx + 1}`,
        pinned: isPinned,
        unread: idx % 3 === 0 ? 2 : 0,
        hidden: false,
        muted: idx % 4 === 0,
        blocked: false,
        lastTs: Date.now() - idx * 1000 * 60 * 9,
        lastMessage: isTestFriend
          ? "테스트 대화가 준비되어 있습니다."
          : "로컬-퍼스트 채팅을 준비하고 있어요.",
        participants: [user.id, friend.id],
      },
      friend,
      idx,
    };
  });
  const conversations = conversationEntries.map((entry) => entry.conv);

  for (const entry of conversationEntries) {
    const { conv, friend } = entry;
    await saveConversation(conv);
    const isTestFriend = friend.displayName === "테스트 친구";
    const customMessages = [
      "안녕하세요! 테스트용 채팅입니다.",
      "프로필/정보 패널 표시를 확인하고 있어요.",
      "미디어 탭에는 추후 파일 미리보기가 들어옵니다.",
      "설정 탭에서 알림/차단/음소거를 제어할 수 있어요.",
      "여기까지가 테스트 시나리오입니다.",
    ];
    const messages: Message[] = Array.from({ length: 20 }).map((_, mIdx) => {
      const senderId = mIdx % 2 === 0 ? user.id : conv.participants[1];
      const text = isTestFriend
        ? customMessages[mIdx % customMessages.length]
        : mIdx % 2 === 0
          ? "로컬에서 안전하게 저장됩니다."
          : "좋아요, 계속 진행해요.";
      return {
        id: createId(),
        convId: conv.id,
        senderId,
        text,
        ts: conv.lastTs - (20 - mIdx) * 1000 * 60,
      };
    });
    for (const message of messages) {
      await saveMessage(message);
    }
  }

  return { friends, conversations };
};

export const rotateVaultKeys = async (
  newStartKey: string,
  onProgress?: (value: number) => void
) => {
  await ensureDbOpen();
  const oldVk = requireVaultKey();
  const newHeader = await createVaultHeader();
  const newMkm = await deriveMkm(newStartKey, newHeader);
  const newVk = await deriveVk(newMkm);

  const profiles = await db.profiles.toArray();
  const conversations = await db.conversations.toArray();
  const messages = await db.messages.toArray();
  const mediaChunks = await db.mediaChunks.toArray();
  const total =
    profiles.length + conversations.length + messages.length + mediaChunks.length;
  let processed = 0;

  const bump = () => {
    processed += 1;
    if (onProgress && total > 0) {
      onProgress(Math.round((processed / total) * 100));
    }
  };

  if (onProgress && total === 0) {
    onProgress(100);
  }

  for (const record of profiles) {
    const data = await decryptJsonRecord<UserProfile>(
      oldVk,
      record.id,
      "profile",
      record.enc_b64
    );
    const enc_b64 = await encryptJsonRecord(newVk, record.id, "profile", data);
    await db.profiles.put({ ...record, enc_b64, updatedAt: Date.now() });
    bump();
  }

  for (const record of conversations) {
    const data = await decryptJsonRecord<Conversation>(
      oldVk,
      record.id,
      "conv",
      record.enc_b64
    );
    const enc_b64 = await encryptJsonRecord(newVk, record.id, "conv", data);
    await db.conversations.put({ ...record, enc_b64, updatedAt: Date.now() });
    bump();
  }

  for (const record of messages) {
    const data = await decryptJsonRecord<Message>(
      oldVk,
      record.id,
      "message",
      record.enc_b64
    );
    const enc_b64 = await encryptJsonRecord(newVk, record.id, "message", data);
    await db.messages.put({ ...record, enc_b64 });
    bump();
  }

  for (const record of mediaChunks) {
    const data = await decodeBinaryEnvelope(
      oldVk,
      record.id,
      "mediaChunk",
      record.enc_b64
    );
    const enc_b64 = await encodeBinaryEnvelope(
      newVk,
      record.id,
      "mediaChunk",
      data
    );
    await db.mediaChunks.put({ ...record, enc_b64, updatedAt: Date.now() });
    bump();
  }

  await db.meta.put({ key: VAULT_META_KEY, value: JSON.stringify(newHeader) });
  setVaultKey(newVk);
  await setVaultKeyId(newVk);
};

export const resetVaultStorage = async () => {
  clearVaultKey();
  await resetDb();
};

export const wipeVault = async () => {
  await resetVaultStorage();
};

export type VaultUsage = {
  bytes: number;
  breakdown: {
    profiles: number;
    conversations: number;
    messages: number;
    media: number;
    outbox: number;
    meta: number;
  };
};

const sizeOfString = (value?: string | null) => (value ? value.length : 0);

export const getVaultUsage = async (): Promise<VaultUsage> => {
  await ensureDbOpen();
  const profiles = await db.profiles.toArray();
  const conversations = await db.conversations.toArray();
  const messages = await db.messages.toArray();
  const media = await db.mediaChunks.toArray();
  const outbox = db.outbox ? await db.outbox.toArray() : [];
  const meta = await db.meta.toArray();

  const breakdown = {
    profiles: profiles.reduce((sum, record) => sum + sizeOfString(record.enc_b64), 0),
    conversations: conversations.reduce((sum, record) => sum + sizeOfString(record.enc_b64), 0),
    messages: messages.reduce((sum, record) => sum + sizeOfString(record.enc_b64), 0),
    media: media.reduce((sum, record) => sum + sizeOfString(record.enc_b64), 0),
    outbox: outbox.reduce((sum, record) => sum + sizeOfString(record.ciphertext), 0),
    meta: meta.reduce((sum, record) => sum + sizeOfString(record.value), 0),
  };

  return {
    bytes:
      breakdown.profiles +
      breakdown.conversations +
      breakdown.messages +
      breakdown.media +
      breakdown.outbox +
      breakdown.meta,
    breakdown,
  };
};

type DecryptedOutboxRecord = OutboxItem & { payload: OutboxPayload };

export const enqueueOutbox = async (item: OutboxItem, payload: Uint8Array) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const payloadB64u = encodeBase64Url(payload);
  const ciphertext = await encryptJsonRecord(vk, item.id, "outbox", {
    ...item,
    payload: { payloadB64u },
  } satisfies DecryptedOutboxRecord);
  const record: OutboxRecord = {
    ...item,
    lastError: item.lastError ?? "",
    ciphertext,
    createdAtMs: item.createdAt,
    expiresAtMs: item.createdAt + item.ttlMs,
    nextAttemptAtMs: item.nextAttemptAt,
    attempts: item.attempt,
    status: "pending",
  };
  await db.outbox.put(record);
};

export const listDueOutboxByConv = async (convId: string, now: number, limit = 10) => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const records = await db.outbox
    .where("[convId+nextAttemptAt]")
    .between([convId, Dexie.minKey], [convId, now], true, true)
    .limit(limit)
    .toArray();

  const decoded = await Promise.all(
    records.map(async (record) => {
      const item = await decryptJsonRecord<DecryptedOutboxRecord>(
        vk,
        record.id,
        "outbox",
        record.ciphertext
      );
      const meta: OutboxItem = {
        id: record.id,
        convId: record.convId,
        createdAt: record.createdAt ?? item.createdAt,
        ttlMs: record.ttlMs ?? item.ttlMs,
        attempt: record.attempt ?? item.attempt,
        nextAttemptAt: record.nextAttemptAt ?? item.nextAttemptAt,
        lastError: record.lastError || undefined,
      };
      return {
        meta,
        payload: decodeBase64Url(item.payload.payloadB64u),
      };
    })
  );

  return decoded;
};

export const markOutboxRetry = async (id: string, err: string) => {
  await ensureDbOpen();
  const record = await db.outbox.get(id);
  if (!record) return;
  const now = Date.now();
  const nextAttempt = (record.attempt ?? 0) + 1;
  const nextAttemptAt = nextOutboxAttemptAt(nextAttempt, now);
  await db.outbox.update(id, {
    attempt: nextAttempt,
    attempts: nextAttempt,
    nextAttemptAt,
    nextAttemptAtMs: nextAttemptAt,
    lastError: err,
    status: "pending",
  });
};

export const removeOutbox = async (id: string) => {
  await ensureDbOpen();
  await db.outbox.delete(id);
};

export const dropExpiredOutboxByConv = async (convId: string, now: number) => {
  await ensureDbOpen();
  const records = await db.outbox.where("convId").equals(convId).toArray();
  const expired = records.filter((record) => {
    const createdAt = record.createdAt ?? record.createdAtMs ?? 0;
    const ttlMs =
      record.ttlMs ??
      (typeof record.expiresAtMs === "number" ? Math.max(0, record.expiresAtMs - createdAt) : 0);
    return createdAt + ttlMs <= now;
  });
  if (!expired.length) return;
  await db.outbox.bulkDelete(expired.map((record) => record.id));
};

const randomBytes = (length: number) => {
  if (!globalThis.crypto?.getRandomValues) {
    return new Uint8Array(length);
  }
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
};

const secureEraseMessages = async (records: MessageRecord[]) => {
  if (!records.length) return;
  const vk = requireVaultKey();
  const now = Date.now();
  const sanitized = await Promise.all(
    records.map(async (record) => {
      const payload: Message = {
        id: record.id,
        convId: record.convId,
        senderId: "wiped",
        text: "",
        ts: 0,
      };
      const enc_b64 = await encryptJsonRecord(vk, record.id, "message", payload);
      return { ...record, enc_b64, ts: 0, updatedAt: now } as MessageRecord & {
        updatedAt: number;
      };
    })
  );
    await db.messages.bulkPut(
      sanitized.map((record) => {
        const { updatedAt, ...rest } = record;
        void updatedAt;
        return rest;
      })
    );
  await db.messages.bulkDelete(records.map((record) => record.id));
};

const secureEraseMediaChunks = async (records: MediaChunkRecord[]) => {
  if (!records.length) return;
  const vk = requireVaultKey();
  const now = Date.now();
  const sanitized = await Promise.all(
    records.map(async (record) => {
      const enc_b64 = await encodeBinaryEnvelope(
        vk,
        record.id,
        "mediaChunk",
        randomBytes(32)
      );
      return { ...record, enc_b64, updatedAt: now };
    })
  );
  await db.mediaChunks.bulkPut(sanitized);
  await db.mediaChunks.bulkDelete(records.map((record) => record.id));
};

export const deleteMessagesById = async (messageIds: string[]) => {
  if (!messageIds.length) return;
  await ensureDbOpen();
  requireVaultKey();
  const uniqueIds = Array.from(new Set(messageIds));
  const now = Date.now();
  const messageRecords = (await db.messages.bulkGet(uniqueIds)).filter(
    (record): record is MessageRecord => Boolean(record)
  );
  await secureEraseMessages(messageRecords);
  const mediaRecords = await db.mediaChunks
    .where("ownerId")
    .anyOf(uniqueIds)
    .and((chunk) => chunk.ownerType === "message")
    .toArray();
  await secureEraseMediaChunks(mediaRecords);
  await db.tombstones.bulkPut(
    uniqueIds.map((id) => ({ id, type: "message", deletedAt: now }))
  );
};

export const deleteAllMedia = async () => {
  await ensureDbOpen();
  requireVaultKey();

  const profiles = await listProfiles();
  await Promise.all(
    profiles.map(async (profile) => {
      if (!profile.avatarRef) return;
      await saveProfile({ ...profile, avatarRef: undefined, updatedAt: Date.now() });
    })
  );

  const messageRecords = await db.messages.toArray();
  const updatedMessages = await Promise.all(
    messageRecords.map(async (record) => {
      const vk = requireVaultKey();
      const message = await decryptJsonRecord<Message>(
        vk,
        record.id,
        "message",
        record.enc_b64
      );
      if (!message.media) return null;
      const updated: Message = { ...message, media: undefined };
      const enc_b64 = await encryptJsonRecord(vk, record.id, "message", updated);
      return { ...record, enc_b64 };
    })
  );
  const messageUpdates = updatedMessages.filter(
    (record): record is MessageRecord => Boolean(record)
  );
  if (messageUpdates.length) {
    await db.messages.bulkPut(messageUpdates);
  }

  const mediaRecords = await db.mediaChunks.toArray();
  await secureEraseMediaChunks(mediaRecords);
};

export const clearChatHistory = async () => {
  await ensureDbOpen();
  const vk = requireVaultKey();
  const conversations = await listConversations();
  await Promise.all(
    conversations.map(async (conv) => {
      const updated: Conversation = {
        ...conv,
        lastMessage: "",
        unread: 0,
        lastTs: 0,
      };
      const enc_b64 = await encryptJsonRecord(vk, conv.id, "conv", updated);
      await db.conversations.put({ id: conv.id, enc_b64, updatedAt: Date.now() });
    })
  );

  const messageRecords = await db.messages.toArray();
  await secureEraseMessages(messageRecords);

  const mediaRecords = await db.mediaChunks
    .where("ownerType")
    .equals("message")
    .toArray();
  await secureEraseMediaChunks(mediaRecords);

};
