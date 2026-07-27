import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startOnionController, type OnionControllerHandle } from "../onionController";
import { TorManager } from "../torManager";
import { NativeWorkerClient } from "../nativeWorkerClient";
import { createNativeSocksTransport } from "../socksHttpClient";
import {
  enrichFriendControlFrameWithProtocol,
  signFriendControlFrame,
  verifyFriendControlFrameProtocol,
  verifyFriendControlFrameSignature,
  type FriendControlFrame,
  type UnsignedFriendControlFrame,
} from "../../friends/friendControlFrame";
import { decodeFriendCodeV1, encodeFriendCodeV1, type FriendCodeV1 } from "../../security/friendCode";
import { decodeBase64Url, encodeBase64Url } from "../../security/base64url";
import { getSodium } from "../../security/sodium";
import { INLINE_MEDIA_CHUNK_SIZE } from "../../net/mediaTransferLimits";
import {
  decryptEnvelope,
  deriveConversationKey,
  encryptEnvelope,
  type Envelope,
  type EnvelopeHeader,
} from "../../crypto/box";

const LIVE_TOR_ENABLED = process.env.NKC_LIVE_TOR_E2E === "1";
const LIVE_TOR_LARGE_ENABLED = process.env.NKC_LIVE_TOR_LARGE_E2E === "1";
const LIVE_TOR_ONLY_LARGE = process.env.NKC_LIVE_TOR_ONLY_LARGE === "1";
const LIVE_TOR_CHAT_BYTES = process.env.NKC_LIVE_TOR_CHAT_MIB === "1" ? 1024 * 1024 : 0;
const LIVE_TOR_FILE_MB = Math.min(
  500,
  Math.max(1, Number.parseInt(process.env.NKC_LIVE_TOR_FILE_MB ?? "10", 10) || 10)
);
const LIVE_FILE_CHUNK_BYTES = Math.min(
  INLINE_MEDIA_CHUNK_SIZE,
  Math.max(
    128 * 1024,
    (Number.parseInt(process.env.NKC_LIVE_TOR_CHUNK_KIB ?? "1024", 10) || 1024) * 1024
  )
);
const LIVE_TOR_ROUTE_READY_TIMEOUT_MS = LIVE_TOR_LARGE_ENABLED ? 480_000 : 240_000;
const DEVICE_A = randomUUID();
const DEVICE_B = randomUUID();

type InboxResponse = {
  ok: boolean;
  items: Array<{ id: string; from: string; envelope: string }>;
  nextAfter: string | null;
};

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const waitForTorRoute = async (
  controller: OnionControllerHandle,
  onionAddress: string,
  timeoutMs = LIVE_TOR_ROUTE_READY_TIMEOUT_MS
) => {
  const startedAt = Date.now();
  let attempts = 0;
  const observedErrors = new Set<string>();
  let lastResult: Awaited<ReturnType<OnionControllerHandle["prewarmTorRoute"]>> | null = null;
  while (Date.now() - startedAt < timeoutMs) {
    attempts += 1;
    lastResult = await controller.prewarmTorRoute(onionAddress, { timeoutMs: 15_000 });
    if (lastResult.ok) {
      return { ...lastResult, attempts, totalElapsedMs: Date.now() - startedAt };
    }
    if (lastResult.error) observedErrors.add(lastResult.error);
    if (lastResult.error === "native_transport_unavailable") {
      throw new Error(`Tor route cannot start: ${lastResult.error}`);
    }
    await wait(2_000);
  }
  throw new Error(
    `Tor route did not become reachable: ${JSON.stringify({ attempts, observedErrors: [...observedErrors], lastResult })}`
  );
};

const postJson = async (url: string, payload: unknown, authToken?: string) => {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { "X-NKC-Controller-Token": authToken } : {}),
    },
    body: JSON.stringify(payload),
  });
  const body = (await response.json()) as {
    ok?: boolean;
    forwarded?: boolean;
    via?: string;
    error?: string;
  };
  return { status: response.status, body };
};

const sendOverTor = async (
  sender: OnionControllerHandle,
  recipientOnion: string,
  recipientInboxWriteToken: string,
  fromDeviceId: string,
  toDeviceId: string,
  envelope: string
) => {
  let lastResult: Awaited<ReturnType<typeof postJson>> | null = null;
  const maxAttempts = 5;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    lastResult = await postJson(
      `${sender.baseUrl}/onion/send`,
      {
        toDeviceId,
        fromDeviceId,
        toOnion: recipientOnion,
        envelope,
        route: {
          mode: "manual",
          torOnion: recipientOnion,
          inboxWriteToken: recipientInboxWriteToken,
        },
      },
      sender.authToken
    );
    if (
      lastResult.status === 200 &&
      lastResult.body.ok === true &&
      lastResult.body.forwarded === true &&
      lastResult.body.via === "tor"
    ) {
      return lastResult;
    }
    if (attempt < maxAttempts) {
      await sender.prewarmTorRoute(recipientOnion, { timeoutMs: 15_000 }).catch(() => null);
      await wait(Math.min(attempt * 5_000, 15_000));
    }
  }
  throw new Error(`Tor forwarding failed: ${JSON.stringify(lastResult)}`);
};

const readInbox = async (
  controller: OnionControllerHandle,
  deviceId: string,
  mailboxToken: string,
  after: string | null = null
) => {
  const params = new URLSearchParams({ deviceId });
  if (after) params.set("after", after);
  const response = await fetch(
    `${controller.baseUrl}/onion/inbox?${params}`,
    {
      headers: {
        "X-NKC-Controller-Token": controller.authToken,
        "X-NKC-Mailbox-Token": mailboxToken,
      },
    }
  );
  expect(response.status).toBe(200);
  return (await response.json()) as InboxResponse;
};

const requireFriendCode = (code: string) => {
  const decoded = decodeFriendCodeV1(code);
  if ("error" in decoded) throw new Error(decoded.error);
  if (!decoded.deviceId || !decoded.onionAddr || !decoded.inboxWriteToken) {
    throw new Error("Friend code is missing Tor routing metadata");
  }
  return decoded as FriendCodeV1 & {
    deviceId: string;
    onionAddr: string;
    inboxWriteToken: string;
  };
};

describe.runIf(LIVE_TOR_ENABLED)("live Tor bidirectional transfer", () => {
  let rootA: string;
  let rootB: string;
  let torA: TorManager;
  let torASecondary: TorManager | null = null;
  let torATertiary: TorManager | null = null;
  let torB: TorManager;
  let nativeWorker: NativeWorkerClient;
  let controllerA: OnionControllerHandle;
  let controllerB: OnionControllerHandle;
  let onionA: string;
  let onionB: string;
  let friendCodeA: string;
  let friendCodeB: string;
  let mailboxTokenA: string;
  let mailboxTokenB: string;
  let identityPrivA: Uint8Array;
  let identityPrivB: Uint8Array;
  let dhPrivA: Uint8Array;
  let dhPrivB: Uint8Array;
  let torProxyA: string;
  let torProxyASecondary: string | null = null;
  let torProxyATertiary: string | null = null;

  beforeAll(async () => {
    rootA = await fs.mkdtemp(path.join(os.tmpdir(), "nkc-live-tor-a-"));
    rootB = await fs.mkdtemp(path.join(os.tmpdir(), "nkc-live-tor-b-"));
    const workerExecutable =
      process.env.NKC_GO_WORKER_PATH ||
      path.join(
        process.cwd(),
        "native",
        "bin",
        process.platform === "win32" ? "nkc-worker.exe" : "nkc-worker"
      );
    nativeWorker = new NativeWorkerClient(workerExecutable);
    await nativeWorker.start();
    const socksTransport = createNativeSocksTransport(nativeWorker);
    torA = new TorManager({ appDataDir: rootA });
    torB = new TorManager({ appDataDir: rootB });
    controllerA = await startOnionController({
      port: 0,
      getTorStatus: () => torA.getStatus(),
      socksTransport,
    });
    controllerB = await startOnionController({
      port: 0,
      getTorStatus: () => torB.getStatus(),
      socksTransport,
    });
    const [mailboxA, mailboxB] = await Promise.all([
      controllerA.registerMailbox(DEVICE_A),
      controllerB.registerMailbox(DEVICE_B),
    ]);
    if (!mailboxA.ok || !mailboxA.inboxWriteToken) {
      throw new Error(`Failed to register mailbox A: ${mailboxA.error ?? "missing-token"}`);
    }
    if (!mailboxB.ok || !mailboxB.inboxWriteToken) {
      throw new Error(`Failed to register mailbox B: ${mailboxB.error ?? "missing-token"}`);
    }
    mailboxTokenA = mailboxA.inboxWriteToken;
    mailboxTokenB = mailboxB.inboxWriteToken;

    // Start sequentially so each manager observes the SOCKS port held by the previous instance.
    const serviceA = await torA.ensureHiddenService({ localPort: controllerA.port, virtPort: 80 });
    const serviceB = await torB.ensureHiddenService({ localPort: controllerB.port, virtPort: 80 });
    onionA = serviceA.onionHost;
    onionB = serviceB.onionHost;

    const statusA = torA.getStatus();
    const statusB = torB.getStatus();
    if (statusA.state !== "running" || statusB.state !== "running") {
      throw new Error(`Tor did not start: ${JSON.stringify({ statusA, statusB })}`);
    }
    const requestedLanes = Math.max(
      1,
      Math.min(3, Number.parseInt(process.env.NKC_LIVE_TOR_SEND_WINDOW ?? "1", 10) || 1)
    );
    if (requestedLanes >= 2) {
      torASecondary = new TorManager({ appDataDir: rootA, instanceId: "lane-2" });
      await torASecondary.start();
      const secondaryStatus = torASecondary.getStatus();
      if (secondaryStatus.state !== "running") {
        throw new Error(`Secondary Tor lane did not start: ${JSON.stringify(secondaryStatus)}`);
      }
      torProxyASecondary = secondaryStatus.socksProxyUrl;
    }
    if (requestedLanes >= 3) {
      torATertiary = new TorManager({ appDataDir: rootA, instanceId: "lane-3" });
      await torATertiary.start();
      const tertiaryStatus = torATertiary.getStatus();
      if (tertiaryStatus.state !== "running") {
        throw new Error(`Tertiary Tor lane did not start: ${JSON.stringify(tertiaryStatus)}`);
      }
      torProxyATertiary = tertiaryStatus.socksProxyUrl;
    }
    await controllerA.setTorSocksProxies(
      [statusA.socksProxyUrl, torProxyASecondary, torProxyATertiary].filter(
        (value): value is string => Boolean(value)
      )
    );
    await controllerB.setTorSocksProxy(statusB.socksProxyUrl);
    controllerA.setTorOnionHost(onionA);
    controllerB.setTorOnionHost(onionB);
    torProxyA = statusA.socksProxyUrl;
    const localHealth = await Promise.all([
      fetch(`${controllerA.baseUrl}/onion/health`),
      fetch(`${controllerB.baseUrl}/onion/health`),
    ]);
    expect(localHealth.map((response) => response.status)).toEqual([200, 200]);

    const routeResults = await Promise.allSettled([
      waitForTorRoute(controllerA, onionB),
      waitForTorRoute(controllerB, onionA),
    ]);
    const routeFailures = routeResults.flatMap((result) =>
      result.status === "rejected"
        ? [result.reason instanceof Error ? result.reason.message : String(result.reason)]
        : []
    );
    if (routeFailures.length > 0) {
      throw new Error(
        `Tor hidden-service readiness failed: ${JSON.stringify({
          routeFailures,
          torA: torA.getDiagnostics(),
          torB: torB.getDiagnostics(),
          localControllersReachable: true,
        })}`
      );
    }
    const [routeAtoB, routeBtoA] = routeResults.map((result) =>
      result.status === "fulfilled" ? result.value : null
    );
    console.info("Tor hidden services reachable", {
      routeAtoBMs: routeAtoB?.totalElapsedMs,
      routeBtoAMs: routeBtoA?.totalElapsedMs,
      routeAtoBAttempts: routeAtoB?.attempts,
      routeBtoAAttempts: routeBtoA?.attempts,
    });

    const sodium = await getSodium();
    const identityA = sodium.crypto_sign_keypair();
    const identityB = sodium.crypto_sign_keypair();
    const dhA = sodium.crypto_kx_keypair();
    const dhB = sodium.crypto_kx_keypair();
    identityPrivA = identityA.privateKey;
    identityPrivB = identityB.privateKey;
    dhPrivA = dhA.privateKey;
    dhPrivB = dhB.privateKey;
    friendCodeA = encodeFriendCodeV1({
      v: 1,
      identityPub: encodeBase64Url(identityA.publicKey),
      dhPub: encodeBase64Url(dhA.publicKey),
      deviceId: DEVICE_A,
      onionAddr: onionA,
      inboxWriteToken: mailboxTokenA,
    });
    friendCodeB = encodeFriendCodeV1({
      v: 1,
      identityPub: encodeBase64Url(identityB.publicKey),
      dhPub: encodeBase64Url(dhB.publicKey),
      deviceId: DEVICE_B,
      onionAddr: onionB,
      inboxWriteToken: mailboxTokenB,
    });
  }, LIVE_TOR_LARGE_ENABLED ? 660_000 : 360_000);

  afterAll(async () => {
    await Promise.allSettled([
      controllerA?.close(),
      controllerB?.close(),
      torA?.stop(),
      torASecondary?.stop(),
      torATertiary?.stop(),
      torB?.stop(),
      nativeWorker?.stop(),
    ]);
    await Promise.allSettled([
      rootA ? fs.rm(rootA, { recursive: true, force: true }) : Promise.resolve(),
      rootB ? fs.rm(rootB, { recursive: true, force: true }) : Promise.resolve(),
    ]);
  }, 30_000);

  it.skipIf(LIVE_TOR_ONLY_LARGE)(
    "uses friend codes to establish trust and exchange a file and chat through real onion services",
    async () => {
      expect(onionA).toMatch(/^[a-z2-7]{56}\.onion$/);
      expect(onionB).toMatch(/^[a-z2-7]{56}\.onion$/);
      expect(friendCodeA).toMatch(/^NKC1-/);
      expect(friendCodeB).toMatch(/^NKC1-/);

      const alice = requireFriendCode(friendCodeA);
      const bob = requireFriendCode(friendCodeB);
      expect(alice).toMatchObject({ deviceId: DEVICE_A, onionAddr: onionA });
      expect(bob).toMatchObject({ deviceId: DEVICE_B, onionAddr: onionB });

      const unsignedRequest: UnsignedFriendControlFrame = {
        type: "friend_req",
        traceId: randomUUID(),
        from: {
          identityPub: alice.identityPub,
          dhPub: alice.dhPub,
          deviceId: alice.deviceId,
          friendCode: friendCodeA,
        },
        profile: { displayName: "Alice", status: "Tor live friend request" },
        ts: Date.now(),
      };
      const enrichedRequest = await enrichFriendControlFrameWithProtocol(
        unsignedRequest,
        identityPrivA,
        {
          localFriendCode: friendCodeA,
          localDhPriv: dhPrivA,
          remoteFriendCode: friendCodeB,
          remoteIdentityPub: bob.identityPub,
          remoteDhPub: bob.dhPub,
          remoteDeviceId: bob.deviceId,
          remoteOnionAddr: bob.onionAddr,
        }
      );
      const friendRequest: FriendControlFrame = {
        ...enrichedRequest,
        sig: await signFriendControlFrame(enrichedRequest, identityPrivA),
      } as FriendControlFrame;
      await sendOverTor(
        controllerA,
        bob.onionAddr,
        bob.inboxWriteToken,
        alice.deviceId,
        bob.deviceId,
        JSON.stringify(friendRequest)
      );
      const requestInbox = await readInbox(controllerB, bob.deviceId, bob.inboxWriteToken);
      const receivedRequest = JSON.parse(
        requestInbox.items.at(-1)?.envelope ?? "null"
      ) as FriendControlFrame;
      expect(receivedRequest).toMatchObject({ type: "friend_req", profile: { displayName: "Alice" } });
      expect(await verifyFriendControlFrameSignature(receivedRequest)).toBe(true);
      expect(await verifyFriendControlFrameProtocol(receivedRequest, {
        localFriendCode: friendCodeB,
        localDhPriv: dhPrivB,
      }))
        .toMatchObject({ ok: true, verified: true });

      const unsignedAccept: UnsignedFriendControlFrame = {
        type: "friend_accept",
        traceId: randomUUID(),
        from: {
          identityPub: bob.identityPub,
          dhPub: bob.dhPub,
          deviceId: bob.deviceId,
          friendCode: friendCodeB,
        },
        profile: { displayName: "Bob", status: "Tor live friend accepted" },
        ts: Date.now(),
      };
      const enrichedAccept = await enrichFriendControlFrameWithProtocol(
        unsignedAccept,
        identityPrivB,
        {
          localFriendCode: friendCodeB,
          localDhPriv: dhPrivB,
          remoteFriendCode: friendCodeA,
          remoteIdentityPub: alice.identityPub,
          remoteDhPub: alice.dhPub,
          remoteDeviceId: alice.deviceId,
          remoteOnionAddr: alice.onionAddr,
        }
      );
      const friendAccept: FriendControlFrame = {
        ...enrichedAccept,
        sig: await signFriendControlFrame(enrichedAccept, identityPrivB),
      } as FriendControlFrame;
      await sendOverTor(
        controllerB,
        alice.onionAddr,
        alice.inboxWriteToken,
        bob.deviceId,
        alice.deviceId,
        JSON.stringify(friendAccept)
      );
      const acceptInbox = await readInbox(controllerA, alice.deviceId, alice.inboxWriteToken);
      const receivedAccept = JSON.parse(
        acceptInbox.items.at(-1)?.envelope ?? "null"
      ) as FriendControlFrame;
      expect(receivedAccept).toMatchObject({ type: "friend_accept", profile: { displayName: "Bob" } });
      expect(await verifyFriendControlFrameSignature(receivedAccept)).toBe(true);
      expect(await verifyFriendControlFrameProtocol(receivedAccept, {
        localFriendCode: friendCodeA,
        localDhPriv: dhPrivA,
      }))
        .toMatchObject({ ok: true, verified: true });

      const fileBytes = Buffer.from(
        Array.from({ length: 32 * 1024 }, (_, index) => (index * 31 + 17) % 256)
      );
      const fileSha256 = createHash("sha256").update(fileBytes).digest("hex");
      const fileEnvelope = JSON.stringify({
        type: "file",
        name: "tor-live-roundtrip.bin",
        mime: "application/octet-stream",
        bytesBase64: fileBytes.toString("base64"),
        sha256: fileSha256,
      });
      const prewarmAtoB = await controllerA.prewarmTorRoute(bob.onionAddr);
      console.info("Tor prewarm A->B", prewarmAtoB);
      const fileStartedAt = Date.now();
      await sendOverTor(
        controllerA,
        bob.onionAddr,
        bob.inboxWriteToken,
        alice.deviceId,
        bob.deviceId,
        fileEnvelope
      );
      const fileTransferMs = Date.now() - fileStartedAt;

      const inboxB = await readInbox(controllerB, bob.deviceId, bob.inboxWriteToken);
      const receivedFile = JSON.parse(inboxB.items.at(-1)?.envelope ?? "null") as {
        type?: string;
        bytesBase64?: string;
        sha256?: string;
      } | null;
      expect(receivedFile?.type).toBe("file");
      expect(receivedFile?.sha256).toBe(fileSha256);
      expect(
        createHash("sha256")
          .update(Buffer.from(receivedFile?.bytesBase64 ?? "", "base64"))
          .digest("hex")
      ).toBe(fileSha256);

      const chatText = LIVE_TOR_CHAT_BYTES > 0
        ? "C".repeat(LIVE_TOR_CHAT_BYTES)
        : `Tor live reply ${Date.now()}`;
      const chatSha256 = createHash("sha256").update(chatText).digest("hex");
      const chatEnvelope = JSON.stringify({
        type: "chat",
        text: chatText,
      });
      const prewarmBtoA = await controllerB.prewarmTorRoute(alice.onionAddr);
      console.info("Tor prewarm B->A", prewarmBtoA);
      const chatStartedAt = Date.now();
      await sendOverTor(
        controllerB,
        alice.onionAddr,
        alice.inboxWriteToken,
        bob.deviceId,
        alice.deviceId,
        chatEnvelope
      );
      const chatTransferMs = Date.now() - chatStartedAt;

      const inboxA = await readInbox(controllerA, alice.deviceId, alice.inboxWriteToken);
      expect(inboxA.items.at(-1)).toMatchObject({ from: bob.deviceId, envelope: chatEnvelope });
      const receivedChat = JSON.parse(inboxA.items.at(-1)?.envelope ?? "null") as { text?: string };
      expect(createHash("sha256").update(receivedChat.text ?? "").digest("hex")).toBe(chatSha256);

      console.info(
        JSON.stringify({
          torConnected: true,
          friendRequestVerified: true,
          friendAcceptVerified: true,
          fileAtoB: true,
          fileBytes: fileBytes.length,
          fileSha256,
          prewarmAtoBMs: prewarmAtoB.elapsedMs,
          fileTransferMs,
          chatBtoA: true,
          chatBytes: Buffer.byteLength(chatText),
          chatSha256,
          prewarmBtoAMs: prewarmBtoA.elapsedMs,
          chatTransferMs,
        })
      );
    },
    300_000
  );

  it.runIf(LIVE_TOR_LARGE_ENABLED)(
    `streams ${LIVE_TOR_FILE_MB}MB in app-sized chunks, carries chat, and resumes after interruption`,
    async () => {
      const alice = requireFriendCode(friendCodeA);
      const bob = requireFriendCode(friendCodeB);
      const totalBytes = LIVE_TOR_FILE_MB * 1024 * 1024;
      const totalChunks = Math.ceil(totalBytes / LIVE_FILE_CHUNK_BYTES);
      const conversationKeyA = await deriveConversationKey(
        dhPrivA,
        decodeBase64Url(bob.dhPub)
      );
      const conversationKeyB = await deriveConversationKey(
        dhPrivB,
        decodeBase64Url(alice.dhPub)
      );
      expect(Buffer.from(conversationKeyB)).toEqual(Buffer.from(conversationKeyA));
      const senderHash = createHash("sha256");
      const receiverHash = createHash("sha256");
      const chunkDurations: number[] = [];
      const receivedEventIds = new Set<string>();
      let duplicateDeliveries = 0;
      let receivedBytes = 0;
      let inboxBCursor = (
        await readInbox(controllerB, bob.deviceId, bob.inboxWriteToken)
      ).nextAfter;
      let inboxACursor = (
        await readInbox(controllerA, alice.deviceId, alice.inboxWriteToken)
      ).nextAfter;
      let interruptionVerified = false;
      let chatTransferMs = 0;

      const prewarm = await controllerA.prewarmTorRoute(bob.onionAddr);
      expect(prewarm.ok).toBe(true);
      const transferStartedAt = Date.now();
      // Default to the reliable serial lane; explicit live benchmarks may compare two lanes.
      const requestedSendWindow = Number.parseInt(process.env.NKC_LIVE_TOR_SEND_WINDOW ?? "1", 10);
      const sendWindow = Math.max(1, Math.min(3, requestedSendWindow || 1));
      const progressEveryChunks = Math.max(
        1,
        Math.round((32 * 1024 * 1024) / LIVE_FILE_CHUNK_BYTES)
      );

      for (let windowStart = 0; windowStart < totalChunks; windowStart += sendWindow) {
        const windowEnd = Math.min(totalChunks, windowStart + sendWindow);
        const outgoing: Array<{ index: number; envelope: string }> = [];
        for (let index = windowStart; index < windowEnd; index += 1) {
          const offset = index * LIVE_FILE_CHUNK_BYTES;
          const length = Math.min(LIVE_FILE_CHUNK_BYTES, totalBytes - offset);
          const bytes = Buffer.allocUnsafe(length);
          for (let byteIndex = 0; byteIndex < length; byteIndex += 1) {
            bytes[byteIndex] = ((offset + byteIndex) * 31 + 17) & 0xff;
          }
          senderHash.update(bytes);
          const header: EnvelopeHeader = {
            v: 1,
            convId: "tor-live-large-file",
            eventId: randomUUID(),
            authorDeviceId: alice.deviceId,
            ts: Date.now(),
            lamport: index + 1,
          };
          const encrypted = await encryptEnvelope(
            conversationKeyA,
            header,
            {
              type: "media",
              phase: "chunk",
              ownerId: "tor-live-large-file",
              idx: index,
              total: totalChunks,
              chunkSize: LIVE_FILE_CHUNK_BYTES,
              mime: "application/octet-stream",
              name: "tor-live-large-file.bin",
              size: totalBytes,
              b64: encodeBase64Url(bytes),
            },
            identityPrivA
          );
          const envelope = JSON.stringify(encrypted);

          if (!interruptionVerified && index >= Math.floor(totalChunks / 2)) {
            const chatEnvelope = JSON.stringify({
              type: "chat",
              text: `chat-during-file-${Date.now()}`,
            });
            const chatStartedAt = Date.now();
            await sendOverTor(
              controllerB,
              alice.onionAddr,
              alice.inboxWriteToken,
              bob.deviceId,
              alice.deviceId,
              chatEnvelope
            );
            chatTransferMs = Date.now() - chatStartedAt;
            const chatInbox = await readInbox(
              controllerA,
              alice.deviceId,
              alice.inboxWriteToken,
              inboxACursor
            );
            inboxACursor = chatInbox.nextAfter;
            expect(chatInbox.items.at(-1)?.envelope).toBe(chatEnvelope);

            await controllerA.setTorSocksProxy(null);
            const pausedResult = await postJson(
              `${controllerA.baseUrl}/onion/send`,
              {
                toDeviceId: bob.deviceId,
                fromDeviceId: alice.deviceId,
                toOnion: bob.onionAddr,
                envelope,
                route: {
                  mode: "manual",
                  torOnion: bob.onionAddr,
                  inboxWriteToken: bob.inboxWriteToken,
                },
              },
              controllerA.authToken
            );
            expect(pausedResult.body.forwarded).not.toBe(true);
            await controllerA.setTorSocksProxies(
              [torProxyA, torProxyASecondary, torProxyATertiary].filter(
                (value): value is string => Boolean(value)
              )
            );
            const resumedPrewarm = await controllerA.prewarmTorRoute(bob.onionAddr);
            expect(resumedPrewarm.ok).toBe(true);
            interruptionVerified = true;
          }
          outgoing.push({ index, envelope });
        }

        await Promise.all(
          outgoing.map(async ({ envelope }) => {
            const chunkStartedAt = Date.now();
            await sendOverTor(
              controllerA,
              bob.onionAddr,
              bob.inboxWriteToken,
              alice.deviceId,
              bob.deviceId,
              envelope
            );
            chunkDurations.push(Date.now() - chunkStartedAt);
          })
        );

        const receivedByIndex = new Map<number, Buffer>();
        const receiveDeadline = Date.now() + 60_000;
        while (receivedByIndex.size < outgoing.length && Date.now() < receiveDeadline) {
          const inbox = await readInbox(
            controllerB,
            bob.deviceId,
            bob.inboxWriteToken,
            inboxBCursor
          );
          inboxBCursor = inbox.nextAfter;
          for (const item of inbox.items) {
            const receivedEnvelope = JSON.parse(item.envelope) as Envelope;
            if (receivedEventIds.has(receivedEnvelope.header.eventId)) {
              duplicateDeliveries += 1;
              continue;
            }
            receivedEventIds.add(receivedEnvelope.header.eventId);
            const candidate = await decryptEnvelope<{ idx: number; b64: string }>(
              conversationKeyB,
              receivedEnvelope,
              decodeBase64Url(alice.identityPub)
            );
            if (candidate.idx >= windowStart && candidate.idx < windowEnd) {
              receivedByIndex.set(candidate.idx, Buffer.from(decodeBase64Url(candidate.b64)));
            }
          }
          if (receivedByIndex.size < outgoing.length) await wait(25);
        }
        for (const { index } of outgoing) {
          const receivedChunk = receivedByIndex.get(index);
          if (!receivedChunk) throw new Error(`Missing unique chunk ${index}`);
          receiverHash.update(receivedChunk);
          receivedBytes += receivedChunk.length;
        }
        const completedChunks = windowEnd;
        if (completedChunks === totalChunks || completedChunks % progressEveryChunks === 0) {
          const elapsedMs = Date.now() - transferStartedAt;
          console.log(
            JSON.stringify({
              event: "tor-large-transfer-progress",
              completedMiB: Number((receivedBytes / (1024 * 1024)).toFixed(1)),
              totalMiB: LIVE_TOR_FILE_MB,
              percent: Number(((completedChunks / totalChunks) * 100).toFixed(1)),
              elapsedMs,
              throughputMiBps: Number(
                (receivedBytes / (1024 * 1024) / (elapsedMs / 1000)).toFixed(3)
              ),
            })
          );
        }
      }

      const transferMs = Date.now() - transferStartedAt;
      const sortedDurations = [...chunkDurations].sort((left, right) => left - right);
      const percentile = (value: number) =>
        sortedDurations[Math.min(sortedDurations.length - 1, Math.floor(sortedDurations.length * value))];
      const senderSha256 = senderHash.digest("hex");
      const receiverSha256 = receiverHash.digest("hex");

      expect(receivedBytes).toBe(totalBytes);
      expect(receiverSha256).toBe(senderSha256);
      expect(interruptionVerified).toBe(true);
      console.info(
        JSON.stringify({
          torLargeTransfer: true,
          fileMiB: LIVE_TOR_FILE_MB,
          chunks: totalChunks,
          chunkBytes: LIVE_FILE_CHUNK_BYTES,
          sendWindow,
          transferMs,
          throughputMiBps: Number((LIVE_TOR_FILE_MB / (transferMs / 1000)).toFixed(3)),
          chunkP50Ms: percentile(0.5),
          chunkP95Ms: percentile(0.95),
          chatDuringTransferMs: chatTransferMs,
          interruptionVerified,
          duplicateDeliveries,
          senderSha256,
          receiverSha256,
        })
      );
    },
    Math.max(10 * 60_000, LIVE_TOR_FILE_MB * 15_000)
  );
});
