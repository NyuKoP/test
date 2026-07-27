import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Transport } from "../../adapters/transports/types";
import type { OutboxRecord } from "../../db/schema";
import { encodeFriendCodeV1 } from "../../security/friendCode";
import { encodeBase64Url } from "../../security/base64url";

const createTransport = (
  name: Transport["name"] = "selfOnion",
  sendImpl?: () => Promise<void>
): Transport => {
  const transport: Transport = {
    name,
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn().mockResolvedValue(undefined),
    send: vi.fn(async () => {
      if (sendImpl) await sendImpl();
    }),
    onMessage: vi.fn(),
    onAck: vi.fn(),
    onState: vi.fn(),
  };
  return transport;
};

const TEST_CONFIG = {
  mode: "selfOnion",
  onionProxyEnabled: false,
  onionProxyUrl: "socks5://127.0.0.1:9050",
  webrtcRelayOnly: false,
  disableLinkPreview: false,
  selfOnionEnabled: true,
  selfOnionMinRelays: 3,
  allowRemoteProxy: false,
  onionEnabled: false,
  onionSelectedNetwork: "tor",
  tor: { installed: false, status: "idle" },
  lastUpdateCheckAtMs: undefined,
} as const;

describe("router routing metadata", () => {
  let resetRouter: (() => void) | null = null;

  beforeEach(() => {
    vi.resetModules();
    resetRouter = null;
  });

  afterEach(() => {
    resetRouter?.();
  });

  it("replaces stale outbox alias target with the latest friend deviceId", async () => {
    const updateOutbox = vi.fn(async () => {});
    vi.doMock("../../storage/outboxStore", () => ({
      putOutbox: async () => {},
      updateOutbox,
      deleteOutbox: async () => {},
      deleteExpiredOutbox: async () => 0,
    }));

    const { useAppStore } = await import("../../app/store");
    useAppStore.getState().setData({
      user: {
        id: "me",
        displayName: "me",
        status: "",
        theme: "dark",
        kind: "user",
      },
      friends: [
        {
          id: "friend-profile-id",
          friendId: "friend-public-id",
          primaryDeviceId: "123e4567-e89b-42d3-a456-426614174000",
          displayName: "friend",
          status: "",
          theme: "dark",
          kind: "friend",
        },
      ],
      convs: [
        {
          id: "conv-1",
          type: "direct",
          name: "dm",
          pinned: false,
          unread: 0,
          hidden: false,
          muted: false,
          blocked: false,
          lastTs: Date.now(),
          lastMessage: "",
          participants: ["me", "friend-profile-id"],
        },
      ],
      messagesByConv: {},
    });

    const router = await import("../router");
    resetRouter = router.__testResetRouter;

    const selfOnionTransport = createTransport("selfOnion");
    const record: OutboxRecord = {
      id: "msg-1",
      convId: "conv-1",
      ciphertext: "enc",
      toDeviceId: "friend-public-id",
      createdAtMs: Date.now(),
      expiresAtMs: Date.now() + 60_000,
      nextAttemptAtMs: Date.now(),
      attempts: 1,
      status: "pending",
    };

    const result = await router.sendOutboxRecord(record, {
      config: TEST_CONFIG,
      resolveTransport: () => "selfOnion",
      transports: { selfOnion: selfOnionTransport },
    });

    expect(result.ok).toBe(true);
    expect(updateOutbox).toHaveBeenCalledWith(
      "msg-1",
      expect.objectContaining({
        toDeviceId: "123e4567-e89b-42d3-a456-426614174000",
      })
    );
    const sentPacket = (
      selfOnionTransport.send as unknown as { mock?: { calls?: unknown[][] } }
    ).mock?.calls?.[0]?.[0] as { toDeviceId?: string } | undefined;
    expect(sentPacket?.toDeviceId).toBe("123e4567-e89b-42d3-a456-426614174000");
  });

  it("recovers outbox routing metadata from friendCode when stored deviceId is missing", async () => {
    const updateOutbox = vi.fn(async () => {});
    vi.doMock("../../storage/outboxStore", () => ({
      putOutbox: async () => {},
      updateOutbox,
      deleteOutbox: async () => {},
      deleteExpiredOutbox: async () => 0,
    }));

    const { useAppStore } = await import("../../app/store");
    const identityPub = encodeBase64Url(new Uint8Array(32).fill(7));
    const dhPub = encodeBase64Url(new Uint8Array(32).fill(8));
    const inboxWriteToken = encodeBase64Url(new Uint8Array(32).fill(9));
    const friendCode = encodeFriendCodeV1({
      v: 1,
      identityPub,
      dhPub,
      deviceId: "987e6543-e21b-42d3-a456-426614174999",
      onionAddr: "peer-recovered.onion",
      inboxWriteToken,
    });
    useAppStore.getState().setData({
      user: {
        id: "me",
        displayName: "me",
        status: "",
        theme: "dark",
        kind: "user",
      },
      friends: [
        {
          id: "friend-profile-id",
          friendId: "friend-public-id",
          displayName: "friend",
          status: "",
          theme: "dark",
          kind: "friend",
          profileVcard: { friendCode, updatedAt: Date.now() },
        },
      ],
      convs: [
        {
          id: "conv-2",
          type: "direct",
          name: "dm",
          pinned: false,
          unread: 0,
          hidden: false,
          muted: false,
          blocked: false,
          lastTs: Date.now(),
          lastMessage: "",
          participants: ["me", "friend-profile-id"],
        },
      ],
      messagesByConv: {},
    });

    const router = await import("../router");
    resetRouter = router.__testResetRouter;

    const onionRouterTransport = createTransport("onionRouter");
    const record: OutboxRecord = {
      id: "msg-2",
      convId: "conv-2",
      ciphertext: "enc",
      createdAtMs: Date.now(),
      expiresAtMs: Date.now() + 60_000,
      nextAttemptAtMs: Date.now(),
      attempts: 1,
      status: "pending",
    };

    const result = await router.sendOutboxRecord(record, {
      config: TEST_CONFIG,
      resolveTransport: () => "selfOnion",
      transports: { onionRouter: onionRouterTransport },
    });

    expect(result.ok).toBe(true);
    expect(updateOutbox).toHaveBeenCalledWith(
      "msg-2",
      expect.objectContaining({
        toDeviceId: "987e6543-e21b-42d3-a456-426614174999",
        torOnion: "peer-recovered.onion",
      })
    );
    const sentPacket = (
      onionRouterTransport.send as unknown as { mock?: { calls?: unknown[][] } }
    ).mock?.calls?.[0]?.[0] as {
      toDeviceId?: string;
      route?: { torOnion?: string; inboxWriteToken?: string };
    } | undefined;
    expect(sentPacket?.toDeviceId).toBe("987e6543-e21b-42d3-a456-426614174999");
    expect(sentPacket?.route).toEqual({
      torOnion: "peer-recovered.onion",
      inboxWriteToken,
    });
  });
});
