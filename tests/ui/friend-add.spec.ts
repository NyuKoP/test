import http from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import { test, expect } from "@playwright/test";
import {
  disableAnimations,
  enableFriendFlowCapture,
  ensureOnboarded,
  filterFriendFlowLogsByAction,
  readFriendFlowLogs,
  resetFriendFlowLogs,
} from "./helpers";

type OnionInboxItem = {
  id: string;
  ts: number;
  from: string;
  envelope: string;
};

type OnionTestServer = {
  baseUrl: string;
  getInboxCount: (deviceId: string) => number;
  registerMailbox: (
    deviceId: string
  ) => { ok: boolean; inboxWriteToken?: string; error?: string };
  close: () => Promise<void>;
};

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const applyCors = (res: http.ServerResponse) => {
  Object.entries(CORS_HEADERS).forEach(([key, value]) => res.setHeader(key, value));
};

const sendJson = (res: http.ServerResponse, status: number, payload: unknown) => {
  applyCors(res);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(payload));
};

const readBody = (req: http.IncomingMessage) =>
  new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });

const startOnionTestServer = async (): Promise<OnionTestServer> => {
  const inbox = new Map<string, OnionInboxItem[]>();
  const mailboxTokens = new Map<string, string>();

  const server = http.createServer(async (req, res) => {
    if (req.method === "OPTIONS") {
      applyCors(res);
      res.statusCode = 204;
      res.end();
      return;
    }

    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method === "GET" && url.pathname === "/onion/health") {
      sendJson(res, 200, { ok: true, network: "none", details: "local-only mode" });
      return;
    }

    if (req.method === "GET" && url.pathname === "/onion/inbox") {
      const deviceId = url.searchParams.get("deviceId") ?? "";
      if (!deviceId) {
        sendJson(res, 400, { ok: false, items: [], nextAfter: null, error: "missing-device" });
        return;
      }
      const expectedToken = mailboxTokens.get(deviceId);
      const suppliedToken = req.headers["x-nkc-mailbox-token"];
      if (!expectedToken || suppliedToken !== expectedToken) {
        sendJson(res, 403, {
          ok: false,
          items: [],
          nextAfter: null,
          error: "mailbox-read-capability-required",
        });
        return;
      }
      const afterRaw = url.searchParams.get("after");
      const after = afterRaw ? Number.parseInt(afterRaw, 10) : -1;
      const start = Number.isFinite(after) ? after + 1 : 0;
      const limitRaw = url.searchParams.get("limit");
      const limit = limitRaw ? Math.max(1, Number.parseInt(limitRaw, 10)) : 50;
      const list = inbox.get(deviceId) ?? [];
      const slice = list.slice(start, start + limit);
      const nextAfter = slice.length > 0 ? String(start + slice.length - 1) : afterRaw ?? null;
      sendJson(res, 200, { ok: true, items: slice, nextAfter });
      return;
    }

    if (req.method === "POST" && url.pathname === "/onion/send") {
      let parsed: {
        toDeviceId?: string;
        fromDeviceId?: string;
        envelope?: string;
        route?: { inboxWriteToken?: string };
      };
      try {
        parsed = JSON.parse(await readBody(req)) as {
          toDeviceId?: string;
          fromDeviceId?: string;
          envelope?: string;
          route?: { inboxWriteToken?: string };
        };
      } catch {
        sendJson(res, 400, { ok: false, error: "invalid-json" });
        return;
      }

      if (!parsed.toDeviceId || !parsed.envelope) {
        sendJson(res, 400, { ok: false, error: "missing-fields" });
        return;
      }
      const expectedToken = mailboxTokens.get(parsed.toDeviceId);
      if (!expectedToken || parsed.route?.inboxWriteToken !== expectedToken) {
        sendJson(res, 401, { ok: false, error: "invalid-mailbox-capability" });
        return;
      }

      const id = randomUUID();
      const ts = Date.now();
      const items = inbox.get(parsed.toDeviceId) ?? [];
      items.push({
        id,
        ts,
        from: parsed.fromDeviceId ?? "",
        envelope: parsed.envelope,
      });
      inbox.set(parsed.toDeviceId, items);
      sendJson(res, 200, { ok: true, msgId: id, forwarded: false });
      return;
    }

    sendJson(res, 404, { ok: false, error: "not-found" });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Failed to start onion test server");
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    baseUrl,
    getInboxCount: (deviceId: string) => inbox.get(deviceId)?.length ?? 0,
    registerMailbox: (deviceId: string) => {
      const normalized = deviceId.trim();
      if (!normalized) return { ok: false, error: "invalid-device-id" };
      const existing = mailboxTokens.get(normalized);
      if (existing) return { ok: true, inboxWriteToken: existing };
      const inboxWriteToken = randomBytes(32).toString("base64url");
      mailboxTokens.set(normalized, inboxWriteToken);
      return { ok: true, inboxWriteToken };
    },
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
};

const encodeBase64Url = (bytes: Uint8Array) =>
  Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

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

const canonicalize = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }
  if (value && typeof value === "object") {
    const sortedKeys = Object.keys(value as Record<string, unknown>).sort();
    const next: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      next[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return next;
  }
  return value;
};

const makeFriendCode = () => {
  const identityPub = randomBytes(32);
  const dhPub = randomBytes(32);
  const deviceId = randomUUID();
  const payload = {
    v: 1 as const,
    identityPub: encodeBase64Url(identityPub),
    dhPub: encodeBase64Url(dhPub),
    deviceId,
  };
  const payloadBytes = Buffer.from(JSON.stringify(canonicalize(payload)), "utf8");
  const checksum = hash32Bytes(payloadBytes).slice(0, 4);
  const combined = Buffer.concat([payloadBytes, Buffer.from(checksum)]);
  const friendCode = `NKC1-${encodeBase64Url(combined)}`;
  const friendId = encodeBase64Url(hash32Bytes(identityPub)).slice(0, 16);
  return { friendCode, expectedDisplayName: `Friend ${friendId.slice(0, 6)}` };
};

const seedNetworkConfig = async (
  page: import("@playwright/test").Page,
  onionServer: OnionTestServer,
  options?: {
    serviceAddress?: string;
    mode?: "onionRouter" | "selfOnion";
  }
) => {
  await page.exposeFunction(
    "__nkcE2EControllerFetch",
    async (req: {
      url: string;
      method: string;
      headers?: Record<string, string>;
      bodyBase64?: string;
    }) => {
      const response = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.bodyBase64 ? Buffer.from(req.bodyBase64, "base64") : undefined,
      });
      const body = Buffer.from(await response.arrayBuffer());
      return {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        bodyBase64: body.toString("base64"),
      };
    }
  );
  await page.exposeFunction("__nkcE2ERegisterMailbox", async (deviceId: string) =>
    onionServer.registerMailbox(deviceId)
  );
  await page.addInitScript(({ url, serviceAddress, mode }) => {
    const secureStoragePrefix = "nkc-e2e-secure-storage:";
    Object.defineProperty(window, "electron", {
      configurable: true,
      value: {
        secureStorage: {
          isAvailable: async () => true,
          get: async (key: string) => localStorage.getItem(`${secureStoragePrefix}${key}`),
          set: async (key: string, value: string) => {
            localStorage.setItem(`${secureStoragePrefix}${key}`, value);
            return true;
          },
          remove: async (key: string) => {
            localStorage.removeItem(`${secureStoragePrefix}${key}`);
            return true;
          },
        },
      },
    });
    const bridge = window as typeof window & {
      __nkcE2EControllerFetch: (req: {
        url: string;
        method: string;
        headers?: Record<string, string>;
        bodyBase64?: string;
      }) => Promise<unknown>;
      __nkcE2ERegisterMailbox: (
        deviceId: string
      ) => Promise<{ ok: boolean; inboxWriteToken?: string; error?: string }>;
    };
    Object.defineProperty(window, "nkc", {
      configurable: true,
      value: {
        getOnionControllerUrl: async () => url,
        onionControllerFetch: (req: {
          url: string;
          method: string;
          headers?: Record<string, string>;
          bodyBase64?: string;
        }) => bridge.__nkcE2EControllerFetch(req),
        registerOnionMailbox: (deviceId: string) =>
          bridge.__nkcE2ERegisterMailbox(deviceId),
        ensureHiddenService: async () => ({ ok: true }),
        getMyOnionAddress: async () => serviceAddress ?? "",
        prewarmOnionRoute: async () => ({ ok: true, elapsedMs: 1 }),
        startTor: async () => ({ ok: true }),
        stopTor: async () => ({ ok: true }),
        getTorStatus: async () => ({ state: "running", socksProxyUrl: "socks5://127.0.0.1:9050" }),
        checkSocksProxyReachable: async () => true,
        setOnionForwardProxy: async () => ({ ok: true }),
      },
    });
    localStorage.setItem(
      "netConfig.v1",
      JSON.stringify({
        mode,
        onionProxyEnabled: mode === "onionRouter",
        onionProxyUrl: "http://127.0.0.1:8080",
        webrtcRelayOnly: mode === "onionRouter",
        disableLinkPreview: mode === "onionRouter",
        selfOnionEnabled: true,
        selfOnionMinRelays: 3,
        allowRemoteProxy: false,
        onionEnabled: mode === "onionRouter",
        onionSelectedNetwork: "tor",
        tor: { installed: true, status: "ready" },
      })
    );
    localStorage.setItem("onion_controller_url_v1", url);
  }, {
    url: onionServer.baseUrl,
    serviceAddress: options?.serviceAddress ?? "",
    mode: options?.mode ?? "onionRouter",
  });
};

const onboardAs = async (page: import("@playwright/test").Page, displayName: string) => {
  const createButton = page.getByTestId("onboarding-create-button");
  if (await createButton.isVisible()) {
    await page.getByTestId("onboarding-display-name").fill(displayName);
    await page.getByTestId("onboarding-confirm-checkbox").check();
    await createButton.click();
  }
  await expect(page.getByTestId("open-settings")).toBeVisible();
};

const openFriendAddDialog = async (page: import("@playwright/test").Page) => {
  await page.getByTestId("list-mode-friends").click();
  await page.getByRole("button", { name: /친구 추가|Add friend/i }).first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
};

const readOwnFriendCode = async (page: import("@playwright/test").Page) => {
  await openFriendAddDialog(page);
  const input = page.getByTestId("friend-add-my-code");
  await expect.poll(async () => input.inputValue()).toMatch(/^NKC1-/);
  const code = await input.inputValue();
  await page.getByRole("button", { name: /닫기|Close/i }).click();
  return code;
};

const addFriendCode = async (page: import("@playwright/test").Page, code: string) => {
  await openFriendAddDialog(page);
  await page.getByTestId("friend-add-code-input").fill(code);
  await page.getByTestId("friend-add-submit").click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
};

const decodeFriendCodePayload = (code: string) => {
  const raw = code.replace(/^NKC1-/i, "");
  const normalized = raw.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const decoded = Buffer.from(padded, "base64");
  return JSON.parse(decoded.slice(0, -4).toString("utf8")) as {
    deviceId?: string;
    onionAddr?: string;
  };
};

test.describe("Friend add E2E", () => {
  let onionServer: OnionTestServer;

  test.beforeAll(async () => {
    onionServer = await startOnionTestServer();
  });

  test.afterAll(async () => {
    await onionServer.close();
  });

  test("adds friend and shows it in friend list", async ({ page }) => {
    const { friendCode, expectedDisplayName } = makeFriendCode();
    await seedNetworkConfig(page, onionServer);
    await enableFriendFlowCapture(page);

    await page.goto("/");
    await disableAnimations(page);
    await ensureOnboarded(page);
    await resetFriendFlowLogs(page);

    await page.getByTestId("list-mode-friends").click();
    await page.getByRole("button", { name: /친구 추가|Add friend/i }).first().click();

    const dialog = page.getByRole("dialog");
    const friendCodeInput = dialog
      .locator("label", { hasText: /친구 코드|Friend code/i })
      .locator("input");
    await friendCodeInput.fill(friendCode);

    await dialog.getByRole("button", { name: /^친구 추가$|^Add friend$/i }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);

    await page.getByTestId("list-mode-friends").click();
    await expect(page.getByTestId("sidebar").getByText(expectedDisplayName, { exact: true })).toBeVisible();

    await expect
      .poll(async () => {
        const logs = await readFriendFlowLogs(page);
        const addLogs = filterFriendFlowLogsByAction(logs, "add");
        return addLogs.length;
      })
      .toBeGreaterThan(0);

    await expect
      .poll(async () => {
        const logs = await readFriendFlowLogs(page);
        const addLogs = filterFriendFlowLogsByAction(logs, "add");
        const events = addLogs
          .map((record) => record.event)
          .filter((event): event is { result?: unknown; stage?: unknown } => {
            return Boolean(event && typeof event === "object");
          });
        const startIndex = events.findIndex(
          (event) => event.result === "progress" && event.stage === "progress:start"
        );
        const doneIndex = events.findIndex(
          (event) =>
            event.result === "added" &&
            typeof event.stage === "string" &&
            event.stage.startsWith("result:added-")
        );
        return startIndex >= 0 && doneIndex > startIndex;
      })
      .toBe(true);
  });

  const runMutualEndpointExchange = async (
    browser: import("@playwright/test").Browser,
    mode: "onionRouter" | "selfOnion" = "onionRouter"
  ) => {
    const aliceContext = await browser.newContext();
    const bobContext = await browser.newContext();
    const alice = await aliceContext.newPage();
    const bob = await bobContext.newPage();
    const aliceServiceAddress = `${"a".repeat(56)}.onion`;
    const bobServiceAddress = `${"b".repeat(56)}.onion`;
    await seedNetworkConfig(alice, onionServer, {
      serviceAddress: aliceServiceAddress,
      mode,
    });
    await seedNetworkConfig(bob, onionServer, {
      serviceAddress: bobServiceAddress,
      mode,
    });
    await enableFriendFlowCapture(alice);
    await enableFriendFlowCapture(bob);

    try {
      await alice.goto("/");
      await bob.goto("/");
      await disableAnimations(alice);
      await disableAnimations(bob);
      await onboardAs(alice, "Alice");
      await onboardAs(bob, "Bob");
      await resetFriendFlowLogs(alice);
      await resetFriendFlowLogs(bob);

      const aliceCode = await readOwnFriendCode(alice);
      const bobCode = await readOwnFriendCode(bob);
      const alicePayload = decodeFriendCodePayload(aliceCode);
      expect(alicePayload.onionAddr).toBe(aliceServiceAddress);
      const bobPayload = decodeFriendCodePayload(bobCode);
      expect(bobPayload.onionAddr).toBe(bobServiceAddress);
      expect(bobPayload.deviceId).toBeTruthy();

      const friendRequestStartedAt = Date.now();
      await addFriendCode(alice, bobCode);
      await expect
        .poll(() => onionServer.getInboxCount(bobPayload.deviceId ?? ""), { timeout: 10_000 })
        .toBeGreaterThan(0);
      await expect
        .poll(async () => {
          await bob.getByTestId("list-mode-friends").click();
          return bob.getByTestId("sidebar").getByText("Alice", { exact: true }).count();
        }, { timeout: 30_000 })
        .toBeGreaterThan(0);
      expect(Date.now() - friendRequestStartedAt).toBeLessThan(10_000);

      await bob.getByTestId("sidebar").getByText("Alice", { exact: true }).first().click();
      const requestProfile = bob.getByTestId("message-request-profile");
      await expect(requestProfile).toBeVisible();
      await expect(requestProfile.getByText("Alice", { exact: true })).toBeVisible();
      await requestProfile.getByRole("button", { name: "안전 팁" }).click();
      await expect(bob.getByTestId("message-request-safety-tips")).toBeVisible();
      await expect(bob.getByRole("button", { name: "차단", exact: true })).toBeVisible();
      await expect(bob.getByRole("button", { name: "신고", exact: true })).toHaveCount(0);
      await expect(bob.getByTestId("chat-message-input")).toHaveCount(0);
      const friendAcceptStartedAt = Date.now();
      await expect(bob.getByRole("button", { name: "수락", exact: true })).toBeVisible();
      await bob.getByRole("button", { name: "수락", exact: true }).click();
      await expect
        .poll(() => onionServer.getInboxCount(alicePayload.deviceId ?? ""), { timeout: 10_000 })
        .toBeGreaterThan(0);
      await expect
        .poll(async () => {
          const logs = await readFriendFlowLogs(alice);
          return logs.some((record) => {
            if (record.channel !== "friend-route") return false;
            const event = record.event as {
              direction?: unknown;
              status?: unknown;
              frameType?: unknown;
            };
            return (
              event.direction === "incoming" &&
              event.status === "handled" &&
              event.frameType === "friend_accept"
            );
          });
        }, { timeout: 30_000 })
        .toBe(true);
      expect(Date.now() - friendAcceptStartedAt).toBeLessThan(10_000);

      await expect
        .poll(async () => {
          await alice.getByTestId("list-mode-friends").click();
          return alice.getByTestId("sidebar").getByText("Bob", { exact: true }).count();
        }, { timeout: 30_000 })
        .toBeGreaterThan(0);
      await expect
        .poll(async () => {
          const aliceLogs = await readFriendFlowLogs(alice);
          const bobLogs = await readFriendFlowLogs(bob);
          return [...aliceLogs, ...bobLogs].some((record) => {
            if (record.channel !== "friend-route") return false;
            const event = record.event as { status?: unknown; frameType?: unknown };
            return (
              event.status === "sent" &&
              (event.frameType === "friend_req" || event.frameType === "friend_accept")
            );
          });
        })
        .toBe(true);

      const receivedMessage = `Alice to Bob ${randomUUID()}`;
      await alice.getByTestId("sidebar").getByText("Bob", { exact: true }).first().click();
      await expect(alice.getByTestId("chat-message-input")).toBeVisible();
      await alice.getByTestId("chat-message-input").fill(receivedMessage);
      await alice.getByTestId("chat-send-button").click();

      await expect
        .poll(async () => {
          await bob.getByTestId("list-mode-friends").click();
          await bob.getByTestId("sidebar").getByText("Alice", { exact: true }).first().click();
          return bob
            .getByTestId("chat-view")
            .getByText(receivedMessage, { exact: true })
            .count();
        }, { timeout: 30_000 })
        .toBeGreaterThan(0);
    } finally {
      await aliceContext.close();
      await bobContext.close();
    }
  };

  test("mutual endpoint exchange completes over onion controller (tor mode)", async ({
    browser,
  }) => {
    await runMutualEndpointExchange(browser);
  });

  test("first friend exchange bootstraps over Tor from default selfOnion mode", async ({
    browser,
  }) => {
    await runMutualEndpointExchange(browser, "selfOnion");
  });
});
