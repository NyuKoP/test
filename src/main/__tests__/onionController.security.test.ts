import { afterEach, describe, expect, it } from "vitest";
import { startOnionController, type OnionControllerHandle } from "../onionController";

let controller: OnionControllerHandle | null = null;

afterEach(async () => {
  await controller?.close();
  controller = null;
});

const request = (path: string, init?: RequestInit) =>
  fetch(`${controller?.baseUrl}${path}`, init);

const authorizedHeaders = () => ({
  "Content-Type": "application/json",
  "X-NKC-Controller-Token": controller?.authToken ?? "",
});

describe("onion controller security boundary", () => {
  it("blocks browser-origin requests and unauthenticated local routes", async () => {
    controller = await startOnionController({ port: 0 });

    const browserResponse = await request("/onion/health", {
      headers: { Origin: "https://attacker.example" },
    });
    expect(browserResponse.status).toBe(403);
    expect(browserResponse.headers.get("access-control-allow-origin")).toBeNull();

    const unauthenticatedResponse = await request("/onion/address");
    expect(unauthenticatedResponse.status).toBe(401);

    const authenticatedResponse = await request("/onion/address", {
      headers: authorizedHeaders(),
    });
    expect(authenticatedResponse.status).toBe(200);
  });

  it("accepts a valid mailbox capability and drains acknowledged inbox entries", async () => {
    controller = await startOnionController({ port: 0 });
    const mailbox = await controller.registerMailbox("device-a");
    expect(mailbox.ok).toBe(true);

    const ingestResponse = await request("/onion/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: "same-delivery-id",
        toDeviceId: "device-a",
        from: "peer-a",
        envelope: "ciphertext",
        inboxWriteToken: mailbox.inboxWriteToken,
      }),
    });
    expect(ingestResponse.status).toBe(200);
    const replayResponse = await request("/onion/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: "same-delivery-id",
        toDeviceId: "device-a",
        from: "peer-a",
        envelope: "ciphertext",
        inboxWriteToken: mailbox.inboxWriteToken,
      }),
    });
    expect(replayResponse.status).toBe(200);

    const firstPoll = await request("/onion/inbox?deviceId=device-a", {
      headers: {
        ...authorizedHeaders(),
        "X-NKC-Mailbox-Token": mailbox.inboxWriteToken ?? "",
      },
    });
    const firstPayload = (await firstPoll.json()) as {
      items: Array<{ envelope: string }>;
      nextAfter: string | null;
    };
    expect(firstPayload.items).toHaveLength(1);
    expect(firstPayload.items[0]?.envelope).toBe("ciphertext");
    expect(firstPayload.nextAfter).toBe("0");

    const acknowledgedPoll = await request("/onion/inbox?deviceId=device-a&after=0", {
      headers: {
        ...authorizedHeaders(),
        "X-NKC-Mailbox-Token": mailbox.inboxWriteToken ?? "",
      },
    });
    const acknowledgedPayload = (await acknowledgedPoll.json()) as { items: unknown[] };
    expect(acknowledgedPayload.items).toEqual([]);
  });

  it("rejects unknown mailboxes, wrong capabilities, and cross-mailbox polling", async () => {
    controller = await startOnionController({ port: 0 });
    const mailbox = await controller.registerMailbox("device-a");

    const unknown = await request("/onion/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        toDeviceId: "device-b",
        envelope: "ciphertext",
        inboxWriteToken: mailbox.inboxWriteToken,
      }),
    });
    expect(unknown.status).toBe(404);

    const wrongCapability = await request("/onion/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        toDeviceId: "device-a",
        envelope: "ciphertext",
        inboxWriteToken: "A".repeat(43),
      }),
    });
    expect(wrongCapability.status).toBe(401);

    const unregisteredPoll = await request("/onion/inbox?deviceId=device-b", {
      headers: authorizedHeaders(),
    });
    expect(unregisteredPoll.status).toBe(403);

    const wrongMailboxPoll = await request("/onion/inbox?deviceId=device-a", {
      headers: {
        ...authorizedHeaders(),
        "X-NKC-Mailbox-Token": "A".repeat(43),
      },
    });
    expect(wrongMailboxPoll.status).toBe(403);
  });

  it("keeps tokenless legacy ingress inside a small per-mailbox queue", async () => {
    controller = await startOnionController({ port: 0 });
    await controller.registerMailbox("device-a");

    for (let index = 0; index < 32; index += 1) {
      const response = await request("/onion/ingest", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: `legacy-${index}`,
          toDeviceId: "device-a",
          envelope: "ciphertext",
        }),
      });
      expect(response.status).toBe(200);
    }
    const overflow = await request("/onion/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: "legacy-overflow",
        toDeviceId: "device-a",
        envelope: "ciphertext",
      }),
    });
    expect(overflow.status).toBe(429);
  });

  it("rejects malformed ingress identifiers without destabilizing the controller", async () => {
    controller = await startOnionController({ port: 0 });

    const malformedResponse = await request("/onion/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ toDeviceId: { nested: true }, envelope: "ciphertext" }),
    });
    expect(malformedResponse.status).toBe(400);

    const healthResponse = await request("/onion/health");
    expect(healthResponse.status).toBe(200);
  });
});
