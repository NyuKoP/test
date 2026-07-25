import { app, ipcMain } from "electron";
import crypto from "node:crypto";
import path from "node:path";
import type { NativeWorkerClient } from "../nativeWorkerClient";
import type { AssertTrustedIpcSender, IsTrustedIpcSender } from "./types";

type RegisterNativeWorkerIpcOptions = {
  assertTrustedIpcSender: AssertTrustedIpcSender;
  isTrustedIpcSender: IsTrustedIpcSender;
  getNativeWorkerClient: () => NativeWorkerClient | null;
};

const isFiniteInteger = (value: unknown) =>
  typeof value === "number" && Number.isSafeInteger(value);

const isSchedulePayload = (payload: unknown) => {
  if (!payload || typeof payload !== "object") return false;
  const value = payload as {
    now?: unknown;
    mode?: unknown;
    batchSize?: unknown;
    items?: unknown;
  };
  if (
    !isFiniteInteger(value.now) ||
    !["direct", "tor", "onion"].includes(String(value.mode)) ||
    !isFiniteInteger(value.batchSize) ||
    (value.batchSize as number) < 1 ||
    (value.batchSize as number) > 100 ||
    !Array.isArray(value.items) ||
    value.items.length > 400
  ) {
    return false;
  }
  return value.items.every((item) => {
    if (!item || typeof item !== "object") return false;
    const record = item as Record<string, unknown>;
    return (
      typeof record.id === "string" &&
      record.id.length > 0 &&
      record.id.length <= 256 &&
      (record.priority === "high" || record.priority === "normal") &&
      isFiniteInteger(record.attempts) &&
      (record.attempts as number) >= 0 &&
      isFiniteInteger(record.nextAttemptAtMs) &&
      isFiniteInteger(record.expiresAtMs) &&
      isFiniteInteger(record.createdAtMs)
    );
  });
};

let preloadToken = crypto.randomUUID();
let isTokenConsumed = false;

export const resetPreloadToken = () => {
  preloadToken = crypto.randomUUID();
  isTokenConsumed = false;
};

export const registerNativeWorkerIpc = (options: RegisterNativeWorkerIpcOptions) => {
	const requireClient = (token?: string) => {
		if (!token || token !== preloadToken) throw new Error("Unauthorized file access: Invalid or missing token");
		return options.getNativeWorkerClient();
	};
  ipcMain.on("security:get-preload-token", (event) => {
    if (!options.isTrustedIpcSender(event) || isTokenConsumed) {
      event.returnValue = null;
      return;
    }
    isTokenConsumed = true;
    event.returnValue = preloadToken;
  });

  ipcMain.handle(
    "nativeWorker:fileInspect",
    async (event, payload: { path?: string; chunkSize?: number; token?: string }) => {
      options.assertTrustedIpcSender(event);
      if (!payload?.token || payload.token !== preloadToken) {
        throw new Error("Unauthorized file access: Invalid or missing token");
      }
      const client = options.getNativeWorkerClient();
      if (!client) return { ok: false, error: "native-worker-unavailable" };
      if (!payload.path || !path.isAbsolute(payload.path) || !Number.isInteger(payload.chunkSize)) {
        return { ok: false, error: "invalid-file-request" };
      }
      const result = await client.request(
        "file.inspect",
        { path: payload.path, chunkSize: payload.chunkSize },
        120_000
      );
      return { ok: true, result };
    }
  );

  ipcMain.handle(
    "nativeWorker:fileChunk",
    async (
      event,
      payload: { path?: string; index?: number; chunkSize?: number; token?: string }
    ) => {
      options.assertTrustedIpcSender(event);
      if (!payload?.token || payload.token !== preloadToken) {
        throw new Error("Unauthorized file access: Invalid or missing token");
      }
      const client = options.getNativeWorkerClient();
      if (!client) return { ok: false, error: "native-worker-unavailable" };
      if (
        !payload.path ||
        !path.isAbsolute(payload.path) ||
        !Number.isInteger(payload.index) ||
        !Number.isInteger(payload.chunkSize)
      ) {
        return { ok: false, error: "invalid-file-request" };
      }
      const response = await client.requestBinary<{ index: number; bytes: number }>(
        "file.chunk.binary",
        { path: payload.path, index: payload.index, chunkSize: payload.chunkSize },
        undefined,
        30_000
      );
      return {
        ok: true,
        result: { ...response.result, data: new Uint8Array(response.body) },
      };
    }
  );

  ipcMain.handle("nativeWorker:schedule", async (event, payload: unknown) => {
    options.assertTrustedIpcSender(event);
    if (!isSchedulePayload(payload)) return { ok: false, error: "invalid-schedule-request" };
    const client = options.getNativeWorkerClient();
    if (!client) return { ok: false, error: "native-worker-unavailable" };
    const result = await client.request("scheduler.plan", payload, 5_000);
    return { ok: true, result };
  });

  ipcMain.handle("nativeWorker:receiveInit", async (event, payload: {
    token?: string; transferId?: string; fileName?: string; fileSize?: number;
    chunkSize?: number; totalChunks?: number; sha256?: string;
  }) => {
    options.assertTrustedIpcSender(event);
    const client = requireClient(payload?.token);
    if (!client) return { ok: false, error: "native-worker-unavailable" };
    const fileName = path.basename(String(payload.fileName ?? ""));
    if (!payload.transferId || !fileName || fileName === "." || fileName === ".." || fileName !== payload.fileName) return { ok: false, error: "invalid-receive-request" };
    const result = await client.request("file.receive.init", {
      ...payload,
      token: undefined,
      directory: path.join(app.getPath("userData"), "received-files"),
      fileName,
    }, 30_000);
    return { ok: true, result };
  });

  ipcMain.handle("nativeWorker:receiveWrite", async (event, payload: { token?: string; transferId?: string; index?: number; data?: string | Uint8Array }) => {
    options.assertTrustedIpcSender(event);
    const client = requireClient(payload?.token);
    if (!client) return { ok: false, error: "native-worker-unavailable" };
    if (!payload.transferId || !Number.isInteger(payload.index) || !(typeof payload.data === "string" || payload.data instanceof Uint8Array)) return { ok: false, error: "invalid-receive-request" };
    const result = payload.data instanceof Uint8Array
      ? (await client.requestBinary("file.receive.write.binary", { transferId: payload.transferId, index: payload.index }, payload.data, 30_000)).result
      : await client.request("file.receive.write", { transferId: payload.transferId, index: payload.index, data: payload.data }, 30_000);
    return { ok: true, result };
  });

  for (const operation of ["checkpoint", "finalize", "abort"] as const) {
    ipcMain.handle(`nativeWorker:receive:${operation}`, async (event, payload: { token?: string; transferId?: string }) => {
      options.assertTrustedIpcSender(event);
      const client = requireClient(payload?.token);
      if (!client) return { ok: false, error: "native-worker-unavailable" };
      if (!payload.transferId) return { ok: false, error: "invalid-receive-request" };
      const result = await client.request(`file.receive.${operation}`, { transferId: payload.transferId }, operation === "finalize" ? 120_000 : 30_000);
      return { ok: true, result };
    });
  }
};
