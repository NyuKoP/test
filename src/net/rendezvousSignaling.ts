import { onionFetch } from "../adapters/transports/onionRouterTransport";
import { fetchWithTimeout } from "./fetchWithTimeout";

export type RendezvousConfig = {
  baseUrl: string;
  useOnionProxy: boolean;
  onionProxyUrl?: string | null;
  onOnionProxyFallback?: (detail: { url: string; reason: string }) => void;
};

export type RendezvousItem = { id: string; ts: number; payload: string };

type RendezvousResponse = { items: RendezvousItem[] };

type FetchInit = RequestInit & { timeoutMs?: number };

const seenIdsByCode = new Map<string, Set<string>>();

const normalizeBaseUrl = (value: string) => value.replace(/\/+$/, "");

const toBase64Url = (bytes: Uint8Array) => {
  let binary = "";
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const hashFallback = async (value: string) => {
  const encoder = new TextEncoder();
  if (globalThis.crypto?.subtle?.digest) {
    const hash = await globalThis.crypto.subtle.digest("SHA-256", encoder.encode(value));
    const bytes = new Uint8Array(hash);
    return toBase64Url(bytes).slice(0, 16);
  }
  if (globalThis.crypto?.getRandomValues) {
    const bytes = new Uint8Array(12);
    globalThis.crypto.getRandomValues(bytes);
    return toBase64Url(bytes);
  }
  throw new Error("Secure random generator is unavailable");
};

const toErrorMessage = (error: unknown) =>
  error instanceof Error ? error.message : String(error ?? "unknown_error");

const isOnionUnavailableError = (error: unknown) =>
  toErrorMessage(error).toLowerCase().includes("onion fetch unavailable");

const fetchRendezvous = async (
  url: string,
  init: FetchInit,
  useOnionProxy: boolean,
  onOnionProxyFallback?: (detail: { url: string; reason: string }) => void
) => {
  try {
    return await onionFetch(url, init);
  } catch (error) {
    if (!isOnionUnavailableError(error)) {
      throw error;
    }
    if (useOnionProxy) {
      onOnionProxyFallback?.({
        url,
        reason: toErrorMessage(error),
      });
    }
  }
  const timeoutMs = init.timeoutMs ?? 10_000;
  const { signal: parentSignal, ...fetchInit } = init;
  delete fetchInit.timeoutMs;
  return fetchWithTimeout(url, fetchInit, {
    timeoutMs,
    parentSignal: parentSignal ?? undefined,
    opId: url,
    traceSource: "rendezvous",
  });
};

const getSeenSet = (syncCode: string) => {
  const key = syncCode.toUpperCase();
  let set = seenIdsByCode.get(key);
  if (!set) {
    set = new Set();
    seenIdsByCode.set(key, set);
  }
  return set;
};

export class RendezvousClient {
  private readonly config: RendezvousConfig;

  constructor(config: RendezvousConfig) {
    this.config = config;
  }

  async publish(syncCode: string, deviceId: string, payloads: string[]) {
    if (!payloads.length) return;
    const now = Date.now();
    const items = await Promise.all(
      payloads.map(async (payload, index) => {
        const seed = `${deviceId}:${now}:${index}:${payload}`;
        const id = globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : await hashFallback(seed);
        return { id, ts: Date.now(), payload } satisfies RendezvousItem;
      })
    );
    const seen = getSeenSet(syncCode);
    items.forEach((item) => seen.add(item.id));

    const url = `${normalizeBaseUrl(this.config.baseUrl)}/rendezvous/${syncCode}/signals`;
    const response = await fetchRendezvous(
      url,
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deviceId, items }),
        timeoutMs: 10_000,
      },
      this.config.useOnionProxy,
      this.config.onOnionProxyFallback
    );
    if (!response.ok) {
      throw new Error(`Rendezvous publish failed (${response.status})`);
    }
  }

  async poll(syncCode: string, deviceId: string, afterTs: number) {
    const url = new URL(
      `${normalizeBaseUrl(this.config.baseUrl)}/rendezvous/${syncCode}/signals`
    );
    url.searchParams.set("afterTs", String(afterTs));
    url.searchParams.set("limit", "50");
    url.searchParams.set("deviceId", deviceId);

    const response = await fetchRendezvous(
      url.toString(),
      { method: "GET", timeoutMs: 10_000 },
      this.config.useOnionProxy,
      this.config.onOnionProxyFallback
    );
    if (!response.ok) {
      throw new Error(`Rendezvous poll failed (${response.status})`);
    }
    const json = (await response.json()) as RendezvousResponse;
    const items = Array.isArray(json.items) ? json.items : [];
    const seen = getSeenSet(syncCode);
    const filtered: RendezvousItem[] = [];
    let maxTs = afterTs;
    for (const item of items) {
      if (!item?.id || typeof item.payload !== "string") continue;
      if (seen.has(item.id)) continue;
      seen.add(item.id);
      filtered.push(item);
      if (typeof item.ts === "number") {
        maxTs = Math.max(maxTs, item.ts);
      }
    }
    if (seen.size > 1000) {
      const trimmed = new Set(Array.from(seen).slice(-500));
      seenIdsByCode.set(syncCode.toUpperCase(), trimmed);
    }
    return { items: filtered, nextAfterTs: maxTs };
  }
}
