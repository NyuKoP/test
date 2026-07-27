import type { HttpClient } from "../../net/httpClient";
import type { NetConfig } from "../../net/netConfig";
import { OnionInboxClient } from "../../net/onionInboxClient";
import {
  decodeBase64,
  decodeBase64Url,
  encodeBase64,
  encodeBase64Url,
} from "../../security/base64url";
import { getOrCreateDeviceId } from "../../security/deviceRole";
import { getOnionControllerUrlOverride, getRoutePolicy } from "../../security/preferences";
import type { RouteMode } from "../../main/routePolicy";
import { TorRuntime } from "../../net/tor/TorRuntime";
import { createTransportError } from "../../net/transportErrors";
import type { Transport, TransportPacket, TransportState } from "./types";
import { decodeBinaryTransportPacket, encodeBinaryTransportPacket } from "./packetCodec";

type Handler<T> = (payload: T) => void;

const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_SEEN_IDS = 500;
const STATE_DEBOUNCE_MS = 1000;
const START_HEALTH_RETRY_DELAYS_MS = [0, 350, 900] as const;
const SEND_PROXY_RETRY_DELAYS_MS = [0, 250, 700] as const;

type OnionFetchRequest = {
  url: string;
  method: string;
  headers?: Record<string, string>;
  bodyBase64?: string;
  timeoutMs?: number;
};

type OnionFetchResponse = {
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  bodyBase64: string;
  error?: string;
};

type TorStatusResponse = {
  state?: unknown;
  socksProxyUrl?: unknown;
};

const isForwardProxyNotReadyError = (message: string) => {
  const text = message.toLowerCase();
  return (
    text.includes("forward_failed:proxy_unreachable") ||
    text.includes("forward_failed:no_proxy")
  );
};

const isForwardNoRouteError = (message: string) => {
  const text = message.toLowerCase();
  return text.includes("forward_failed:no_route") && !text.includes("forward_failed:no_route_target");
};

type RouteCodedError = Error & { code: string };

const createRouteError = (code: string, message: string) => {
  const err = new Error(message) as RouteCodedError;
  err.code = code;
  return err;
};

const wait = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });

const normalizeSocksProxyUrl = (raw: unknown) =>
  typeof raw === "string" && raw.trim() ? raw.trim() : null;

const syncOnionForwardProxyFromRuntime = async () => {
  const nkc = (
    globalThis as {
      nkc?: {
        getTorStatus?: () => Promise<unknown>;
        setOnionForwardProxy?: (proxyUrl: string | null) => Promise<unknown>;
      };
    }
  ).nkc;
  if (!nkc?.getTorStatus || !nkc?.setOnionForwardProxy) {
    return false;
  }
  try {
    const status = (await nkc.getTorStatus()) as TorStatusResponse;
    if (status?.state !== "running") {
      return false;
    }
    const socksProxyUrl = normalizeSocksProxyUrl(status.socksProxyUrl);
    if (!socksProxyUrl) {
      return false;
    }
    await nkc.setOnionForwardProxy(socksProxyUrl);
    return true;
  } catch {
    return false;
  }
};

const extractAbortSignal = (packet: TransportPacket) =>
  (packet as { signal?: AbortSignal }).signal ??
  (packet as { meta?: { signal?: AbortSignal } }).meta?.signal ??
  (packet as { route?: { signal?: AbortSignal } }).route?.signal;

type SendRoute = {
  mode: RouteMode;
  torOnion?: string;
  inboxWriteToken?: string;
};

const normalizeSendRoute = (route: SendRoute): SendRoute =>
  route.torOnion ? { ...route, mode: "preferTor" } : route;

const buildRelaxedRoute = (route: SendRoute): SendRoute => {
  const hasTor = Boolean(route.torOnion);
  if (hasTor) {
    return { ...route, mode: "preferTor" };
  }
  return route;
};

export async function onionFetch(
  url: string,
  init: RequestInit & { timeoutMs?: number } = {}
): Promise<Response> {
  const nkc = (
    globalThis as { nkc?: { onionFetch?: (req: OnionFetchRequest) => Promise<OnionFetchResponse> } }
  ).nkc;
  if (!nkc?.onionFetch) {
    throw new Error("Onion fetch unavailable");
  }
  const headers = new Headers(init.headers ?? {});
  let bodyBase64: string | undefined;
  if (init.body !== undefined && init.body !== null) {
    if (typeof init.body === "string") {
      bodyBase64 = encodeBase64(new TextEncoder().encode(init.body));
    } else if (init.body instanceof Uint8Array) {
      bodyBase64 = encodeBase64(init.body);
    } else if (init.body instanceof ArrayBuffer) {
      bodyBase64 = encodeBase64(new Uint8Array(init.body));
    } else {
      throw new Error("Unsupported onion fetch body");
    }
  }
  const response = await nkc.onionFetch({
    url,
    method: init.method ?? "GET",
    headers: Object.fromEntries(headers.entries()),
    bodyBase64,
    timeoutMs: init.timeoutMs,
  });
  const body = response.bodyBase64 ? decodeBase64(response.bodyBase64) : new Uint8Array();
  const respHeaders = new Headers(response.headers ?? {});
  return new Response(body, { status: response.status, headers: respHeaders });
}

type OnionRouterOptions = {
  httpClient: HttpClient;
  config: NetConfig;
  torRuntime?: Pick<TorRuntime, "start" | "awaitReady" | "markDegraded"> & {
    recover?: TorRuntime["recover"];
  };
};

export const createOnionRouterTransport = ({
  httpClient,
  config,
  torRuntime: torRuntimeOverride,
}: OnionRouterOptions): Transport => {
  const torRuntime = torRuntimeOverride ?? TorRuntime.getInstance();
  let state: TransportState = "idle";
  let client: OnionInboxClient | null = null;
  let pollerStop: (() => void) | null = null;
  let errorStreak = 0;
  let stateTimer: ReturnType<typeof setTimeout> | null = null;
  const seenIds = new Set<string>();
  const seenOrder: string[] = [];
  const messageHandlers: Array<Handler<TransportPacket>> = [];
  const ackHandlers: Array<Handler<{ id: string; rttMs: number }>> = [];
  const stateHandlers: Array<Handler<TransportState>> = [];

  const emitState = (next: TransportState) => {
    state = next;
    stateHandlers.forEach((handler) => handler(next));
  };

  const requestState = (next: TransportState, immediate = false) => {
    if (state === next) return;
    const flipFlop =
      (state === "connected" && next === "degraded") ||
      (state === "degraded" && next === "connected");
    if (!immediate && flipFlop) {
      if (stateTimer) clearTimeout(stateTimer);
      stateTimer = setTimeout(() => {
        stateTimer = null;
        emitState(next);
      }, STATE_DEBOUNCE_MS);
      return;
    }
    if (stateTimer) {
      clearTimeout(stateTimer);
      stateTimer = null;
    }
    emitState(next);
  };

  const rememberId = (id: string) => {
    if (seenIds.has(id)) return false;
    seenIds.add(id);
    seenOrder.push(id);
    if (seenOrder.length > MAX_SEEN_IDS) {
      const overflow = seenOrder.splice(0, seenOrder.length - MAX_SEEN_IDS);
      overflow.forEach((oldId) => seenIds.delete(oldId));
    }
    return true;
  };

  const updateStateForError = () => {
    if (errorStreak >= 6) {
      requestState("failed", true);
    } else if (errorStreak >= 3) {
      requestState("degraded");
    }
  };

  const decodeEnvelope = (envelope: string): TransportPacket | null => {
    try {
      const bytes = decodeBase64Url(envelope);
      const binary = decodeBinaryTransportPacket(bytes);
      if (binary) return binary;
      const json = new TextDecoder().decode(bytes);
      const parsed = JSON.parse(json) as TransportPacket;
      if (!parsed || typeof parsed !== "object") return null;
      return parsed;
    } catch {
      return null;
    }
  };

  const ensureTorReady = async (signal?: AbortSignal) => {
    try {
      await torRuntime.start({ timeoutMs: 15_000 });
      await torRuntime.awaitReady(15_000, signal);
      await syncOnionForwardProxyFromRuntime();
    } catch {
      throw createRouteError("TOR_NOT_READY", "TOR_NOT_READY: Tor runtime is not ready");
    }
  };

  const recoverTorProxyInBackground = (result: { queued?: boolean; error?: string }) => {
    if (!result.queued || !result.error || !isForwardProxyNotReadyError(result.error)) return;
    torRuntime.markDegraded("proxy_unreachable", result.error);
    if (!torRuntime.recover) return;
    void torRuntime.recover({ timeoutMs: 30_000 }).catch((error) => {
      torRuntime.markDegraded("proxy_recovery_failed", error);
    });
  };

  const resolveControllerUrl = async () => {
    const nkc = (
      globalThis as { nkc?: { getOnionControllerUrl?: () => Promise<string> } }
    ).nkc;
    let localUrl = "";
    if (nkc?.getOnionControllerUrl) {
      try {
        localUrl = await nkc.getOnionControllerUrl();
      } catch {
        localUrl = "";
      }
    }
    const override = (await getOnionControllerUrlOverride()).trim();
    if (override) return override;
    if (localUrl) return localUrl;
    return "http://127.0.0.1:3210";
  };

  const handlePollSuccess = (result: Awaited<ReturnType<OnionInboxClient["poll"]>>) => {
    errorStreak = 0;
    if (state === "degraded" || state === "failed") {
      requestState("connected");
    }
    result.items.forEach((item) => {
      if (!rememberId(item.id)) return;
      const packet = decodeEnvelope(item.envelope);
      if (!packet) return;
      messageHandlers.forEach((handler) => handler(packet));
    });
  };

  const handlePollError = () => {
    errorStreak += 1;
    updateStateForError();
  };

  return {
    name: "onionRouter",
    async start() {
      void httpClient;
      requestState("connecting", true);
      if (config.onionSelectedNetwork === "tor") {
        try {
          await ensureTorReady();
        } catch {
          requestState("failed", true);
          throw createRouteError("TOR_NOT_READY", "TOR_NOT_READY: Tor runtime is not ready");
        }
      }
      const baseUrl = await resolveControllerUrl();
      const localDeviceId = getOrCreateDeviceId();
      let mailboxToken: string | undefined;
      const nkc = (
        globalThis as {
          nkc?: {
            registerOnionMailbox?: (
              deviceId: string
            ) => Promise<{ ok: boolean; inboxWriteToken?: string; error?: string }>;
          };
        }
      ).nkc;
      if (nkc?.registerOnionMailbox) {
        const mailbox = await nkc.registerOnionMailbox(localDeviceId);
        if (!mailbox.ok) {
          throw new Error(mailbox.error ?? "mailbox-registration-failed");
        }
        mailboxToken = mailbox.inboxWriteToken;
      }
      client = new OnionInboxClient({
        baseUrl,
        deviceId: localDeviceId,
        mailboxToken,
      });
      let health = await client.health();
      for (const delayMs of START_HEALTH_RETRY_DELAYS_MS.slice(1)) {
        if (health.ok) break;
        await wait(delayMs);
        health = await client.health();
      }
      if (!health.ok) {
        requestState("failed", true);
        throw new Error(health.details ?? "Onion controller unavailable");
      }
      requestState("connected", true);
      pollerStop = client.startPolling(
        {
          onResult: handlePollSuccess,
          onError: handlePollError,
        },
        { limit: 50 }
      ).stop;
    },
    async stop() {
      if (pollerStop) {
        pollerStop();
        pollerStop = null;
      }
      if (stateTimer) {
        clearTimeout(stateTimer);
        stateTimer = null;
      }
      errorStreak = 0;
      seenIds.clear();
      seenOrder.length = 0;
      client = null;
      requestState("idle", true);
    },
    async send(packet: TransportPacket) {
      const signal = extractAbortSignal(packet);
      const torOnion =
        (packet as { torOnion?: string }).torOnion ??
        (packet as { toOnion?: string }).toOnion ??
        (packet as { route?: { torOnion?: string; toOnion?: string } }).route?.torOnion ??
        (packet as { route?: { torOnion?: string; toOnion?: string } }).route?.toOnion ??
        (packet as { meta?: { torOnion?: string; toOnion?: string } }).meta?.torOnion ??
        (packet as { meta?: { torOnion?: string; toOnion?: string } }).meta?.toOnion;
      const inboxWriteToken =
        (packet as { route?: { inboxWriteToken?: string } }).route?.inboxWriteToken ??
        (packet as { meta?: { inboxWriteToken?: string } }).meta?.inboxWriteToken;
      const routeMode =
        ((packet as { route?: { mode?: RouteMode } }).route?.mode ??
          (packet as { meta?: { routeMode?: RouteMode } }).meta?.routeMode ??
          (packet as { meta?: { routePolicy?: RouteMode } }).meta?.routePolicy) ??
        ((await getRoutePolicy()) as RouteMode);
      const toDeviceId =
        (packet as { toDeviceId?: string }).toDeviceId ??
        (packet as { meta?: { toDeviceId?: string } }).meta?.toDeviceId ??
        (packet as { route?: { toDeviceId?: string } }).route?.toDeviceId ??
        (packet as { to?: string }).to ??
        (packet as { route?: { to?: string } }).route?.to ??
        (packet as { meta?: { to?: string } }).meta?.to;
      if (!toDeviceId || !toDeviceId.trim()) {
        console.warn(
          `[net][route] missing_to skip route=onionRouter opId=${(packet as { id?: string }).id ?? "unknown"}`
        );
        throw createTransportError("FATAL_MISCONFIG", "FATAL_MISCONFIG: missing destination 'to'");
      }
      const initialRoute =
        torOnion
          ? {
              mode: routeMode,
              torOnion,
              inboxWriteToken,
            }
          : undefined;
      let route = initialRoute ? normalizeSendRoute(initialRoute) : undefined;
      await ensureTorReady(signal);
      if (signal?.aborted) {
        throw createRouteError("TOR_NOT_READY", "TOR_NOT_READY: send aborted");
      }
      if (!client) {
        throw new Error("Onion controller is not ready");
      }
      const activeClient = client;
      const binaryPacket = encodeBinaryTransportPacket(packet);
      const envelope = encodeBase64Url(
        binaryPacket ?? new TextEncoder().encode(JSON.stringify(packet))
      );
      const sendOnce = () =>
        activeClient.send(toDeviceId, envelope, DEFAULT_TTL_MS, route, signal, packet.id);
      if (!torOnion) {
        let result = await sendOnce();
        if (!result.ok) {
          const message = result.error ?? "Onion send failed";
          if (isForwardProxyNotReadyError(message)) {
            const resynced = await syncOnionForwardProxyFromRuntime();
            if (resynced) {
              result = await sendOnce();
            }
            if (!result.ok) {
              const fallbackMessage = result.error ?? message;
              torRuntime.markDegraded("proxy_unreachable", fallbackMessage);
              throw createRouteError("PROXY_UNREACHABLE", `PROXY_UNREACHABLE: ${fallbackMessage}`);
            }
            ackHandlers.forEach((handler) => handler({ id: packet.id, rttMs: 0 }));
            return;
          }
          throw new Error(message);
        }
        recoverTorProxyInBackground(result);
        ackHandlers.forEach((handler) => handler({ id: packet.id, rttMs: 0 }));
        return;
      }
      let lastError = "Onion send failed";
      let relaxedRouteTried = false;
      let proxyResynced = false;
      for (const delayMs of SEND_PROXY_RETRY_DELAYS_MS) {
        if (signal?.aborted) {
          throw createRouteError("TOR_NOT_READY", "TOR_NOT_READY: send aborted");
        }
        if (delayMs > 0) {
          await wait(delayMs);
        }
        const result = await sendOnce();
        if (result.ok) {
          recoverTorProxyInBackground(result);
          ackHandlers.forEach((handler) => handler({ id: packet.id, rttMs: 0 }));
          return;
        }
        lastError = result.error ?? "Onion send failed";
        if (
          route &&
          !relaxedRouteTried &&
          isForwardNoRouteError(lastError)
        ) {
          route = buildRelaxedRoute(route);
          relaxedRouteTried = true;
          continue;
        }
        if (isForwardProxyNotReadyError(lastError) && !proxyResynced) {
          proxyResynced = await syncOnionForwardProxyFromRuntime();
          if (proxyResynced) {
            continue;
          }
        }
        if (!isForwardProxyNotReadyError(lastError)) {
          break;
        }
      }
      if (isForwardProxyNotReadyError(lastError)) {
        torRuntime.markDegraded("proxy_unreachable", lastError);
        throw createRouteError("PROXY_UNREACHABLE", `PROXY_UNREACHABLE: ${lastError}`);
      }
      throw new Error(lastError);
    },
    onMessage(cb) {
      messageHandlers.push(cb);
    },
    onAck(cb) {
      ackHandlers.push((payload) => cb(payload.id, payload.rttMs));
    },
    onState(cb) {
      stateHandlers.push(cb);
      cb(state);
    },
  };
};
