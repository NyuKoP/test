import type { NetConfig } from "./netConfig";
import { useNetConfigStore } from "./netConfigStore";
import { createRouteController, type RouteController } from "./routeController";
import { createHttpClient, type HttpClient } from "./httpClient";
import type { OutboxRecord } from "../db/schema";
import { computeExpiresAt } from "../policies/ttl";
import { enqueueOutgoing, onAckReceived } from "../policies/deliveryPolicy";
import { putOutbox, updateOutbox } from "../storage/outboxStore";
import type { Transport, TransportPacket, TransportState } from "../adapters/transports/types";
import { createDirectP2PTransport } from "../adapters/transports/directP2PTransport";
import { createSelfOnionTransport } from "../adapters/transports/selfOnionTransport";
import { createOnionRouterTransport } from "../adapters/transports/onionRouterTransport";
import { getConnectionStatus, updateConnectionStatus } from "./connectionStatus";
import { decideRouterTransport } from "./transportPolicy";
import { useAppStore } from "../app/store";
import { useInternalOnionRouteStore } from "../stores/internalOnionRouteStore";
import { emitFlowTraceLog } from "../diagnostics/infoCollectionLogs";
import { createTransportError, getTransportErrorCode } from "./transportErrors";
import { decodeFriendCodeV1 } from "../security/friendCode";
import { createSafeConsole } from "../diagnostics/safeConsole";

const console = createSafeConsole(globalThis.console);

export type TransportKind = "directP2P" | "selfOnion" | "onionRouter";
export type IncomingPacketMeta = {
  via: TransportKind;
};

type SendPayload = {
  convId: string;
  messageId: string;
  ciphertext: string;
  priority?: "high" | "normal";
  outboxRetention?: "standard" | "transient";
  transferId?: string;
  chunkIndex?: number;
  binaryTransport?: boolean;
  toDeviceId?: string;
  route?: {
    torOnion?: string;
    inboxWriteToken?: string;
  };
};

type SendDeps = {
  config?: NetConfig;
  routeController?: RouteController;
  httpClient?: HttpClient;
  transports?: Partial<Record<TransportKind, Transport>>;
  resolveTransport?: (config: NetConfig, controller: RouteController) => TransportKind;
};

type PrewarmDeps = SendDeps & {
  includeFallback?: boolean;
};

const defaultRouteController = createRouteController();
const defaultHttpClient = createHttpClient();
const transportCache = new Map<TransportKind, Transport>();
let transportStarted = new WeakSet<Transport>();
const inboundAttachedKinds = new Set<TransportKind>();
const transportStateByKind: Partial<Record<TransportKind, TransportState>> = {};

const debugLog = (label: string, payload: Record<string, unknown>) => {
  void label;
  void payload;
};

type DerivedRoutingMeta = {
  toDeviceId?: string;
  route?: { torOnion?: string; inboxWriteToken?: string };
  staleDeviceAliases?: string[];
};

const deriveRoutingMetaFromStores = (
  convId: string
): DerivedRoutingMeta => {
  const state = useAppStore.getState();
  const conv = state.convs.find((item) => item.id === convId);
  const me = state.userProfile;
  if (!conv || !me) return {};
  const isDirect =
    !(conv.type === "group" || conv.participants.length > 2) &&
    conv.participants.length === 2;
  if (!isDirect) return {};
  const partnerId = conv.participants.find((id) => id && id !== me.id) ?? null;
  if (!partnerId) return {};
  const partner = state.friends.find((friend) => friend.id === partnerId) ?? null;
  if (!partner) return {};
  const friendCode = partner.profileVcard?.friendCode?.trim();
  const decodedFriendCode =
    friendCode && friendCode.length > 0 ? decodeFriendCodeV1(friendCode) : null;
  const recovered =
    decodedFriendCode && !("error" in decodedFriendCode)
      ? {
          toDeviceId: decodedFriendCode.deviceId,
          torOnion: decodedFriendCode.onionAddr,
          inboxWriteToken: decodedFriendCode.inboxWriteToken,
        }
      : undefined;
  const toDeviceId =
    partner.routingHints?.deviceId ??
    partner.primaryDeviceId ??
    partner.deviceId ??
    recovered?.toDeviceId;
  const torOnion = partner.routingHints?.onionAddr ?? recovered?.torOnion;
  const inboxWriteToken =
    partner.routingHints?.inboxWriteToken ?? recovered?.inboxWriteToken;
  return {
    toDeviceId,
    route: torOnion ? { torOnion, inboxWriteToken } : undefined,
    staleDeviceAliases: [partner.friendId, partner.id].filter(
      (value): value is string => Boolean(value && value.trim())
    ),
  };
};

const attachHandlers = (
  transport: Transport,
  controller: RouteController,
  kind: TransportKind
) => {
  transport.onAck((messageId, rttMs) => {
    controller.reportAck(messageId, rttMs);
    void onAckReceived(messageId);
  });
  transport.onState((state) => {
    transportStateByKind[kind] = state;
    updateConnectionStatus(state, kind);
  });
};

const getTransport = (
  kind: TransportKind,
  config: NetConfig,
  controller: RouteController,
  httpClient: HttpClient,
  overrides?: Partial<Record<TransportKind, Transport>>
) => {
  if (overrides?.[kind]) return overrides[kind] as Transport;
  if (transportCache.has(kind)) return transportCache.get(kind) as Transport;

  let transport: Transport;
  if (kind === "directP2P") {
    transport = createDirectP2PTransport();
  } else if (kind === "selfOnion") {
    transport = createSelfOnionTransport({ routeController: controller });
  } else {
    transport = createOnionRouterTransport({ httpClient, config });
  }
  attachHandlers(transport, controller, kind);
  if (!inboundAttachedKinds.has(kind)) {
    transport.onMessage((packet) => {
      inboundHandlers.forEach((handler) => handler(packet, { via: kind }));
    });
    inboundAttachedKinds.add(kind);
  }
  transportCache.set(kind, transport);
  return transport;
};

const ensureStarted = async (transport: Transport) => {
  if (transportStarted.has(transport)) return;
  await transport.start();
  transportStarted.add(transport);
};

export const resolveTransport = (
  config: NetConfig,
  controller: RouteController = defaultRouteController
): TransportKind => decideRouterTransport(config, controller);

export const __testResetRouter = () => {
  transportCache.clear();
  transportStarted = new WeakSet<Transport>();
  inboundAttachedKinds.clear();
  delete transportStateByKind.directP2P;
  delete transportStateByKind.onionRouter;
  delete transportStateByKind.selfOnion;
  if (inboundRetryTimer) clearTimeout(inboundRetryTimer);
  inboundRetryTimer = null;
  inboundRetryAttempt = 0;
  inboundStartPromise = null;
};

const warnOnionRouterGuards = (config: NetConfig) => {
  if (config.mode !== "onionRouter" && !config.onionEnabled) return;
  if (!config.disableLinkPreview || !config.webrtcRelayOnly) return;
};

const toErrorMessage = (error: unknown) => {
  const code = getTransportErrorCode(error);
  const message = error instanceof Error ? error.message : String(error);
  if (!code) return message;
  if (message.toLowerCase().includes(code.toLowerCase())) return message;
  return `${code}:${message}`;
};

const createMissingDestinationError = (kind: TransportKind, opId: string) => {
  console.warn(`[net][route] missing_to skip route=${kind} opId=${opId}`);
  return createTransportError("FATAL_MISCONFIG", "FATAL_MISCONFIG: missing destination 'to'");
};

const isFatalMisconfigError = (error: unknown) => getTransportErrorCode(error) === "FATAL_MISCONFIG";

const isOnionFirstPolicy = (config: NetConfig) =>
  config.mode === "onionRouter" || config.mode === "selfOnion" || config.onionEnabled;

const isDirectNotOpenError = (message: string) => message.toLowerCase().includes("direct_not_open");

const isOnionNotReadyError = (error: unknown, message?: string) => {
  const code = getTransportErrorCode(error);
  if (code === "INTERNAL_ONION_NOT_READY" || code === "TOR_NOT_READY") return true;
  const text = (message ?? toErrorMessage(error)).toLowerCase();
  return (
    text.includes("internal_onion_not_ready") ||
    text.includes("internal onion route is not ready") ||
    text.includes("tor_not_ready")
  );
};

const toRouteDecisionReason = (error: unknown, message?: string) => {
  const text = message ?? toErrorMessage(error);
  if (isFatalMisconfigError(error)) return "MISSING_TO_SKIP";
  if (isRouteTargetMissingError(text)) return "ROUTE_TARGET_MISSING";
  if (isOnionNotReadyError(error, text)) return "ONION_NOT_READY_DEFER";
  if (isDirectNotOpenError(text)) return "DIRECT_NOT_OPEN_SKIP";
  if (isRouteCandidateMissingError(text)) return "NO_ROUTE_CANDIDATE";
  if (isOnionProxyUnavailableError(text)) return "PROXY_UNAVAILABLE";
  return "ROUTE_ERROR";
};

const isRouteTargetMissingError = (message: string) =>
  message.includes("forward_failed:no_route_target") ||
  message.includes("forward_failed:no_route");

const isRouteCandidateMissingError = (message: string) =>
  message.includes("forward_failed:no_route") &&
  !message.includes("forward_failed:no_route_target");

const isOnionProxyUnavailableError = (message: string) => {
  const normalized = message.toLowerCase();
  return (
    message.includes("forward_failed:no_proxy") ||
    message.includes("forward_failed:proxy_unreachable") ||
    normalized.includes("proxy_unreachable") ||
    normalized.includes("tor_not_ready") ||
    normalized.includes("onion controller unavailable") ||
    normalized.includes("operation was aborted")
  );
};

const isSelfOnionRouteNotReadyError = (message: string) => {
  const normalized = message.toLowerCase();
  return (
    normalized.includes("internal onion route is not ready") ||
    normalized.includes("internal_onion_not_ready") ||
    normalized.includes("route_not_ready")
  );
};

const SELF_ONION_RETRY_DELAY_MS = 450;

const wait = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });

const getByteLength = (value: string) => new TextEncoder().encode(value).byteLength;

type RouteGateSnapshot = {
  onionReady: boolean;
  torBootstrapped: boolean | null;
  torControlReady: null;
  directOpen: boolean;
  wakuReady: null;
  hasRouteTarget: boolean;
};

type GateDecision =
  | { ok: true; snapshot: RouteGateSnapshot }
  | {
      ok: false;
      snapshot: RouteGateSnapshot;
      kind: "DEFER";
      reason: "INTERNAL_ONION_NOT_READY";
      retryAfterMs: number | null;
    }
  | {
      ok: false;
      snapshot: RouteGateSnapshot;
      kind: "FATAL";
      reason: "MISSING_TO" | "MISCONFIG";
    };

const toRouteGateSnapshot = (
  config: NetConfig,
  route?: { torOnion?: string }
): RouteGateSnapshot => {
  const routeState = useInternalOnionRouteStore.getState().route;
  const connection = getConnectionStatus();
  const onionRouterState = transportStateByKind.onionRouter;
  const routerConnected =
    onionRouterState === "connected" ||
    onionRouterState === "degraded" ||
    (connection.transport === "onionRouter" &&
      (connection.state === "connected" || connection.state === "degraded"));
  const directState = transportStateByKind.directP2P;
  const directOpen =
    directState === "connected" ||
    directState === "degraded" ||
    (connection.transport === "directP2P" &&
      (connection.state === "connected" || connection.state === "degraded"));
  const onionReady =
    config.mode === "onionRouter" || config.onionEnabled
      ? routerConnected
      : routeState.status === "ready";
  return {
    onionReady,
    torBootstrapped: config.onionSelectedNetwork === "tor" ? routerConnected : null,
    torControlReady: null,
    directOpen,
    wakuReady: null,
    hasRouteTarget: Boolean(route?.torOnion),
  };
};

const emitRouteGateCheck = (
  opId: string,
  wanted: TransportKind,
  snapshot: RouteGateSnapshot
) => {
  emitFlowTraceLog({
    event: "routeGate:check",
    opId,
    wanted,
    ...snapshot,
  });
};

const enforceRouteGate = (args: {
  opId: string;
  wanted: TransportKind;
  config: NetConfig;
  toDeviceId?: string;
  route?: { torOnion?: string };
}): GateDecision => {
  const snapshot = toRouteGateSnapshot(args.config, args.route);
  emitRouteGateCheck(args.opId, args.wanted, snapshot);

  if (!args.toDeviceId || !args.toDeviceId.trim()) {
    return {
      ok: false,
      snapshot,
      kind: "FATAL",
      reason: "MISSING_TO",
    };
  }

  if (
    (args.wanted === "onionRouter" || args.wanted === "selfOnion") &&
    args.config.mode === "onionRouter" &&
    args.config.onionEnabled &&
    snapshot.hasRouteTarget &&
    !snapshot.onionReady
  ) {
    return {
      ok: false,
      snapshot,
      kind: "DEFER",
      reason: "INTERNAL_ONION_NOT_READY",
      retryAfterMs: null,
    };
  }

  return { ok: true, snapshot };
};

const getPrewarmKinds = (
  chosen: TransportKind,
  includeFallback: boolean
): TransportKind[] => {
  if (!includeFallback) return [chosen];
  if (chosen === "onionRouter") return ["onionRouter", "directP2P", "selfOnion"];
  if (chosen === "directP2P") return ["directP2P", "onionRouter", "selfOnion"];
  return ["selfOnion", "onionRouter", "directP2P"];
};

const inboundHandlers = new Set<(packet: TransportPacket, meta: IncomingPacketMeta) => void>();
let inboundAttached = false;
let inboundStartPromise: Promise<void> | null = null;
let inboundRetryTimer: ReturnType<typeof setTimeout> | null = null;
let inboundRetryAttempt = 0;
const INBOUND_RETRY_BASE_MS = 2_000;
const INBOUND_RETRY_MAX_MS = 30_000;

export const prewarmRouter = async (deps: PrewarmDeps = {}) => {
  const config = deps.config ?? useNetConfigStore.getState().config;
  const controller = deps.routeController ?? defaultRouteController;
  const httpClient = deps.httpClient ?? defaultHttpClient;
  const resolve = deps.resolveTransport ?? resolveTransport;
  const chosen = resolve(config, controller);
  const requested = [...new Set(getPrewarmKinds(chosen, deps.includeFallback ?? true))];
  const settled = await Promise.all(
    requested.map(async (kind) => {
      try {
        const transport = getTransport(kind, config, controller, httpClient, deps.transports);
        await ensureStarted(transport);
        return { kind, ok: true as const };
      } catch (error) {
        controller.reportSendFail(kind);
        return { kind, ok: false as const, error: toErrorMessage(error) };
      }
    })
  );
  return {
    chosenTransport: chosen,
    requested,
    started: settled.filter((item) => item.ok).map((item) => item.kind),
    failed: settled
      .filter((item) => !item.ok)
      .map((item) => ({
        transport: item.kind,
        error: (item as { error?: string }).error ?? "unknown error",
      })),
    mode: config.mode,
    onionEnabled: config.onionEnabled,
    onionSelectedNetwork: config.onionSelectedNetwork,
  };
};

const ensureInboundListener = async () => {
  if (inboundStartPromise) return inboundStartPromise;
  if (inboundHandlers.size === 0) return;
  const config = useNetConfigStore.getState().config;
  const controller = defaultRouteController;
  const httpClient = defaultHttpClient;
  const transports = [
    getTransport("onionRouter", config, controller, httpClient),
    getTransport("selfOnion", config, controller, httpClient),
  ];
  if (!inboundAttached) inboundAttached = true;
  inboundStartPromise = Promise.allSettled(
    transports.map((transport) => ensureStarted(transport))
  )
    .then((results) => {
      const onionRouterFailed = results[0]?.status === "rejected";
      if (onionRouterFailed && inboundHandlers.size > 0 && !inboundRetryTimer) {
        const delayMs = Math.min(
          INBOUND_RETRY_MAX_MS,
          INBOUND_RETRY_BASE_MS * 2 ** inboundRetryAttempt
        );
        inboundRetryAttempt += 1;
        inboundRetryTimer = setTimeout(() => {
          inboundRetryTimer = null;
          void ensureInboundListener();
        }, delayMs);
      } else if (!onionRouterFailed) {
        inboundRetryAttempt = 0;
      }
      const allFailed = results.every((result) => result.status === "rejected");
      if (allFailed) {
        throw new Error("All inbound transports failed to start");
      }
    })
    .catch((error) => {
      void error;
    })
    .finally(() => {
      inboundStartPromise = null;
    });
  return inboundStartPromise;
};

const resolveTransportForExplicitRoute = (
  chosen: TransportKind,
  route?: { torOnion?: string }
) => {
  if (chosen !== "selfOnion") return chosen;
  if (!route?.torOnion) return chosen;
  const routeState = useInternalOnionRouteStore.getState().route;
  return routeState.status === "ready" ? chosen : "onionRouter";
};

export const sendCiphertext = async (
  payload: SendPayload,
  deps: SendDeps = {}
) => {
  const config = deps.config ?? useNetConfigStore.getState().config;
  const controller = deps.routeController ?? defaultRouteController;
  const httpClient = deps.httpClient ?? defaultHttpClient;
  const derived = payload.toDeviceId
    ? {}
    : deriveRoutingMetaFromStores(payload.convId);
  const toDeviceId = (payload.toDeviceId ?? derived.toDeviceId)?.trim();
  const route = payload.route ?? derived.route;
  const policy = config.mode === "onionRouter" || config.onionEnabled ? "STRICT" : "ALLOW_FALLBACK";
  const createdAtMs = Date.now();
  const record: OutboxRecord = {
    id: payload.messageId,
    convId: payload.convId,
    ciphertext: payload.ciphertext,
    priority: payload.priority ?? "normal",
    toDeviceId,
    torOnion: route?.torOnion,
    createdAtMs,
    expiresAtMs: computeExpiresAt(createdAtMs),
    lastAttemptAtMs: createdAtMs,
    nextAttemptAtMs: createdAtMs,
    attempts: 0,
    status: "pending",
    retention: payload.outboxRetention ?? "standard",
    transferId: payload.transferId,
    chunkIndex: payload.chunkIndex,
    binaryTransport: payload.binaryTransport,
  };

  warnOnionRouterGuards(config);
  const resolve = deps.resolveTransport ?? resolveTransport;
  const chosen = resolveTransportForExplicitRoute(resolve(config, controller), route);
  const attemptTrace: Array<{
    transport: TransportKind;
    phase: "primary" | "fallback";
    ok: boolean;
    error?: string;
  }> = [];
  const gateDecision = enforceRouteGate({
    opId: payload.messageId,
    wanted: chosen,
    config,
    toDeviceId,
    route,
  });

  if (!gateDecision.ok) {
    if (gateDecision.kind === "DEFER") {
      await enqueueOutgoing(record);
      emitFlowTraceLog({
        event: "routeGate:block",
        opId: payload.messageId,
        reason: gateDecision.reason,
        nextRetryAt: null,
        backoffMs: gateDecision.retryAfterMs,
      });
      emitFlowTraceLog({
        event: "routeSelect:decision",
        opId: payload.messageId,
        wanted: chosen,
        attempted: [],
        fallbackUsed: false,
        policy,
        reason: "ONION_NOT_READY_DEFER",
        why: gateDecision.reason,
      });
      emitFlowTraceLog({
        event: "requestSend:deferred",
        opId: payload.messageId,
        reason: "RETRYABLE_SEND_FAILURE",
        nextRetryAt: null,
        attempt: 0,
        errCode: gateDecision.reason,
      });
      return {
        ok: false,
        transport: chosen,
        error: `RETRYABLE_SEND_FAILURE:${gateDecision.reason}`,
        diagnostic: {
          chosenTransport: chosen,
          attempts: attemptTrace,
          deferredReason: gateDecision.reason,
          hasToDeviceId: Boolean(toDeviceId),
          hasTorOnion: Boolean(route?.torOnion),
          mode: config.mode,
          onionEnabled: config.onionEnabled,
          onionSelectedNetwork: config.onionSelectedNetwork,
        },
      };
    }

    const misconfig =
      gateDecision.reason === "MISSING_TO"
        ? createMissingDestinationError(chosen, payload.messageId)
        : createTransportError("FATAL_MISCONFIG", "FATAL_MISCONFIG: route gate rejected send");
    emitFlowTraceLog({
      event: "routeSelect:decision",
      opId: payload.messageId,
      wanted: chosen,
      attempted: [],
      fallbackUsed: false,
      policy,
      reason: "MISSING_TO_SKIP",
      why: misconfig.message,
    });
    emitFlowTraceLog({
      event: "requestSend:failed",
      opId: payload.messageId,
      routeAttempted: chosen,
      errCode: "FATAL_MISCONFIG",
      errDetail: misconfig.message,
      attempt: 0,
    });
    return {
      ok: false,
      transport: chosen,
      error: misconfig.message,
      diagnostic: {
        chosenTransport: chosen,
        attempts: attemptTrace,
        hasToDeviceId: Boolean(toDeviceId),
        hasTorOnion: Boolean(route?.torOnion),
        mode: config.mode,
        onionEnabled: config.onionEnabled,
        onionSelectedNetwork: config.onionSelectedNetwork,
      },
    };
  }

  emitFlowTraceLog({
    event: "routeSelect:decision",
    opId: payload.messageId,
    wanted: chosen,
    attempted: [chosen],
    fallbackUsed: false,
    policy,
    reason: "INITIAL_SELECTION",
    why: "initial-selection",
  });
  debugLog("[net] sendCiphertext: chosen transport", {
    convId: payload.convId,
    messageId: payload.messageId,
    chosen,
    mode: config.mode,
    onionEnabled: config.onionEnabled,
    onionSelectedNetwork: config.onionSelectedNetwork,
    hasToDeviceId: Boolean(toDeviceId),
    hasRoute: Boolean(route?.torOnion),
  });

  await enqueueOutgoing(record);

  const attemptSend = async (
    kind: TransportKind,
    options?: {
      allowDirectWhenOnionGuarded?: boolean;
      allowSelfOnionWhenOnionGuarded?: boolean;
    }
  ) => {
    if (!toDeviceId) {
      throw createMissingDestinationError(kind, payload.messageId);
    }
    if (
      (config.mode === "onionRouter" || config.onionEnabled) &&
      kind === "directP2P" &&
      !options?.allowDirectWhenOnionGuarded
    ) {
      emitFlowTraceLog({
        event: "routeGate:block",
        opId: payload.messageId,
        reason: "DIRECT_BLOCKED_IN_ONION_MODE",
        nextRetryAt: null,
        backoffMs: null,
      });
      throw new Error("Direct P2P blocked in onion router mode");
    }
    if (
      (config.mode === "onionRouter" || config.onionEnabled) &&
      kind === "selfOnion" &&
      !options?.allowSelfOnionWhenOnionGuarded
    ) {
      emitFlowTraceLog({
        event: "routeGate:block",
        opId: payload.messageId,
        reason: "SELF_ONION_BLOCKED_WHILE_ROUTER_ENABLED",
        nextRetryAt: null,
        backoffMs: null,
      });
      throw new Error("Self-onion blocked while onion router is enabled");
    }
    const transport = getTransport(kind, config, controller, httpClient, deps.transports);
    await ensureStarted(transport);
    record.attempts += 1;
    record.lastAttemptAtMs = Date.now();
    await putOutbox(record);
    const packet: TransportPacket = {
      id: payload.messageId,
      payload: payload.binaryTransport
        ? new TextEncoder().encode(payload.ciphertext)
        : payload.ciphertext,
      toDeviceId,
      route,
    } as TransportPacket;
    const startedAt = Date.now();
    emitFlowTraceLog({
      event: "requestSend:start",
      opId: payload.messageId,
      routeAttempted: kind,
      msgType: "ciphertext",
      bytes: getByteLength(payload.ciphertext),
      timeoutMs: null,
    });
    try {
      await transport.send(packet);
      emitFlowTraceLog({
        event: "requestSend:ok",
        opId: payload.messageId,
        routeAttempted: kind,
        durMs: Math.max(0, Date.now() - startedAt),
      });
    } catch (error) {
      emitFlowTraceLog({
        event: "requestSend:failed",
        opId: payload.messageId,
        routeAttempted: kind,
        errCode:
          error && typeof error === "object" && typeof (error as { code?: unknown }).code === "string"
            ? ((error as { code?: string }).code ?? "UNKNOWN")
            : "UNKNOWN",
        errDetail: error instanceof Error ? error.message : String(error),
        durMs: Math.max(0, Date.now() - startedAt),
        attempt: record.attempts,
      });
      throw error;
    }
    return kind;
  };

  try {
    const used = await attemptSend(chosen);
    attemptTrace.push({ transport: chosen, phase: "primary", ok: true });
    debugLog("[net] sendCiphertext: send ok", {
      convId: payload.convId,
      messageId: payload.messageId,
      transport: used,
    });
    return {
      ok: true,
      transport: used,
      diagnostic: {
        chosenTransport: chosen,
        attempts: attemptTrace,
        hasToDeviceId: Boolean(toDeviceId),
        hasTorOnion: Boolean(route?.torOnion),
        mode: config.mode,
        onionEnabled: config.onionEnabled,
        onionSelectedNetwork: config.onionSelectedNetwork,
      },
    };
  } catch (error) {
    const primaryErrorCode = getTransportErrorCode(error);
    const primaryErrorMessage = toErrorMessage(error);
    if (!isFatalMisconfigError(error)) {
      attemptTrace.push({
        transport: chosen,
        phase: "primary",
        ok: false,
        error: primaryErrorMessage,
      });
    }
    const attemptErrors: string[] = [
      `${chosen}: ${primaryErrorMessage}`,
    ];
    if (!isFatalMisconfigError(error)) {
      controller.reportSendFail(chosen);
    }
    debugLog("[net] sendCiphertext: send failed", {
      convId: payload.convId,
      messageId: payload.messageId,
      chosen,
      error: primaryErrorMessage,
    });
    if (isFatalMisconfigError(error)) {
      emitFlowTraceLog({
        event: "routeSelect:decision",
        opId: payload.messageId,
        wanted: chosen,
        attempted: [],
        fallbackUsed: false,
        policy,
        reason: "MISSING_TO_SKIP",
        why: primaryErrorMessage,
      });
      emitFlowTraceLog({
        event: "requestSend:failed",
        opId: payload.messageId,
        routeAttempted: chosen,
        errCode: "FATAL_MISCONFIG",
        errDetail: primaryErrorMessage,
        attempt: 0,
      });
      return {
        ok: false,
        transport: chosen,
        error: primaryErrorMessage,
        diagnostic: {
          chosenTransport: chosen,
          attempts: attemptTrace,
          hasToDeviceId: Boolean(toDeviceId),
          hasTorOnion: Boolean(route?.torOnion),
          mode: config.mode,
          onionEnabled: config.onionEnabled,
          onionSelectedNetwork: config.onionSelectedNetwork,
        },
      };
    }
    if (isOnionFirstPolicy(config) && (chosen === "onionRouter" || chosen === "selfOnion") && isOnionNotReadyError(error, primaryErrorMessage)) {
      const deferredReason = primaryErrorCode === "TOR_NOT_READY" ? "TOR_NOT_READY" : "INTERNAL_ONION_NOT_READY";
      emitFlowTraceLog({
        event: "routeGate:block",
        opId: payload.messageId,
        reason: deferredReason,
        nextRetryAt: null,
        backoffMs: null,
      });
      emitFlowTraceLog({
        event: "routeSelect:decision",
        opId: payload.messageId,
        wanted: chosen,
        attempted: [chosen],
        fallbackUsed: false,
        policy,
        reason: "ONION_NOT_READY_DEFER",
        why: primaryErrorMessage,
      });
      emitFlowTraceLog({
        event: "requestSend:deferred",
        opId: payload.messageId,
        reason: "RETRYABLE_SEND_FAILURE",
        nextRetryAt: null,
        attempt: record.attempts,
        errCode: deferredReason,
      });
      return {
        ok: false,
        transport: chosen,
        error: `RETRYABLE_SEND_FAILURE:${deferredReason}`,
        diagnostic: {
          chosenTransport: chosen,
          attempts: attemptTrace,
          deferredReason,
          hasToDeviceId: Boolean(toDeviceId),
          hasTorOnion: Boolean(route?.torOnion),
          mode: config.mode,
          onionEnabled: config.onionEnabled,
          onionSelectedNetwork: config.onionSelectedNetwork,
        },
      };
    }
    const allowDirectFallback =
      chosen === "onionRouter" &&
      (isRouteTargetMissingError(primaryErrorMessage) ||
        isOnionProxyUnavailableError(primaryErrorMessage));
    const allowSelfOnionFallback =
      chosen === "onionRouter" &&
      (isOnionProxyUnavailableError(primaryErrorMessage) ||
        isRouteCandidateMissingError(primaryErrorMessage));
    const fallbackKinds: TransportKind[] =
      allowSelfOnionFallback
        ? ["selfOnion", "directP2P"]
        : allowDirectFallback
        ? ["directP2P"]
        : chosen === "directP2P"
        ? ["onionRouter", "selfOnion"]
        : config.mode === "selfOnion" && chosen === "selfOnion"
          ? ["onionRouter"]
          : [];
    emitFlowTraceLog({
      event: "routeSelect:decision",
      opId: payload.messageId,
      wanted: chosen,
      attempted: [chosen, ...fallbackKinds],
      fallbackUsed: fallbackKinds.length > 0,
      policy,
      reason: toRouteDecisionReason(error, primaryErrorMessage),
      why: primaryErrorMessage,
    });
    for (const fallbackKind of fallbackKinds) {
      const maxAttempts = fallbackKind === "selfOnion" ? 2 : 1;
      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        try {
          const used = await attemptSend(fallbackKind, {
            allowDirectWhenOnionGuarded: allowDirectFallback && fallbackKind === "directP2P",
            allowSelfOnionWhenOnionGuarded:
              allowSelfOnionFallback && fallbackKind === "selfOnion",
          });
          attemptTrace.push({ transport: fallbackKind, phase: "fallback", ok: true });
          debugLog("[net] sendCiphertext: fallback ok", {
            convId: payload.convId,
            messageId: payload.messageId,
            transport: used,
          });
          return {
            ok: true,
            transport: used,
            diagnostic: {
              chosenTransport: chosen,
              attempts: attemptTrace,
              allowDirectFallback,
              allowSelfOnionFallback,
              fallbackKinds,
              hasToDeviceId: Boolean(toDeviceId),
              hasTorOnion: Boolean(route?.torOnion),
              mode: config.mode,
              onionEnabled: config.onionEnabled,
              onionSelectedNetwork: config.onionSelectedNetwork,
            },
          };
        } catch (fallbackError) {
          const fallbackErrorMessage = toErrorMessage(fallbackError);
          if (!isFatalMisconfigError(fallbackError)) {
            attemptTrace.push({
              transport: fallbackKind,
              phase: "fallback",
              ok: false,
              error: fallbackErrorMessage,
            });
          }
          if (
            isOnionFirstPolicy(config) &&
            (fallbackKind === "onionRouter" || fallbackKind === "selfOnion") &&
            isOnionNotReadyError(fallbackError, fallbackErrorMessage)
          ) {
            const fallbackCode = getTransportErrorCode(fallbackError);
            const deferredReason =
              fallbackCode === "TOR_NOT_READY" ? "TOR_NOT_READY" : "INTERNAL_ONION_NOT_READY";
            emitFlowTraceLog({
              event: "routeGate:block",
              opId: payload.messageId,
              reason: deferredReason,
              nextRetryAt: null,
              backoffMs: null,
            });
            emitFlowTraceLog({
              event: "routeSelect:decision",
              opId: payload.messageId,
              wanted: chosen,
              attempted: [chosen, fallbackKind],
              fallbackUsed: true,
              policy,
              reason: "ONION_NOT_READY_DEFER",
              why: fallbackErrorMessage,
            });
            emitFlowTraceLog({
              event: "requestSend:deferred",
              opId: payload.messageId,
              reason: "RETRYABLE_SEND_FAILURE",
              nextRetryAt: null,
              attempt: record.attempts,
              errCode: deferredReason,
            });
            return {
              ok: false,
              transport: chosen,
              error: `RETRYABLE_SEND_FAILURE:${deferredReason}`,
              diagnostic: {
                chosenTransport: chosen,
                attempts: attemptTrace,
                allowDirectFallback,
                allowSelfOnionFallback,
                fallbackKinds,
                deferredReason,
                hasToDeviceId: Boolean(toDeviceId),
                hasTorOnion: Boolean(route?.torOnion),
                mode: config.mode,
                onionEnabled: config.onionEnabled,
                onionSelectedNetwork: config.onionSelectedNetwork,
              },
            };
          }
          const shouldRetrySelfOnion =
            fallbackKind === "selfOnion" &&
            attempt < maxAttempts &&
            isSelfOnionRouteNotReadyError(fallbackErrorMessage) &&
            !isOnionFirstPolicy(config);
          if (shouldRetrySelfOnion) {
            debugLog("[net] sendCiphertext: fallback retry", {
              convId: payload.convId,
              messageId: payload.messageId,
              fallbackKind,
              attempt,
              maxAttempts,
              error: fallbackErrorMessage,
            });
            await wait(SELF_ONION_RETRY_DELAY_MS);
            continue;
          }
          attemptErrors.push(
            `${fallbackKind}: ${fallbackErrorMessage}`
          );
          if (!isFatalMisconfigError(fallbackError)) {
            controller.reportSendFail(fallbackKind);
          }
          debugLog("[net] sendCiphertext: fallback failed", {
            convId: payload.convId,
            messageId: payload.messageId,
            fallbackKind,
            error: fallbackErrorMessage,
          });
          break;
        }
      }
    }
    emitFlowTraceLog({
      event: "requestSend:failed",
      opId: payload.messageId,
      routeAttempted: chosen,
      errCode: "ALL_ROUTE_ATTEMPTS_FAILED",
      errDetail: attemptErrors.join(" || "),
      attempt: attemptTrace.length,
    });
    return {
      ok: false,
      transport: chosen,
      error: attemptErrors.join(" || "),
      diagnostic: {
        chosenTransport: chosen,
        attempts: attemptTrace,
        allowDirectFallback,
        allowSelfOnionFallback,
        fallbackKinds,
        hasToDeviceId: Boolean(toDeviceId),
        hasTorOnion: Boolean(route?.torOnion),
        mode: config.mode,
        onionEnabled: config.onionEnabled,
        onionSelectedNetwork: config.onionSelectedNetwork,
      },
    };
  }
};

export const sendOutboxRecord = async (
  record: OutboxRecord,
  deps: SendDeps = {}
) => {
  const config = deps.config ?? useNetConfigStore.getState().config;
  const controller = deps.routeController ?? defaultRouteController;
  const httpClient = deps.httpClient ?? defaultHttpClient;
  const derived = deriveRoutingMetaFromStores(record.convId);
  const recordToDeviceId = record.toDeviceId?.trim();
  const hasStaleAlias = recordToDeviceId
    ? Boolean(derived.staleDeviceAliases?.includes(recordToDeviceId))
    : false;
  const toDeviceId = (hasStaleAlias ? derived.toDeviceId : record.toDeviceId ?? derived.toDeviceId)?.trim();
  const torOnion = record.torOnion ?? derived.route?.torOnion;
  const inboxWriteToken = derived.route?.inboxWriteToken;
  const policy = config.mode === "onionRouter" || config.onionEnabled ? "STRICT" : "ALLOW_FALLBACK";

  if ((!record.toDeviceId || hasStaleAlias) && (toDeviceId || torOnion)) {
    const patch: Partial<OutboxRecord> = {};
    if (toDeviceId) patch.toDeviceId = toDeviceId;
    if (torOnion) patch.torOnion = torOnion;
    if (Object.keys(patch).length) {
      await updateOutbox(record.id, patch);
    }
  }

  warnOnionRouterGuards(config);
  const resolve = deps.resolveTransport ?? resolveTransport;
  const chosen = resolveTransportForExplicitRoute(
    resolve(config, controller),
    torOnion ? { torOnion } : undefined
  );
  const gateDecision = enforceRouteGate({
    opId: record.id,
    wanted: chosen,
    config,
    toDeviceId,
    route: torOnion ? { torOnion } : undefined,
  });

  if (!gateDecision.ok) {
    if (gateDecision.kind === "DEFER") {
      emitFlowTraceLog({
        event: "routeGate:block",
        opId: record.id,
        reason: gateDecision.reason,
        nextRetryAt: record.nextAttemptAtMs,
        backoffMs:
          record.nextAttemptAtMs != null
            ? Math.max(0, record.nextAttemptAtMs - Date.now())
            : gateDecision.retryAfterMs,
      });
      emitFlowTraceLog({
        event: "routeSelect:decision",
        opId: record.id,
        wanted: chosen,
        attempted: [],
        fallbackUsed: false,
        policy,
        reason: "ONION_NOT_READY_DEFER",
        why: gateDecision.reason,
      });
      emitFlowTraceLog({
        event: "requestSend:deferred",
        opId: record.id,
        reason: "RETRYABLE_SEND_FAILURE",
        nextRetryAt: record.nextAttemptAtMs,
        attempt: record.attempts,
        errCode: gateDecision.reason,
      });
      return { ok: false as const, retryable: true };
    }

    const misconfig =
      gateDecision.reason === "MISSING_TO"
        ? createMissingDestinationError(chosen, record.id)
        : createTransportError("FATAL_MISCONFIG", "FATAL_MISCONFIG: route gate rejected send");
    emitFlowTraceLog({
      event: "routeSelect:decision",
      opId: record.id,
      wanted: chosen,
      attempted: [],
      fallbackUsed: false,
      policy,
      reason: "MISSING_TO_SKIP",
      why: misconfig.message,
    });
    emitFlowTraceLog({
      event: "requestSend:failed",
      opId: record.id,
      routeAttempted: chosen,
      errCode: "FATAL_MISCONFIG",
      errDetail: misconfig.message,
      attempt: record.attempts,
    });
    return { ok: false as const, retryable: false };
  }

  emitFlowTraceLog({
    event: "routeSelect:decision",
    opId: record.id,
    wanted: chosen,
    attempted: [chosen],
    fallbackUsed: false,
    policy,
    reason: "OUTBOX_SELECTION",
    why: "outbox-selection",
  });
  debugLog("[net] sendOutboxRecord: chosen transport", {
    convId: record.convId,
    messageId: record.id,
    chosen,
    mode: config.mode,
    onionEnabled: config.onionEnabled,
    onionSelectedNetwork: config.onionSelectedNetwork,
    hasToDeviceId: Boolean(toDeviceId),
    hasRoute: Boolean(torOnion),
  });

  if (config.onionEnabled && chosen === "selfOnion") {
    controller.reportSendFail(chosen);
    emitFlowTraceLog({
      event: "routeGate:block",
      opId: record.id,
      reason: "SELF_ONION_BLOCKED_WHILE_ROUTER_ENABLED",
      nextRetryAt: record.nextAttemptAtMs,
      backoffMs: Math.max(0, (record.nextAttemptAtMs ?? Date.now()) - Date.now()),
    });
    emitFlowTraceLog({
      event: "requestSend:deferred",
      opId: record.id,
      reason: "SELF_ONION_BLOCKED_WHILE_ROUTER_ENABLED",
      nextRetryAt: record.nextAttemptAtMs,
      attempt: record.attempts,
    });
    return { ok: false as const, retryable: false };
  }

  const attemptSend = async (
    kind: TransportKind,
    options?: {
      allowDirectWhenOnionGuarded?: boolean;
      allowSelfOnionWhenOnionGuarded?: boolean;
    }
  ) => {
    if (!toDeviceId) {
      throw createMissingDestinationError(kind, record.id);
    }
    if (
      (config.mode === "onionRouter" || config.onionEnabled) &&
      kind === "directP2P" &&
      !options?.allowDirectWhenOnionGuarded
    ) {
      emitFlowTraceLog({
        event: "routeGate:block",
        opId: record.id,
        reason: "DIRECT_BLOCKED_IN_ONION_MODE",
        nextRetryAt: record.nextAttemptAtMs,
        backoffMs: Math.max(0, (record.nextAttemptAtMs ?? Date.now()) - Date.now()),
      });
      throw new Error("Direct P2P blocked in onion router mode");
    }
    if (
      (config.mode === "onionRouter" || config.onionEnabled) &&
      kind === "selfOnion" &&
      !options?.allowSelfOnionWhenOnionGuarded
    ) {
      emitFlowTraceLog({
        event: "routeGate:block",
        opId: record.id,
        reason: "SELF_ONION_BLOCKED_WHILE_ROUTER_ENABLED",
        nextRetryAt: record.nextAttemptAtMs,
        backoffMs: Math.max(0, (record.nextAttemptAtMs ?? Date.now()) - Date.now()),
      });
      throw new Error("Self-onion blocked while onion router is enabled");
    }
    const transport = getTransport(kind, config, controller, httpClient, deps.transports);
    await ensureStarted(transport);
    const packet: TransportPacket = {
      id: record.id,
      payload: record.binaryTransport
        ? new TextEncoder().encode(record.ciphertext)
        : record.ciphertext,
      toDeviceId,
      route: torOnion ? { torOnion, inboxWriteToken } : undefined,
    } as TransportPacket;
    const startedAt = Date.now();
    emitFlowTraceLog({
      event: "requestSend:start",
      opId: record.id,
      routeAttempted: kind,
      msgType: "ciphertext",
      bytes: getByteLength(record.ciphertext),
      timeoutMs: null,
    });
    try {
      await transport.send(packet);
      emitFlowTraceLog({
        event: "requestSend:ok",
        opId: record.id,
        routeAttempted: kind,
        durMs: Math.max(0, Date.now() - startedAt),
      });
    } catch (error) {
      emitFlowTraceLog({
        event: "requestSend:failed",
        opId: record.id,
        routeAttempted: kind,
        errCode:
          error && typeof error === "object" && typeof (error as { code?: unknown }).code === "string"
            ? ((error as { code?: string }).code ?? "UNKNOWN")
            : "UNKNOWN",
        errDetail: error instanceof Error ? error.message : String(error),
        durMs: Math.max(0, Date.now() - startedAt),
        attempt: (record.attempts ?? 0) + 1,
      });
      throw error;
    }
    return kind;
  };

  try {
    await attemptSend(chosen);
    debugLog("[net] sendOutboxRecord: send ok", {
      convId: record.convId,
      messageId: record.id,
      transport: chosen,
    });
    return { ok: true as const };
  } catch (error) {
    const primaryErrorCode = getTransportErrorCode(error);
    const primaryErrorMessage = toErrorMessage(error);
    if (!isFatalMisconfigError(error)) {
      controller.reportSendFail(chosen);
    }
    debugLog("[net] sendOutboxRecord: send failed", {
      convId: record.convId,
      messageId: record.id,
      chosen,
      error: primaryErrorMessage,
    });
    if (isFatalMisconfigError(error)) {
      emitFlowTraceLog({
        event: "routeSelect:decision",
        opId: record.id,
        wanted: chosen,
        attempted: [],
        fallbackUsed: false,
        policy,
        reason: "MISSING_TO_SKIP",
        why: primaryErrorMessage,
      });
      emitFlowTraceLog({
        event: "requestSend:failed",
        opId: record.id,
        routeAttempted: chosen,
        errCode: "FATAL_MISCONFIG",
        errDetail: primaryErrorMessage,
        attempt: record.attempts,
      });
      return { ok: false as const, retryable: false };
    }
    if (isOnionFirstPolicy(config) && (chosen === "onionRouter" || chosen === "selfOnion") && isOnionNotReadyError(error, primaryErrorMessage)) {
      const deferredReason = primaryErrorCode === "TOR_NOT_READY" ? "TOR_NOT_READY" : "INTERNAL_ONION_NOT_READY";
      emitFlowTraceLog({
        event: "routeGate:block",
        opId: record.id,
        reason: deferredReason,
        nextRetryAt: record.nextAttemptAtMs,
        backoffMs: Math.max(0, (record.nextAttemptAtMs ?? Date.now()) - Date.now()),
      });
      emitFlowTraceLog({
        event: "routeSelect:decision",
        opId: record.id,
        wanted: chosen,
        attempted: [chosen],
        fallbackUsed: false,
        policy,
        reason: "ONION_NOT_READY_DEFER",
        why: primaryErrorMessage,
      });
      emitFlowTraceLog({
        event: "requestSend:deferred",
        opId: record.id,
        reason: "RETRYABLE_SEND_FAILURE",
        nextRetryAt: record.nextAttemptAtMs,
        attempt: record.attempts,
        errCode: deferredReason,
      });
      return { ok: false as const, retryable: true };
    }
    const allowDirectFallback =
      chosen === "onionRouter" &&
      (isRouteTargetMissingError(primaryErrorMessage) ||
        isOnionProxyUnavailableError(primaryErrorMessage));
    const allowSelfOnionFallback =
      chosen === "onionRouter" &&
      (isOnionProxyUnavailableError(primaryErrorMessage) ||
        isRouteCandidateMissingError(primaryErrorMessage));
    const fallbackKinds: TransportKind[] =
      allowSelfOnionFallback
        ? ["selfOnion", "directP2P"]
        : allowDirectFallback
        ? ["directP2P"]
        : chosen === "directP2P"
        ? ["onionRouter", "selfOnion"]
        : config.mode === "selfOnion" && chosen === "selfOnion"
          ? ["onionRouter"]
          : [];
    emitFlowTraceLog({
      event: "routeSelect:decision",
      opId: record.id,
      wanted: chosen,
      attempted: [chosen, ...fallbackKinds],
      fallbackUsed: fallbackKinds.length > 0,
      policy,
      reason: toRouteDecisionReason(error, primaryErrorMessage),
      why: primaryErrorMessage,
    });
    for (const fallbackKind of fallbackKinds) {
      const maxAttempts = fallbackKind === "selfOnion" ? 2 : 1;
      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        try {
          await attemptSend(fallbackKind, {
            allowDirectWhenOnionGuarded: allowDirectFallback && fallbackKind === "directP2P",
            allowSelfOnionWhenOnionGuarded:
              allowSelfOnionFallback && fallbackKind === "selfOnion",
          });
          debugLog("[net] sendOutboxRecord: fallback ok", {
            convId: record.convId,
            messageId: record.id,
            transport: fallbackKind,
          });
          return { ok: true as const };
        } catch (fallbackError) {
          const fallbackErrorMessage = toErrorMessage(fallbackError);
          if (
            isOnionFirstPolicy(config) &&
            (fallbackKind === "onionRouter" || fallbackKind === "selfOnion") &&
            isOnionNotReadyError(fallbackError, fallbackErrorMessage)
          ) {
            const fallbackCode = getTransportErrorCode(fallbackError);
            const deferredReason =
              fallbackCode === "TOR_NOT_READY" ? "TOR_NOT_READY" : "INTERNAL_ONION_NOT_READY";
            emitFlowTraceLog({
              event: "routeGate:block",
              opId: record.id,
              reason: deferredReason,
              nextRetryAt: record.nextAttemptAtMs,
              backoffMs: Math.max(0, (record.nextAttemptAtMs ?? Date.now()) - Date.now()),
            });
            emitFlowTraceLog({
              event: "routeSelect:decision",
              opId: record.id,
              wanted: chosen,
              attempted: [chosen, fallbackKind],
              fallbackUsed: true,
              policy,
              reason: "ONION_NOT_READY_DEFER",
              why: fallbackErrorMessage,
            });
            emitFlowTraceLog({
              event: "requestSend:deferred",
              opId: record.id,
              reason: "RETRYABLE_SEND_FAILURE",
              nextRetryAt: record.nextAttemptAtMs,
              attempt: record.attempts,
              errCode: deferredReason,
            });
            return { ok: false as const, retryable: true };
          }
          const shouldRetrySelfOnion =
            fallbackKind === "selfOnion" &&
            attempt < maxAttempts &&
            isSelfOnionRouteNotReadyError(fallbackErrorMessage) &&
            !isOnionFirstPolicy(config);
          if (shouldRetrySelfOnion) {
            debugLog("[net] sendOutboxRecord: fallback retry", {
              convId: record.convId,
              messageId: record.id,
              fallbackKind,
              attempt,
              maxAttempts,
              error: fallbackErrorMessage,
            });
            await wait(SELF_ONION_RETRY_DELAY_MS);
            continue;
          }
          if (!isFatalMisconfigError(fallbackError)) {
            controller.reportSendFail(fallbackKind);
          }
          debugLog("[net] sendOutboxRecord: fallback failed", {
            convId: record.convId,
            messageId: record.id,
            fallbackKind,
            error: fallbackErrorMessage,
          });
          break;
        }
      }
    }
    emitFlowTraceLog({
      event: "requestSend:deferred",
      opId: record.id,
      reason: "ALL_ROUTE_ATTEMPTS_FAILED",
      nextRetryAt: record.nextAttemptAtMs,
      attempt: record.attempts,
    });
    return { ok: false as const, retryable: true };
  }
};

export const onIncomingPacket = (
  handler: (packet: TransportPacket, meta: IncomingPacketMeta) => void
) => {
  inboundHandlers.add(handler);
  void ensureInboundListener();
  return () => {
    inboundHandlers.delete(handler);
    if (inboundHandlers.size === 0 && inboundRetryTimer) {
      clearTimeout(inboundRetryTimer);
      inboundRetryTimer = null;
      inboundRetryAttempt = 0;
    }
  };
};
