import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "../appRouter";
import { useAppStore } from "./store";
import Onboarding from "../components/Onboarding";
import Unlock, { type UnlockResult } from "../components/Unlock";
import StartKey from "../components/StartKey";
import FriendAddDialog from "../components/FriendAddDialog";
import GroupCreateDialog from "../components/GroupCreateDialog";
import GroupInviteDialog from "../components/GroupInviteDialog";
import Sidebar from "../components/Sidebar";
import ChatView from "../components/ChatView";
import RightPanel from "../components/RightPanel";
import SettingsDialog from "../components/SettingsDialog";
import ConfirmDialog from "../components/ConfirmDialog";
import Toasts from "../components/Toasts";
import { createId } from "../utils/ids";
import {
  bootstrapVault,
  resetVaultStorage,
  getVaultHeader,
  listConversations,
  listProfiles,
  lockVault,
  repairVaultTextEncoding,
  verifyVaultKeyId,
  rotateVaultKeys,
  deleteProfile,
  deleteMessagesById,
  nextLamportForConv,
  getLastEventHash,
  saveConversation,
  saveEvent,
  saveMessage,
  createMessageMediaRef,
  saveMessageMedia,
  saveProfile,
  saveProfilePhoto,
  saveGroupPhotoRef,
  loadAvatarFromRef,
  seedVaultData,
  unlockVault,
  wipeVault,
  type Conversation,
  type Message,
  type UserProfile,
} from "../db/repo";
import { chunkBuffer, encryptJsonRecord, validateStartKey } from "../crypto/vault";
import { getVaultKey, setVaultKey } from "../crypto/sessionKeyring";
import {
  computeFriendId,
  decodeFriendCodeV1,
  encodeFriendCodeV1,
  type FriendCodeV1,
} from "../security/friendCode";
import { decodeInviteCodeV1 } from "../security/inviteCode";
import { runOneTimeInviteGuard } from "../security/inviteUseStore";
import { checkAllowed, recordFail, recordSuccess } from "../security/rateLimit";
import { applyTOFU } from "../security/trust";
import { sha256 } from "../security/sha256";
import {
  clearSession as clearStoredSession,
  getSession as getStoredSession,
  setSession as setStoredSession,
} from "../security/session";
import { inspectOutgoingMediaFile } from "../security/mediaPolicy";
import { clearPin, clearPinRecord, getPinStatus, isPinUnavailableError, setPin as savePin, verifyPin, wipePinState } from "../security/pin";
import { loadConversationMessages } from "../security/messageStore";
import { clearFriendPsk, getFriendPsk, setFriendPsk } from "../security/pskStore";
import { decodeBase64Url, encodeBase64Url } from "../security/base64url";
import {
  getDhPrivateKey,
  getDhPublicKey,
  getIdentityPrivateKey,
  getIdentityPublicKey,
  getOrCreateDhKeypair,
  getOrCreateIdentityKeypair,
} from "../security/identityKeys";
import { getOrCreateDeviceId } from "../security/deviceRole";
import { computeEnvelopeHash, deriveConversationKeyPair, encryptEnvelope, type EnvelopeHeader } from "../crypto/box";
import { EnvelopeCryptoPool } from "../crypto/envelopeCryptoPool";
import { getSodium } from "../security/sodium";
import { nextSendDhKey, nextSendKey } from "../crypto/ratchet";
import { prewarmRouter, sendCiphertext } from "../net/router";
import { startOutboxScheduler } from "../net/outboxScheduler";
import { onConnectionStatus } from "../net/connectionStatus";
import { useNetConfigStore } from "../net/netConfigStore";
import { shouldAutoPrepareTor } from "../net/netConfig";
import { getOnionStatus } from "../net/onionControl";
import {
  runVerifiedTorAutoUpdate,
  TOR_AUTO_UPDATE_INTERVAL_MS,
} from "../net/torAutoUpdate";
import { TorRuntime } from "../net/tor/TorRuntime";
import {
  selectTorRuntimeCandidate,
  type TorRuntimeCandidate,
} from "../net/tor/runtimeCandidate";
import {
  ensureLocalOnionEndpoint,
  ensurePublishedLocalOnionEndpoint,
} from "../net/tor/localOnionEndpoint";
import { sanitizeRoutingHints } from "../net/privacy";
import {
  buildGroupInviteEvent,
  buildGroupLeaveEvent,
  syncGroupCreate,
  type GroupEventPayload,
} from "../sync/groupSync";
import {
  connectConversation as connectSyncConversation,
  disconnectConversation as disconnectSyncConversation,
  syncContactsNow,
  syncConversation,
  syncConversationsNow,
  canUseBinaryMediaTransport,
} from "../sync/syncEngine";
import {
  getTransportStatus,
  onTransportStatusChange,
  setDirectApprovalHandler,
  type ConversationTransportStatus,
} from "../net/transportManager";
import { putReadCursor } from "../storage/receiptStore";
import { getConvAllowDirect, setGroupAvatarOverride } from "../security/preferences";
import { setFriendAlias } from "../storage/friendStore";
import { resolveDisplayName, resolveFriendDisplayName } from "../utils/displayName";
import { startFriendRequestScheduler } from "../friends/friendRequestScheduler";
import { isTorFriendCodeReady } from "../friends/friendCodeReadiness";
import {
  startFriendResponseScheduler,
  type PendingFriendResponseType,
} from "../friends/friendResponseScheduler";
import { startFriendInboxListener } from "../friends/friendInbox";
import {
  enrichFriendControlFrameWithProtocol,
  isFriendControlFrame,
  signFriendControlFrame,
  stripFriendControlFrameSignature,
  type FriendControlFrame,
} from "../friends/friendControlFrame";
import {
  attachInfoCollectionLogSink,
  emitFriendAddInfoLog,
  emitFriendRouteOutgoingInfoLog,
  type FriendAddInfoLogInput,
  type FriendRouteOutgoingInfoLogInput,
  emitRouterInfoLog,
  type RouterInfoLogInput,
} from "../diagnostics/infoCollectionLogs";
import {
  classifyRouteFailure,
  collectRouteErrorCodes,
  splitRouteErrorParts,
  toInfoLogErrorDetail,
} from "../diagnostics/friendRouteLogUtils";
import { useProfileDecorations } from "./hooks/useProfileDecorations";
import { useTrustState } from "./hooks/useTrustState";
import { onBackgroundStatus, onSyncRun, reportSyncResult } from "../appControl";
import {
  createMediaTransferProgress,
  markMediaTransferStored,
} from "../storage/mediaTransferStore";
import {
  INLINE_MEDIA_CHUNK_SIZE,
  INLINE_MEDIA_MAX_BYTES,
} from "../net/mediaTransferLimits";
import { createSafeConsole } from "../diagnostics/safeConsole";
import { AdaptiveTransferWindow } from "../net/adaptiveTransferWindow";

const console = createSafeConsole(globalThis.console);

const buildNameMap = (
  profiles: UserProfile[],
  aliasesById: Record<string, string | undefined>
) =>
  profiles.reduce<Record<string, string>>((acc, profile) => {
    acc[profile.id] = resolveDisplayName({
      alias: aliasesById[profile.id],
      displayName: profile.displayName,
      friendId: profile.friendId,
      id: profile.id,
    });
    return acc;
  }, {});

const READ_CURSOR_THROTTLE_MS = 1500;
const ROUTE_PENDING_TOAST_COOLDOWN_MS = 10_000;
const FRIEND_ROUTE_SEND_DEADLINE_MS = 70_000;

const newClientBatchId = () => {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  }
  return encodeBase64Url(bytes);
};

const nowMonotonicMs = () => {
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
};

const waitMs = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });

type RuntimeNetworkSnapshot = {
  torState: string | null;
  torDetail: string | null;
};

const EMPTY_RUNTIME_NETWORK_SNAPSHOT: RuntimeNetworkSnapshot = {
  torState: null,
  torDetail: null,
};

const toRuntimeState = (value: unknown) => {
  if (!value || typeof value !== "object") return null;
  const state = (value as { state?: unknown }).state;
  return typeof state === "string" && state.trim().length > 0 ? state : null;
};

const toRuntimeDetail = (value: unknown) => {
  if (!value || typeof value !== "object") return null;
  const details = (value as { details?: unknown; error?: unknown }).details;
  const fallback = (value as { details?: unknown; error?: unknown }).error;
  const source = details ?? fallback;
  return typeof source === "string" && source.trim().length > 0 ? source : null;
};

const sameRoutingHints = (
  lhs?: { onionAddr?: string; deviceId?: string },
  rhs?: { onionAddr?: string; deviceId?: string }
) =>
  (lhs?.deviceId ?? "") === (rhs?.deviceId ?? "") &&
  (lhs?.onionAddr ?? "") === (rhs?.onionAddr ?? "");

const sameRuntimeNetworkSnapshot = (lhs: RuntimeNetworkSnapshot, rhs: RuntimeNetworkSnapshot) =>
  lhs.torState === rhs.torState &&
  lhs.torDetail === rhs.torDetail;

type ViewTransitionDocument = Document & {
  startViewTransition?: (update: () => void) => {
    updateCallbackDone: Promise<unknown>;
  };
};

const applyDocumentTheme = (theme: "dark" | "light", animate = false): Promise<void> => {
  if (typeof document === "undefined") return Promise.resolve();
  const updateTheme = () => {
    const root = document.documentElement;
    root.classList.toggle("light", theme === "light");
    root.classList.toggle("dark", theme === "dark");
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
    window.localStorage.setItem("nkc.theme", theme);
  };
  const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const startViewTransition = (document as ViewTransitionDocument).startViewTransition;
  if (animate && !reduceMotion && typeof startViewTransition === "function") {
    const transition = startViewTransition.call(document, updateTheme);
    return transition.updateCallbackDone.then(() => undefined);
  }
  updateTheme();
  return Promise.resolve();
};

export default function App() {
  const ui = useAppStore((state) => state.ui);
  const userProfile = useAppStore((state) => state.userProfile);
  const friends = useAppStore((state) => state.friends);
  const convs = useAppStore((state) => state.convs);
  const setMode = useAppStore((state) => state.setMode);
  const setSelectedConv = useAppStore((state) => state.setSelectedConv);
  const setIsComposing = useAppStore((state) => state.setIsComposing);
  const setRightPanelOpen = useAppStore((state) => state.setRightPanelOpen);
  const setRightTab = useAppStore((state) => state.setRightTab);
  const setListMode = useAppStore((state) => state.setListMode);
  const setListFilter = useAppStore((state) => state.setListFilter);
  const setSearch = useAppStore((state) => state.setSearch);
  const setSessionState = useAppStore((state) => state.setSession);
  const setUserProfile = useAppStore((state) => state.setUserProfile);
  const setData = useAppStore((state) => state.setData);
  const addToast = useAppStore((state) => state.addToast);
  const confirm = useAppStore((state) => state.ui.confirm);
  const setConfirm = useAppStore((state) => state.setConfirm);

  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const storedTheme = window.localStorage.getItem("nkc.theme");
    const fallbackTheme = storedTheme === "dark" || storedTheme === "light" ? storedTheme : "light";
    void applyDocumentTheme(userProfile?.theme ?? fallbackTheme);
  }, [userProfile?.theme]);

  const [pinEnabled, setPinEnabled] = useState(false);
  const [defaultTab, setDefaultTab] = useState<"create" | "startKey">("create");
  const [pinNeedsReset, setPinNeedsReset] = useState(false);
  const wasHiddenRef = useRef(false);

  const [onboardingError, setOnboardingError] = useState("");
  const [friendAddOpen, setFriendAddOpen] = useState(false);
  const [routeResolveBusy, setRouteResolveBusy] = useState(false);
  const [groupCreateOpen, setGroupCreateOpen] = useState(false);
  const [groupInviteOpen, setGroupInviteOpen] = useState(false);
  const [groupInviteConvId, setGroupInviteConvId] = useState<string | null>(null);
  const [myFriendCode, setMyFriendCode] = useState("");
  const [friendCodeRuntimeSnapshot, setFriendCodeRuntimeSnapshot] = useState<RuntimeNetworkSnapshot>(
    EMPTY_RUNTIME_NETWORK_SNAPSHOT
  );
  const [sidebarRuntimeSnapshot, setSidebarRuntimeSnapshot] = useState<RuntimeNetworkSnapshot>(
    EMPTY_RUNTIME_NETWORK_SNAPSHOT
  );
  const [transportStatusByConv, setTransportStatusByConv] = useState<
    Record<string, ConversationTransportStatus>
  >({});
  const netConfig = useNetConfigStore((state) => state.config);
  const friendRouteWakeSignatureRef = useRef<Record<string, string>>({});
  const friendRequestInFlightRef = useRef(new Map<string, Promise<boolean>>());
  const onionRouteRequired = netConfig.mode === "onionRouter" || netConfig.onionEnabled;

  const setFriendAddDialogOpen = useCallback((open: boolean) => {
    setMyFriendCode("");
    setFriendCodeRuntimeSnapshot(EMPTY_RUNTIME_NETWORK_SNAPSHOT);
    setFriendAddOpen(open);
  }, []);

  const {
    groupAvatarOverrides,
    friendAliasesById,
    groupAvatarRefsByConv,
    refreshGroupAvatarOverrides,
    refreshFriendAliases,
    setFriendAliasInState,
  } = useProfileDecorations({ convs });

  const onboardingLockRef = useRef(false);
  const bootGuardRef = useRef<Promise<void> | null>(null);
  const outboxSchedulerStarted = useRef(false);
  const friendInboxStarted = useRef(false);
  const activeSyncConvRef = useRef<string | null>(null);
  const prewarmedOnionRoutesRef = useRef<Map<string, number>>(new Map());
  const directEnvelopeSendChainsRef = useRef<Map<string, Promise<void>>>(new Map());
  const mediaTransferChainsRef = useRef<Map<string, Promise<void>>>(new Map());
  const lastReadCursorSentAtRef = useRef<Record<string, number>>({});
  const lastReadCursorSentTsRef = useRef<Record<string, number>>({});
  const pendingReadCursorRef = useRef<
    Record<string, { cursorTs: number; anchorMsgId: string } | undefined>
  >({});
  const readCursorThrottleTimerRef = useRef<Record<string, number | undefined>>({});
  const routePendingToastRef = useRef<Record<string, number>>({});
  const onionBootstrapToastAtRef = useRef(0);
  const routerBootstrapRunKeyRef = useRef<string | null>(null);

  const connectionToastShown = useRef(false);
  const connectionToastKey = "nkc.sessionConnectedToastShown";

  const isDev = Boolean((import.meta as { env?: { DEV?: boolean } }).env?.DEV);
  const devLog = useCallback(
    (message: string, detail?: Record<string, unknown>) => {
      if (!isDev) return;
      if (detail) console.debug(`[app] ${message}`, detail);
      else console.debug(`[app] ${message}`);
    },
    [isDev]
  );
  const emitFriendAddTestLog = useCallback((detail: FriendAddInfoLogInput) => {
    emitFriendAddInfoLog(detail);
  }, []);
  const emitFriendRouteTestLog = useCallback((detail: FriendRouteOutgoingInfoLogInput) => {
    emitFriendRouteOutgoingInfoLog(detail);
  }, []);
  const emitRouterTestLog = useCallback((detail: RouterInfoLogInput) => {
    emitRouterInfoLog(detail);
  }, []);
  const resolveRuntimeNetworkSnapshot = useCallback(async (): Promise<RuntimeNetworkSnapshot> => {
    let builtInCandidate: TorRuntimeCandidate | null = null;
    try {
      const onionStatus = await getOnionStatus();
      const runtime = onionStatus.runtime;
      builtInCandidate = {
        state: runtime.status,
        detail: runtime.error ?? null,
        socksUrl:
          runtime.status === "running" &&
          runtime.network === "tor" &&
          typeof runtime.socksPort === "number"
            ? `socks5://127.0.0.1:${runtime.socksPort}`
            : null,
      };
    } catch {
      // Browser-only tests and older preload surfaces may not expose the built-in Onion bridge.
    }

    const nkc = (
      globalThis as {
        nkc?: {
          getTorStatus?: () => Promise<unknown>;
          checkSocksProxyReachable?: (payload: {
            socksUrl: string;
            timeoutMs?: number;
          }) => Promise<boolean>;
        };
      }
    ).nkc;
    let legacyCandidate: TorRuntimeCandidate | null = null;
    if (nkc?.getTorStatus) {
      try {
        const torRaw = await nkc.getTorStatus();
        const socksProxyUrl =
          torRaw && typeof torRaw === "object"
            ? (torRaw as { socksProxyUrl?: unknown }).socksProxyUrl
            : null;
        legacyCandidate = {
          state: toRuntimeState(torRaw),
          detail: toRuntimeDetail(torRaw),
          socksUrl: typeof socksProxyUrl === "string" ? socksProxyUrl : null,
        };
      } catch {
        legacyCandidate = null;
      }
    }

    const candidate = selectTorRuntimeCandidate(builtInCandidate, legacyCandidate);
    let torState = candidate?.state ?? null;
    let torDetail = candidate?.detail ?? null;
    if (torState === "running") {
      let proxyReachable = false;
      if (candidate?.socksUrl && nkc?.checkSocksProxyReachable) {
        try {
          proxyReachable = await nkc.checkSocksProxyReachable({
            socksUrl: candidate.socksUrl,
            timeoutMs: 2_000,
          });
        } catch {
          proxyReachable = false;
        }
      }
      if (!proxyReachable) {
        torState = "starting";
        torDetail = "Tor SOCKS proxy is not reachable yet";
      }
    }
    return {
      torState,
      torDetail,
    };
  }, []);

  const refreshSidebarRuntimeSnapshot = useCallback(async () => {
    const snapshot = await resolveRuntimeNetworkSnapshot();
    setSidebarRuntimeSnapshot((prev) =>
      sameRuntimeNetworkSnapshot(prev, snapshot) ? prev : snapshot
    );
  }, [resolveRuntimeNetworkSnapshot]);

  useEffect(() => {
    void refreshSidebarRuntimeSnapshot();
    const unsubscribe = onBackgroundStatus(() => {
      void refreshSidebarRuntimeSnapshot();
    });
    const timer = window.setInterval(() => {
      void refreshSidebarRuntimeSnapshot();
    }, 4_000);
    return () => {
      unsubscribe();
      window.clearInterval(timer);
    };
  }, [refreshSidebarRuntimeSnapshot]);

  const sidebarNetworkStatus = useMemo(() => {
    const torState = sidebarRuntimeSnapshot.torState ?? "";
    if (torState === "running") {
      return { state: "connected" as const, label: "연결됨" };
    }
    if (torState === "starting") {
      return { state: "connecting" as const, label: "연결 중" };
    }
    if (torState === "error") {
      return { state: "error" as const, label: "오류" };
    }
    return { state: "disconnected" as const, label: "연결 안됨" };
  }, [sidebarRuntimeSnapshot]);

  useEffect(() => {
    return attachInfoCollectionLogSink();
  }, []);

  const settingsOpen = location.pathname === "/settings";
  const getRoutePendingToast = useCallback((error?: string) => {
    const errorParts = splitRouteErrorParts(error);
    const normalizedErrorParts = errorParts.length > 0 ? errorParts : error ? [error] : [];
    const errorCodes = collectRouteErrorCodes(normalizedErrorParts);
    const failureClass = classifyRouteFailure(errorCodes, normalizedErrorParts);

    if (failureClass === "missing-device-id") {
      return {
        key: "missing-device-id",
        text:
          "상대 기기 ID가 없어 전송 경로를 만들 수 없습니다. 친구 코드를 다시 받아 업데이트하세요.",
      };
    }
    if (failureClass === "onion-proxy-not-ready") {
      return {
        key: "onion-proxy-not-ready",
        text:
          "Tor 프록시가 아직 준비되지 않았습니다. Onion 적용 후 연결되면 자동 재시도됩니다.",
      };
    }
    if (failureClass === "direct-channel-not-open") {
      return {
        key: "direct-not-open",
        text:
          "Direct P2P 연결이 아직 열리지 않았습니다. 연결 수립 후 자동 재시도됩니다.",
      };
    }
    if (failureClass === "self-onion-not-ready") {
      return {
        key: "self-onion-not-ready",
        text:
          "내부 Onion 라우트가 아직 준비되지 않았습니다. 네트워크 안정화 후 자동 재시도됩니다.",
      };
    }
    if (failureClass === "missing-route-target") {
      return {
        key: "route-target-missing",
        text:
          "상대의 최신 라우팅 정보(onion 주소 또는 최신 기기 ID)가 없어 전송할 수 없습니다. 상대에게 최신 친구 코드를 다시 받아주세요.",
      };
    }
    if (failureClass === "transport-aborted") {
      return {
        key: "transport-aborted",
        text:
          "라우터 초기화/재시작 중으로 전송이 중단되었습니다. 잠시 후 자동 재시도됩니다.",
      };
    }
    return {
      key: "generic-route-not-ready",
      text:
        "전송 경로가 준비되지 않아 메시지가 대기열에 남았습니다. 연결 후 자동 재시도됩니다.",
    };
  }, []);
  const notifyRoutePendingToast = useCallback(
    (convId: string, error?: string) => {
      const info = getRoutePendingToast(error);
      const now = Date.now();
      const key = `${convId}:${info.key}`;
      const lastAt = routePendingToastRef.current[key] ?? 0;
      if (now - lastAt < ROUTE_PENDING_TOAST_COOLDOWN_MS) {
        return;
      }
      routePendingToastRef.current[key] = now;
      addToast({ message: info.text });
    },
    [addToast, getRoutePendingToast]
  );
  const clearConnectionToastGuard = useCallback(() => {
    connectionToastShown.current = false;
    if (typeof window !== "undefined") {
      window.sessionStorage.removeItem(connectionToastKey);
    }
  }, [connectionToastKey]);

  const resetAppState = useCallback(() => {
    clearConnectionToastGuard();
    setSessionState({ unlocked: false, vkInMemory: false });
    setData({ user: null, friends: [], convs: [], messagesByConv: {} });
    setSelectedConv(null);
  }, [clearConnectionToastGuard, setData, setSelectedConv, setSessionState]);

  const resolveLocalRoutingHintsForFriendCode = useCallback(async () => {
    const localDeviceId = getOrCreateDeviceId();
    const fallback = sanitizeRoutingHints({
      deviceId: localDeviceId,
      onionAddr: userProfile?.routingHints?.onionAddr,
    });
    const nkc = (
      globalThis as {
        nkc?: {
          ensureHiddenService?: () => Promise<unknown>;
          getMyOnionAddress?: () => Promise<string>;
        };
      }
    ).nkc;
    if (!nkc) return fallback;

    let onionAddr: string | undefined;

    if (netConfig.onionSelectedNetwork === "tor") {
      try {
        const value = (await ensureLocalOnionEndpoint())?.trim() ?? "";
        if (value) onionAddr = value;
      } catch {
        onionAddr = undefined;
      }
    }
    const liveHints = sanitizeRoutingHints({
      deviceId: localDeviceId,
      onionAddr,
    });
    if (liveHints) return liveHints;
    return sanitizeRoutingHints({ deviceId: localDeviceId }) ?? fallback;
  }, [
    netConfig.onionSelectedNetwork,
    userProfile?.routingHints?.onionAddr,
  ]);

  const buildLocalFriendCodePayload = useCallback(async (): Promise<Omit<FriendCodeV1, "v">> => {
    const [identityPub, dhPub, localHints] = await Promise.all([
      getIdentityPublicKey(),
      getDhPublicKey(),
      resolveLocalRoutingHintsForFriendCode(),
    ]);
    return {
      identityPub: encodeBase64Url(identityPub),
      dhPub: encodeBase64Url(dhPub),
      deviceId: getOrCreateDeviceId(),
      onionAddr: localHints?.onionAddr,
    };
  }, [resolveLocalRoutingHintsForFriendCode]);

  const refreshFriendCodeRuntimeSnapshot = useCallback(async () => {
    const snapshot = await resolveRuntimeNetworkSnapshot();
    setFriendCodeRuntimeSnapshot((prev) =>
      sameRuntimeNetworkSnapshot(prev, snapshot) ? prev : snapshot
    );
    return snapshot;
  }, [resolveRuntimeNetworkSnapshot]);

  const refreshMyFriendCode = useCallback(async () => {
    if (!friendAddOpen || !userProfile) return;
    const runtimeSnapshot = await resolveRuntimeNetworkSnapshot();
    setFriendCodeRuntimeSnapshot((prev) =>
      sameRuntimeNetworkSnapshot(prev, runtimeSnapshot) ? prev : runtimeSnapshot
    );
    if (runtimeSnapshot.torState !== "running") {
      setMyFriendCode((prev) => (prev ? "" : prev));
      return;
    }
    const payload = await buildLocalFriendCodePayload();
    const verifiedRuntimeSnapshot = await resolveRuntimeNetworkSnapshot();
    setFriendCodeRuntimeSnapshot((prev) =>
      sameRuntimeNetworkSnapshot(prev, verifiedRuntimeSnapshot) ? prev : verifiedRuntimeSnapshot
    );
    if (!isTorFriendCodeReady(verifiedRuntimeSnapshot, payload)) {
      setMyFriendCode((prev) => (prev ? "" : prev));
      return;
    }
    const nextCode = encodeFriendCodeV1({
      v: 1,
      ...payload,
    });
    setMyFriendCode((prev) => (prev === nextCode ? prev : nextCode));
  }, [
    buildLocalFriendCodePayload,
    friendAddOpen,
    resolveRuntimeNetworkSnapshot,
    userProfile,
  ]);

  useEffect(() => {
    if (!friendAddOpen || !userProfile) return;
    let disposed = false;
    const refreshAll = async () => {
      const [runtimeResult, codeResult] = await Promise.allSettled([
        refreshFriendCodeRuntimeSnapshot(),
        refreshMyFriendCode(),
      ]);
      if (disposed) return;
      if (runtimeResult.status === "rejected") {
        console.error("Failed to refresh friend code runtime snapshot", runtimeResult.reason);
      }
      if (codeResult.status === "rejected") {
        console.error("Failed to refresh friend code", codeResult.reason);
      }
      if (
        runtimeResult.status === "rejected" &&
        codeResult.status === "rejected"
      ) {
        console.error("Failed to refresh friend code/runtime snapshot", {
          runtimeError: runtimeResult.reason,
          friendCodeError: codeResult.reason,
        });
      }
    };
    void refreshAll();
    const unsubscribe = onBackgroundStatus(() => {
      void refreshAll();
    });
    const timer = window.setInterval(() => {
      void refreshAll();
    }, 4_000);
    return () => {
      disposed = true;
      unsubscribe();
      window.clearInterval(timer);
    };
  }, [
    friendAddOpen,
    userProfile,
    refreshFriendCodeRuntimeSnapshot,
    refreshMyFriendCode,
    netConfig.onionEnabled,
    netConfig.onionSelectedNetwork,
    netConfig.mode,
  ]);

  const friendAddHint = useMemo(() => {
    if (!friendAddOpen) return null;
    if (!myFriendCode && friendCodeRuntimeSnapshot.torState !== "running") {
      return "Tor 연결이 확인되면 친구 코드가 자동으로 생성됩니다.";
    }
    if (!myFriendCode) {
      return "Tor에 연결되었습니다. Onion 주소를 확인하는 중입니다.";
    }
    const decoded = decodeFriendCodeV1(myFriendCode);
    if ("error" in decoded) {
      return "친구 코드 생성이 불완전할 수 있습니다. 잠시 후 다시 복사해 주세요.";
    }

    if (!isTorFriendCodeReady(friendCodeRuntimeSnapshot, decoded)) {
      return "Tor 연결 또는 Onion 주소가 더 이상 준비되지 않았습니다.";
    }
    return null;
  }, [friendAddOpen, friendCodeRuntimeSnapshot, myFriendCode]);

  useEffect(() => {
    const unsubscribe = onTransportStatusChange((convId, status) => {
      setTransportStatusByConv((prev) => ({ ...prev, [convId]: status }));
    });
    return () => {
      unsubscribe();
    };
  }, []);

  useEffect(() => {
    setDirectApprovalHandler(async (convId) => {
      try {
        return await getConvAllowDirect(convId);
      } catch {
        return true;
      }
    });
    return () => {
      setDirectApprovalHandler(null);
    };
  }, []);

  const withTimeout = useCallback(
    async <T,>(promise: Promise<T>, label: string, ms = 15000) => {
      let timer: number | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timer = window.setTimeout(() => reject(new Error(`${label} timed out`)), ms);
      });
      try {
        return await Promise.race([promise, timeout]);
      } finally {
        if (timer) window.clearTimeout(timer);
      }
    },
    []
  );

  const hydrateVault = useCallback(async () => {
    try {
      devLog("hydrate:start");

      const vk = getVaultKey();
      if (vk) {
        const keyOk = await withTimeout(verifyVaultKeyId(vk), "verifyVaultKeyId");
        if (!keyOk) {
          console.warn("[vault] key mismatch -> reset");
          await withTimeout(resetVaultStorage(), "resetVaultStorage");
          await clearStoredSession();
          lockVault();
          resetAppState();
          setPinEnabled(false);
          setPinNeedsReset(false);
          setDefaultTab("startKey");
          setMode("onboarding");
          return;
        }
      }

      await withTimeout(repairVaultTextEncoding(), "repairVaultTextEncoding");

      const profiles = await withTimeout(listProfiles(), "listProfiles");
      const user = profiles.find((profile) => profile.kind === "user") || null;
      const friendProfiles = profiles.filter((profile) => profile.kind === "friend");

      if (!user) {
        await clearStoredSession();
        lockVault();
        resetAppState();
        setPinEnabled(false);
        setPinNeedsReset(false);
        setDefaultTab("create");
        setMode("onboarding");
        navigate("/", { replace: true });
        return;
      }

      const conversations = await withTimeout(listConversations(), "listConversations");
      const messagesBy: Record<string, Message[]> = {};

      for (const conv of conversations) {
        const isDirect =
          !(conv.type === "group" || conv.participants.length > 2) && conv.participants.length === 2;
        const partnerId = isDirect
          ? conv.participants.find((id) => id && id !== user.id) || null
          : null;
        const partner = partnerId
          ? friendProfiles.find((profile) => profile.id === partnerId) || null
          : null;
        messagesBy[conv.id] = await withTimeout(
          loadConversationMessages(conv, partner, user.id),
          "loadConversationMessages"
        );
      }

      setData({
        user,
        friends: friendProfiles,
        convs: conversations,
        messagesByConv: messagesBy,
      });

      setSessionState({ unlocked: true, vkInMemory: true });
      setMode("app");

      devLog("hydrate:done", { profiles: profiles.length, convs: conversations.length });
    } catch (error) {
      console.error("Failed to hydrate vault", error);

      const message = error instanceof Error ? error.message : String(error);

      if (message.includes("ciphertext") || message.includes("decrypted") || message.includes("Vault key mismatch")) {
        try {
          await withTimeout(resetVaultStorage(), "resetVaultStorage");
        } catch (resetError) {
          console.error("Failed to reset vault storage", resetError);
        }
      }

      await clearStoredSession();
      lockVault();
      resetAppState();

      const pinStatus = await getPinStatus();
      setPinEnabled(pinStatus.enabled);
      setPinNeedsReset(pinStatus.needsReset);

      if (pinStatus.enabled && !pinStatus.needsReset) {
        setMode("locked");
      } else {
        if (pinStatus.needsReset) {
          addToast({ message: "PIN must be reset. Unlock with the start key." });
        }
        setDefaultTab("startKey");
        setMode("onboarding");
      }

      addToast({ message: "세션이 만료되었으니 다시 로그인해 주세요." });
    }
  }, [
    addToast,
    devLog,
    navigate,
    resetAppState,
    setData,
    setDefaultTab,
    setMode,
    setPinEnabled,
    setPinNeedsReset,
    setSessionState,
    withTimeout,
  ]);

  useEffect(() => {
    if (bootGuardRef.current) return;
    let cancelled = false;

    const boot = async () => {
      try {
        const header = await getVaultHeader();
        if (!header) {
          setDefaultTab("create");
          setMode("onboarding");
          return;
        }

        const pinStatus = await getPinStatus();
        if (!cancelled) {
          setPinEnabled(pinStatus.enabled);
          setPinNeedsReset(pinStatus.needsReset);
        }

        if (pinStatus.enabled && !pinStatus.needsReset) {
          setMode("locked");
        } else {
          const session = await getStoredSession();
          if (session?.vaultKey) {
            setVaultKey(session.vaultKey);
            await setStoredSession(session.vaultKey);
            await hydrateVault();
            return;
          }

          if (pinStatus.needsReset) {
          addToast({ message: "PIN must be reset. Unlock with the start key." });
          }
          setDefaultTab("startKey");
          setMode("onboarding");
        }
      } catch (error) {
        console.error("Boot failed", error);
        addToast({ message: "초기화에 실패했습니다." });
        setMode("onboarding");
      }
    };

    bootGuardRef.current = boot().finally(() => {
      bootGuardRef.current = null;
    });

    return () => {
      cancelled = true;
    };
  }, [addToast, hydrateVault, setDefaultTab, setMode, setPinEnabled, setPinNeedsReset]);

  useEffect(() => {
    if (ui.mode !== "app") return;
    if (outboxSchedulerStarted.current) return;
    startOutboxScheduler();
    outboxSchedulerStarted.current = true;
  }, [ui.mode]);

  useEffect(() => {
    if (ui.mode !== "app") return;
    const runUpdate = () => {
      void runVerifiedTorAutoUpdate().catch((error) => {
        console.error("Verified Tor auto-update failed", error);
      });
    };
    runUpdate();
    const interval = window.setInterval(runUpdate, TOR_AUTO_UPDATE_INTERVAL_MS);
    return () => window.clearInterval(interval);
  }, [ui.mode]);

  useEffect(() => {
    if (ui.mode !== "app") return;
    if (friendInboxStarted.current) return;
    startFriendInboxListener((event) => {
      void hydrateVault();
      if (event?.type === "friend_req") {
        addToast({ message: "새 친구 요청이 도착했습니다." });
      }
    }, {
      getLocalFriendCode: async () => {
        const payload = await buildLocalFriendCodePayload();
        return encodeFriendCodeV1({ v: 1, ...payload });
      },
    });
    friendInboxStarted.current = true;
  }, [addToast, buildLocalFriendCodePayload, hydrateVault, ui.mode]);

  useEffect(() => {
    if (ui.mode !== "app") return;
    let disposed = false;
    let preparing = false;
    const prepare = async () => {
      if (disposed || preparing) return;
      preparing = true;
      try {
        const status = await getOnionStatus();
        if (status.runtime.status !== "running") return;
        await ensurePublishedLocalOnionEndpoint();
      } catch {
        // The next status event or timer retries publication readiness.
      } finally {
        preparing = false;
      }
    };
    void prepare();
    const unsubscribe = onBackgroundStatus(() => void prepare());
    const timer = window.setInterval(() => void prepare(), 5_000);
    return () => {
      disposed = true;
      unsubscribe();
      window.clearInterval(timer);
    };
  }, [ui.mode]);

  useEffect(() => {
    if (ui.mode !== "app") {
      routerBootstrapRunKeyRef.current = null;
      return;
    }
    const mode = netConfig.mode;
    const onionEnabled = netConfig.onionEnabled;
    const onionSelectedNetwork = netConfig.onionSelectedNetwork;
    const onionActive = mode === "onionRouter" || onionEnabled;
    const autoPrepareTor = shouldAutoPrepareTor({
      mode,
      onionEnabled,
      torAutoPrepareOnAppStart: netConfig.torAutoPrepareOnAppStart,
    });
    const runKey = `${ui.mode}:${String(onionActive)}:${onionSelectedNetwork}:${String(autoPrepareTor)}`;
    if (routerBootstrapRunKeyRef.current === runKey) return;
    routerBootstrapRunKeyRef.current = runKey;
    let cancelled = false;
    const operationId = `router-bootstrap:${newClientBatchId()}`;
    const startedAt = nowMonotonicMs();
    const elapsedMs = () => Math.max(0, Math.round(nowMonotonicMs() - startedAt));
    void (async () => {
      const runtimeBootstrap: Record<string, unknown> = {};
      const baseContext = {
        mode,
        onionEnabled,
        onionSelectedNetwork,
        autoPrepareTor,
      };
      emitRouterTestLog({
        status: "attempt",
        stage: "app-bootstrap:start",
        source: "app:routerBootstrap",
        operationId,
        elapsedMs: 0,
        context: {
          ...baseContext,
          onionActive,
        },
      });
      try {
        if (onionActive && !autoPrepareTor) {
          emitRouterTestLog({
            status: "ready",
            stage: "app-bootstrap:skipped",
            source: "app:routerBootstrap",
            operationId,
            elapsedMs: elapsedMs(),
            message: "Tor automatic preparation is disabled",
            context: baseContext,
          });
          return;
        }
        if (autoPrepareTor) {
          const torRuntime = TorRuntime.getInstance();
          try {
            await torRuntime.start({ timeoutMs: 15_000 });
            await torRuntime.awaitReady(15_000);
            runtimeBootstrap.torRuntimeState = torRuntime.getState();
            runtimeBootstrap.torDataDir = torRuntime.getDataDir();
            runtimeBootstrap.torSocksPort = (() => {
              const socks = torRuntime.getSocksUrl();
              if (!socks) return null;
              try {
                const parsed = new URL(socks);
                return parsed.port || null;
              } catch {
                return null;
              }
            })();
          } catch (error) {
            runtimeBootstrap.torRuntimeError =
              error instanceof Error ? error.message : String(error);
          }
        }
        const currentConfig = useNetConfigStore.getState().config;
        const warmupConfig = onionActive
          ? { ...currentConfig, mode: "onionRouter" as const }
          : currentConfig;
        const warmup = await prewarmRouter({ includeFallback: true, config: warmupConfig });
        if (!cancelled) {
          const runtimeSnapshot = await resolveRuntimeNetworkSnapshot();
          devLog("router:prewarm", {
            chosen: warmup.chosenTransport,
            requested: warmup.requested,
            started: warmup.started,
            failed: warmup.failed,
            mode: warmup.mode,
            onionEnabled: warmup.onionEnabled,
            onionSelectedNetwork: warmup.onionSelectedNetwork,
            runtimeBootstrap,
            runtimeSnapshot,
          });
          const selectedRuntimeState = runtimeSnapshot.torState;
          const selectedRuntimeDetail = runtimeSnapshot.torDetail;
          const routerOpened = warmup.started.includes("onionRouter");
          const warmupComplete = !onionActive || (selectedRuntimeState === "running" && routerOpened);
          emitRouterTestLog({
            status: warmupComplete ? "ready" : "failed",
            stage: "app-bootstrap:result",
            source: "app:routerBootstrap",
            operationId,
            elapsedMs: elapsedMs(),
            message: warmupComplete ? "Router prewarm completed" : "Router prewarm incomplete",
            error: warmupComplete
              ? undefined
              : `selectedRuntimeState:${selectedRuntimeState ?? "unknown"}|routerOpened:${String(routerOpened)}`,
            context: {
              ...baseContext,
              chosenTransport: warmup.chosenTransport,
              requestedTransports: warmup.requested,
              startedTransports: warmup.started,
              failedTransports: warmup.failed,
              runtimeBootstrap,
              runtimeSnapshot,
              selectedRuntimeState,
              selectedRuntimeDetail,
              routerOpened,
            },
          });
          if (onionActive && (selectedRuntimeState !== "running" || !routerOpened)) {
            const now = Date.now();
            if (now - onionBootstrapToastAtRef.current > 15_000) {
              onionBootstrapToastAtRef.current = now;
              addToast({
                message: routerOpened
                  ? "Onion 네트워크가 아직 준비되지 않았습니다. 설정에서 Tor 상태를 확인해 주세요."
                  : "Onion 라우터 초기화에 실패했습니다. 잠시 후 다시 시도하거나 네트워크 설정을 확인해 주세요.",
              });
            }
          }
        }
      } catch (error) {
        if (!cancelled) {
          emitRouterTestLog({
            status: "failed",
            stage: "app-bootstrap:exception",
            source: "app:routerBootstrap",
            operationId,
            elapsedMs: elapsedMs(),
            error: error instanceof Error ? error.message : String(error),
            errorDetail: toInfoLogErrorDetail(error),
            context: {
              ...baseContext,
              runtimeBootstrap,
            },
          });
          console.error("Failed to bootstrap router warmup", error);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [
    addToast,
    devLog,
    emitRouterTestLog,
    netConfig.mode,
    netConfig.onionEnabled,
    netConfig.onionSelectedNetwork,
    netConfig.torAutoPrepareOnAppStart,
    resolveRuntimeNetworkSnapshot,
    ui.mode,
  ]);

  // cleanup 메모리 문제(EffectCallback) + unsubscribe 방어
  useEffect(() => {
    if (typeof window !== "undefined") {
      connectionToastShown.current = window.sessionStorage.getItem(connectionToastKey) === "1";
    }

    let prevConnected = false;

    const unsubscribe = onConnectionStatus((status) => {
      const connected = status.state === "connected";

      if (!connected || prevConnected) {
        prevConnected = connected;
        return;
      }
      if (ui.mode !== "app") {
        prevConnected = connected;
        return;
      }
      if (connectionToastShown.current) {
        prevConnected = connected;
        return;
      }

      addToast({ message: "세션이 연결되었습니다." });
      connectionToastShown.current = true;

      if (typeof window !== "undefined") {
        window.sessionStorage.setItem(connectionToastKey, "1");
      }

      prevConnected = connected;
    });

    return () => {
      try {
        if (typeof unsubscribe === "function") unsubscribe();
      } catch (e) {
        console.error("Failed to unsubscribe connection status", e);
      }
    };
  }, [addToast, connectionToastKey, ui.mode]);

  const handleCreate = async (displayName: string) => {
    if (onboardingLockRef.current) return;
    onboardingLockRef.current = true;

    try {
      setOnboardingError("");
      devLog("onboarding:create:start");

      await withTimeout(clearStoredSession(), "clearStoredSession");
      await withTimeout(resetVaultStorage(), "resetVaultStorage");
      await withTimeout(bootstrapVault(), "bootstrapVault");

      const vk = getVaultKey();
      if (!vk) throw new Error("Vault key missing after bootstrap.");

      await withTimeout(
        Promise.all([getOrCreateIdentityKeypair(), getOrCreateDhKeypair()]).then(() => undefined),
        "ensureDeviceKeys"
      );
      getOrCreateDeviceId();

      const now = Date.now();
      const user: UserProfile = {
        id: createId(),
        displayName,
        status: "Hello from NKC",
        theme: "light",
        kind: "user",
        createdAt: now,
        updatedAt: now,
      };

      // IndexedDB writes cannot be cancelled safely. The initial sample data contains
      // many encrypted records, so racing it against the generic 15 second timeout can
      // report failure while writes are still running on slower machines.
      await seedVaultData(user);
      await withTimeout(setStoredSession(vk), "setStoredSession");
      await withTimeout(hydrateVault(), "hydrateVault");
    } catch (error) {
      console.error("Vault bootstrap failed", error);
      setOnboardingError(error instanceof Error ? error.message : "금고 초기화에 실패했습니다.");
      lockVault();
      addToast({ message: "금고 초기화에 실패했습니다." });
    } finally {
      onboardingLockRef.current = false;
    }
  };

  const handleStartKeyUnlock = async (startKey: string) => {
    if (onboardingLockRef.current) return;
    onboardingLockRef.current = true;

    if (!validateStartKey(startKey)) {
      addToast({ message: "시작 키 형식이 올바르지 않습니다. (예: NKC-...)" });
      onboardingLockRef.current = false;
      return;
    }

    try {
      setOnboardingError("");
      devLog("onboarding:start-key:start");

      await withTimeout(unlockVault(startKey), "unlockVault");

      const vk = getVaultKey();
      if (!vk) throw new Error("Vault key missing after unlock.");

      await withTimeout(
        Promise.all([getOrCreateIdentityKeypair(), getOrCreateDhKeypair()]).then(() => undefined),
        "ensureDeviceKeys"
      );
      getOrCreateDeviceId();

      const profiles = await withTimeout(listProfiles(), "listProfiles");
      if (!profiles.length) {
        throw new Error("기존 계정 프로필을 찾을 수 없습니다.");
      }

      await withTimeout(setStoredSession(vk), "setStoredSession");
      await withTimeout(hydrateVault(), "hydrateVault");
    } catch (error) {
      console.error("Start key unlock failed", error);
      setOnboardingError(
        error instanceof Error ? error.message : "시작 키로 잠금 해제에 실패했습니다."
      );
      lockVault();
      addToast({ message: "시작 키로 잠금 해제에 실패했습니다." });
    } finally {
      onboardingLockRef.current = false;
    }
  };

  const handlePinUnlock = async (pin: string): Promise<UnlockResult> => {
    const result = await verifyPin(pin);

    if (!result.ok) {
      if (result.reason === "unavailable") {
        return {
          ok: false,
          reason: "unavailable",
          error: result.message || "PIN lock is unavailable on this platform/build.",
        };
      }
      if (result.reason === "not_set") {
        return {
          ok: false,
          reason: "not_set",
          error: "PIN 정보가 없습니다. 시작 키로 재설정해주세요.",
        };
      }

      const reason = result.reason === "locked" ? "locked" : "mismatch";
      return {
        ok: false,
        reason,
        error:
          reason === "locked"
            ? "잠시 후 다시 시도해주세요."
            : "PIN이 올바르지 않습니다.",
        retryAfterMs: result.retryAfterMs,
      };
    }

    try {
      const keyOk = await verifyVaultKeyId(result.vaultKey);
      if (!keyOk) {
        await clearPinRecord();
        setPinEnabled(true);
        setPinNeedsReset(true);
        return {
          ok: false,
          reason: "not_set",
          error: "PIN이 현재 금고와 일치하지 않습니다. 시작 키로 재설정하세요.",
        };
      }
      setVaultKey(result.vaultKey);
      await setStoredSession(result.vaultKey);
      await hydrateVault();
      navigate("/");
      return { ok: true };
    } catch (error) {
      console.error("PIN unlock hydrate failed", error);
      await clearPinRecord();
      setPinEnabled(true);
      setPinNeedsReset(true);
      return { ok: false, error: "잠금 해제에 실패했습니다." };
    }
  };

  const handleLock = useCallback(async () => {
    let enabled = pinEnabled;
    let needsReset = pinNeedsReset;

    // Re-sync with the source of truth in case local state is stale.
    if (!enabled || needsReset) {
      try {
        const pinStatus = await getPinStatus();
        enabled = pinStatus.enabled;
        needsReset = pinStatus.needsReset;
        setPinEnabled(enabled);
        setPinNeedsReset(needsReset);
      } catch (error) {
        console.error("Failed to read PIN status before lock", error);
      }
    }

    if (!enabled || needsReset) {
      if (needsReset) {
        addToast({ message: "Reset your PIN to enable lock." });
        return;
      }
      addToast({ message: "Set a PIN to enable lock." });
      return;
    }

    try {
      await clearStoredSession();
      lockVault();
      resetAppState();
      setMode("locked");
      navigate("/unlock");
    } catch (error) {
      console.error("Failed to lock", error);
      addToast({ message: "Lock failed." });
    }
  }, [
    addToast,
    navigate,
    pinEnabled,
    pinNeedsReset,
    resetAppState,
    setMode,
    setPinEnabled,
    setPinNeedsReset,
  ]);

  useEffect(() => {
    if (!pinEnabled || pinNeedsReset || ui.mode !== "app") return;

    const handleVisibility = () => {
      if (document.visibilityState === "hidden") {
        wasHiddenRef.current = true;
        return;
      }
      if (document.visibilityState === "visible" && wasHiddenRef.current) {
        wasHiddenRef.current = false;
        void handleLock();
      }
    };

    document.addEventListener("visibilitychange", handleVisibility);
    return () => document.removeEventListener("visibilitychange", handleVisibility);
  }, [handleLock, pinEnabled, pinNeedsReset, ui.mode]);

  const handleLogout = async () => {
    try {
      await clearStoredSession();
      lockVault();
      resetAppState();

      const pinStatus = await getPinStatus();
      setPinEnabled(pinStatus.enabled);
      setPinNeedsReset(pinStatus.needsReset);

      if (pinStatus.enabled && !pinStatus.needsReset) {
        setMode("locked");
        navigate("/unlock");
      } else {
        if (pinStatus.needsReset) {
          addToast({ message: "PIN must be reset. Unlock with the start key." });
        }
        setDefaultTab("startKey");
        setMode("onboarding");
        navigate("/");
      }
    } catch (error) {
      console.error("Failed to logout", error);
      addToast({ message: "로그아웃에 실패했습니다." });
    }
  };

  const handleSetPin = async (pin: string) => {
    try {
      await savePin(pin);
      setPinEnabled(true);
      setPinNeedsReset(false);
      addToast({ message: "PIN set." });
      return { ok: true as const };
    } catch (error) {
      if (isPinUnavailableError(error)) {
        return {
          ok: false as const,
          error: "PIN lock is unavailable on this platform/build.",
        };
      }
      const message = String((error as { message?: unknown })?.message ?? error);
      console.error("Failed to set PIN", message);
      return {
        ok: false as const,
        error: message || "Failed to set PIN.",
      };
    }
  };

  const handleDisablePin = async () => {
    try {
      await clearPin();
      const status = await getPinStatus();
      if (status.enabled) {
        throw new Error("PIN disable did not persist");
      }
      setPinEnabled(false);
      setPinNeedsReset(false);
      addToast({ message: "PIN disabled." });
    } catch (error) {
      if (isPinUnavailableError(error)) {
        addToast({ message: "PIN lock is unavailable on this platform/build." });
        throw error;
      }
      console.error("Failed to clear PIN", error);
      addToast({ message: "Failed to disable PIN." });
      throw error;
    }
  };

  const handleRotateStartKey = async (newKey: string) => {
    try {
      if (!validateStartKey(newKey)) {
        addToast({ message: "시작 키 형식이 올바르지 않습니다. (예: NKC-...)" });
        return;
      }

      await rotateVaultKeys(newKey, () => {});
      const vk = getVaultKey();
      if (vk) await setStoredSession(vk);

      await clearPinRecord();
      setPinEnabled(true);
      setPinNeedsReset(true);

      addToast({ message: "시작 키가 변경되었습니다. PIN을 다시 설정해 주세요." });
    } catch (error) {
      console.error("Failed to rotate start key", error);
      addToast({ message: "시작 키 변경에 실패했습니다." });
      throw error;
    }
  };

  const handleSaveProfile = async (payload: { displayName: string; status: string; theme: "dark" | "light" }) => {
    if (!userProfile) return;

    const previousProfile = userProfile;
    const updated: UserProfile = {
      ...userProfile,
      ...payload,
      updatedAt: Date.now(),
    };

    const themeChanged = updated.theme !== previousProfile.theme;
    if (themeChanged) await applyDocumentTheme(updated.theme, true);
    setUserProfile(updated);
    try {
      await saveProfile(updated);
    } catch (error) {
      if (useAppStore.getState().userProfile?.updatedAt === updated.updatedAt) {
        setUserProfile(previousProfile);
        if (themeChanged) await applyDocumentTheme(previousProfile.theme, true);
      }
      throw error;
    }
  };

  const handleToggleTheme = async () => {
    if (!userProfile) return;
    const nextTheme = userProfile.theme === "dark" ? "light" : "dark";
    await handleSaveProfile({
      displayName: userProfile.displayName,
      status: userProfile.status ?? "",
      theme: nextTheme,
    });
  };

  const handleUploadPhoto = async (file: File) => {
    if (!userProfile) return;
    const avatarRef = await saveProfilePhoto(userProfile.id, file);
    const updated: UserProfile = {
      ...userProfile,
      avatarRef,
      updatedAt: Date.now(),
    };
    await saveProfile(updated);
    await hydrateVault();
  };

  const recoverRoutingHintsFromFriendCode = useCallback((profile: UserProfile) => {
    const code = profile.profileVcard?.friendCode?.trim();
    if (!code) return undefined;
    const decoded = decodeFriendCodeV1(code);
    if ("error" in decoded) return undefined;
    return sanitizeRoutingHints({
      deviceId: decoded.deviceId,
      onionAddr: decoded.onionAddr,
    });
  }, []);

  const buildResolvedRoutingMeta = useCallback(
    (profile: UserProfile) => {
      const recovered = recoverRoutingHintsFromFriendCode(profile);
      const toDeviceId =
        profile.routingHints?.deviceId ??
        profile.primaryDeviceId ??
        profile.deviceId ??
        recovered?.deviceId;
      const torOnion = profile.routingHints?.onionAddr ?? recovered?.onionAddr;
      return {
        toDeviceId,
        route: torOnion ? { torOnion } : undefined,
      };
    },
    [recoverRoutingHintsFromFriendCode]
  );

  const recoverAndPersistFriendRouting = useCallback(
    async (friend: UserProfile) => {
      const recovered = recoverRoutingHintsFromFriendCode(friend);
      if (!recovered) return friend;
      const mergedHints = sanitizeRoutingHints({
        deviceId: friend.routingHints?.deviceId ?? recovered.deviceId,
        onionAddr: friend.routingHints?.onionAddr ?? recovered.onionAddr,
      });
      const mergedPrimaryDeviceId = friend.primaryDeviceId ?? friend.deviceId ?? recovered.deviceId;
      const nextRoutingHints = mergedHints ?? friend.routingHints;
      const changed =
        !sameRoutingHints(nextRoutingHints, friend.routingHints) ||
        (mergedPrimaryDeviceId ?? "") !== (friend.primaryDeviceId ?? "");
      if (!changed) return friend;
      const updated: UserProfile = {
        ...friend,
        routingHints: nextRoutingHints,
        primaryDeviceId: mergedPrimaryDeviceId,
        updatedAt: Date.now(),
      };
      await saveProfile(updated);
      return updated;
    },
    [recoverRoutingHintsFromFriendCode]
  );

  const buildRoutingMeta = useCallback((partner: UserProfile) => {
    return buildResolvedRoutingMeta(partner);
  }, [buildResolvedRoutingMeta]);

  const markFriendRequestReachability = useCallback(
    async (
      friendId: string,
      patch: Partial<NonNullable<UserProfile["reachability"]>>
    ) => {
      const latest = useAppStore.getState().friends.find((item) => item.id === friendId);
      if (!latest) return;
      await saveProfile({
        ...latest,
        reachability: {
          ...(latest.reachability ?? { status: "unreachable" as const }),
          ...patch,
        },
        updatedAt: Date.now(),
      });
      await hydrateVault();
    },
    [hydrateVault]
  );

  const sendDirectEnvelope = useCallback(
    async (
      conv: Conversation,
      partner: UserProfile,
      body: unknown,
      priority: "high" | "normal" = "high",
      options?: {
        eventId?: string;
        persistEvent?: boolean;
        cryptoContext?: {
          conversationKey: Uint8Array;
          ratchetBaseKey: Uint8Array;
          identityPrivateKey: Uint8Array;
        };
        encryptor?: typeof encryptEnvelope;
        releaseBeforeRoute?: boolean;
        outboxRetention?: "standard" | "transient";
        transferId?: string;
        chunkIndex?: number;
        binaryTransport?: boolean;
      }
    ) => {
      if (!partner.dhPub || !partner.identityPub) {
        throw new Error("Missing peer keys");
      }
      const previous = directEnvelopeSendChainsRef.current.get(conv.id) ?? Promise.resolve();
      let release!: () => void;
      let released = false;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const tail = previous.catch(() => {}).then(() => gate);
      directEnvelopeSendChainsRef.current.set(conv.id, tail);
      await previous.catch(() => {});
      try {
      const now = Date.now();
      const friendKeyId = partner.friendId ?? partner.id;
      const lamport = await nextLamportForConv(conv.id);
      const header: EnvelopeHeader = {
        v: 1 as const,
        eventId: options?.eventId ?? createId(),
        convId: conv.id,
        ts: now,
        lamport,
        authorDeviceId: getOrCreateDeviceId(),
      };
      header.prev = await getLastEventHash(conv.id);

      let cryptoContext = options?.cryptoContext;
      if (!cryptoContext) {
        const dhPriv = await getDhPrivateKey();
        const theirDhPub = decodeBase64Url(partner.dhPub);
        const pskBytes = await getFriendPsk(friendKeyId);
        const legacyContextBytes = new TextEncoder().encode(`direct:${friendKeyId}`);
        const ratchetContextBytes = new TextEncoder().encode(`conv:${conv.id}`);
        const keys = await deriveConversationKeyPair(
          dhPriv,
          theirDhPub,
          pskBytes,
          legacyContextBytes,
          ratchetContextBytes
        );
        cryptoContext = { ...keys, identityPrivateKey: await getIdentityPrivateKey() };
      }
      const { conversationKey, ratchetBaseKey, identityPrivateKey } = cryptoContext;
      let keyForEnvelope = conversationKey;
      try {
        const ratchet = await nextSendDhKey(conv.id, ratchetBaseKey);
        header.rk = ratchet.headerRk;
        keyForEnvelope = ratchet.msgKey;
      } catch {
        try {
          const ratchet = await nextSendKey(conv.id, ratchetBaseKey);
          header.rk = ratchet.headerRk;
          keyForEnvelope = ratchet.msgKey;
        } catch (error) {
          console.warn("[ratchet] send fallback to legacy", error);
        }
      }

      const envelope = await (options?.encryptor ?? encryptEnvelope)(
        keyForEnvelope,
        header,
        body,
        identityPrivateKey
      );
      const envelopeJson = JSON.stringify(envelope);

      if (options?.persistEvent !== false) {
        const eventHash = await computeEnvelopeHash(envelope);
        await saveEvent({
          eventId: header.eventId,
          convId: header.convId,
          authorDeviceId: header.authorDeviceId,
          lamport: header.lamport,
          ts: header.ts,
          envelopeJson,
          prevHash: header.prev,
          eventHash,
        });
      }

      if (options?.releaseBeforeRoute) {
        released = true;
        release();
      }

      const routed = await sendCiphertext({
        convId: conv.id,
        messageId: header.eventId,
        ciphertext: envelopeJson,
        priority,
        outboxRetention: options?.outboxRetention,
        transferId: options?.transferId,
        chunkIndex: options?.chunkIndex,
        binaryTransport: options?.binaryTransport,
        ...buildRoutingMeta(partner),
      });
      if (!routed.ok) {
        throw new Error(routed.error ?? "Failed to route message");
      }

      return { header, envelopeJson };
      } finally {
        if (!released) release();
        if (directEnvelopeSendChainsRef.current.get(conv.id) === tail) {
          directEnvelopeSendChainsRef.current.delete(conv.id);
        }
      }
    },
    [buildRoutingMeta]
  );

  const buildFriendRequestPayload = useCallback(async (convId: string, traceId?: string) => {
    if (!userProfile) return null;
    const payload = await buildLocalFriendCodePayload();
    const friendCode = encodeFriendCodeV1({
      v: 1,
      ...payload,
    });
    return {
      type: "friend_req" as const,
      convId,
      traceId,
      from: {
        identityPub: payload.identityPub,
        dhPub: payload.dhPub,
        deviceId: payload.deviceId,
        friendCode,
      },
      profile: {
        displayName: userProfile.displayName,
        status: userProfile.status,
        avatarRef: userProfile.avatarRef,
      },
      ts: Date.now(),
    };
  }, [buildLocalFriendCodePayload, userProfile]);

  const ensureDirectConvForFriend = useCallback(
    async (friend: UserProfile) => {
      if (!userProfile) return null;
      const existingConv = convs.find(
        (conv) =>
          !(conv.type === "group" || conv.participants.length > 2) &&
          conv.participants.includes(friend.id)
      );
      if (existingConv) return existingConv;
      const now = Date.now();
      const newConv: Conversation = {
        id: createId(),
        type: "direct",
        name: friend.displayName,
        pinned: friend.isFavorite ?? false,
        unread: 0,
        hidden: false,
        muted: false,
        blocked: false,
        pendingOutgoing: friend.friendStatus === "request_out",
        lastTs: now,
        lastMessage: "친구 요청을 보냈습니다.",
        participants: [userProfile.id, friend.id],
      };
      await saveConversation(newConv);
      return newConv;
    },
    [convs, userProfile]
  );

  const sendFriendControlPacket = useCallback(
    async (
      conv: Conversation,
      partner: UserProfile,
      payload: unknown,
      priority: "high" | "normal" = "high"
    ) => {
      if (!isFriendControlFrame(payload)) {
        throw new Error("Unsupported friend control frame");
      }
      const unsignedPayload = stripFriendControlFrameSignature(payload);
      let signedPayload: FriendControlFrame;
      if (payload.sig) {
        signedPayload = payload;
      } else {
        const identityPriv = await getIdentityPrivateKey();
        const protocolReadyPayload = await enrichFriendControlFrameWithProtocol(
          unsignedPayload,
          identityPriv,
          {
            pskHint: partner.friendId ?? partner.id,
            localFriendCode: unsignedPayload.from.friendCode,
            remoteFriendCode: partner.profileVcard?.friendCode,
            remoteIdentityPub: partner.identityPub,
            remoteDhPub: partner.dhPub,
            remoteDeviceId: partner.routingHints?.deviceId ?? partner.primaryDeviceId,
            remoteOnionAddr: partner.routingHints?.onionAddr,
          }
        );
        signedPayload = {
          ...protocolReadyPayload,
          sig: await signFriendControlFrame(protocolReadyPayload, identityPriv),
        };
      }
      const frameType = signedPayload.type;
      const traceId = signedPayload.traceId;
      const messageId = createId();
      const operationId = `friend-route:${newClientBatchId()}`;
      const startedAt = nowMonotonicMs();
      const elapsedMs = () => Math.max(0, Math.round(nowMonotonicMs() - startedAt));
      const routingMeta = buildRoutingMeta(partner);
      const toDeviceIdSource = partner.routingHints?.deviceId
        ? "routingHints.deviceId"
        : partner.primaryDeviceId
          ? "primaryDeviceId"
          : partner.deviceId
            ? "deviceId"
            : partner.profileVcard?.friendCode
              ? "profileVcard.friendCode"
              : "none";
      const payloadHasSigBeforeSign = Boolean(
        (payload as { sig?: unknown } | null | undefined)?.sig
      );
      const payloadJson = JSON.stringify(signedPayload);
      const payloadByteLength = new TextEncoder().encode(payloadJson).byteLength;
      const netConfig = useNetConfigStore.getState().config;
      const hasExplicitOnionRoute = Boolean(
        routingMeta.route?.torOnion
      );
      // Friend-control frames establish the relationship itself, so they cannot depend on an
      // already-established self-onion relay path. Route them directly to the endpoint embedded
      // in the friend code; normal chat traffic continues to use the configured mode.
      const routingConfig = hasExplicitOnionRoute
        ? { ...netConfig, mode: "onionRouter" as const }
        : netConfig;
      const shouldPrewarmOnionRoute =
        hasExplicitOnionRoute;
      let prewarmResult: Awaited<ReturnType<typeof prewarmRouter>> | null = null;
      if (shouldPrewarmOnionRoute) {
        emitRouterTestLog({
          status: "attempt",
          stage: "friend-control:prewarm:start",
          source: "app:sendFriendControlPacket",
          operationId,
          elapsedMs: elapsedMs(),
          context: {
            frameType,
            convId: conv.id,
            partnerProfileId: partner.id,
            onionSelectedNetwork: routingConfig.onionSelectedNetwork,
            hasTorOnion: Boolean(routingMeta.route?.torOnion),
          },
        });
        try {
          prewarmResult = await withTimeout(
            prewarmRouter({
              config: routingConfig,
              includeFallback: true,
            }),
            "friend-control:prewarm",
            FRIEND_ROUTE_SEND_DEADLINE_MS
          );
          const prewarmOpened = prewarmResult.started.includes("onionRouter");
          emitRouterTestLog({
            status: prewarmOpened ? "ready" : "failed",
            stage: "friend-control:prewarm:result",
            source: "app:sendFriendControlPacket",
            operationId,
            elapsedMs: elapsedMs(),
            message: prewarmOpened
              ? "Friend control prewarm opened onion router"
              : "Friend control prewarm failed to open onion router",
            error: prewarmOpened ? undefined : prewarmResult.failed.join(" || "),
            context: {
              frameType,
              convId: conv.id,
              partnerProfileId: partner.id,
              chosenTransport: prewarmResult.chosenTransport,
              requestedTransports: prewarmResult.requested,
              startedTransports: prewarmResult.started,
              failedTransports: prewarmResult.failed,
            },
          });
        } catch (error) {
          emitRouterTestLog({
            status: "failed",
            stage: "friend-control:prewarm:exception",
            source: "app:sendFriendControlPacket",
            operationId,
            elapsedMs: elapsedMs(),
            error: error instanceof Error ? error.message : String(error),
            errorDetail: toInfoLogErrorDetail(error),
            context: {
              frameType,
              convId: conv.id,
              partnerProfileId: partner.id,
            },
          });
          return false;
        }
      }
      const runtimeSnapshot = await resolveRuntimeNetworkSnapshot();
      const senderDeviceId =
        signedPayload.from?.deviceId ?? getOrCreateDeviceId();
      const commonContext = {
        priority,
        partnerProfileId: partner.id,
        partnerFriendId: partner.friendId,
        partnerFriendStatus: partner.friendStatus,
        partnerReachabilityStatus: partner.reachability?.status ?? null,
        hasToDeviceId: Boolean(routingMeta.toDeviceId),
        hasTorOnion: Boolean(routingMeta.route?.torOnion),
        hasRoutingHintDeviceId: Boolean(partner.routingHints?.deviceId || routingMeta.toDeviceId),
        hasPrimaryDeviceId: Boolean(partner.primaryDeviceId),
        hasLegacyDeviceId: Boolean(partner.deviceId),
        toDeviceIdSource,
        hasRoutingHintOnion: Boolean(partner.routingHints?.onionAddr || routingMeta.route?.torOnion),
        convPendingOutgoing: Boolean(conv.pendingOutgoing),
        convPendingAcceptance: Boolean(conv.pendingAcceptance),
        convPendingFriendResponse: conv.pendingFriendResponse ?? null,
        payloadHasSigBeforeSign,
        payloadHasSigAfterSign: Boolean(signedPayload.sig),
        payloadByteLength,
        payloadTimestamp: signedPayload.ts ?? null,
        payloadConvId: signedPayload.convId ?? null,
        payloadTraceId: traceId ?? null,
        netMode: netConfig.mode,
        effectiveNetMode: routingConfig.mode,
        routeModeOverride: null,
        prewarmChosenTransport: prewarmResult?.chosenTransport ?? null,
        prewarmStartedTransports: prewarmResult?.started ?? null,
        prewarmFailedTransports: prewarmResult?.failed ?? null,
        onionEnabled: netConfig.onionEnabled,
        onionSelectedNetwork: netConfig.onionSelectedNetwork,
        onionProxyEnabled: netConfig.onionProxyEnabled,
        webrtcRelayOnly: netConfig.webrtcRelayOnly,
        disableLinkPreview: netConfig.disableLinkPreview,
        torStatus: netConfig.tor?.status ?? null,
        torRuntimeState: runtimeSnapshot.torState,
        torRuntimeDetail: runtimeSnapshot.torDetail,
      };
      let result:
        | Awaited<ReturnType<typeof sendCiphertext>>
        | null = null;
      emitFriendRouteTestLog({
        direction: "outgoing",
        status: "attempt",
        frameType,
        source: "app:sendFriendControlPacket",
        operationId,
        traceId,
        elapsedMs: 0,
        messageId,
        convId: conv.id,
        senderDeviceId,
        toDeviceId: routingMeta.toDeviceId,
        torOnion: routingMeta.route?.torOnion,
        context: {
          ...commonContext,
          checkpoint: "sendCiphertext:start",
        },
      });
      try {
        result = await withTimeout(
          sendCiphertext(
            {
              convId: conv.id,
              messageId,
              ciphertext: payloadJson,
              priority,
              ...routingMeta,
            },
            { config: routingConfig }
          ),
          "friend-control:send",
          FRIEND_ROUTE_SEND_DEADLINE_MS
        );
      } catch (error) {
        const thrownMessage = error instanceof Error ? error.message : String(error);
        const errorParts = splitRouteErrorParts(thrownMessage);
        const normalizedErrorParts = errorParts.length > 0 ? errorParts : [thrownMessage];
        const errorCodes = collectRouteErrorCodes(normalizedErrorParts);
        emitFriendRouteTestLog({
          direction: "outgoing",
          status: "failed",
          frameType,
          messageId,
          convId: conv.id,
          source: "app:sendFriendControlPacket",
          operationId,
          traceId,
          elapsedMs: elapsedMs(),
          senderDeviceId,
          toDeviceId: routingMeta.toDeviceId,
          torOnion: routingMeta.route?.torOnion,
          error: `sendCiphertext threw: ${thrownMessage}`,
          errorDetail: toInfoLogErrorDetail(error),
          context: {
            ...commonContext,
            checkpoint: "sendCiphertext:throw",
            errorParts: normalizedErrorParts,
            errorCodes,
            failureClass: classifyRouteFailure(errorCodes, normalizedErrorParts),
          },
        });
        return false;
      }
      const retriedWithRouterWarmup = false;
      const finalErrorMessage = result.error ?? "Friend control packet send failed";
      if (!result.ok) {
        const errorMessage = finalErrorMessage;
        const errorParts = splitRouteErrorParts(errorMessage);
        const normalizedErrorParts = errorParts.length > 0 ? errorParts : [errorMessage];
        const errorCodes = collectRouteErrorCodes(normalizedErrorParts);
        emitFriendRouteTestLog({
          direction: "outgoing",
          status: "failed",
          frameType,
          source: "app:sendFriendControlPacket",
          operationId,
          traceId,
          elapsedMs: elapsedMs(),
          via: result.transport,
          messageId,
          convId: conv.id,
          senderDeviceId,
          toDeviceId: routingMeta.toDeviceId,
          torOnion: routingMeta.route?.torOnion,
          error: errorMessage,
          context: {
            ...commonContext,
            checkpoint: "sendCiphertext:result-not-ok",
            errorParts: normalizedErrorParts,
            errorCodes,
            failureClass: classifyRouteFailure(errorCodes, normalizedErrorParts),
            routerDiagnostic: result.diagnostic ?? null,
            retriedWithRouterWarmup,
            ...(frameType === "friend_req"
              ? {
                  peerReceiptConfirmed: false,
                  receiptConfirmation: "awaiting-friend_accept-or-friend_decline",
                }
              : {}),
          },
        });
        return false;
      }
      emitFriendRouteTestLog({
        direction: "outgoing",
        status: "sent",
        frameType,
        source: "app:sendFriendControlPacket",
        operationId,
        traceId,
        elapsedMs: elapsedMs(),
        via: result.transport,
        messageId,
        convId: conv.id,
        senderDeviceId,
        toDeviceId: routingMeta.toDeviceId,
        torOnion: routingMeta.route?.torOnion,
        context: {
          ...commonContext,
          checkpoint: "sendCiphertext:result-ok",
          finalVia: result.transport,
          routerDiagnostic: result.diagnostic ?? null,
          ...(frameType === "friend_req"
            ? {
                peerReceiptConfirmed: false,
                receiptConfirmation: "awaiting-friend_accept-or-friend_decline",
              }
            : {}),
        },
      });
      return true;
    },
    [buildRoutingMeta, emitFriendRouteTestLog, emitRouterTestLog, resolveRuntimeNetworkSnapshot, withTimeout]
  );

  const sendFriendRequestForFriend = useCallback(
    async (friend: UserProfile, traceId?: string) => {
      const existing = friendRequestInFlightRef.current.get(friend.id);
      if (existing) {
        return existing;
      }
      const pending = (async () => {
        const effectiveTraceId = traceId ?? `friend-request:${friend.id}:${newClientBatchId()}`;
        let target = friend;
        try {
          target = await recoverAndPersistFriendRouting(friend);
        } catch (error) {
          console.warn("[friend] failed to recover routing hints from friendCode", error);
        }
        const routingMeta = buildRoutingMeta(target);
        if (!routingMeta.toDeviceId) {
          return false;
        }
        const netConfig = useNetConfigStore.getState().config;
        const routeRequired = netConfig.mode === "onionRouter" || netConfig.onionEnabled;
        const hasRouteTarget = Boolean(routingMeta.route?.torOnion);
        if (routeRequired && !hasRouteTarget) {
          return false;
        }
        const conv = await ensureDirectConvForFriend(target);
        if (!conv) return false;
        const payload = await buildFriendRequestPayload(conv.id, effectiveTraceId);
        if (!payload) return false;
        return sendFriendControlPacket(conv, target, payload, "high");
      })();
      friendRequestInFlightRef.current.set(friend.id, pending);
      try {
        return await pending;
      } finally {
        if (friendRequestInFlightRef.current.get(friend.id) === pending) {
          friendRequestInFlightRef.current.delete(friend.id);
        }
      }
    },
    [
      buildFriendRequestPayload,
      buildRoutingMeta,
      ensureDirectConvForFriend,
      recoverAndPersistFriendRouting,
      sendFriendControlPacket,
    ]
  );

  useEffect(() => {
    const nextSeen: Record<string, string> = {};
    for (const friend of friends) {
      if (friend.friendStatus !== "request_out") continue;
      const routingMeta = buildResolvedRoutingMeta(friend);
      const hasDeviceId = Boolean(routingMeta.toDeviceId);
      const hasRouteTarget = Boolean(routingMeta.route?.torOnion);
      if (!hasDeviceId || (onionRouteRequired && !hasRouteTarget)) continue;
      const signature = [
        routingMeta.toDeviceId ?? "",
        routingMeta.route?.torOnion ?? "",
        friend.profileVcard?.friendCode ?? "",
      ].join("|");
      nextSeen[friend.id] = signature;
      if (friendRouteWakeSignatureRef.current[friend.id] === signature) continue;
      friendRouteWakeSignatureRef.current[friend.id] = signature;
      void (async () => {
        const attemptedAt = Date.now();
        try {
          const sent = await sendFriendRequestForFriend(friend);
          if (!sent) {
            await markFriendRequestReachability(friend.id, {
              status: "unreachable",
              lastAttemptAt: attemptedAt,
              lastError: "Send returned false (Routing or packet drop)",
            });
            return;
          }
          await markFriendRequestReachability(friend.id, {
            status: "ok",
            attempts: 0,
            lastAttemptAt: attemptedAt,
            nextAttemptAt: undefined,
            lastError: undefined,
          });
        } catch (error) {
          console.warn("[friend] immediate route-ready retry failed", error);
          await markFriendRequestReachability(friend.id, {
            status: "unreachable",
            lastAttemptAt: attemptedAt,
            lastError: error instanceof Error ? error.message : String(error),
          });
        }
      })();
    }
    Object.keys(friendRouteWakeSignatureRef.current).forEach((friendId) => {
      if (!nextSeen[friendId]) {
        delete friendRouteWakeSignatureRef.current[friendId];
      }
    });
  }, [
    buildResolvedRoutingMeta,
    friends,
    markFriendRequestReachability,
    onionRouteRequired,
    sendFriendRequestForFriend,
  ]);

  const handleSendMessage = async (text: string, clientBatchId: string) => {
    if (!ui.selectedConvId || !userProfile) return;
    const conv = convs.find((item) => item.id === ui.selectedConvId);
    if (!conv) return;

    const vk = getVaultKey();
    if (!vk) return;

    const isDirect =
      !(conv.type === "group" || conv.participants.length > 2) && conv.participants.length === 2;

    if (isDirect) {
      const partnerId = conv.participants.find((id) => id && id !== userProfile.id) || null;
      const partner = partnerId ? friends.find((friend) => friend.id === partnerId) || null : null;

      if (partner?.dhPub && partner.identityPub) {
        const now = Date.now();
        const messageId = createId();

        await saveMessage({
          id: messageId,
          convId: conv.id,
          senderId: userProfile.id,
          text,
          ts: now,
          clientBatchId,
        });

        const updatedConv: Conversation = {
          ...conv,
          lastMessage: text,
          lastTs: now,
          unread: 0,
        };

        await saveConversation(updatedConv);
        await hydrateVault();
        void sendDirectEnvelope(
          conv,
          partner,
          { type: "msg", text, clientBatchId },
          "high",
          { eventId: messageId }
        ).catch((error) => {
          console.error("Failed to route message", error);
          notifyRoutePendingToast(
            conv.id,
            error instanceof Error ? error.message : String(error)
          );
        });
        return;
      }
    }

    const message: Message = {
      id: createId(),
      convId: conv.id,
      senderId: userProfile.id,
      text,
      ts: Date.now(),
      clientBatchId,
    };

    const ciphertext = await encryptJsonRecord(vk, message.id, "message", message);

    await saveMessage(message);

    const updatedConv: Conversation = {
      ...conv,
      lastMessage: text,
      lastTs: message.ts,
      unread: 0,
    };

    await saveConversation(updatedConv);
    await hydrateVault();
    void sendCiphertext({
      convId: conv.id,
      messageId: message.id,
      ciphertext,
      priority: "high",
    }).then((routed) => {
      if (!routed.ok) {
        console.error("Failed to route message", routed.error);
        notifyRoutePendingToast(conv.id, routed.error);
      }
    }).catch((error) => {
      console.error("Failed to route message", error);
      notifyRoutePendingToast(conv.id, error instanceof Error ? error.message : String(error));
    });
  };

  const handleSendMedia = async (files: File[], clientBatchId: string) => {
    if (!ui.selectedConvId || !userProfile) return;
    const conv = convs.find((item) => item.id === ui.selectedConvId);
    if (!conv) return;

    const vk = getVaultKey();
    if (!vk) return;

    const sendSingleMedia = async (file: File) => {
      if (file.size > INLINE_MEDIA_MAX_BYTES) {
        addToast({ message: "Attachment too large (max 500MB)." });
        return;
      }

      const isDirect =
        !(conv.type === "group" || conv.participants.length > 2) &&
        conv.participants.length === 2;

      if (isDirect) {
        const partnerId = conv.participants.find((id) => id && id !== userProfile.id) || null;
        const partner = partnerId ? friends.find((friend) => friend.id === partnerId) || null : null;

        if (partner?.dhPub && partner.identityPub) {
          const partnerDhPub = partner.dhPub;
          const now = Date.now();
          const messageId = createId();
          const preparedMedia = await inspectOutgoingMediaFile(file);
          const media = createMessageMediaRef(
            messageId,
            file,
            INLINE_MEDIA_CHUNK_SIZE,
            preparedMedia
          );
          const label = media.mime.startsWith("image/") ? "Photo" : media.name || "File";

          await saveMessage({
            id: messageId,
            convId: conv.id,
            senderId: userProfile.id,
            text: label,
            ts: now,
            media,
            clientBatchId,
          });

          const updatedConv: Conversation = {
            ...conv,
            lastMessage: label,
            lastTs: now,
            unread: 0,
          };

          await saveConversation(updatedConv);
          await hydrateVault();

          const sendTransfer = async () => {
            await getSodium();
            const friendKeyId = partner.friendId ?? partner.id;
            const dhPriv = await getDhPrivateKey();
            const pskBytes = await getFriendPsk(friendKeyId);
            const keys = await deriveConversationKeyPair(
              dhPriv,
              decodeBase64Url(partnerDhPub),
              pskBytes,
              new TextEncoder().encode(`direct:${friendKeyId}`),
              new TextEncoder().encode(`conv:${conv.id}`)
            ).finally(() => {
              dhPriv.fill(0);
              pskBytes?.fill(0);
            });
            const cryptoContext = {
              ...keys,
              identityPrivateKey: await getIdentityPrivateKey(),
            };
            let cryptoPool: EnvelopeCryptoPool | null = null;
            let encryptor: typeof encryptEnvelope = encryptEnvelope;
            const transferWindow = new AdaptiveTransferWindow(media.total >= 8 ? 2 : 1);
            const inFlight = new Set<Promise<void>>();
            let transferError: unknown = null;
            try {
              await createMediaTransferProgress(messageId, conv.id, media.total);
              try {
                cryptoPool = new EnvelopeCryptoPool(file.size >= 200 * 1024 * 1024 ? 2 : 1);
                await cryptoPool.prewarm();
                encryptor = (...args) => cryptoPool!.encrypt(...args);
              } catch (error) {
                cryptoPool?.close();
                cryptoPool = null;
                console.warn("[crypto] worker unavailable; using renderer fallback", error);
              }
              await sendDirectEnvelope(
                conv,
                partner,
                { type: "msg", text: label, media, clientBatchId },
                "high",
                { eventId: messageId, cryptoContext, encryptor }
              );
              await saveMessageMedia(
                messageId,
                file,
                INLINE_MEDIA_CHUNK_SIZE,
                async ({ idx, bytes }) => {
                  await markMediaTransferStored(messageId, idx);
                  if (transferError) return;
                  const chunkBase64 = encodeBase64Url(bytes);
                  const chunkBody = {
                    type: "media",
                    phase: "chunk",
                    ownerId: messageId,
                    idx,
                    total: media.total,
                    chunkSize: INLINE_MEDIA_CHUNK_SIZE,
                    mime: media.mime,
                    name: media.name,
                    size: media.size,
                    b64: chunkBase64,
                    clientBatchId,
                  };
                  const task = sendDirectEnvelope(conv, partner, chunkBody, "normal", {
                    persistEvent: false,
                    cryptoContext,
                    encryptor,
                    releaseBeforeRoute: transferWindow.current > 1,
                    outboxRetention: "transient",
                    transferId: messageId,
                    chunkIndex: idx,
                    binaryTransport: canUseBinaryMediaTransport(conv.id),
                  })
                    .then(() => {
                      transferWindow.onSuccess();
                    })
                    .catch((error) => {
                      transferWindow.onFailure();
                      transferError ??= error;
                    });
                  inFlight.add(task);
                  void task.finally(() => inFlight.delete(task)).catch(() => {});
                  if (inFlight.size >= transferWindow.current) await Promise.race(inFlight);
                  if (idx > 0 && idx % 8 === 0) {
                    await new Promise<void>((resolve) => setTimeout(resolve, 0));
                  }
                },
                preparedMedia
              );
              await Promise.all(inFlight);
              if (transferError) throw transferError;
            } finally {
              await Promise.allSettled(inFlight);
              cryptoPool?.close();
              cryptoContext.conversationKey.fill(0);
              cryptoContext.ratchetBaseKey.fill(0);
              cryptoContext.identityPrivateKey.fill(0);
            }
          };
          const previousTransfer = mediaTransferChainsRef.current.get(conv.id) ?? Promise.resolve();
          const transfer = previousTransfer.catch(() => {}).then(sendTransfer);
          mediaTransferChainsRef.current.set(conv.id, transfer);
          void transfer.finally(() => {
            if (mediaTransferChainsRef.current.get(conv.id) === transfer) {
              mediaTransferChainsRef.current.delete(conv.id);
            }
          }).catch((error) => {
            console.error("Failed to send media chunks", error);
          });
          return;
        }
      }

      const messageId = createId();
      const media = await saveMessageMedia(messageId, file);
      const label = media.mime.startsWith("image/") ? "Photo" : media.name || "File";

      const message: Message = {
        id: messageId,
        convId: conv.id,
        senderId: userProfile.id,
        text: label,
        ts: Date.now(),
        media,
        clientBatchId,
      };

      const ciphertext = await encryptJsonRecord(vk, message.id, "message", message);

      await saveMessage(message);

      void sendCiphertext({
        convId: conv.id,
        messageId: message.id,
        ciphertext,
        priority: "high",
      }).catch((error) => {
        console.error("Failed to route message", error);
      });

      const updatedConv: Conversation = {
        ...conv,
        lastMessage: label,
        lastTs: message.ts,
        unread: 0,
      };

      await saveConversation(updatedConv);
      await hydrateVault();
    };

    for (const file of files) {
      try {
        await sendSingleMedia(file);
      } catch (error) {
        console.error("Failed to send media", error);
        addToast({ message: "Failed to send attachment." });
      }
    }
  };

  const handleSendBatch = async (payload: { text: string; files: File[] }) => {
    const trimmed = payload.text.trim();
    const hasText = Boolean(trimmed);
    const hasFiles = payload.files.length > 0;
    if (!hasText && !hasFiles) return;
    const clientBatchId = newClientBatchId();
    if (hasText) {
      await handleSendMessage(trimmed, clientBatchId);
    }
    if (hasFiles) {
      await handleSendMedia(payload.files, clientBatchId);
    }
  };

  const handleDeleteMessages = useCallback(
    (payload: { convId: string; messageIds: string[] }) => {
      if (!payload.messageIds.length) return;
      setConfirm({
        title: "메시지 삭제",
        message:
          "이 메시지는 내 기기에서만 삭제됩니다. 삭제 후 복구할 수 없습니다. 계속할까요?",
        onConfirm: async () => {
          try {
            await deleteMessagesById(payload.messageIds);
            const messageIdSet = new Set(payload.messageIds);
            const currentMessagesByConv = useAppStore.getState().messagesByConv;
            const existing = currentMessagesByConv[payload.convId] || [];
            const remaining = existing.filter((msg) => !messageIdSet.has(msg.id));
            const updatedMessagesByConv = {
              ...currentMessagesByConv,
              [payload.convId]: remaining,
            };
            let updatedConvs = convs;
            const conv = convs.find((item) => item.id === payload.convId);
            if (conv) {
              const last = remaining[remaining.length - 1];
              const lastMessage = last
                ? last.text?.trim()
                  ? last.text
                  : last.media
                    ? last.media.mime.startsWith("image/")
                      ? "사진"
                      : last.media.name || "파일"
                    : ""
                : "";
              const lastTs = last?.ts ?? 0;
              if (lastMessage !== conv.lastMessage || lastTs !== conv.lastTs) {
                const updatedConv: Conversation = {
                  ...conv,
                  lastMessage,
                  lastTs,
                };
                await saveConversation(updatedConv);
                updatedConvs = convs.map((item) =>
                  item.id === updatedConv.id ? updatedConv : item
                );
              }
            }
            setData({
              user: userProfile,
              friends,
              convs: updatedConvs,
              messagesByConv: updatedMessagesByConv,
            });
            window.dispatchEvent(
              new CustomEvent("nkc:messages-updated", {
                detail: { convId: payload.convId },
              })
            );
            addToast({ message: "메시지를 삭제했습니다." });
          } catch (error) {
            console.error("Failed to delete message", error);
            addToast({ message: "메시지 삭제에 실패했습니다." });
          }
        },
      });
    },
    [addToast, convs, friends, setConfirm, setData, userProfile]
  );

  const findDirectConvWithFriend = useCallback(
    (friendId: string) =>
      convs.find(
        (conv) =>
          !(conv.type === "group" || conv.participants.length > 2) &&
          conv.participants.includes(friendId)
      ),
    [convs]
  );

  const handleSendReadReceipt = useCallback(
    async (payload: { convId: string; msgId: string; msgTs: number }) => {
      if (!userProfile) return;
      const conv = convs.find((item) => item.id === payload.convId);
      if (!conv) return;
      const cursorTs = payload.msgTs;
      await putReadCursor({
        convId: conv.id,
        actorId: userProfile.id,
        cursorTs,
        anchorMsgId: payload.msgId,
      });

      const sendNow = async (targetConv: Conversation, targetCursorTs: number, anchorMsgId: string) => {
        lastReadCursorSentAtRef.current[targetConv.id] = Date.now();
        lastReadCursorSentTsRef.current[targetConv.id] = targetCursorTs;

        const isDirect =
          !(targetConv.type === "group" || targetConv.participants.length > 2) &&
          targetConv.participants.length === 2;
        if (isDirect) {
          const partnerId =
            targetConv.participants.find((id) => id && id !== userProfile.id) || null;
          const partner = partnerId
            ? friends.find((friend) => friend.id === partnerId) || null
            : null;
          if (!partner?.dhPub || !partner.identityPub) return;

          try {
            await sendDirectEnvelope(
              targetConv,
              partner,
              {
                type: "rcpt",
                kind: "read_cursor",
                convId: targetConv.id,
                cursorTs: targetCursorTs,
                anchorMsgId,
                ts: Date.now(),
              },
              "normal"
            );
          } catch (error) {
            console.error("Failed to send read cursor", error);
          }
          return;
        }

        const targets = targetConv.participants.filter((id) => id && id !== userProfile.id);
        for (const memberId of targets) {
          const friend = friends.find((item) => item.id === memberId);
          if (!friend?.dhPub || !friend.identityPub) continue;
          const directConv = findDirectConvWithFriend(friend.id);
          if (!directConv) continue;
          try {
            await sendDirectEnvelope(
              directConv,
              friend,
              {
                type: "rcpt",
                kind: "read_cursor",
                convId: targetConv.id,
                cursorTs: targetCursorTs,
                anchorMsgId,
                ts: Date.now(),
              },
              "normal"
            );
          } catch (error) {
            console.error("Failed to send group read cursor", { memberId }, error);
          }
        }
      };

      const lastCursorTs = lastReadCursorSentTsRef.current[conv.id] ?? 0;
      if (cursorTs <= lastCursorTs) return;

      const now = Date.now();
      const lastSentAt = lastReadCursorSentAtRef.current[conv.id] ?? 0;
      const elapsed = now - lastSentAt;
      if (elapsed < READ_CURSOR_THROTTLE_MS) {
        const pending = pendingReadCursorRef.current[conv.id];
        if (!pending || cursorTs > pending.cursorTs) {
          pendingReadCursorRef.current[conv.id] = { cursorTs, anchorMsgId: payload.msgId };
        }
        if (!readCursorThrottleTimerRef.current[conv.id]) {
          const waitMs = Math.max(READ_CURSOR_THROTTLE_MS - elapsed, 0);
          readCursorThrottleTimerRef.current[conv.id] = window.setTimeout(() => {
            readCursorThrottleTimerRef.current[conv.id] = undefined;
            const next = pendingReadCursorRef.current[conv.id];
            if (!next) return;
            const latestConv = convs.find((item) => item.id === conv.id);
            if (!latestConv) return;
            const sentTs = lastReadCursorSentTsRef.current[conv.id] ?? 0;
            if (next.cursorTs <= sentTs) {
              pendingReadCursorRef.current[conv.id] = undefined;
              return;
            }
            pendingReadCursorRef.current[conv.id] = undefined;
            void sendNow(latestConv, next.cursorTs, next.anchorMsgId);
          }, waitMs);
        }
        return;
      }

      pendingReadCursorRef.current[conv.id] = undefined;
      void sendNow(conv, cursorTs, payload.msgId);
    },
    [convs, findDirectConvWithFriend, friends, sendDirectEnvelope, userProfile]
  );

  const ensureDirectConvForFanout = useCallback(
    async (friend: UserProfile, ts: number) => {
      if (!userProfile) return null;
      const existing = findDirectConvWithFriend(friend.id);
      if (existing) return existing;
      const directConv: Conversation = {
        id: createId(),
        type: "direct",
        name: friend.displayName || "Direct channel",
        pinned: false,
        unread: 0,
        hidden: true,
        muted: false,
        blocked: false,
        lastTs: ts,
        lastMessage: "",
        participants: [userProfile.id, friend.id],
      };
      await saveConversation(directConv);
      return directConv;
    },
    [findDirectConvWithFriend, userProfile]
  );

  const fanoutGroupAvatarChunks = useCallback(
    async (
      groupId: string,
      sharedAvatarRef: string | undefined,
      memberIds: string[],
      options?: { allowCreateDirect?: boolean }
    ) => {
      if (!userProfile || !sharedAvatarRef) return;
      const allowCreateDirect = Boolean(options?.allowCreateDirect);
      const blob = await loadAvatarFromRef(sharedAvatarRef);
      if (!blob) return;

      const buffer = await blob.arrayBuffer();
      const chunks = chunkBuffer(buffer, INLINE_MEDIA_CHUNK_SIZE);
      const total = chunks.length;
      if (!total) return;

      const targets = Array.from(new Set(memberIds)).filter(
        (id) => id && id !== userProfile.id
      );
      for (const memberId of targets) {
        const friend = friends.find((item) => item.id === memberId);
        if (!friend?.dhPub || !friend.identityPub) continue;
        let directConv = findDirectConvWithFriend(memberId) || null;
        if (!directConv && allowCreateDirect) {
          directConv = await ensureDirectConvForFanout(friend, Date.now());
        }
        if (!directConv) continue;

        const sendChunks = async () => {
          for (let idx = 0; idx < chunks.length; idx += 1) {
            await sendDirectEnvelope(
              directConv,
              friend,
              {
                type: "media",
                phase: "chunk",
                ownerType: "group",
                ownerId: groupId,
                idx,
                total,
                mime: blob.type || "image/png",
                b64: encodeBase64Url(chunks[idx]),
              },
              "normal"
            );
            if (idx > 0 && idx % 32 === 0) {
              await new Promise<void>((resolve) => setTimeout(resolve, 0));
            }
          }
        };

        void sendChunks().catch((error) => {
          console.error("Failed to fanout group avatar chunks", { memberId }, error);
        });
      }
    },
    [
      ensureDirectConvForFanout,
      findDirectConvWithFriend,
      friends,
      sendDirectEnvelope,
      userProfile,
    ]
  );

  const fanoutGroupEvent = useCallback(
    async (
      memberIds: string[],
      event: GroupEventPayload,
      options?: { allowCreateDirect?: boolean; toastOnFailure?: boolean; sendAvatarChunks?: boolean }
    ) => {
      if (!userProfile) return;
      const allowCreateDirect = Boolean(options?.allowCreateDirect);
      const toastOnFailure = options?.toastOnFailure ?? true;
      const sendAvatarChunks = options?.sendAvatarChunks ?? true;
      const targets = Array.from(new Set(memberIds)).filter((id) => id && id !== userProfile.id);
      if (!targets.length) return;

      const failures: string[] = [];
      for (const memberId of targets) {
        const friend = friends.find((item) => item.id === memberId);
        if (!friend?.dhPub || !friend.identityPub) {
          failures.push(memberId);
          continue;
        }
        let directConv = findDirectConvWithFriend(memberId) || null;
        if (!directConv && allowCreateDirect) {
          directConv = await ensureDirectConvForFanout(friend, event.ts);
        }
        if (!directConv) {
          failures.push(memberId);
          continue;
        }
        try {
          await sendDirectEnvelope(directConv, friend, event, "normal");
        } catch (error) {
          console.error("Failed to fanout group event", { memberId }, error);
          failures.push(memberId);
        }
      }

      if (failures.length && toastOnFailure) {
        addToast({ message: `Some members could not be notified (${failures.length}).` });
      }

      if (event.kind === "group.create" && event.sharedAvatarRef && sendAvatarChunks) {
        await fanoutGroupAvatarChunks(event.id, event.sharedAvatarRef, targets, {
          allowCreateDirect,
        });
      }
    },
    [
      addToast,
      ensureDirectConvForFanout,
      fanoutGroupAvatarChunks,
      findDirectConvWithFriend,
      friends,
      sendDirectEnvelope,
      userProfile,
    ]
  );

  const handleSelectFriend = async (friendId: string) => {
    const existing = findDirectConvWithFriend(friendId);
    if (existing) {
      setSelectedConv(existing.id);
      setMode("app");
      return;
    }

    if (!userProfile) return;

    const friend = friends.find((item) => item.id === friendId);

    const now = Date.now();
    const newConv: Conversation = {
      id: createId(),
      type: "direct",
      name: friend?.displayName || "새 채팅",
      pinned: friend?.isFavorite ?? false,
      unread: 0,
      hidden: false,
      muted: false,
      blocked: false,
      pendingOutgoing: friend?.friendStatus === "request_out",
      lastTs: now,
      lastMessage: "채팅을 시작했어요.",
      participants: [userProfile.id, friendId],
    };

    await saveConversation(newConv);

    await saveMessage({
      id: createId(),
      convId: newConv.id,
      senderId: userProfile.id,
      text: "채팅을 시작했어요.",
      ts: now,
    });

    await hydrateVault();
    setSelectedConv(newConv.id);
  };

  const updateConversation = async (convId: string, updates: Partial<Conversation>) => {
    const target = convs.find((conv) => conv.id === convId);
    if (!target) return;
    const updated = { ...target, ...updates };
    await saveConversation(updated);
    await hydrateVault();
  };

  const updateConversationOrThrow = useCallback(
    async (convId: string, updates: Partial<Conversation>) => {
      const target = useAppStore.getState().convs.find((conv) => conv.id === convId);
      if (!target) {
        throw new Error(`Conversation not found: ${convId}`);
      }
      const updated = { ...target, ...updates };
      await saveConversation(updated);
      await hydrateVault();
    },
    [hydrateVault]
  );

  const handleSelectConv = (convId: string) => {
    setSelectedConv(convId);
    const target = convs.find((conv) => conv.id === convId);
    if (target && target.unread > 0) {
      void updateConversation(convId, { unread: 0 });
    }
  };

  const handleHide = (convId: string) => {
    void updateConversation(convId, { hidden: true });
    addToast({
      message: "채팅을 숨겼어요.",
      actionLabel: "Undo",
      onAction: () => {
        void updateConversation(convId, { hidden: false });
      },
    });
  };

  const handleDelete = (convId: string) => {
    setConfirm({
      title: "채팅을 삭제할까요?",
      message: "삭제하면 복구할 수 없습니다.",
      onConfirm: async () => {
        await updateConversation(convId, { hidden: true });
        addToast({
          message: "채팅을 삭제했어요.",
          actionLabel: "Undo",
          onAction: () => {
            void updateConversation(convId, { hidden: false });
          },
        });
      },
    });
  };

  const handleTogglePin = (convId: string) => {
    const target = convs.find((conv) => conv.id === convId);
    if (!target) return;
    void updateConversation(convId, { pinned: !target.pinned });
  };

  const handleMute = (convId: string) => {
    const target = convs.find((conv) => conv.id === convId);
    if (!target) return;
    void updateConversation(convId, { muted: !target.muted });
  };

  const handleBlock = (convId: string) => {
    const target = convs.find((conv) => conv.id === convId);
    if (!target) return;
    void updateConversation(convId, { blocked: !target.blocked });
  };

  const handleFriendChat = async (friendId: string) => {
    try {
      await handleSelectFriend(friendId);
      setListMode("chats");
      setListFilter("all");
    } catch (error) {
      console.error("Failed to open chat", error);
      addToast({ message: "채팅 열기에 실패했습니다." });
    }
  };

  const handleFriendViewProfile = async (friendId: string) => {
    try {
      await handleSelectFriend(friendId);
      setListMode("chats");
      setListFilter("all");
      setRightTab("about");
      setRightPanelOpen(true);
    } catch (error) {
      console.error("Failed to open profile", error);
      addToast({ message: "프로필 열기에 실패했습니다." });
    }
  };

  const updateFriend = async (friendId: string, updates: Partial<UserProfile>) => {
    const target = friends.find((friend) => friend.id === friendId);
    if (!target) return;

    const updated: UserProfile = {
      ...target,
      ...updates,
      updatedAt: Date.now(),
    };

    try {
      await saveProfile(updated);
      await hydrateVault();
    } catch (error) {
      console.error("Failed to update friend", error);
      addToast({ message: "친구 변경에 실패했습니다." });
    }
  };

  const updateFriendOrThrow = useCallback(
    async (friendId: string, updates: Partial<UserProfile>) => {
      const target = useAppStore.getState().friends.find((friend) => friend.id === friendId);
      if (!target) {
        throw new Error(`Friend not found: ${friendId}`);
      }
      const updated: UserProfile = {
        ...target,
        ...updates,
        updatedAt: Date.now(),
      };
      await saveProfile(updated);
      await hydrateVault();
    },
    [hydrateVault]
  );

  const handleFriendToggleFavorite = async (friendId: string) => {
    const target = friends.find((friend) => friend.id === friendId);
    if (!target) return;

    const nextFavorite = !target.isFavorite;

    try {
      await updateFriend(friendId, { isFavorite: nextFavorite });
      const existing = findDirectConvWithFriend(friendId);
      if (existing) {
        await updateConversation(existing.id, { pinned: nextFavorite });
      }
    } catch (error) {
      console.error("Failed to toggle favorite", error);
      addToast({ message: "즐겨찾기 변경에 실패했습니다." });
    }
  };

  const handleFriendHide = (friendId: string) => {
    setConfirm({
      title: "Hide this friend?",
      message: "Hidden friends can be restored later from friend management.",
      onConfirm: async () => {
        await updateFriend(friendId, { friendStatus: "hidden" });
        const existing = findDirectConvWithFriend(friendId);
        if (existing) {
          await updateConversation(existing.id, { hidden: true });
        }
      },
    });
  };

  const handleFriendBlock = (friendId: string) => {
    setConfirm({
      title: "Block this friend?",
      message: "Blocking will hide their conversations.",
      onConfirm: async () => {
        try {
          await updateFriend(friendId, { friendStatus: "blocked" });
          const existing = findDirectConvWithFriend(friendId);
          if (existing) {
            await updateConversation(existing.id, { hidden: true, blocked: true });
          }
        } catch (error) {
          console.error("Failed to block friend", error);
          addToast({ message: "Failed to block friend." });
        }
      },
    });
  };

  const handleFriendUnhide = async (friendId: string) => {
    await updateFriend(friendId, { friendStatus: "normal" });
  };

  const handleFriendUnblock = async (friendId: string) => {
    try {
      await updateFriend(friendId, { friendStatus: "normal" });
      const existing = findDirectConvWithFriend(friendId);
      if (existing) {
        await updateConversation(existing.id, { blocked: false, hidden: false });
      }
    } catch (error) {
      console.error("Failed to unblock friend", error);
      addToast({ message: "Failed to unblock friend." });
    }
  };

  const handleFriendDelete = (friendId: string) => {
    const target = friends.find((friend) => friend.id === friendId);
    if (!target) return;
    setConfirm({
      title: "Delete this friend?",
      message: "This removes the friend from your list. You can re-add them later.",
      onConfirm: async () => {
        try {
          const existing = findDirectConvWithFriend(friendId);
          if (existing) {
            await updateConversation(existing.id, { hidden: true, blocked: true });
          }
          const pskKeyId = target.friendId ?? target.id;
          await clearFriendPsk(pskKeyId);
          await deleteProfile(friendId);
          await hydrateVault();
        } catch (error) {
          console.error("Failed to delete friend", error);
          addToast({ message: "Failed to delete friend." });
        }
      },
    });
  };

  const handleCopyFriendCode = async () => {
    try {
      if (!myFriendCode) {
        addToast({ message: "친구 코드가 아직 준비되지 않았습니다." });
        return;
      }
      await navigator.clipboard.writeText(myFriendCode);
      const decoded = decodeFriendCodeV1(myFriendCode);
      const hasRouteTarget = !("error" in decoded) && Boolean(decoded.onionAddr);
      addToast({
        message: hasRouteTarget
          ? "친구 코드가 복사되었습니다."
          : "친구 코드는 복사되었지만 onion 주소가 없어 상대가 먼저 연결하지 못할 수 있습니다. Tor 연결 후 다시 복사해 주세요.",
      });
    } catch (error) {
      console.error("Failed to copy friend code", error);
      addToast({ message: "친구 코드 복사에 실패했습니다." });
    }
  };
  const handleResolveFriendRoute = useCallback(async () => {
    if (routeResolveBusy) return;
    const operationId = `friend-route-resolve:${newClientBatchId()}`;
    const startedAt = nowMonotonicMs();
    const elapsedMs = () => Math.max(0, Math.round(nowMonotonicMs() - startedAt));
    const baseContext = {
      mode: netConfig.mode,
      onionEnabled: netConfig.onionEnabled,
      onionSelectedNetwork: netConfig.onionSelectedNetwork,
      torStatus: netConfig.tor.status,
    };
    const runtimeBootstrap: Record<string, unknown> = {};
    emitRouterTestLog({
      status: "attempt",
      stage: "friend-route-resolve:start",
      source: "app:handleResolveFriendRoute",
      operationId,
      elapsedMs: 0,
      context: baseContext,
    });
    setRouteResolveBusy(true);
    try {
      const nkc = (
        globalThis as {
          nkc?: {
            startTor?: () => Promise<unknown>;
            ensureHiddenService?: () => Promise<unknown>;
          };
        }
      ).nkc;
      if (nkc) {
        if (netConfig.onionSelectedNetwork === "tor") {
          try {
            const torRuntime = TorRuntime.getInstance();
            await torRuntime.start({ timeoutMs: 15_000 });
            await torRuntime.awaitReady(15_000);
            runtimeBootstrap.torRuntimeState = torRuntime.getState();
            runtimeBootstrap.torDataDir = torRuntime.getDataDir();
          } catch (error) {
            runtimeBootstrap.torStartError = error instanceof Error ? error.message : String(error);
          }
        }
        if (nkc.ensureHiddenService) {
          try {
            await nkc.ensureHiddenService();
          } catch (error) {
            runtimeBootstrap.hiddenServiceError =
              error instanceof Error ? error.message : String(error);
          }
        }
      }
      const warmupConfig = {
        ...netConfig,
        mode: "onionRouter" as const,
        onionEnabled: true,
      };
      const warmup = await prewarmRouter({
        config: warmupConfig,
        includeFallback: true,
      });

      let refreshed = "";
      let hasRouteTarget = false;
      let refreshAttempts = 0;
      setMyFriendCode("");
      for (const delayMs of [0, 700, 1400]) {
        if (delayMs > 0) {
          await waitMs(delayMs);
        }
        refreshAttempts += 1;
        const payload = await buildLocalFriendCodePayload();
        const candidateRuntime = await resolveRuntimeNetworkSnapshot();
        if (!isTorFriendCodeReady(candidateRuntime, payload)) {
          setMyFriendCode("");
          continue;
        }
        refreshed = encodeFriendCodeV1({ v: 1, ...payload });
        setMyFriendCode(refreshed);
        const decoded = decodeFriendCodeV1(refreshed);
        hasRouteTarget = !("error" in decoded) && Boolean(decoded.onionAddr);
        if (hasRouteTarget) break;
      }

      const routerOpened = warmup.started.includes("onionRouter");
      const runtimeSnapshot = await resolveRuntimeNetworkSnapshot();
      setFriendCodeRuntimeSnapshot((prev) =>
        sameRuntimeNetworkSnapshot(prev, runtimeSnapshot) ? prev : runtimeSnapshot
      );
      const resolved = hasRouteTarget && routerOpened && runtimeSnapshot.torState === "running";
      if (!resolved) {
        setMyFriendCode("");
      }
      emitRouterTestLog({
        status: resolved ? "ready" : "failed",
        stage: "friend-route-resolve:result",
        source: "app:handleResolveFriendRoute",
        operationId,
        elapsedMs: elapsedMs(),
        message: resolved
          ? "Friend route resolve completed with onion route target"
          : "Friend route resolve completed without stable router/route target",
        error: resolved
          ? undefined
          : `hasRouteTarget:${String(hasRouteTarget)}|routerOpened:${String(routerOpened)}`,
        context: {
          ...baseContext,
          runtimeBootstrap,
          chosenTransport: warmup.chosenTransport,
          requestedTransports: warmup.requested,
          startedTransports: warmup.started,
          failedTransports: warmup.failed,
          hasRouteTarget,
          routerOpened,
          refreshAttempts,
          friendCodeLength: refreshed.length,
          runtimeSnapshot,
        },
      });
      addToast({
        message: hasRouteTarget && routerOpened
          ? "경로 정보를 찾았습니다. 코드를 다시 복사해 전달해 주세요."
          : hasRouteTarget
            ? "코드 경로 정보는 준비됐지만 라우터 초기화가 지연됩니다. 잠시 후 다시 시도해 주세요."
            : "아직 경로 정보를 찾지 못했습니다. 잠시 후 다시 시도하거나 상대가 먼저 친구 추가하도록 안내해 주세요.",
      });
    } catch (error) {
      emitRouterTestLog({
        status: "failed",
        stage: "friend-route-resolve:exception",
        source: "app:handleResolveFriendRoute",
        operationId,
        elapsedMs: elapsedMs(),
        error: error instanceof Error ? error.message : String(error),
        errorDetail: toInfoLogErrorDetail(error),
        context: {
          ...baseContext,
          runtimeBootstrap,
        },
      });
      console.error("Failed to resolve friend route", error);
      addToast({ message: "경로 확인에 실패했습니다." });
    } finally {
      setRouteResolveBusy(false);
    }
  }, [
    addToast,
    buildLocalFriendCodePayload,
    emitRouterTestLog,
    netConfig,
    resolveRuntimeNetworkSnapshot,
    routeResolveBusy,
  ]);
  const normalizeInviteCode = (value: string) => {
    let next = value.replace(/[\u200B-\u200D\uFEFF]/g, "").trim();
    next = next.replace(/^[\s"'`([{<]+/, "");
    next = next.replace(/[\s"'`)\]}>:;,.!?]+$/, "");
    return next.replace(/\s+/g, "").toUpperCase();
  };

  const computeInviteFingerprint = async (normalized: string) => {
    if (!globalThis.crypto?.subtle) {
      const fallback = sha256(new TextEncoder().encode(normalized));
      return encodeBase64Url(fallback).slice(0, 22);
    }
    const digest = await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(normalized)
    );
    return encodeBase64Url(new Uint8Array(digest)).slice(0, 22);
  };


  const handleCreateGroup = () => {
    setGroupCreateOpen(true);
  };

  const handleInviteToGroup = (convId: string) => {
    setGroupInviteConvId(convId);
    setGroupInviteOpen(true);
    setRightTab("about");
    setRightPanelOpen(true);
  };

  const handleSubmitGroupInvite = async (convId: string, memberIds: string[]) => {
    if (!userProfile) return { ok: false as const, error: "User profile missing." };
    const conv = convs.find((item) => item.id === convId);
    if (!conv || (conv.type !== "group" && conv.participants.length <= 2)) {
      return { ok: false as const, error: "Group not found." };
    }

    const prevParticipants = conv.participants;
    const newMembers = Array.from(new Set(memberIds)).filter(
      (id) => id && id !== userProfile.id && !prevParticipants.includes(id)
    );
    if (!newMembers.length) {
      return { ok: false as const, error: "Select at least one new member." };
    }

    try {
      const now = Date.now();
      const nextParticipants = Array.from(new Set([...prevParticipants, ...newMembers]));
      const updated: Conversation = {
        ...conv,
        participants: nextParticipants,
        hidden: false,
        lastTs: now,
        lastMessage: "Members invited",
      };
      await saveConversation(updated);

      const inviteEvent = buildGroupInviteEvent({
        groupId: conv.id,
        memberIds: newMembers,
        actorId: userProfile.id,
        ts: now,
      });
      const existingRecipients = prevParticipants.filter((id) => id && id !== userProfile.id);
      await fanoutGroupEvent(existingRecipients, inviteEvent);

      const createEvent = await syncGroupCreate({
        id: conv.id,
        name: conv.name,
        memberIds: nextParticipants,
        actorId: userProfile.id,
        ts: now,
        sharedAvatarRef: conv.sharedAvatarRef,
      });
      await fanoutGroupEvent(newMembers, createEvent, {
        allowCreateDirect: true,
        toastOnFailure: false,
      });

      await hydrateVault();
      return { ok: true as const };
    } catch (error) {
      console.error("Failed to invite group members", error);
      return { ok: false as const, error: "Failed to invite members." };
    }
  };

  const handleLeaveGroup = (convId: string) => {
    if (!userProfile) return;
    const conv = convs.find((item) => item.id === convId);
    if (!conv || (conv.type !== "group" && conv.participants.length <= 2)) return;

    setConfirm({
      title: "Leave this group?",
      message: "You will stop seeing new messages from this group.",
      onConfirm: async () => {
        try {
          const now = Date.now();
          const remaining = conv.participants.filter((id) => id && id !== userProfile.id);
          const leaveEvent = buildGroupLeaveEvent({
            groupId: conv.id,
            memberIds: [userProfile.id],
            actorId: userProfile.id,
            ts: now,
          });

          await saveConversation({
            ...conv,
            participants: remaining,
            hidden: true,
            lastTs: now,
            lastMessage: "Left group",
          });

          await fanoutGroupEvent(remaining, leaveEvent);
          await hydrateVault();
          if (ui.selectedConvId === conv.id) {
            setSelectedConv(null);
            setRightPanelOpen(false);
          }
          if (groupInviteConvId === conv.id) {
            setGroupInviteOpen(false);
            setGroupInviteConvId(null);
          }
        } catch (error) {
          console.error("Failed to leave group", error);
          addToast({ message: "Failed to leave group." });
        }
      },
    });
  };

  const handleSetGroupAvatarOverride = useCallback(
    async (convId: string, file: File | null) => {
      if (!userProfile) return;
      if (!file) {
        await setGroupAvatarOverride(convId, null);
        refreshGroupAvatarOverrides();
        return;
      }
      try {
        const ownerId = `group-local:${convId}:${userProfile.id}`;
        const ref = await saveGroupPhotoRef(ownerId, file);
        await setGroupAvatarOverride(convId, ref);
        refreshGroupAvatarOverrides();
      } catch (error) {
        console.error("Failed to set group avatar override", error);
        addToast({ message: "Failed to update local group image." });
      }
    },
    [addToast, refreshGroupAvatarOverrides, userProfile]
  );

  const handleSetFriendAlias = useCallback(async (friendId: string, alias: string | null) => {
    await setFriendAlias(friendId, alias);
    refreshFriendAliases();
    setFriendAliasInState(friendId, alias);
  }, [refreshFriendAliases, setFriendAliasInState]);

  const handleSubmitGroup = async (payload: {
    name: string;
    memberIds: string[];
    avatarFile?: File | null;
  }) => {
    if (!userProfile) return { ok: false as const, error: "User profile missing." };

    const members = Array.from(new Set(payload.memberIds)).filter((id) => id && id !== userProfile.id);
    if (!members.length) return { ok: false as const, error: "Select at least one friend." };

    try {
      const now = Date.now();
      const convId = createId();
      let sharedAvatarRef: string | undefined;
      if (payload.avatarFile) {
        try {
          sharedAvatarRef = await saveGroupPhotoRef(convId, payload.avatarFile);
        } catch (avatarError) {
          console.error("Failed to save group avatar", avatarError);
        }
      }

      const conv: Conversation = {
        id: convId,
        type: "group",
        name: payload.name,
        pinned: false,
        unread: 0,
        hidden: false,
        muted: false,
        blocked: false,
        lastTs: now,
        lastMessage: "Group created",
        participants: [userProfile.id, ...members],
        sharedAvatarRef,
      };

      await saveConversation(conv);

      await saveMessage({
        id: createId(),
        convId: conv.id,
        senderId: userProfile.id,
        text: "Group created",
        ts: now,
      });

      const groupEvent = await syncGroupCreate({
        id: conv.id,
        name: conv.name,
        memberIds: conv.participants,
        actorId: userProfile.id,
        ts: now,
        sharedAvatarRef,
      });
      await fanoutGroupEvent(conv.participants, groupEvent, {
        allowCreateDirect: true,
        toastOnFailure: false,
      });
      await hydrateVault();

      setSelectedConv(conv.id);
      setListMode("chats");
      setListFilter("all");

      return { ok: true as const };
    } catch (error) {
      console.error("Failed to create group", error);
      return { ok: false as const, error: "Failed to create group." };
    }
  };

  const handleAddFriend = async (payload: { code: string; psk?: string }) => {
    type FriendAddLogExtras = Omit<
      FriendAddInfoLogInput,
      "result" | "stage" | "source" | "operationId" | "elapsedMs"
    >;
    const operationId = `friend-add:${newClientBatchId()}`;
    const traceId = operationId;
    const startedAt = nowMonotonicMs();
    const elapsedMs = () => Math.max(0, Math.round(nowMonotonicMs() - startedAt));
    const emitFriendAddWithMeta = (
      detail: Omit<FriendAddInfoLogInput, "source" | "operationId" | "elapsedMs">
    ) => {
      emitFriendAddTestLog({
        source: "app:handleAddFriend",
        operationId,
        traceId,
        elapsedMs: elapsedMs(),
        ...detail,
      });
    };
    const emitProgressWithTestLog = (
      stage: string,
      extras?: FriendAddLogExtras
    ) => {
      emitFriendAddWithMeta({
        result: "progress",
        stage,
        ...extras,
      });
    };
    const failWithTestLog = (
      errorMessage: string,
      stage: string,
      extras?: FriendAddLogExtras,
      errorCause?: unknown
    ) => {
      emitFriendAddWithMeta({
        result: "not_added",
        stage,
        message: errorMessage,
        errorDetail:
          extras?.errorDetail ?? (errorCause !== undefined ? toInfoLogErrorDetail(errorCause) : undefined),
        ...extras,
      });
      return { ok: false as const, error: errorMessage };
    };

    if (!userProfile) {
      return failWithTestLog("User profile missing.", "guard:user-profile-missing");
    }

    const rawInput = payload.code.trim();
    const normalized = normalizeInviteCode(rawInput);
    const prefixProbe = normalized.replace(/[^A-Z0-9]/g, "");
    const inputKind = prefixProbe.startsWith("NKI1")
      ? "invite"
      : prefixProbe.startsWith("NKC1")
      ? "friend-code-v1"
      : "unknown";
    emitProgressWithTestLog("progress:start", {
      message: `Friend add requested. inputKind=${inputKind}`,
      context: {
        inputKind,
        rawLength: rawInput.length,
        normalizedLength: normalized.length,
      },
    });
    let attemptKey = normalized || "empty";
    let inviteFingerprint: string | null = null;
    let invitePsk: Uint8Array | null = null;
    let oneTimeInvite = false;

    if (prefixProbe.startsWith("NCK") || (prefixProbe.startsWith("NKC") && !prefixProbe.startsWith("NKC1"))) {
      recordFail(attemptKey);
      return failWithTestLog(
        "레거시 친구 ID(NCK-/NKC-)는 더 이상 지원하지 않습니다. 상대에게 NKC1- 친구 코드를 요청하세요.",
        "guard:legacy-code",
        {
          context: {
            inputKind,
            prefixProbe: prefixProbe.slice(0, 8),
          },
        }
      );
    }

    if (prefixProbe.startsWith("NKI1")) {
      try {
        inviteFingerprint = await computeInviteFingerprint(normalized);
        attemptKey = `invite:${inviteFingerprint}`;
      } catch (error) {
        return failWithTestLog(
          "Invite code invalid.",
          "guard:invite-fingerprint-invalid",
          {
            context: {
              inputKind,
              normalizedLength: normalized.length,
            },
          },
          error
        );
      }
    }

    const firstGate = checkAllowed(attemptKey);
    if (!firstGate.ok) {
      const waitSeconds = Math.ceil((firstGate.waitMs ?? 0) / 1000);
      return failWithTestLog(
        `Too many attempts. Try again in ${waitSeconds}s.`,
        "guard:rate-limit-initial",
        {
          context: {
            attemptKey,
            waitSeconds,
          },
        }
      );
    }
    emitProgressWithTestLog("progress:rate-limit-initial-passed", {
      context: {
        attemptKey,
      },
    });

    let friendCode = rawInput;
    if (prefixProbe.startsWith("NKI1")) {
      const decodedInvite = decodeInviteCodeV1(rawInput);
      if ("error" in decodedInvite) {
        recordFail(attemptKey);
        if (decodedInvite.error.toLowerCase().includes("expired")) {
          return failWithTestLog("Invite expired.", "decode:invite-expired");
        }
        return failWithTestLog(decodedInvite.error, "decode:invite-invalid");
      }
      oneTimeInvite = Boolean(decodedInvite.oneTime);
      try {
        invitePsk = decodeBase64Url(decodedInvite.psk);
      } catch {
        recordFail(attemptKey);
        return failWithTestLog("Invalid invite PSK.", "decode:invite-psk-invalid");
      }
      friendCode = encodeFriendCodeV1(decodedInvite.friend);
      emitProgressWithTestLog("progress:invite-decoded", {
        message: oneTimeInvite
          ? "Invite decoded (one-time)."
          : "Invite decoded (reusable).",
        context: {
          oneTimeInvite,
          inviteFingerprint: inviteFingerprint?.slice(0, 12),
        },
      });
    }

    const decoded = decodeFriendCodeV1(friendCode);
    if ("error" in decoded) {
      recordFail(attemptKey);
      return failWithTestLog(decoded.error, "decode:friend-code-invalid", {
        context: {
          inputKind,
          oneTimeInvite,
        },
      });
    }

    const identityPubBytes = decodeBase64Url(decoded.identityPub);
    const friendId = computeFriendId(identityPubBytes);
    emitProgressWithTestLog("progress:friend-code-decoded", {
      friendId,
      context: {
        hasDeviceId: Boolean(decoded.deviceId),
        hasOnionAddr: Boolean(decoded.onionAddr),
      },
    });
    const finalKey = prefixProbe.startsWith("NKI1") ? attemptKey : `friend:${friendId}`;
    if (finalKey !== attemptKey) {
      const gate = checkAllowed(finalKey);
      if (!gate.ok) {
        const waitSeconds = Math.ceil((gate.waitMs ?? 0) / 1000);
        return failWithTestLog(
            `Too many attempts. Try again in ${waitSeconds}s.`,
            "guard:rate-limit-friend-id",
            {
              friendId,
              context: {
                finalKey,
                waitSeconds,
              },
            }
        );
      }
    }
    emitProgressWithTestLog("progress:rate-limit-final-passed", {
      friendId,
      context: {
        finalKey,
      },
    });

    try {
      const myIdentityPub = await getIdentityPublicKey();
      if (encodeBase64Url(myIdentityPub) === decoded.identityPub) {
        recordFail(finalKey);
        return failWithTestLog("You cannot add yourself.", "guard:self-add", { friendId });
      }
      emitProgressWithTestLog("progress:self-check-passed", { friendId });
    } catch (error) {
      emitProgressWithTestLog("progress:self-check-skipped", {
        friendId,
        message: "Self-check skipped due to local identity read failure.",
        errorDetail: toInfoLogErrorDetail(error),
      });
    }

    const finalizeFriendAdd = async () => {
      try {
        const existing = friends.find(
          (friend) => friend.friendId === friendId || friend.identityPub === decoded.identityPub
        );
        emitProgressWithTestLog("progress:finalize-start", {
          friendId,
          profileId: existing?.id,
          context: {
            finalKey,
            hasExistingProfile: Boolean(existing),
            oneTimeInvite,
          },
        });
        if (existing?.friendStatus === "request_out") {
          return failWithTestLog("이미 친구 추가 요청을 보냈습니다.", "guard:duplicate-request-out", {
            friendId,
            profileId: existing.id,
            context: {
              finalKey,
              existingStatus: existing.friendStatus,
            },
          });
        }
        if (existing?.friendStatus === "normal") {
          return failWithTestLog("이미 추가된 친구입니다.", "guard:duplicate-friend-normal", {
            friendId,
            profileId: existing.id,
            context: {
              finalKey,
              existingStatus: existing.friendStatus,
            },
          });
        }

        const tofu = applyTOFU(
          existing?.identityPub && existing?.dhPub
            ? { identityPub: existing.identityPub, dhPub: existing.dhPub }
            : null,
          { identityPub: decoded.identityPub, dhPub: decoded.dhPub }
        );

        const now = Date.now();
        if (!tofu.ok) {
          if (existing) {
            await saveProfile({
              ...existing,
              trust: {
                pinnedAt: existing.trust?.pinnedAt ?? now,
                status: "blocked",
                reason: tofu.reason,
              },
              friendStatus: "blocked",
              updatedAt: now,
            });
            await hydrateVault();
          }
          recordFail(finalKey);
          return failWithTestLog("Friend keys changed; blocked.", "verify:tofu-blocked", {
            profileId: existing?.id,
            friendId,
            context: {
              tofuReason: tofu.reason,
            },
          });
        }
        emitProgressWithTestLog("progress:tofu-passed", {
          friendId,
          profileId: existing?.id,
          context: {
            trustStatus: existing?.trust?.status ?? "new",
          },
        });

        const psk =
          invitePsk ?? (payload.psk?.trim() ? new TextEncoder().encode(payload.psk.trim()) : null);
        if (psk) {
          await setFriendPsk(friendId, psk);
          emitProgressWithTestLog("progress:psk-stored", {
            friendId,
            profileId: existing?.id,
            context: {
              pskSource: invitePsk ? "invite" : "manual",
            },
          });
        }

        const routingHints = sanitizeRoutingHints(
          decoded.onionAddr || decoded.deviceId
            ? {
                onionAddr: decoded.onionAddr,
                deviceId: decoded.deviceId,
              }
            : undefined
        );
        const hasDeviceId = Boolean(decoded.deviceId);
        const hasRouteTarget = Boolean(decoded.onionAddr);
        const netConfig = useNetConfigStore.getState().config;
        const routeRequired = netConfig.mode === "onionRouter" || netConfig.onionEnabled;
        if (!decoded.deviceId) {
          console.warn("[friend] missing deviceId in friend code; marking unreachable", {
            friendId,
          });
        } else if (routeRequired && !hasRouteTarget) {
          console.warn("[friend] missing route target in friend code; request send deferred", {
            friendId,
          });
        }

        const short = friendId.slice(0, 6);
        const reachability = (() => {
          if (hasDeviceId && (!routeRequired || hasRouteTarget)) {
            return {
              status: "ok" as const,
              attempts: existing?.reachability?.attempts ?? 0,
              lastAttemptAt: existing?.reachability?.lastAttemptAt,
              nextAttemptAt: existing?.reachability?.nextAttemptAt,
            };
          }
          return {
            status: "unreachable" as const,
            lastError: hasDeviceId
              ? "Missing onion route target in friend code"
              : "Missing deviceId in friend code",
            attempts: existing?.reachability?.attempts ?? 0,
            lastAttemptAt: Date.now(),
            nextAttemptAt: existing?.reachability?.nextAttemptAt,
          };
        })();

        const nextFriendStatus =
          existing?.friendStatus === "request_in"
            ? "normal"
            : existing?.friendStatus ?? "request_out";
        const friend: UserProfile = {
          id: existing?.id ?? createId(),
          friendId,
          displayName: existing?.displayName ?? (short ? `Friend ${short}` : "Friend"),
          status: existing?.status ?? "Friend",
          theme: existing?.theme ?? "dark",
          kind: "friend",
          friendStatus: nextFriendStatus,
          isFavorite: existing?.isFavorite ?? false,
          identityPub: decoded.identityPub,
          dhPub: decoded.dhPub,
          routingHints,
          primaryDeviceId: decoded.deviceId ?? existing?.primaryDeviceId,
          trust: { pinnedAt: existing?.trust?.pinnedAt ?? now, status: "trusted" },
          verification: existing?.verification ?? { status: "unverified" },
          reachability,
          pskHint: Boolean(psk) || existing?.pskHint,
          profileVcard: {
            ...(existing?.profileVcard ?? {}),
            friendCode,
            updatedAt: now,
          },
          createdAt: existing?.createdAt ?? now,
          updatedAt: now,
        };

        await saveProfile(friend);
        if (existing?.friendStatus === "request_in") {
          const existingConv = convs.find(
            (conv) =>
              !(conv.type === "group" || conv.participants.length > 2) &&
              conv.participants.includes(friend.id)
          );
          if (existingConv) {
            await saveConversation({
              ...existingConv,
              pendingAcceptance: false,
              pendingOutgoing: false,
              pendingFriendResponse: undefined,
              hidden: false,
            });
          }
        }
        emitProgressWithTestLog("progress:profile-saved", {
          friendId,
          profileId: friend.id,
          context: {
            friendStatus: friend.friendStatus,
            hasDeviceId: Boolean(friend.routingHints?.deviceId || friend.primaryDeviceId || friend.deviceId),
            hasRouteTarget: Boolean(friend.routingHints?.onionAddr),
          },
        });

        let requestSent = false;
        const canAttemptRequest = hasDeviceId && (!routeRequired || hasRouteTarget);
        if (canAttemptRequest) {
          emitProgressWithTestLog("progress:request-send-attempt", {
            friendId,
            profileId: friend.id,
            requestSent: false,
            context: {
              requestTraceId: traceId,
              convPendingOutgoing: friend.friendStatus === "request_out",
            },
          });
          try {
            requestSent = await sendFriendRequestForFriend(friend, traceId);
          } catch (error) {
            console.warn("[friend] failed to send friend request", error);
            const message = error instanceof Error ? error.message : String(error);
            emitProgressWithTestLog("progress:request-send-error", {
              friendId,
              profileId: friend.id,
              message,
              requestSent: false,
              errorDetail: toInfoLogErrorDetail(error),
              context: {
                checkpoint: "sendFriendRequestForFriend",
                requestTraceId: traceId,
              },
            });
          }
        } else {
          emitProgressWithTestLog("progress:request-send-skipped", {
            friendId,
            profileId: friend.id,
            requestSent: false,
            context: {
              requestTraceId: traceId,
              missingDeviceId: !hasDeviceId,
              missingRouteTarget: routeRequired && !hasRouteTarget,
            },
          });
        }
        emitProgressWithTestLog(
          requestSent ? "progress:request-send-success" : "progress:request-send-deferred",
          {
            friendId,
            profileId: friend.id,
            requestSent,
            context: {
              requestTraceId: traceId,
              retryExpected: !requestSent,
            },
          }
        );
        if (!requestSent) {
          await hydrateVault();
          if (!hasDeviceId) {
            addToast({
              message:
                "친구는 추가되었지만 코드에 기기 ID가 없어 요청을 보낼 수 없습니다. 상대가 최신 버전에서 코드를 다시 복사해 보내야 합니다.",
            });
            emitFriendAddWithMeta({
              result: "added",
              stage: "result:added-missing-device-id",
              message: "Friend added without deviceId; friend request not sent.",
              profileId: friend.id,
              friendId,
              requestSent: false,
              context: {
                finalKey,
                hasDeviceId: false,
                retryExpected: false,
              },
            });
            return {
              ok: true as const,
            };
          }
          if (routeRequired && !hasRouteTarget) {
            addToast({
              message:
                "친구는 추가되었지만 코드에 onion 주소가 없어 요청을 보낼 수 없습니다. 상대에게 최신 친구 코드를 요청하거나, 내 코드를 보내 상대가 먼저 추가하도록 안내해 주세요.",
            });
            emitFriendAddWithMeta({
              result: "added",
              stage: "result:added-missing-route-target",
              message: "Friend added without route target; friend request not sent.",
              profileId: friend.id,
              friendId,
              requestSent: false,
              context: {
                finalKey,
                hasDeviceId: true,
                hasRouteTarget: false,
                retryExpected: false,
              },
            });
            return {
              ok: true as const,
            };
          }
          addToast({
            message:
              "친구를 목록에 추가했습니다. 요청 전송이 지연되어 백그라운드에서 재시도됩니다.",
          });
          emitFriendAddWithMeta({
            result: "added",
            stage: "result:added-request-delayed",
            message: "Friend added; request send delayed and scheduled for retry.",
            profileId: friend.id,
            friendId,
            requestSent: false,
            context: {
              finalKey,
              hasDeviceId: true,
              hasRouteTarget: true,
              retryExpected: true,
            },
          });
          return {
            ok: true as const,
          };
        }

        await hydrateVault();
        devLog("friend:add:success", { id: friend.id, friendId });
        emitFriendAddWithMeta({
          result: "added",
          stage: "result:added-request-sent",
          message: "Friend added and request sent.",
          profileId: friend.id,
          friendId,
          requestSent: true,
          context: {
            finalKey,
            retryExpected: false,
          },
        });

        recordSuccess(finalKey);
        return { ok: true as const };
      } catch (error) {
        console.error("Friend:add failed", error);
        recordFail(finalKey);
        return failWithTestLog(
          "Failed to add friend.",
          "exception:add-failed",
          {
            friendId,
            context: {
              finalKey,
              checkpoint: "finalizeFriendAdd",
            },
          },
          error
        );
      }
    };

    if (oneTimeInvite && inviteFingerprint) {
      emitProgressWithTestLog("progress:invite-guard-check", {
        friendId,
        context: {
          inviteFingerprint: inviteFingerprint.slice(0, 12),
        },
      });
      const guarded = await runOneTimeInviteGuard(
        inviteFingerprint,
        finalizeFriendAdd,
        (result) => result.ok
      );
      if (!guarded.ok) {
        recordFail(finalKey);
        return failWithTestLog("Invite already used.", "guard:invite-already-used", {
          friendId,
          context: {
            inviteFingerprint: inviteFingerprint.slice(0, 12),
          },
        });
      }
      emitProgressWithTestLog("progress:invite-guard-passed", {
        friendId,
        context: {
          inviteFingerprint: inviteFingerprint.slice(0, 12),
        },
      });
      return guarded.value;
    }

    return finalizeFriendAdd();
  };

  const currentConversation = ui.selectedConvId
    ? convs.find((conv) => conv.id === ui.selectedConvId) || null
    : null;
  const currentTransportStatus = currentConversation
    ? transportStatusByConv[currentConversation.id] ??
      getTransportStatus(currentConversation.id)
    : null;
  const groupInviteConversation = groupInviteConvId
    ? convs.find((conv) => conv.id === groupInviteConvId) || null
    : null;
  const groupInviteExistingMemberIds = groupInviteConversation?.participants ?? [];

  const nameMap = useMemo(
    () =>
      buildNameMap(
        [...(friends || []), ...(userProfile ? [userProfile] : [])],
        friendAliasesById
      ),
    [friendAliasesById, friends, userProfile]
  );

  const profilesById = useMemo(() => {
    const map: Record<string, UserProfile> = {};
    friends.forEach((friend) => {
      map[friend.id] = friend;
    });
    if (userProfile) {
      map[userProfile.id] = userProfile;
    }
    return map;
  }, [friends, userProfile]);

  const currentGroupAvatarRef = currentConversation
    ? groupAvatarRefsByConv[currentConversation.id]
    : undefined;
  const currentGroupAvatarOverrideRef = currentConversation
    ? groupAvatarOverrides[currentConversation.id] ?? null
    : null;
  useEffect(() => {
    const prev = activeSyncConvRef.current;
    if (prev && prev !== ui.selectedConvId) {
      void disconnectSyncConversation(prev);
    }

    if (!ui.selectedConvId || !userProfile) {
      activeSyncConvRef.current = null;
      return;
    }

    const conv = convs.find((item) => item.id === ui.selectedConvId);
    if (!conv) return;
    const isDirect =
      !(conv.type === "group" || conv.participants.length > 2) && conv.participants.length === 2;
    if (!isDirect) return;

    const partnerId = conv.participants.find((id) => id && id !== userProfile.id) || null;
    const partner = partnerId ? friends.find((friend) => friend.id === partnerId) || null : null;
    if (!partner?.identityPub || !partner.dhPub) return;

    void connectSyncConversation(conv.id, {
      friendKeyId: partner.friendId ?? partner.id,
      identityPub: partner.identityPub,
      dhPub: partner.dhPub,
      onionAddr: partner.routingHints?.onionAddr,
    });
    const onionAddress = partner.routingHints?.onionAddr?.trim().toLowerCase();
    const lastPrewarmedAt = onionAddress
      ? prewarmedOnionRoutesRef.current.get(onionAddress) ?? 0
      : 0;
    if (onionAddress && Date.now() - lastPrewarmedAt >= 45_000) {
      const nkc = (
        globalThis as typeof globalThis & {
          nkc?: {
            prewarmOnionRoute?: (payload: { onionAddress: string }) => Promise<{ ok?: boolean }>;
          };
        }
      ).nkc;
      if (nkc?.prewarmOnionRoute) {
        prewarmedOnionRoutesRef.current.set(onionAddress, Date.now());
        void nkc
          .prewarmOnionRoute({ onionAddress })
          .then((result) => {
            if (!result?.ok) prewarmedOnionRoutesRef.current.delete(onionAddress);
          })
          .catch(() => prewarmedOnionRoutesRef.current.delete(onionAddress));
      }
    }
    activeSyncConvRef.current = conv.id;
  }, [ui.selectedConvId, convs, friends, userProfile]);

  const partnerProfile = useMemo(() => {
    if (!currentConversation) return null;
    const isGroup =
      currentConversation.type === "group" || currentConversation.participants.length > 2;
    if (isGroup) return null;
    const partnerId = currentConversation.participants.find((id) => id !== userProfile?.id);
    return friends.find((friend) => friend.id === partnerId) || null;
  }, [currentConversation, friends, userProfile]);

  const { currentTrustState } = useTrustState({
    friends,
    currentConversation,
    currentTransportStatus,
    partnerProfile,
  });

  const currentConversationDisplayName = useMemo(() => {
    if (!currentConversation) return "대화를 선택해주세요.";
    const isGroup =
      currentConversation.type === "group" || currentConversation.participants.length > 2;
    if (isGroup) return currentConversation.name;
    return resolveFriendDisplayName(partnerProfile ?? undefined, friendAliasesById);
  }, [currentConversation, friendAliasesById, partnerProfile]);

  const sendFriendResponseControl = useCallback(
    async (
      conv: Conversation,
      partner: UserProfile,
      response: PendingFriendResponseType
    ): Promise<{ ok: true } | { ok: false; reason: "missing-device" | "send-failed" }> => {
      const traceId = `friend-response:${response}:${newClientBatchId()}`;
      const routingMeta = buildRoutingMeta(partner);
      if (!routingMeta.toDeviceId) {
        return { ok: false, reason: "missing-device" };
      }
      const [identityPub, dhPub] = await Promise.all([getIdentityPublicKey(), getDhPublicKey()]);
      const localFriendCodePayload = await buildLocalFriendCodePayload();
      const localFriendCode = encodeFriendCodeV1({
        v: 1,
        ...localFriendCodePayload,
      });
      const payload =
        response === "accept"
          ? {
              type: "friend_accept" as const,
              convId: conv.id,
              traceId,
              from: {
                identityPub: encodeBase64Url(identityPub),
                dhPub: encodeBase64Url(dhPub),
                deviceId: getOrCreateDeviceId(),
                friendCode: localFriendCode,
              },
              profile: {
                displayName: userProfile?.displayName,
                status: userProfile?.status,
                avatarRef: userProfile?.avatarRef,
              },
              ts: Date.now(),
            }
          : {
              type: "friend_decline" as const,
              convId: conv.id,
              traceId,
              from: {
                identityPub: encodeBase64Url(identityPub),
                dhPub: encodeBase64Url(dhPub),
                deviceId: getOrCreateDeviceId(),
                friendCode: localFriendCode,
              },
              ts: Date.now(),
            };
      const sent = await sendFriendControlPacket(conv, partner, payload);
      return sent ? { ok: true } : { ok: false, reason: "send-failed" };
    },
    [buildLocalFriendCodePayload, buildRoutingMeta, sendFriendControlPacket, userProfile?.avatarRef, userProfile?.displayName, userProfile?.status]
  );

  const applyFriendResponseLocally = useCallback(
    async (convId: string, friendId: string, response: PendingFriendResponseType) => {
      if (response === "accept") {
        await updateFriendOrThrow(friendId, { friendStatus: "normal" });
        await updateConversationOrThrow(convId, {
          hidden: false,
          pendingAcceptance: false,
          pendingOutgoing: false,
          pendingFriendResponse: undefined,
        });
        return;
      }
      await updateFriendOrThrow(friendId, { friendStatus: "blocked" });
      await updateConversationOrThrow(convId, {
        hidden: true,
        pendingAcceptance: false,
        pendingOutgoing: false,
        pendingFriendResponse: undefined,
      });
    },
    [updateConversationOrThrow, updateFriendOrThrow]
  );

  const handleAcceptRequest = async () => {
    if (!currentConversation || !partnerProfile) return;
    try {
      const outcome = await sendFriendResponseControl(currentConversation, partnerProfile, "accept");
      if (!outcome.ok) {
        await updateConversationOrThrow(currentConversation.id, {
          pendingFriendResponse: "accept",
        });
        addToast({
          message:
            outcome.reason === "missing-device"
              ? "상대 기기 정보가 없어 수락 전송이 지연됩니다. 정보가 갱신되면 자동 재시도합니다."
              : "수락 전송이 지연되었습니다. 백그라운드에서 자동 재시도합니다.",
        });
        return;
      }
      await applyFriendResponseLocally(currentConversation.id, partnerProfile.id, "accept");
    } catch (error) {
      console.error("Failed to accept request", error);
      addToast({ message: "메시지 요청 수락에 실패했습니다." });
    }
  };

  useEffect(() => {
    if (!userProfile) return;
    const scheduler = startFriendRequestScheduler({
      getTargets: () => {
        const state = useAppStore.getState();
        const config = useNetConfigStore.getState().config;
        const routeRequired = config.mode === "onionRouter" || config.onionEnabled;
        if (!routeRequired) {
          return state.friends;
        }
        return state.friends.filter((friend) => {
          if (friend.routingHints?.onionAddr) {
            return true;
          }
          const code = friend.profileVcard?.friendCode?.trim();
          if (!code) return false;
          const decoded = decodeFriendCodeV1(code);
          if ("error" in decoded) return false;
          return Boolean(decoded.onionAddr);
        });
      },
      onAttempt: async (friend) => {
        try {
          return await sendFriendRequestForFriend(friend);
        } catch (error) {
          console.warn("[friend] request retry failed", error);
          return false;
        }
      },
      onUpdate: async (friendId, patch) => {
        const latest = useAppStore.getState().friends.find((item) => item.id === friendId);
        if (!latest) return;
        await saveProfile({
          ...latest,
          ...patch,
          updatedAt: Date.now(),
        });
        await hydrateVault();
      },
    });
    return () => scheduler.stop();
  }, [hydrateVault, sendFriendRequestForFriend, userProfile]);

  useEffect(() => {
    if (!userProfile) return;
    const scheduler = startFriendResponseScheduler({
      getTargets: () => {
        const state = useAppStore.getState();
        const myId = state.userProfile?.id;
        if (!myId) return [];
        return state.convs.flatMap((conv) => {
          const pending = conv.pendingFriendResponse;
          if (pending !== "accept" && pending !== "decline") return [];
          const isDirect =
            !(conv.type === "group" || conv.participants.length > 2) &&
            conv.participants.length === 2;
          if (!isDirect) return [];
          const friendId = conv.participants.find((id) => id && id !== myId);
          if (!friendId) return [];
          const partner = state.friends.find((friend) => friend.id === friendId);
          if (!partner) return [];
          return [{ convId: conv.id, friendId: partner.id, response: pending }];
        });
      },
      onAttempt: async (target) => {
        const state = useAppStore.getState();
        const conv = state.convs.find((item) => item.id === target.convId);
        const partner = state.friends.find((item) => item.id === target.friendId);
        if (!conv || !partner) return false;
        try {
          const outcome = await sendFriendResponseControl(conv, partner, target.response);
          if (!outcome.ok) return false;
          await applyFriendResponseLocally(conv.id, partner.id, target.response);
          return true;
        } catch (error) {
          console.warn("[friend] response retry failed", error);
          return false;
        }
      },
    });
    return () => scheduler.stop();
  }, [applyFriendResponseLocally, sendFriendResponseControl, userProfile]);

  const runBackgroundSync = useCallback(async () => {
    await syncContactsNow();
    await syncConversationsNow();
    if (activeSyncConvRef.current) {
      await syncConversation(activeSyncConvRef.current);
    }
    await hydrateVault();
  }, [hydrateVault]);

  useEffect(() => {
    const unsubscribe = onSyncRun((payload) => {
      if (!payload?.requestId) return;
      const complete = (ok: boolean, error?: string) => {
        try {
          reportSyncResult({ requestId: payload.requestId, ok, error });
        } catch (reportError) {
          console.error("Failed to report sync result", reportError);
        }
      };
      void (async () => {
        if (ui.mode !== "app") {
          throw new Error("app-not-ready");
        }
        await runBackgroundSync();
      })()
        .then(() => complete(true))
        .catch((error) => {
          const message = error instanceof Error ? error.message : String(error);
          complete(false, message);
        });
    });
    return () => {
      unsubscribe();
    };
  }, [runBackgroundSync, ui.mode]);

  const handleDeclineRequest = async () => {
    if (!currentConversation || !partnerProfile) return;
    try {
      const outcome = await sendFriendResponseControl(currentConversation, partnerProfile, "decline");
      if (!outcome.ok) {
        await updateConversationOrThrow(currentConversation.id, {
          pendingFriendResponse: "decline",
        });
        addToast({
          message:
            outcome.reason === "missing-device"
              ? "상대 기기 정보가 없어 거절 전송이 지연됩니다. 정보가 갱신되면 자동 재시도합니다."
              : "거절 전송이 지연되었습니다. 백그라운드에서 자동 재시도합니다.",
        });
        return;
      }
      await applyFriendResponseLocally(currentConversation.id, partnerProfile.id, "decline");
    } catch (error) {
      console.error("Failed to decline request", error);
      addToast({ message: "메시지 요청 거절에 실패했습니다." });
    }
  };

  const handleCancelOutgoingFriendRequest = async () => {
    if (!currentConversation || !partnerProfile) return;
    try {
      friendRequestInFlightRef.current.delete(partnerProfile.id);
      delete friendRouteWakeSignatureRef.current[partnerProfile.id];
      await updateFriendOrThrow(partnerProfile.id, {
        friendStatus: "hidden",
        reachability: {
          ...(partnerProfile.reachability ?? { status: "unreachable" as const }),
          nextAttemptAt: undefined,
        },
      });
      await updateConversationOrThrow(currentConversation.id, {
        hidden: true,
        pendingOutgoing: false,
        pendingAcceptance: false,
        pendingFriendResponse: undefined,
      });
      addToast({ message: "친구 추가 요청을 취소했습니다." });
      if (ui.selectedConvId === currentConversation.id) {
        setSelectedConv(null);
      }
    } catch (error) {
      console.error("Failed to cancel outgoing friend request", error);
      addToast({ message: "친구 추가 요청 취소에 실패했습니다." });
    }
  };

  if (ui.mode === "onboarding") {
    return (
      <>
        <Onboarding
          onCreate={handleCreate}
          onUnlockWithStartKey={handleStartKeyUnlock}
          defaultTab={defaultTab}
          errorMessage={onboardingError}
        />
        <Toasts />
      </>
    );
  }

  const appShell = (
    <div className="flex h-full min-w-0 overflow-hidden bg-nkc-bg">
      <Sidebar
        convs={convs}
        friends={friends}
        userId={userProfile?.id || null}
        groupAvatarRefsByConv={groupAvatarRefsByConv}
        friendAliasesById={friendAliasesById}
        selectedConvId={ui.selectedConvId}
        networkStatus={sidebarNetworkStatus}
        listMode={ui.listMode}
        listFilter={ui.listFilter}
        search={ui.search}
        onSearch={setSearch}
        onSelectConv={handleSelectConv}
        onAddFriend={() => setFriendAddDialogOpen(true)}
        onCreateGroup={handleCreateGroup}
        onFriendChat={handleFriendChat}
        onFriendViewProfile={handleFriendViewProfile}
        onFriendToggleFavorite={handleFriendToggleFavorite}
        onFriendHide={handleFriendHide}
        onFriendDelete={handleFriendDelete}
        onFriendBlock={handleFriendBlock}
        onSetFriendAlias={handleSetFriendAlias}
        onListModeChange={setListMode}
        onListFilterChange={setListFilter}
        theme={userProfile?.theme ?? "light"}
        onToggleTheme={handleToggleTheme}
        onSettings={() => navigate("/settings")}
        onHide={handleHide}
        onDelete={handleDelete}
        onTogglePin={handleTogglePin}
        onMute={handleMute}
        onBlock={handleBlock}
      />

      <ChatView
        key={currentConversation?.id ?? "none"}
        conversation={currentConversation}
        conversationDisplayName={currentConversationDisplayName}
        transportStatus={currentTransportStatus}
        currentUserId={userProfile?.id || null}
        nameMap={nameMap}
        profilesById={profilesById}
        isComposing={ui.isComposing}
        onComposingChange={setIsComposing}
        onSendBatch={handleSendBatch}
        onSendReadReceipt={handleSendReadReceipt}
        onAcceptRequest={handleAcceptRequest}
        onDeclineRequest={handleDeclineRequest}
        onCancelOutgoingRequest={handleCancelOutgoingFriendRequest}
        onDeleteMessages={handleDeleteMessages}
        onToast={(message) => addToast({ message })}
        onBack={() => {
          setSelectedConv(null);
          setRightPanelOpen(false);
        }}
        onToggleRight={() => setRightPanelOpen(!ui.rightPanelOpen)}
        rightPanelOpen={ui.rightPanelOpen}
      />

      <RightPanel
        open={ui.rightPanelOpen}
        tab={ui.rightTab}
        onTabChange={setRightTab}
        conversation={currentConversation}
        friendProfile={partnerProfile}
        currentUserId={userProfile?.id ?? null}
        profilesById={profilesById}
        groupAvatarRef={currentGroupAvatarRef}
        groupAvatarOverrideRef={currentGroupAvatarOverrideRef}
        friendAliasesById={friendAliasesById}
        trustState={currentTrustState}
        onOpenSettings={() => navigate("/settings")}
        onInviteToGroup={handleInviteToGroup}
        onLeaveGroup={handleLeaveGroup}
        onSetGroupAvatarOverride={handleSetGroupAvatarOverride}
        onToggleMute={handleMute}
        onTogglePin={handleTogglePin}
        onHideConversation={handleHide}
        onToggleBlock={handleBlock}
      />

      {userProfile ? (
        <SettingsDialog
          open={settingsOpen}
          onOpenChange={(open) => {
            if (!open) navigate("/");
          }}
          user={userProfile}
          onSaveProfile={handleSaveProfile}
          onUploadPhoto={handleUploadPhoto}
          onLock={handleLock}
          pinEnabled={pinEnabled}
          onSetPin={handleSetPin}
          onDisablePin={handleDisablePin}
          onRotateStartKey={handleRotateStartKey}
          hiddenFriends={friends.filter((friend) => friend.friendStatus === "hidden")}
          blockedFriends={friends.filter((friend) => friend.friendStatus === "blocked")}
          onUnhideFriend={handleFriendUnhide}
          onUnblockFriend={handleFriendUnblock}
          onLogout={() =>
            setConfirm({
              title: "로그아웃할까요?",
              message: "세션을 종료하고 로컬 데이터는 유지됩니다.",
              onConfirm: handleLogout,
            })
          }
          onWipe={() =>
            setConfirm({
              title: "데이터를 삭제할까요?",
              message: "로컬 금고가 초기화됩니다.",
              onConfirm: async () => {
                await clearStoredSession();
                await wipePinState();
                await wipeVault();
                window.location.reload();
              },
            })
          }
        />
      ) : null}

      {userProfile ? (
        <FriendAddDialog
          open={friendAddOpen}
          onOpenChange={setFriendAddDialogOpen}
          myCode={myFriendCode}
          myCodeHint={friendAddHint}
          myCodeLoading={!myFriendCode}
          routeResolveBusy={routeResolveBusy}
          onCopyCode={handleCopyFriendCode}
          onResolveRoute={handleResolveFriendRoute}
          onAdd={handleAddFriend}
        />
      ) : null}

      {userProfile ? (
        <GroupInviteDialog
          open={groupInviteOpen && Boolean(groupInviteConversation)}
          onOpenChange={(open) => {
            setGroupInviteOpen(open);
            if (!open) setGroupInviteConvId(null);
          }}
          friends={friends}
          existingMemberIds={groupInviteExistingMemberIds}
          onSubmit={(memberIds) =>
            groupInviteConversation
              ? handleSubmitGroupInvite(groupInviteConversation.id, memberIds)
              : Promise.resolve({ ok: false as const, error: "Group not found." })
          }
        />
      ) : null}

      {userProfile ? (
        <GroupCreateDialog
          open={groupCreateOpen}
          onOpenChange={setGroupCreateOpen}
          friends={friends}
          onCreate={handleSubmitGroup}
        />
      ) : null}
    </div>
  );

  return (
    <>
      <Routes>
        <Route
          path="/unlock"
          element={
            ui.mode === "locked" ? (
              <Unlock
                onUnlock={handlePinUnlock}
                onUseStartKey={async () => {
                  try {
                    await clearPinRecord();
                  } catch (error) {
                    console.warn("Failed to mark PIN reset", error);
                  }
                  setPinEnabled(true);
                  setPinNeedsReset(true);
                  setDefaultTab("startKey");
                  setMode("onboarding");
                  navigate("/");
                }}
              />
            ) : (
              <Navigate to="/" replace />
            )
          }
        />
        <Route
          path="/start-key"
          element={
            ui.mode === "app" ? (
              <StartKey
                onRotate={handleRotateStartKey}
                onDone={() => navigate("/settings")}
              />
            ) : (
              <Navigate to="/unlock" replace />
            )
          }
        />
        <Route path="/settings" element={ui.mode === "app" ? appShell : <Navigate to="/unlock" replace />} />
        <Route path="/*" element={ui.mode === "app" ? appShell : <Navigate to="/unlock" replace />} />
      </Routes>

      <ConfirmDialog
        open={Boolean(confirm)}
        title={confirm?.title || ""}
        message={confirm?.message || ""}
        onConfirm={() => {
          // confirm?.onConfirm()가 Promise를 반환해도 UI는 void 처리
          void confirm?.onConfirm?.();
        }}
        onClose={() => setConfirm(null)}
      />

      <Toasts />
    </>
  );
}
