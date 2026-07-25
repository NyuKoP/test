import { useCallback, useEffect, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import {
  AlertTriangle,
  Check,
  Clock,
  Key,
} from "lucide-react";
import type { UserProfile } from "../db/repo";
import {
  clearChatHistory,
  deleteAllMedia,
  listConversations,
  listMessagesByConv,
  listProfiles,
} from "../db/repo";
import { estimateStorageUsage, type StorageUsage } from "../storage/storageUsage";
import { clearOutboxQueue } from "../storage/outboxStore";
import { useAppStore } from "../app/store";
import {
  defaultPrivacyPrefs,
  getPrivacyPrefs,
  setPrivacyPrefs,
} from "../security/preferences";
import {
  applyAppPrefsPatch,
  defaultAppPrefs,
  getAppPrefs,
  setAppPrefs,
  type DeviceSyncTransportPolicy,
  type AppPreferencesPatch,
} from "../preferences";
import { syncNow } from "../appControl";
import { isPinAvailable } from "../security/pin";
import {
  applyOnionUpdate,
  checkOnionUpdates,
  getOnionStatus,
  installOnion,
  onOnionProgress,
  setOnionMode,
  uninstallOnion,
} from "../net/onionControl";
import type { OnionStatus } from "../net/onionControl";
import { useNetConfigStore } from "../net/netConfigStore";
import { getRouteInfo } from "../net/routeInfo";
import type { OnionNetwork } from "../net/netConfig";
import type { NetworkMode } from "../net/mode";
import {
  getHopsProgressText,
  getRouteStatusText,
  useInternalOnionRouteStore,
} from "../stores/internalOnionRouteStore";
import { getConnectionStatus, onConnectionStatus } from "../net/connectionStatus";
import { validateProxyUrl } from "../net/proxyControl";
import Avatar from "./Avatar";
import ConfirmDialog from "./ConfirmDialog";
import StartKey from "./StartKey";
import SettingsBackHeader from "./settings/SettingsBackHeader";
import DevicesSettings from "./settings/sections/DevicesSettings";
import { useDeviceSyncSettings } from "./settings/hooks/useDeviceSyncSettings";
import LoginSettings from "./settings/sections/LoginSettings";
import FriendsSettings from "./settings/sections/FriendsSettings";
import NetworkSettings from "./settings/sections/NetworkSettings";
import NotificationsSettings from "./settings/sections/NotificationsSettings";
import PrivacySettings from "./settings/sections/PrivacySettings";
import StorageSettings from "./settings/sections/StorageSettings";
import AppUpdateSettings from "./settings/sections/AppUpdateSettings";
import {
  SETTINGS_ROUTES,
  routeIconByView,
  themeOptions,
  type ConnectionChoice,
  type LocalizedLabel,
  type SettingsView,
} from "./settings/settingsTypes";

type SettingsDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user: UserProfile;

  onSaveProfile: (payload: {
    displayName: string;
    status: string;
    theme: "dark" | "light";
  }) => Promise<void>;

  onUploadPhoto: (file: File) => Promise<void>;
  onLock: () => void;

  pinEnabled: boolean;
  onSetPin: (pin: string) => Promise<{ ok: boolean; error?: string }>;
  onDisablePin: () => Promise<void>;
  onRotateStartKey: (key: string) => Promise<void>;

  hiddenFriends: UserProfile[];
  blockedFriends: UserProfile[];
  onUnhideFriend: (id: string) => Promise<void>;
  onUnblockFriend: (id: string) => Promise<void>;

  onLogout: () => void;
  onWipe: () => void;
};

const getConnectionChoiceFromConfig = (mode: NetworkMode): ConnectionChoice => {
  if (mode === "onionRouter") {
    return "torOnion";
  }
  if (mode === "selfOnion") return "selfOnion";
  return "directP2P";
};

export default function SettingsDialog({
  open,
  onOpenChange,
  user,
  onSaveProfile,
  onUploadPhoto,
  onLock,
  pinEnabled,
  onSetPin,
  onDisablePin,
  onRotateStartKey,
  hiddenFriends,
  blockedFriends,
  onUnhideFriend,
  onUnblockFriend,
  onLogout,
  onWipe,
}: SettingsDialogProps) {
  const [view, setView] = useState<SettingsView>("main");
  const prevOpenRef = useRef(open);
  const {
    config: netConfig,
    setMode,
    setProxy,
    setOnionEnabled,
    setOnionNetwork,
    setTorAutoPrepareOnAppStart,
    setComponentState,
    setLastUpdateCheckAt,
    setSelfOnionMinRelays,
  } = useNetConfigStore();
  const internalOnionRoute = useInternalOnionRouteStore((state) => state.route);

  // profile
  const [displayName, setDisplayName] = useState(user.displayName);
  const [status, setStatus] = useState(user.status);
  const [theme, setTheme] = useState<"dark" | "light">(user.theme);
  const [editing, setEditing] = useState(false);
  const [displayNameDraft, setDisplayNameDraft] = useState(user.displayName);
  const [statusDraft, setStatusDraft] = useState(user.status);

  // privacy
  const [privacyPrefs, setPrivacyPrefsState] = useState(defaultPrivacyPrefs);
  const [appPrefs, setAppPrefsState] = useState(defaultAppPrefs);
  const [prefsLoaded, setPrefsLoaded] = useState(false);

  // pin
  const [pinDraft, setPinDraft] = useState("");
  const [pinError, setPinError] = useState("");
  const [pinAvailable, setPinAvailable] = useState(true);
  const [pinEnabledUi, setPinEnabledUi] = useState(pinEnabled);

  // network
  const [onionEnabledDraft, setOnionEnabledDraft] = useState(netConfig.onionEnabled);
  const [onionNetworkDraft, setOnionNetworkDraft] = useState(netConfig.onionSelectedNetwork);
  const [torAutoPrepareDraft, setTorAutoPrepareDraft] = useState(
    netConfig.torAutoPrepareOnAppStart !== false
  );
  const [connectionChoiceDraft, setConnectionChoiceDraft] = useState<ConnectionChoice>(
    getConnectionChoiceFromConfig(netConfig.mode)
  );
  const [onionStatus, setOnionStatus] = useState<OnionStatus | null>(null);
  const [proxyUrlDraft, setProxyUrlDraft] = useState(netConfig.onionProxyUrl);
  const [proxyUrlError, setProxyUrlError] = useState("");
  const [torInstallBusy, setTorInstallBusy] = useState(false);
  const [torCheckBusy, setTorCheckBusy] = useState(false);
  const [torApplyBusy, setTorApplyBusy] = useState(false);
  const [torUninstallBusy, setTorUninstallBusy] = useState(false);
  const [torStatusBusy, setTorStatusBusy] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState(getConnectionStatus());
  const [chatWipeBusy, setChatWipeBusy] = useState(false);
  const [mediaWipeBusy, setMediaWipeBusy] = useState(false);
  const [pendingWipeBusy, setPendingWipeBusy] = useState(false);
  const [wipeConfirmOpen, setWipeConfirmOpen] = useState(false);
  const [wipeConfirmType, setWipeConfirmType] = useState<"chat" | "media" | "pending" | null>(
    null
  );
  const [storageUsage, setStorageUsage] = useState<StorageUsage>({
    chatBytes: 0,
    mediaBytes: 0,
    pendingBytes: 0,
    totalBytes: 0,
  });
  const pendingSectionRef = useRef<HTMLDivElement | null>(null);
  const [pendingFocusRequested, setPendingFocusRequested] = useState(false);

  const refreshStorageUsage = useCallback(async () => {
    try {
      const usage = await estimateStorageUsage();
      setStorageUsage(usage);
    } catch (error) {
      console.error("Failed to estimate storage usage", error);
    }
  }, []);

  const language = useAppStore((state) => state.ui.language);
  const setLanguage = useAppStore((state) => state.setLanguage);
  const setData = useAppStore((state) => state.setData);
  const setSelectedConv = useAppStore((state) => state.setSelectedConv);
  const userProfileState = useAppStore((state) => state.userProfile);
  const addToast = useAppStore((state) => state.addToast);

  const t = useCallback(
    (ko: string, en: string) => (language === "en" ? en : ko),
    [language]
  );
  const tl = useCallback(
    (label: LocalizedLabel) => (language === "en" ? label.en : label.ko),
    [language]
  );

  const handleProxyUrlChange = (value: string) => {
    setProxyUrlDraft(value);
    const trimmed = value.trim();
    if (!trimmed) {
      setProxyUrlError("");
      setProxy(netConfig.onionProxyEnabled, "");
      return;
    }
    try {
      const { normalized } = validateProxyUrl(trimmed);
      setProxyUrlError("");
      setProxy(netConfig.onionProxyEnabled, normalized);
    } catch {
      setProxyUrlError(t("유효하지 않은 프록시 URL입니다.", "Invalid proxy URL."));
    }
  };

  // misc
  const [saveMessage, setSaveMessage] = useState("");

  useEffect(() => {
    setDisplayName(user.displayName);
    setStatus(user.status);
    setTheme(user.theme);
    setDisplayNameDraft(user.displayName);
    setStatusDraft(user.status);
    setEditing(false);
  }, [user]);

  useEffect(() => {
    const wasOpen = prevOpenRef.current;
    if (!wasOpen && open) {
      setView("main");
      setOnionEnabledDraft(netConfig.onionEnabled);
      setOnionNetworkDraft(netConfig.onionSelectedNetwork);
      setTorAutoPrepareDraft(netConfig.torAutoPrepareOnAppStart !== false);
      setConnectionChoiceDraft(
        getConnectionChoiceFromConfig(netConfig.mode)
      );
      setProxyUrlDraft(netConfig.onionProxyUrl);
      setProxyUrlError("");
      setPrefsLoaded(false);
      getPrivacyPrefs()
        .then(setPrivacyPrefsState)
        .catch((e) => console.error("Failed to load privacy prefs", e));
      getAppPrefs()
        .then((prefs) => {
          setAppPrefsState(prefs);
          setPrefsLoaded(true);
        })
        .catch((e) => {
          console.error("Failed to load app prefs", e);
          setPrefsLoaded(true);
        });
    }
    prevOpenRef.current = open;
  }, [
    open,
    netConfig.onionEnabled,
    netConfig.onionSelectedNetwork,
    netConfig.torAutoPrepareOnAppStart,
    netConfig.onionProxyUrl,
    netConfig.mode,
  ]);

  useEffect(() => {
    if (!open) return;
    isPinAvailable()
      .then(setPinAvailable)
      .catch(() => setPinAvailable(false));
    setPinEnabledUi(pinEnabled);
  }, [open, pinEnabled]);

  useEffect(() => {
    setPinEnabledUi(pinEnabled);
  }, [pinEnabled]);


  useEffect(() => {
    if (!open || view !== "network") return;
    setConnectionStatus(getConnectionStatus());
    const unsubscribe = onConnectionStatus(setConnectionStatus);
    const interval = window.setInterval(() => {
      setConnectionStatus(getConnectionStatus());
    }, 1500);
    return () => {
      unsubscribe();
      window.clearInterval(interval);
    };
  }, [open, view]);

  useEffect(() => {
    if (!open || view !== "network") return;
    const refresh = async () => {
      try {
        const status = await getOnionStatus();
        setOnionStatus(status);
        setComponentState("tor", status.components.tor);
      } catch {
        // Ignore transient polling errors.
      }
    };
    void refresh();
    const interval = window.setInterval(refresh, 1500);
    const unsubscribe = onOnionProgress((payload) => {
      setComponentState(payload.network, payload.status);
      setOnionStatus((prev) =>
        prev
          ? {
              ...prev,
              components: { ...prev.components, [payload.network]: payload.status },
            }
          : prev
      );
    });
    return () => {
      window.clearInterval(interval);
      unsubscribe();
    };
  }, [open, setComponentState, view]);

  useEffect(() => {
    if (!open) return;
    void refreshStorageUsage();
  }, [open, refreshStorageUsage]);

  useEffect(() => {
    if (!saveMessage) return;
    const t = window.setTimeout(() => setSaveMessage(""), 2000);
    return () => window.clearTimeout(t);
  }, [saveMessage]);

  const updatePrivacy = async (next: typeof privacyPrefs) => {
    setPrivacyPrefsState(next);
    try {
      await setPrivacyPrefs(next);
    } catch (e) {
      console.error("Failed to save privacy prefs", e);
    }
  };

  const updateAppPrefs = useCallback(async (patch: AppPreferencesPatch) => {
    setAppPrefsState((current) => applyAppPrefsPatch(current, patch));
    try {
      const next = await setAppPrefs(patch);
      setAppPrefsState(next);
    } catch (e) {
      console.error("Failed to save app prefs", e);
      try {
        setAppPrefsState(await getAppPrefs());
      } catch {
        // Keep the optimistic state when the bridge cannot be queried either.
      }
    }
  }, []);

  const setDeviceSyncTransportPolicy = useCallback(
    async (transportPolicy: DeviceSyncTransportPolicy) => {
      await updateAppPrefs({ deviceSync: { transportPolicy } });
    },
    [updateAppPrefs]
  );

  const deviceSyncSettings = useDeviceSyncSettings({
    t,
    view,
    open,
    deviceSyncTransportPolicy: appPrefs.deviceSync.transportPolicy,
    onChangeDeviceSyncTransportPolicy: setDeviceSyncTransportPolicy,
    addToast,
  });

  const refreshOnionStatus = async () => {
    try {
      const status = await getOnionStatus();
      setOnionStatus(status);
      setComponentState("tor", status.components.tor);
    } catch (error) {
      console.error("Failed to refresh onion status", error);
    }
  };

  const handleTorStatus = async () => {
    if (torStatusBusy) return;
    setTorStatusBusy(true);
    try {
      await refreshOnionStatus();
      setSaveMessage(t("Tor 상태 확인 완료", "Tor status checked"));
    } catch (error) {
      console.error("Failed to refresh tor status", error);
      setSaveMessage(t("Tor 상태 확인 실패", "Tor status check failed"));
    } finally {
      setTorStatusBusy(false);
    }
  };

  const handleCheckUpdates = async () => {
    if (torCheckBusy) return;
    setTorCheckBusy(true);
    try {
      const status = await checkOnionUpdates();
      setOnionStatus(status);
      setComponentState("tor", status.components.tor);
      setLastUpdateCheckAt(Date.now());
      setSaveMessage(t("업데이트 확인 완료", "Update check complete"));
    } catch (error) {
      console.error("Failed to check onion updates", error);
      setSaveMessage(t("업데이트 확인 실패", "Update check failed"));
    } finally {
      setTorCheckBusy(false);
    }
  };

  const handleApplyUpdate = async (network: OnionNetwork) => {
    if (torApplyBusy) return;
    setTorApplyBusy(true);
    try {
      await applyOnionUpdate(network);
      await refreshOnionStatus();
      setSaveMessage(t("업데이트 적용 완료", "Update applied"));
    } catch (error) {
      console.error("Failed to apply onion update", error);
      setSaveMessage(t("업데이트 적용 실패", "Update failed"));
    } finally {
      setTorApplyBusy(false);
    }
  };

  const handleInstall = async (network: OnionNetwork) => {
    if (torInstallBusy) return;
    setTorInstallBusy(true);
    try {
      await installOnion(network);
      await refreshOnionStatus();
      try {
        const status = await checkOnionUpdates();
        setOnionStatus(status);
        setComponentState("tor", status.components.tor);
        setLastUpdateCheckAt(Date.now());
      } catch (error) {
        console.error("Failed to check onion updates after install", error);
      }
      setSaveMessage(t("Tor 설치 완료", "Tor installed"));
    } catch (error) {
      console.error("Failed to install onion component", error);
      setSaveMessage(t("Tor 설치 실패", "Tor install failed"));
    } finally {
      setTorInstallBusy(false);
    }
  };

  const handleUninstall = async (network: OnionNetwork) => {
    if (torUninstallBusy) return;
    setTorUninstallBusy(true);
    try {
      await uninstallOnion(network);
      await refreshOnionStatus();
      setSaveMessage(t("Tor 제거 완료", "Tor removed"));
    } catch (error) {
      console.error("Failed to uninstall onion component", error);
      setSaveMessage(t("Tor 제거 실패", "Tor remove failed"));
    } finally {
      setTorUninstallBusy(false);
    }
  };

  const handleSaveOnion = async () => {
    const nextMode: typeof netConfig.mode =
      connectionChoiceDraft === "directP2P"
        ? "directP2P"
        : connectionChoiceDraft === "selfOnion"
          ? "selfOnion"
          : "onionRouter";
    const nextOnionNetwork: OnionNetwork = "tor";
    const nextOnionEnabled = nextMode === "onionRouter" ? onionEnabledDraft : false;
    try {
      setMode(nextMode);
      setOnionNetwork(nextOnionNetwork);
      setTorAutoPrepareOnAppStart(torAutoPrepareDraft);
      setOnionEnabled(nextOnionEnabled);
      await setOnionMode(nextOnionEnabled, nextOnionNetwork);
      setSaveMessage(t("저장됨", "Saved"));
    } catch (error) {
      console.error("Failed to save onion settings", error);
      setSaveMessage(t("저장에 실패했습니다.", "Save failed."));
    }
  };

  const handleConnectOnion = async (network?: OnionNetwork) => {
    try {
      const nextNetwork = network ?? onionNetworkDraft;
      setOnionNetworkDraft(nextNetwork);
      setOnionEnabledDraft(true);
      await setOnionMode(true, nextNetwork);
      setSaveMessage(t("연결 중...", "Connecting..."));
      await refreshOnionStatus();
    } catch (error) {
      console.error("Failed to start onion runtime", error);
      setSaveMessage(t("연결 실패", "Connect failed"));
    }
  };

  const handleDisconnectOnion = async (network?: OnionNetwork) => {
    try {
      const nextNetwork = network ?? onionNetworkDraft;
      setOnionNetworkDraft(nextNetwork);
      setOnionEnabledDraft(false);
      setOnionEnabled(false);
      await setOnionMode(false, nextNetwork);
      setSaveMessage(t("연결 해제 중...", "Disconnecting..."));
      await refreshOnionStatus();
    } catch (error) {
      console.error("Failed to stop onion runtime", error);
      setSaveMessage(t("연결 해제 실패", "Disconnect failed"));
    }
  };

  const handleConnectionChoiceChange = (choice: ConnectionChoice) => {
    setConnectionChoiceDraft(choice);
    if (choice === "directP2P") {
      setOnionEnabledDraft(false);
      return;
    }
    if (choice === "selfOnion") {
      setOnionEnabledDraft(false);
      return;
    }
    if (choice === "torOnion") {
      setOnionNetworkDraft("tor");
      setOnionEnabledDraft(true);
      return;
    }
  };

  const formatBytes = (value: number) => {
    if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
    if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
    return `${value} B`;
  };

  const handleCopyAddress = async (value: string, label: string) => {
    if (!value) return;
    try {
      if (!navigator.clipboard) throw new Error("Clipboard not available");
      await navigator.clipboard.writeText(value);
      addToast({ message: t(`${label} 주소를 복사했습니다.`, `${label} address copied.`) });
    } catch (error) {
      console.error("Failed to copy address", error);
      addToast({ message: t("주소 복사에 실패했습니다.", "Failed to copy address.") });
    }
  };

  const refreshAppData = async () => {
    const profiles = await listProfiles();
    const user = profiles.find((profile) => profile.kind === "user") || null;
    const friends = profiles.filter((profile) => profile.kind === "friend");
    const conversations = await listConversations();
    const messagesBy: Record<string, Awaited<ReturnType<typeof listMessagesByConv>>> = {};
    for (const conv of conversations) {
      messagesBy[conv.id] = await listMessagesByConv(conv.id);
    }
    setData({ user, friends, convs: conversations, messagesByConv: messagesBy });
    if (userProfileState && user?.id !== userProfileState.id) {
      setSelectedConv(null);
    }
  };

  useEffect(() => {
    if (view !== "danger" || !pendingFocusRequested) return;
    const element = pendingSectionRef.current;
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      element.focus({ preventScroll: true });
    }
    setPendingFocusRequested(false);
  }, [pendingFocusRequested, view]);

  const renderBackHeader = (title: string) => (
    <SettingsBackHeader
      title={title}
      backLabel={t("뒤로", "Back")}
      onBack={() => setView("main")}
    />
  );

  const startEdit = () => {
    setDisplayNameDraft(displayName);
    setStatusDraft(status);
    setEditing(true);
  };

  const cancelEdit = () => {
    setDisplayNameDraft(displayName);
    setStatusDraft(status);
    setEditing(false);
  };

  const saveEdit = async () => {
    try {
      await onSaveProfile({
        displayName: displayNameDraft.trim() || displayName,
        status: statusDraft,
        theme,
      });
      setDisplayName(displayNameDraft.trim() || displayName);
      setStatus(statusDraft);
      setEditing(false);
      setSaveMessage(t("저장되었습니다.", "Saved."));
    } catch (e) {
      console.error("Failed to save profile", e);
      setSaveMessage(t("저장에 실패했습니다.", "Save failed."));
    }
  };

  const handleSetPin = async () => {
    setPinError("");
    if (!pinAvailable) {
      setPinError(t("PIN lock is unavailable on this platform/build.", "PIN lock is unavailable on this platform/build."));
      return;
    }
    const value = pinDraft.trim();
    if (value.length < 4) {
      setPinError(t("PIN은 최소 4자리 이상이어야 합니다.", "PIN must be at least 4 digits."));
      return;
    }
    const result = await onSetPin(value);
    if (!result.ok) {
      setPinError(result.error || t("PIN 설정에 실패했습니다.", "Failed to set PIN."));
      return;
    }
    setPinDraft("");
    setSaveMessage(t("PIN이 설정되었습니다.", "PIN set."));
  };

  const handleTogglePin = async (next: boolean) => {
    setPinError("");
    if (!pinAvailable) {
      setPinError(t("PIN lock is unavailable on this platform/build.", "PIN lock is unavailable on this platform/build."));
      return;
    }
    if (next) {
      // Show PIN entry UI immediately; persistence happens on "Set PIN".
      setPinEnabledUi(true);
      return;
    }
    try {
      await onDisablePin();
      setPinDraft("");
      setPinEnabledUi(false);
      setSaveMessage(t("PIN disabled.", "PIN disabled."));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setPinEnabledUi(true);
      setPinError(message || t("PIN 해제에 실패했습니다.", "Failed to disable PIN."));
    }
  };

  type DotState = "running" | "starting" | "stopped" | "error";

  const getDotState = (kind: OnionNetwork, status: OnionStatus | null): DotState => {
    const component = status?.components?.[kind];
    if (component?.error || component?.status === "failed") return "error";
    if (status?.runtime?.status === "running" && status.runtime.network === kind) return "running";
    if (
      (status?.runtime?.status === "starting" && status.runtime.network === kind) ||
      component?.status === "downloading" ||
      component?.status === "installing"
    ) {
      return "starting";
    }
    return "stopped";
  };

  const getDotClass = (state: DotState) => {
    if (state === "running") return "bg-emerald-300";
    if (state === "starting") return "bg-amber-300 animate-pulse";
    if (state === "error") return "bg-red-400";
    return "bg-nkc-muted";
  };

  const formatActiveRouteLabel = (snapshot: {
    connection: typeof connectionStatus;
    mode: typeof netConfig.mode;
    runtime?: OnionStatus["runtime"];
    internalRoute: typeof internalOnionRoute;
    torAddress?: string;
  }) => {
    const {
      connection,
      mode,
      runtime,
      internalRoute,
      torAddress,
    } = snapshot;

    if (mode === "selfOnion" || connection.transport === "selfOnion") {
      if (internalRoute.status === "ready") {
        return t(
          `경로: 내부 Onion (${internalRoute.establishedHops}/${internalRoute.desiredHops} hops)`,
          `Route: Built-in Onion (${internalRoute.establishedHops}/${internalRoute.desiredHops} hops)`
        );
      }
      if (internalRoute.status === "degraded") {
        return t("경로: 내부 Onion (불안정)", "Route: Built-in Onion (degraded)");
      }
      if (internalRoute.status === "building" || internalRoute.status === "rebuilding") {
        return t("경로: 내부 Onion (재구성중)", "Route: Built-in Onion (rebuilding)");
      }
      return t("경로: 내부 Onion (대기)", "Route: Built-in Onion (idle)");
    }

    if (connection.transport === "directP2P") {
      if (connection.state === "connected") {
        return t("경로: Direct P2P", "Route: Direct P2P");
      }
      if (connection.state === "connecting") {
        return t("경로: Direct P2P (연결 중)", "Route: Direct P2P (connecting)");
      }
      if (connection.state === "failed") {
        return t("경로: Direct P2P (실패)", "Route: Direct P2P (failed)");
      }
      if (connection.state === "degraded") {
        return t("경로: Direct P2P (불안정)", "Route: Direct P2P (degraded)");
      }
      return t("경로: Direct P2P (대기)", "Route: Direct P2P (idle)");
    }

    if (connection.transport === "onionRouter") {
      const network = runtime?.network;
      const status = runtime?.status;
      if (network === "tor") {
        if (status === "running" && torAddress) {
          return t("경로: Tor Hidden Service", "Route: Tor Hidden Service");
        }
        if (status === "running") {
          return t("경로: Tor (Onion)", "Route: Tor (Onion)");
        }
        if (status === "starting") {
          return t("경로: Tor (연결 중)", "Route: Tor (connecting)");
        }
        if (status === "failed") {
          return t("경로: Tor (실패)", "Route: Tor (failed)");
        }
        if (status === "idle") {
          return t("경로: Tor (대기)", "Route: Tor (idle)");
        }
        return t("경로: Tor", "Route: Tor");
      }
      if (status === "starting") {
        return t("경로: Onion (연결 중)", "Route: Onion (connecting)");
      }
      if (status === "failed") {
        return t("경로: Onion (실패)", "Route: Onion (failed)");
      }
      if (status === "running") {
        return t("경로: Onion (연결됨)", "Route: Onion (connected)");
      }
    }

    return t("경로: 대기", "Route: idle");
  };

  const draftMode: typeof netConfig.mode =
    connectionChoiceDraft === "directP2P"
      ? "directP2P"
      : connectionChoiceDraft === "selfOnion"
        ? "selfOnion"
        : "onionRouter";
  const routeInfo = getRouteInfo(netConfig.mode, netConfig, internalOnionRoute);
  const runtime = onionStatus?.runtime;
  const torAddress = userProfileState?.routingHints?.onionAddr ?? "";
  const activeRouteLabel = formatActiveRouteLabel({
    connection: connectionStatus,
    mode: netConfig.mode,
    runtime,
    internalRoute: internalOnionRoute,
    torAddress,
  });
  const runtimeStateLabel = runtime
    ? runtime.status === "running"
      ? t("상태: 실행 중", "Status: running")
      : runtime.status === "starting"
        ? t("상태: 시작 중", "Status: starting")
        : runtime.status === "failed"
          ? t("상태: 실패", "Status: failed")
          : t("상태: 대기", "Status: idle")
    : t("상태: 확인 필요", "Status: check required");
  const runtimeNetworkLabel = runtime?.network
    ? `${t("네트워크", "Network")}: ${runtime.network}`
    : `${t("네트워크", "Network")}: -`;
  const runtimeSocksLabel =
    runtime && runtime.status === "running" && runtime.network === "tor" && runtime.socksPort
      ? ` · SOCKS 127.0.0.1:${runtime.socksPort}`
      : "";
  const runtimeErrorDetail = runtime?.error ?? "";
  const runtimeErrorLabel = runtimeErrorDetail
    ? runtimeErrorDetail.includes("MACOS_TOR_BLOCKED")
      ? t(
          "macOS가 Tor 실행을 차단했습니다. 자동 서명 복구 후에도 실패하면 시스템 Tor를 설치해 주세요.",
          "macOS blocked Tor. If automatic signature repair still fails, install system Tor."
        )
      : t("Tor 연결을 시작하지 못했습니다.", "Tor could not be started.")
    : "";
  const runtimeStatusTooltip =
    runtime?.status === "running"
      ? t("Onion 상태: 실행 중", "Onion status: running")
      : runtime?.status === "failed"
        ? t("Onion 상태: 실패", "Onion status: failed")
        : t(
            "자동/대기 상태: 설정이 없거나 연결 경로를 자동으로 선택 중",
            "Auto/pending: no setting or auto-selecting route"
          );
  const runtimeStatusIcon =
    runtime?.status === "running" ? (
      <Check size={12} className="text-nkc-accent" />
    ) : runtime?.status === "failed" ? (
      <AlertTriangle size={12} className="text-red-300" />
    ) : (
      <Clock size={12} className="text-nkc-muted" />
    );

  const formatOnionError = (value?: string) => {
    if (!value) return null;
    if (value === "PINNED_HASH_MISSING")
      return t("실패: 검증 데이터 없음", "Failed: missing verification data");
    if (value === "ASSET_NOT_FOUND")
      return t("실패: 지원 자산 없음", "Failed: no compatible asset");
    const trimmed = value.split("| details=")[0].trim();
    const match = trimmed.match(/^\[([^\]]+)\]\s*(.*)$/);
    const code = match?.[1] ?? "";
    const message = match?.[2] ?? trimmed;
    const label =
      code === "DOWNLOAD_FAILED"
        ? t("다운로드 실패", "Download failed")
        : code === "HASH_MISMATCH"
          ? t("검증 실패", "Hash mismatch")
          : code === "EXTRACT_FAILED"
            ? t("압축 해제 실패", "Extraction failed")
            : code === "PERMISSION_DENIED"
              ? t("권한 부족", "Permission denied")
                : code === "BINARY_MISSING"
                  ? t("실행 파일 없음", "Binary missing")
                  : code === "ASSET_NOT_FOUND"
                    ? t("지원 자산 없음", "No compatible asset")
                  : code === "FS_ERROR"
                    ? t("파일 시스템 오류", "File system error")
                  : code === "PINNED_HASH_MISSING"
                    ? t("검증 데이터 없음", "Missing verification data")
                    : code === "UNKNOWN_ERROR"
                      ? t("알 수 없는 오류", "Unknown error")
                      : null;
    const shortMessage = label ? `${label}${message ? ` · ${message}` : ""}` : message;
    return `${t("실패", "Failed")}: ${shortMessage}`;
  };

  const selfOnionHopTarget = internalOnionRoute.desiredHops;
  const selfOnionHopConnected = Math.min(
    internalOnionRoute.establishedHops,
    internalOnionRoute.desiredHops
  );
  const selfOnionRouteLabel = getRouteStatusText(internalOnionRoute, language);
  const selfOnionHopProgressText = getHopsProgressText(internalOnionRoute);
  const selfOnionHopDetails = internalOnionRoute.hops;
  const selfOnionLastError = internalOnionRoute.lastError;

  const buildComponentLabel = (state: typeof netConfig.tor) => {
    if (state.status === "downloading") return t("다운로드 중", "Downloading");
    if (state.status === "installing") return t("설치 중", "Installing");
    if (state.status === "failed") return t("실패", "Failed");
    if (state.installed) return t("설치됨", "Installed");
    return t("미설치", "Not installed");
  };

  const isComponentReady = (state: typeof netConfig.tor) =>
    state.installed && (state.status === "ready" || state.status === "idle");

  const torUpdateAvailable = Boolean(
    netConfig.tor.latest && netConfig.tor.latest !== netConfig.tor.version
  );
  const torUpdateStatus = netConfig.lastUpdateCheckAtMs
    ? netConfig.tor.error === "PINNED_HASH_MISSING"
      ? t("검증 데이터 없음", "Missing verification data")
      : netConfig.tor.error === "ASSET_NOT_FOUND"
        ? t("지원 자산 없음", "No compatible asset")
      : torUpdateAvailable
        ? `${t("업데이트 가능", "Update available")}: ${netConfig.tor.latest}`
        : t("최신 상태", "Up to date")
    : "";
  const torErrorLabel = formatOnionError(netConfig.tor.error);

  const canSaveOnion =
    draftMode !== "onionRouter" ||
    !onionEnabledDraft ||
    netConfig.tor.installed;

  const connectionDescription =
    draftMode === "onionRouter"
      ? t(
          "외부 Onion: Tor 경로를 사용합니다.",
          "External Onion: uses a Tor route."
        )
      : draftMode === "directP2P"
        ? t(
            "Direct P2P: 프록시 없이 직접 연결을 시도합니다.",
            "Direct P2P: attempts a direct connection without a proxy."
          )
      : t("내부 Onion: 앱 내부 hop 경로를 사용합니다.", "Built-in Onion: uses in-app hops.");
  const showDirectWarning = draftMode === "directP2P";
  const proxyAuto = !proxyUrlDraft.trim();
  const prefsDisabled = !prefsLoaded;
  const backgroundDisabled = !appPrefs.background.enabled || appPrefs.login.closeToExit;
  const notificationsDisabled = !appPrefs.notifications.enabled;

  return (
    <>
      <Dialog.Root open={open} onOpenChange={onOpenChange}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 bg-black/60" />
          <Dialog.Content className="fixed left-1/2 top-1/2 h-[80vh] w-[92vw] max-w-2xl -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-nkc border border-nkc-border bg-nkc-panel p-8 shadow-soft">
          <Dialog.Title className="text-lg font-semibold text-nkc-text">
            {t("설정", "Settings")}
          </Dialog.Title>
          <Dialog.Description className="sr-only">
            {t("설정 대화상자", "Settings dialog")}
          </Dialog.Description>

          {/* MAIN */}
          {view === "main" && (
            <div className="mt-6 grid gap-6">
              <section className="rounded-nkc border border-nkc-border bg-nkc-panelMuted p-6">
                <div className="flex items-start gap-4">
                  <Avatar name={displayName} colorKey={user.id} avatarRef={user.avatarRef} size={64} />
                  <div className="min-w-0 flex-1">
                    {!editing ? (
                      <>
                        <div className="truncate text-sm font-semibold text-nkc-text">
                          {displayName}
                        </div>
                        <div className="mt-1 truncate text-xs text-nkc-muted">
                          {status ? status : t("상태 메시지가 없습니다.", "No status message.")}
                        </div>
                        <div className="mt-3 flex flex-wrap gap-2">
                          <button
                            type="button"
                            onClick={startEdit}
                            className="rounded-nkc border border-nkc-border px-3 py-2 text-xs text-nkc-text hover:bg-nkc-panel"
                          >
                            {t("편집", "Edit")}
                          </button>
                        </div>
                      </>
                    ) : (
                      <>
                        <label className="text-sm text-nkc-text">
                          {t("표시 이름", "Display name")}
                          <input
                            value={displayNameDraft}
                            onChange={(e) => setDisplayNameDraft(e.target.value)}
                            className="mt-2 w-full rounded-nkc border border-nkc-border bg-nkc-panel px-3 py-2 text-sm text-nkc-text"
                          />
                        </label>
                        <label className="mt-3 block text-sm text-nkc-text">
                          {t("상태 메시지", "Status message")}
                          <input
                            value={statusDraft}
                            onChange={(e) => setStatusDraft(e.target.value)}
                            className="mt-2 w-full rounded-nkc border border-nkc-border bg-nkc-panel px-3 py-2 text-sm text-nkc-text"
                          />
                        </label>

                        <div className="mt-3 flex flex-wrap gap-2">
                          <label className="cursor-pointer rounded-nkc border border-nkc-border px-3 py-2 text-xs text-nkc-text hover:bg-nkc-panel">
                            {t("사진 업로드", "Upload photo")}
                            <input
                              type="file"
                              accept="image/png,image/jpeg,image/gif,image/webp"
                              className="hidden"
                              onChange={async (e) => {
                                const file = e.target.files?.[0];
                                if (!file) return;
                                try {
                                  await onUploadPhoto(file);
                                  setSaveMessage(t("사진이 업로드되었습니다.", "Photo uploaded."));
                                } catch (err) {
                                  console.error("Upload failed", err);
                                  setSaveMessage(t("사진 업로드에 실패했습니다.", "Photo upload failed."));
                                } finally {
                                  e.currentTarget.value = "";
                                }
                              }}
                            />
                          </label>

                          <button
                            type="button"
                            onClick={saveEdit}
                            className="rounded-nkc bg-nkc-accent px-3 py-2 text-xs font-semibold text-nkc-accentText"
                          >
                            {t("저장", "Save")}
                          </button>
                          <button
                            type="button"
                            onClick={cancelEdit}
                            className="rounded-nkc border border-nkc-border px-3 py-2 text-xs text-nkc-text hover:bg-nkc-panel"
                          >
                            {t("취소", "Cancel")}
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </section>

              <section className="rounded-nkc border border-nkc-border bg-nkc-panelMuted">
                <div className="flex flex-col">
                  {SETTINGS_ROUTES.map((route, idx, list) => (
                      <button
                        key={route.key}
                        type="button"
                        onClick={() => setView(route.view)}
                        data-testid={route.testId}
                        className={`flex w-full items-center gap-[0.7rem] px-4 py-3 text-left text-sm text-nkc-text hover:bg-nkc-panel ${
                          idx === list.length - 1 ? "" : "border-b border-nkc-border"
                        }`}
                      >
                        {(() => {
                          const RouteIcon = routeIconByView[route.view as keyof typeof routeIconByView];
                          return RouteIcon ? (
                            <RouteIcon size={16} className="text-nkc-muted" />
                          ) : null;
                        })()}
                        {tl(route.label)}
                      </button>
                    ))}
                </div>
              </section>

              <div className="h-3" />

              <section className="rounded-nkc border border-nkc-border bg-nkc-panelMuted">
                <div className="flex flex-col">
                  <div className="px-4 pb-1 pt-3 text-xs font-semibold text-nkc-muted">
                    {t("복구 / 위험", "Recovery / Danger")}
                  </div>

                  <button
                    type="button"
                    onClick={() => setView("privacyKeys")}
                    className="flex w-full items-center gap-[0.7rem] border-b border-nkc-border px-4 py-3 text-left text-sm text-nkc-text hover:bg-nkc-panel"
                  >
                    <Key size={16} className="text-nkc-muted" />
                    {t("시작키 설정", "Start key")}
                  </button>

                  <button
                    type="button"
                    onClick={() => setView("danger")}
                    className="flex w-full items-center gap-[0.7rem] px-4 py-3 text-left text-sm text-nkc-text hover:bg-red-500/20"
                  >
                    <AlertTriangle size={16} className="text-red-500" />
                    <span className="text-red-500 font-semibold">
                      {t("위험 구역", "Danger zone")}
                    </span>
                  </button>
                </div>
              </section>


              <div className="flex justify-end gap-2">
                <Dialog.Close asChild>
                  <button className="rounded-nkc border border-nkc-border px-4 py-2 text-sm text-nkc-text hover:bg-nkc-panelMuted">
                    {t("닫기", "Close")}
                  </button>
                </Dialog.Close>
              </div>

              {saveMessage ? (
                <div className="text-right text-xs text-nkc-muted">{saveMessage}</div>
              ) : null}
            </div>
          )}

          {/* NOTIFICATIONS */}
          {view === "notifications" && (
            <NotificationsSettings
              t={t}
              onBack={() => setView("main")}
              appPrefs={appPrefs}
              prefsDisabled={prefsDisabled}
              notificationsDisabled={notificationsDisabled}
              onUpdateAppPrefs={updateAppPrefs}
            />
          )}

          {/* LOGIN */}
          {view === "login" && (
            <LoginSettings
              t={t}
              onBack={() => setView("main")}
              appPrefs={appPrefs}
              prefsDisabled={prefsDisabled}
              backgroundDisabled={backgroundDisabled}
              onUpdateAppPrefs={updateAppPrefs}
              onManualSync={() =>
                void syncNow().catch((e) => console.error("Manual sync failed", e))
              }
            />
          )}

          {/* THEME */}
          {view === "theme" && (
            <div className="mt-6 grid gap-6">
              {renderBackHeader(t("테마", "Theme"))}
              <section className="rounded-nkc border border-nkc-border bg-nkc-panelMuted p-6">
                <div className="flex flex-wrap gap-3">
                  {themeOptions.map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => setTheme(opt.value)}
                      data-testid={`theme-option-${opt.value}`}
                      className={`rounded-nkc border px-4 py-2 text-xs ${
                        theme === opt.value
                          ? "border-nkc-accent bg-nkc-panel text-nkc-text"
                          : "border-nkc-border text-nkc-muted hover:bg-nkc-panel"
                      }`}
                    >
                      {tl(opt.label)}
                    </button>
                  ))}
                </div>
                <div className="mt-4 text-xs font-semibold text-nkc-text">
                  {t("언어", "Language")}
                </div>
                <div className="mt-2 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => setLanguage("ko")}
                    className={`rounded-nkc border px-3 py-2 text-xs ${
                      language === "ko"
                        ? "border-nkc-accent bg-nkc-panel text-nkc-text"
                        : "border-nkc-border text-nkc-muted hover:bg-nkc-panel"
                    }`}
                  >
                    {t("한국어", "Korean")}
                  </button>
                  <button
                    type="button"
                    onClick={() => setLanguage("en")}
                    className={`rounded-nkc border px-3 py-2 text-xs ${
                      language === "en"
                        ? "border-nkc-accent bg-nkc-panel text-nkc-text"
                        : "border-nkc-border text-nkc-muted hover:bg-nkc-panel"
                    }`}
                  >
                    English
                  </button>
                </div>
              </section>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  data-testid="theme-save-button"
                  onClick={async () => {
                    await onSaveProfile({ displayName, status, theme });
                    setSaveMessage(t("저장되었습니다.", "Saved."));
                    setView("main");
                  }}
                  className="rounded-nkc bg-nkc-accent px-4 py-2 text-sm font-semibold text-nkc-accentText"
                >
                  {t("저장", "Save")}
                </button>
              </div>

              {saveMessage ? (
                <div className="text-right text-xs text-nkc-muted">{saveMessage}</div>
              ) : null}
            </div>
          )}

          {/* NETWORK */}
          {view === "network" && (
            <NetworkSettings
              t={t}
              onBack={() => setView("main")}
              connectionChoice={connectionChoiceDraft}
              onConnectionChoiceChange={handleConnectionChoiceChange}
              draftMode={draftMode}
              onionStatus={onionStatus}
              getDotState={getDotState}
              getDotClass={getDotClass}
              buildComponentLabel={buildComponentLabel}
              netConfig={netConfig}
              runtimeStatusTooltip={runtimeStatusTooltip}
              runtimeStatusIcon={runtimeStatusIcon}
              activeRouteLabel={activeRouteLabel}
              runtimeSocksLabel={runtimeSocksLabel}
              runtimeStateLabel={runtimeStateLabel}
              runtimeNetworkLabel={runtimeNetworkLabel}
              runtimeErrorLabel={runtimeErrorLabel}
              runtimeErrorDetail={runtimeErrorDetail}
              torUpdateStatus={torUpdateStatus}
              torErrorLabel={torErrorLabel}
              torInstallBusy={torInstallBusy}
              torStatusBusy={torStatusBusy}
              torCheckBusy={torCheckBusy}
              torApplyBusy={torApplyBusy}
              torUninstallBusy={torUninstallBusy}
              torUpdateAvailable={torUpdateAvailable}
              isComponentReady={isComponentReady}
              onInstall={handleInstall}
              onTorStatus={handleTorStatus}
              onConnectOnion={handleConnectOnion}
              onDisconnectOnion={handleDisconnectOnion}
              onCheckUpdates={handleCheckUpdates}
              onApplyUpdate={handleApplyUpdate}
              onUninstall={handleUninstall}
              routeInfo={routeInfo}
              connectionDescription={connectionDescription}
              selfOnionHopConnected={selfOnionHopConnected}
              selfOnionHopTarget={selfOnionHopTarget}
              selfOnionHopProgressText={selfOnionHopProgressText}
              selfOnionRouteLabel={selfOnionRouteLabel}
              selfOnionHopDetails={selfOnionHopDetails}
              selfOnionLastError={selfOnionLastError}
              onSelfOnionHopChange={setSelfOnionMinRelays}
              showDirectWarning={showDirectWarning}
              torAddress={torAddress}
              onCopyAddress={handleCopyAddress}
              onionEnabledDraft={onionEnabledDraft}
              setOnionEnabledDraft={setOnionEnabledDraft}
              torAutoPrepareOnAppStart={torAutoPrepareDraft}
              setTorAutoPrepareOnAppStart={setTorAutoPrepareDraft}
              proxyAuto={proxyAuto}
              proxyUrlDraft={proxyUrlDraft}
              proxyUrlError={proxyUrlError}
              onProxyUrlChange={handleProxyUrlChange}
              canSaveOnion={canSaveOnion}
              onSaveOnion={handleSaveOnion}
              saveMessage={saveMessage}
            />
          )}
          {/* DEVICES */}
          {view === "devices" && (
            <DevicesSettings
              t={t}
              onBack={() => setView("main")}
              onGenerateSyncCode={deviceSyncSettings.handleGenerateSyncCode}
              onCopySyncCode={deviceSyncSettings.handleCopySyncCode}
              syncCodeState={deviceSyncSettings.syncCodeState}
              syncCodeExpired={deviceSyncSettings.syncCodeExpired}
              syncCodeRemainingMs={deviceSyncSettings.syncCodeRemainingMs}
              formatCountdown={deviceSyncSettings.formatCountdown}
              pairingRequest={deviceSyncSettings.pairingRequest}
              formatTimestamp={deviceSyncSettings.formatTimestamp}
              pairingRequestBusy={deviceSyncSettings.pairingRequestBusy}
              pairingRequestError={deviceSyncSettings.pairingRequestError}
              onApproveRequest={deviceSyncSettings.handleApproveRequest}
              onRejectRequest={deviceSyncSettings.handleRejectRequest}
              deviceSyncTransportPolicy={appPrefs.deviceSync.transportPolicy}
              onChangeDeviceSyncTransportPolicy={deviceSyncSettings.handleDeviceSyncPolicyChange}
              linkCodeDraft={deviceSyncSettings.linkCodeDraft}
              setLinkCodeDraft={deviceSyncSettings.setLinkCodeDraft}
              linkStatus={deviceSyncSettings.linkStatus}
              setLinkStatus={deviceSyncSettings.setLinkStatus}
              setLinkMessage={deviceSyncSettings.setLinkMessage}
              linkBusy={deviceSyncSettings.linkBusy}
              linkStatusClass={deviceSyncSettings.linkStatusClass}
              linkMessage={deviceSyncSettings.linkMessage}
              onSubmitLink={deviceSyncSettings.handleSubmitLink}
              rendezvousBaseUrlDraft={deviceSyncSettings.rendezvousBaseUrlDraft}
              onRendezvousBaseUrlChange={deviceSyncSettings.handleRendezvousBaseUrlChange}
              onRendezvousBaseUrlBlur={deviceSyncSettings.handleRendezvousBaseUrlBlur}
              rendezvousUseOnionProxy={deviceSyncSettings.rendezvousUseOnionProxy}
              onRendezvousUseOnionChange={deviceSyncSettings.handleRendezvousUseOnionChange}
              hostRendezvousStatus={deviceSyncSettings.hostRendezvousStatus}
              guestRendezvousStatus={deviceSyncSettings.guestRendezvousStatus}
            />
          )}
          {/* PRIVACY */}
          {view === "privacy" && (
            <PrivacySettings
              t={t}
              onBack={() => setView("main")}
              onOpenKeys={() => setView("privacyKeys")}
              onLock={onLock}
              pinEnabled={pinEnabledUi}
              pinAvailable={pinAvailable}
              pinDraft={pinDraft}
              setPinDraft={setPinDraft}
              pinError={pinError}
              onTogglePin={handleTogglePin}
              onSetPin={handleSetPin}
              privacyPrefs={privacyPrefs}
              onUpdatePrivacy={updatePrivacy}
            />
          )}
          {/* PRIVACY KEYS */}
          {view === "privacyKeys" && (
            <div className="mt-6 grid gap-6">
              <SettingsBackHeader
                title={t("키 / 복구", "Keys / Recovery")}
                backLabel={t("뒤로", "Back")}
                onBack={() => setView("privacy")}
              />
              <StartKey onRotate={onRotateStartKey} onDone={() => setView("privacy")} />
            </div>
          )}

          {/* FRIENDS */}
          {view === "friends" && (
            <FriendsSettings
              t={t}
              onBack={() => setView("main")}
              hiddenFriends={hiddenFriends}
              blockedFriends={blockedFriends}
              onUnhideFriend={onUnhideFriend}
              onUnblockFriend={onUnblockFriend}
            />
          )}
          {/* DANGER */}
          {view === "danger" && (
            <div className="mt-6 grid gap-6">
              {renderBackHeader(t("위험 구역", "Danger zone"))}
              <section className="rounded-nkc border border-red-500/50 bg-red-500/20 p-6">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h3 className="text-sm font-semibold text-black">
                      {t("위험 구역", "Danger zone")}
                    </h3>
                    <p className="mt-1 text-xs text-black/80">
                      {t("로그아웃 또는 데이터 삭제를 진행합니다.", "Proceed with logout or data reset.")}
                    </p>
                    <div className="mt-3 space-y-1 text-xs text-black/80">
                      <div>
                        {t(
                          "기존 기기가 온라인일 때만 동기화/기기 추가가 가능합니다.",
                          "Syncing and adding devices only works while an existing device is online."
                        )}
                      </div>
                      <div>
                        {t(
                          "기존 기기를 분실/파손하면 이 계정은 복구할 수 없고 새 계정을 만들어야 합니다.",
                          "If the existing device is lost or broken, this account cannot be recovered and you must create a new account."
                        )}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={onLogout}
                    className="rounded-nkc border border-red-400/60 px-3 py-2 text-xs text-black hover:bg-red-500/20"
                  >
                    {t("로그아웃", "Logout")}
                  </button>
                  <button
                    type="button"
                    onClick={onWipe}
                    className="rounded-nkc border border-red-300 bg-red-500/30 px-3 py-2 text-xs font-semibold text-black hover:bg-red-500/40"
                  >
                    {t("데이터 삭제", "Delete data")}
                  </button>
                </div>
              </section>
              <section
                ref={pendingSectionRef}
                tabIndex={-1}
                className="rounded-nkc border border-red-500/50 bg-red-500/10 p-6 outline-none focus-visible:ring-2 focus-visible:ring-red-400/70"
              >
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h3 className="text-sm font-semibold text-black">
                      {t("전송 대기 메시지 (고급)", "Pending messages (advanced)")}
                    </h3>
                    <p className="mt-1 text-xs text-black/80">
                      {t(
                        "아직 상대방에게 전달되지 않았을 수 있는 암호화 메시지입니다.",
                        "These may be encrypted messages not yet delivered to the other party."
                      )}
                    </p>
                    <div className="mt-3 space-y-1 text-xs text-black/80">
                      <div>
                        {t("삭제하면 영구적으로 손실됩니다.", "Deletion is permanent.")}
                      </div>
                      <div>
                        {t("다른 기기에는 영향을 주지 않습니다.", "Other devices are not affected.")}
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-[11px] uppercase tracking-wide text-black/70">
                      {t("현재 크기", "Current size")}
                    </div>
                    <div className="text-sm font-semibold text-black">
                      {formatBytes(storageUsage.pendingBytes)}
                    </div>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      if (pendingWipeBusy) return;
                      setWipeConfirmType("pending");
                      setWipeConfirmOpen(true);
                    }}
                    disabled={pendingWipeBusy}
                    className="rounded-nkc border border-red-300 bg-red-500/30 px-3 py-2 text-xs font-semibold text-black hover:bg-red-500/40 disabled:opacity-50"
                  >
                    {pendingWipeBusy
                      ? t("처리 중...", "Working...")
                      : t("전송 대기 메시지 삭제", "Delete pending messages")}
                  </button>
                </div>
              </section>
            </div>
          )}

          {/* STORAGE */}
          {view === "storage" && (
            <StorageSettings
              t={t}
              onBack={() => setView("main")}
              storageUsage={storageUsage}
              formatBytes={formatBytes}
              chatWipeBusy={chatWipeBusy}
              mediaWipeBusy={mediaWipeBusy}
              onRequestWipeChat={() => {
                if (chatWipeBusy) return;
                setWipeConfirmType("chat");
                setWipeConfirmOpen(true);
              }}
              onRequestWipeMedia={() => {
                if (mediaWipeBusy) return;
                setWipeConfirmType("media");
                setWipeConfirmOpen(true);
              }}
              onNavigateToPending={() => {
                setView("danger");
                setPendingFocusRequested(true);
              }}
            />
          )}
          {/* APP UPDATES */}
          {view === "updates" && (
            <AppUpdateSettings t={t} onBack={() => setView("main")} />
          )}
          {/* HELP */}
          {view === "help" && (
            <div className="mt-6 grid gap-6">
              {renderBackHeader(t("도움말", "Help"))}
              <section className="rounded-nkc border border-nkc-border bg-nkc-panelMuted p-6">
                <div className="text-sm text-nkc-text">
                  {t("준비중입니다.", "Coming soon.")}
                </div>
                <div className="mt-2 text-xs text-nkc-muted">
                  {t(
                    "도움말 콘텐츠는 추후 업데이트될 예정입니다.",
                    "Help content will be updated later."
                  )}
                </div>
              </section>
            </div>
          )}

          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
      <ConfirmDialog
        open={wipeConfirmOpen}
        title={
          wipeConfirmType === "pending"
            ? t("전송 대기 메시지 삭제 경고", "Pending deletion warning")
            : wipeConfirmType === "media"
              ? t("미디어 삭제 경고", "Media deletion warning")
              : t("채팅 삭제 경고", "Chat deletion warning")
        }
        message={
          wipeConfirmType === "pending"
            ? t(
                "전송 대기 메시지를 삭제합니다. 아직 상대방에게 전달되지 않았을 수 있는 암호화 메시지입니다. 삭제하면 영구적으로 손실됩니다. 다른 기기에는 영향을 주지 않습니다. 계속할까요?",
                "This deletes pending messages. They may be encrypted messages not yet delivered to the other party. Deletion is permanent. Other devices are not affected. Continue?"
              )
            : wipeConfirmType === "media"
              ? t(
                  "모든 미디어(첨부파일/아바타)를 초기화합니다. 복구할 수 없으며, 잔여 데이터 복구를 어렵게 하기 위해 암호화로 덮어쓴 뒤 제거합니다. 계속할까요?",
                  "This deletes all media (attachments/avatars). It cannot be undone; remaining data is overwritten with encryption before removal. Continue?"
                )
              : t(
                  "채팅 내역을 초기화합니다. 복구할 수 없으며, 잔여 데이터 복구를 어렵게 하기 위해 암호화로 덮어쓴 뒤 제거합니다. 계속할까요?",
                  "This resets chat history. It cannot be undone; remaining data is overwritten with encryption before removal. Continue?"
                )
        }
        onClose={() => {
          setWipeConfirmOpen(false);
          setWipeConfirmType(null);
        }}
        onConfirm={async () => {
          if (!wipeConfirmType) return;

          if (wipeConfirmType === "pending") {
            if (pendingWipeBusy) return;
            setPendingWipeBusy(true);
            try {
              await clearOutboxQueue();
              await refreshStorageUsage();
              setSaveMessage(t("전송 대기 메시지를 삭제했습니다.", "Pending messages deleted."));
            } catch (error) {
              console.error("Failed to clear pending outbox", error);
              setSaveMessage(t("전송 대기 메시지 삭제에 실패했습니다.", "Pending delete failed."));
            } finally {
              setPendingWipeBusy(false);
            }
            return;
          }

          if (wipeConfirmType === "chat") {
            if (chatWipeBusy) return;
            setChatWipeBusy(true);
            try {
              await clearChatHistory();
              await refreshAppData();
              await refreshStorageUsage();
              setSaveMessage(t("채팅 내역이 초기화되었습니다.", "Chat history reset."));
            } catch (error) {
              console.error("Failed to clear chat history", error);
              setSaveMessage(t("채팅 내역 초기화 실패", "Chat reset failed"));
            } finally {
              setChatWipeBusy(false);
            }
            return;
          }

          if (mediaWipeBusy) return;
          setMediaWipeBusy(true);
          try {
            await deleteAllMedia();
            await refreshAppData();
            await refreshStorageUsage();
            setSaveMessage(t("미디어가 초기화되었습니다.", "Media reset."));
          } catch (error) {
            console.error("Failed to delete media", error);
            setSaveMessage(t("미디어 초기화 실패", "Media reset failed"));
          } finally {
            setMediaWipeBusy(false);
          }
        }}
      />
      </>
    );
  }
