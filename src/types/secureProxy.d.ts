export {};

type P2PConnectionStatusPayload = {
  convId: string;
  state: "idle" | "connecting" | "connected" | "reconnecting" | "closed";
  detail?: string;
  changedAt?: number;
};

type P2PChatMessagePayload = {
  id: string;
  convId: string;
  ts: number;
  createdAt?: number;
  senderId: string;
  text: string;
  status?: "PENDING" | "SENT" | "FAILED";
  clientBatchId?: string;
  kind?: string;
};

type P2PChatMessageEventPayload =
  | {
      type: "MESSAGE_RECEIVED" | "MESSAGE_ACK";
      message: P2PChatMessagePayload;
    }
  | {
      type: "MESSAGE_FAILED";
      messageId: string;
      error?: string;
    };

declare global {
  interface Window {
    electron?: {
      secureStorage: {
        isAvailable: () => Promise<boolean>;
        get: (key: string) => Promise<string | null>;
        set: (key: string, value: string) => Promise<boolean>;
        remove: (key: string) => Promise<boolean>;
      };
      p2p?: {
        getMessages?: (conversationId: string) => Promise<P2PChatMessagePayload[]>;
        sendMessage?: (payload: {
          conversationId: string;
          message: P2PChatMessagePayload;
        }) => Promise<P2PChatMessagePayload | void>;
        onMessageEvent?: (
          conversationId: string,
          cb: (payload: P2PChatMessageEventPayload) => void
        ) => () => void;
      };
    };
    secureProxy?: {
      applyProxy: (payload: {
        proxyUrl: string;
        enabled: boolean;
        allowRemote: boolean;
      }) => Promise<void>;
      checkProxy: () => Promise<{ ok: boolean; message: string }>;
    };
    onion?: {
      install: (payload: { network: "tor" }) => Promise<void>;
      uninstall: (payload: { network: "tor" }) => Promise<void>;
      setMode: (payload: { enabled: boolean; network: "tor" }) => Promise<void>;
      status: () => Promise<unknown>;
      checkUpdates: () => Promise<unknown>;
      applyUpdate: (payload: { network: "tor" }) => Promise<void>;
      onProgress: (cb: (payload: unknown) => void) => () => void;
    };
    nkc?: {
      getOnionControllerUrl?: () => Promise<string>;
      registerOnionMailbox?: (deviceId: string) => Promise<{
        ok: boolean;
        inboxWriteToken?: string;
        error?: string;
      }>;
      [key: string]: unknown;
    };
    prefs?: {
      get: () => Promise<unknown>;
      set: (patch: unknown) => Promise<unknown>;
    };
    appControls?: {
      show: () => Promise<void>;
      hide: () => Promise<void>;
      quit: () => Promise<void>;
      syncNow: () => Promise<void>;
      reportSyncResult: (payload: {
        requestId: string;
        ok: boolean;
        error?: string;
      }) => void;
      onSyncRun: (
        cb: (payload: { requestId: string; reason: "manual" | "interval" }) => void
      ) => () => void;
      onSyncStatus: (cb: (payload: unknown) => void) => () => void;
      onBackgroundStatus: (cb: (payload: unknown) => void) => () => void;
    };
    p2p?: {
      onConnectionStatus: (
        cb: (payload: P2PConnectionStatusPayload) => void
      ) => () => void;
      getMessages?: (conversationId: string) => Promise<P2PChatMessagePayload[]>;
      sendMessage?: (payload: {
        conversationId: string;
        message: P2PChatMessagePayload;
      }) => Promise<P2PChatMessagePayload | void>;
      onMessageEvent?: (
        conversationId: string,
        cb: (payload: P2PChatMessageEventPayload) => void
      ) => () => void;
    };
    nativeWorker?: {
      inspectFile: (
        file: File,
        chunkSize: number
      ) => Promise<{
        ok: boolean;
        error?: string;
        result?: { size: number; chunkSize: number; total: number; sha256: string };
      }>;
      readFileChunk: (
        file: File,
        index: number,
        chunkSize: number
      ) => Promise<{
        ok: boolean;
        error?: string;
        result?: { index: number; bytes: number; data: Uint8Array };
      }>;
      receiveInit: (payload: {
        transferId: string; fileName: string; fileSize: number; chunkSize: number;
        totalChunks: number; sha256: string;
      }) => Promise<{ ok: boolean; error?: string; result?: { receivedChunks: number; totalChunks: number; complete: boolean } }>;
      receiveWrite: (payload: { transferId: string; index: number; data: string | Uint8Array }) => Promise<{ ok: boolean; error?: string; result?: { duplicate: boolean; checkpointed: boolean } }>;
      receiveCheckpoint: (transferId: string) => Promise<{ ok: boolean; error?: string; result?: unknown }>;
      receiveFinalize: (transferId: string) => Promise<{ ok: boolean; error?: string; result?: { path: string; sha256: string } }>;
      receiveAbort: (transferId: string) => Promise<{ ok: boolean; error?: string; result?: unknown }>;
      planDelivery: (payload: unknown) => Promise<{
        ok: boolean;
        error?: string;
        result?: {
          selected: Array<{ id: string; attempts: number; nextAttemptAtMs: number }>;
        };
      }>;
    };
    testLog?: {
      append: (payload: { channel: string; event: unknown; at?: string }) => Promise<{
        ok: boolean;
        path: string;
      }>;
      getPath: () => Promise<string>;
      getFriendFlowPath: () => Promise<string>;
    };
  }
}
