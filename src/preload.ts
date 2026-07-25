import { contextBridge, ipcRenderer, webUtils, type IpcRendererEvent } from "electron";

type ProxyHealth = {
  ok: boolean;
  message: string;
};

const P2P_CONNECTION_STATUS_CHANNEL = "p2p:connection-status";

contextBridge.exposeInMainWorld("electron", {
  secureStorage: {
    isAvailable: () => ipcRenderer.invoke("secretStore:isAvailable") as Promise<boolean>,
    get: (key: string) => ipcRenderer.invoke("secretStore:get", key) as Promise<string | null>,
    set: (key: string, value: string) =>
      ipcRenderer.invoke("secretStore:set", key, value) as Promise<boolean>,
    remove: (key: string) => ipcRenderer.invoke("secretStore:remove", key) as Promise<boolean>,
  },
});

contextBridge.exposeInMainWorld("secureProxy", {
  applyProxy: (payload: { proxyUrl: string; enabled: boolean; allowRemote: boolean }) =>
    ipcRenderer.invoke("proxy:apply", payload) as Promise<void>,
  checkProxy: () => ipcRenderer.invoke("proxy:check") as Promise<ProxyHealth>,
});

contextBridge.exposeInMainWorld("onion", {
  install: (payload: { network: "tor" }) =>
    ipcRenderer.invoke("onion:install", payload) as Promise<void>,
  uninstall: (payload: { network: "tor" }) =>
    ipcRenderer.invoke("onion:uninstall", payload) as Promise<void>,
  setMode: (payload: { enabled: boolean; network: "tor" }) =>
    ipcRenderer.invoke("onion:setMode", payload) as Promise<void>,
  status: () => ipcRenderer.invoke("onion:status") as Promise<unknown>,
  checkUpdates: () => ipcRenderer.invoke("onion:checkUpdates") as Promise<unknown>,
  applyUpdate: (payload: { network: "tor" }) =>
    ipcRenderer.invoke("onion:applyUpdate", payload) as Promise<void>,
  onProgress: (cb: (payload: unknown) => void) => {
    const handler = (_event: IpcRendererEvent, payload: unknown) => cb(payload);
    ipcRenderer.on("onion:progress", handler);
    return () => ipcRenderer.removeListener("onion:progress", handler);
  },
});

contextBridge.exposeInMainWorld("nkc", {
  onionFetch: (req: {
    url: string;
    method: string;
    headers?: Record<string, string>;
    bodyBase64?: string;
    timeoutMs?: number;
  }) => ipcRenderer.invoke("nkc:onionFetch", req) as Promise<unknown>,
  authorizeOnionFetchOrigin: (url: string) =>
    ipcRenderer.invoke("nkc:authorizeOnionFetchOrigin", url) as Promise<{
      ok: boolean;
      origin?: string;
      error?: string;
    }>,
  setOnionProxy: (proxyUrl: string | null) =>
    ipcRenderer.invoke("nkc:setOnionProxy", proxyUrl) as Promise<unknown>,
  getOnionControllerUrl: () =>
    ipcRenderer.invoke("nkc:getOnionControllerUrl") as Promise<string>,
  setOnionForwardProxy: (proxyUrl: string | null) =>
    ipcRenderer.invoke("nkc:setOnionForwardProxy", proxyUrl) as Promise<{ ok: boolean }>,
  onionControllerFetch: (req: {
    url: string;
    method: string;
    headers?: Record<string, string>;
    bodyBase64?: string;
    timeoutMs?: number;
  }) => ipcRenderer.invoke("nkc:onionControllerFetch", req) as Promise<unknown>,
  prewarmOnionRoute: (payload: { onionAddress: string }) =>
    ipcRenderer.invoke("nkc:prewarmOnionRoute", payload) as Promise<{
      ok: boolean;
      elapsedMs: number;
      error?: string;
    }>,
  getTorStatus: () => ipcRenderer.invoke("nkc:getTorStatus") as Promise<unknown>,
  startTor: (payload?: { profileScopedDataDir?: boolean }) =>
    ipcRenderer.invoke("nkc:startTor", payload) as Promise<unknown>,
  stopTor: () => ipcRenderer.invoke("nkc:stopTor") as Promise<unknown>,
  checkSocksProxyReachable: (payload: { socksUrl: string; timeoutMs?: number }) =>
    ipcRenderer.invoke("nkc:checkSocksProxyReachable", payload) as Promise<boolean>,
  ensureHiddenService: () => ipcRenderer.invoke("nkc:ensureHiddenService") as Promise<unknown>,
  getMyOnionAddress: () => ipcRenderer.invoke("nkc:getMyOnionAddress") as Promise<string>,
});

contextBridge.exposeInMainWorld("prefs", {
  get: () => ipcRenderer.invoke("prefs:get") as Promise<unknown>,
  set: (patch: unknown) => ipcRenderer.invoke("prefs:set", patch) as Promise<unknown>,
});

contextBridge.exposeInMainWorld("appControls", {
  show: () => ipcRenderer.invoke("app:show") as Promise<void>,
  hide: () => ipcRenderer.invoke("app:hide") as Promise<void>,
  quit: () => ipcRenderer.invoke("app:quit") as Promise<void>,
  syncNow: () => ipcRenderer.invoke("sync:manual") as Promise<void>,
  reportSyncResult: (payload: { requestId: string; ok: boolean; error?: string }) => {
    ipcRenderer.send("sync:result", payload);
  },
  onSyncRun: (cb: (payload: unknown) => void) => {
    const handler = (_event: IpcRendererEvent, payload: unknown) => cb(payload);
    ipcRenderer.on("sync:run", handler);
    return () => ipcRenderer.removeListener("sync:run", handler);
  },
  onSyncStatus: (cb: (payload: unknown) => void) => {
    const handler = (_event: IpcRendererEvent, payload: unknown) => cb(payload);
    ipcRenderer.on("sync:status", handler);
    return () => ipcRenderer.removeListener("sync:status", handler);
  },
  onBackgroundStatus: (cb: (payload: unknown) => void) => {
    const handler = (_event: IpcRendererEvent, payload: unknown) => cb(payload);
    ipcRenderer.on("background:status", handler);
    return () => ipcRenderer.removeListener("background:status", handler);
  },
});

contextBridge.exposeInMainWorld("appUpdate", {
  getStatus: () => ipcRenderer.invoke("appUpdate:getStatus") as Promise<unknown>,
  check: () => ipcRenderer.invoke("appUpdate:check") as Promise<unknown>,
  download: () => ipcRenderer.invoke("appUpdate:download") as Promise<unknown>,
  install: () => ipcRenderer.invoke("appUpdate:install") as Promise<void>,
  onStatus: (cb: (payload: unknown) => void) => {
    const handler = (_event: IpcRendererEvent, payload: unknown) => cb(payload);
    ipcRenderer.on("appUpdate:status", handler);
    return () => ipcRenderer.removeListener("appUpdate:status", handler);
  },
});

contextBridge.exposeInMainWorld("p2p", {
  onConnectionStatus: (cb: (payload: unknown) => void) => {
    const handler = (_event: IpcRendererEvent, payload: unknown) => cb(payload);
    ipcRenderer.on(P2P_CONNECTION_STATUS_CHANNEL, handler);
    return () => ipcRenderer.removeListener(P2P_CONNECTION_STATUS_CHANNEL, handler);
  },
});

const preloadToken = ipcRenderer.sendSync("security:get-preload-token") as string | null;

contextBridge.exposeInMainWorld("nativeWorker", {
  inspectFile: (file: File, chunkSize: number) => {
    const filePath = webUtils.getPathForFile(file);
    if (!filePath) return Promise.resolve({ ok: false, error: "file-path-unavailable" });
    return ipcRenderer.invoke("nativeWorker:fileInspect", { path: filePath, chunkSize, token: preloadToken });
  },
  readFileChunk: (file: File, index: number, chunkSize: number) => {
    const filePath = webUtils.getPathForFile(file);
    if (!filePath) return Promise.resolve({ ok: false, error: "file-path-unavailable" });
    return ipcRenderer.invoke("nativeWorker:fileChunk", { path: filePath, index, chunkSize, token: preloadToken });
  },
  receiveInit: (payload: unknown) => ipcRenderer.invoke("nativeWorker:receiveInit", { ...(payload as object), token: preloadToken }),
  receiveWrite: (payload: unknown) => ipcRenderer.invoke("nativeWorker:receiveWrite", { ...(payload as object), token: preloadToken }),
  receiveCheckpoint: (transferId: string) => ipcRenderer.invoke("nativeWorker:receive:checkpoint", { transferId, token: preloadToken }),
  receiveFinalize: (transferId: string) => ipcRenderer.invoke("nativeWorker:receive:finalize", { transferId, token: preloadToken }),
  receiveAbort: (transferId: string) => ipcRenderer.invoke("nativeWorker:receive:abort", { transferId, token: preloadToken }),
  planDelivery: (payload: unknown) => ipcRenderer.invoke("nativeWorker:schedule", payload),
});

contextBridge.exposeInMainWorld("testLog", {
  append: (payload: { channel: string; event: unknown; at?: string }) =>
    ipcRenderer.invoke("testLog:append", payload) as Promise<{ ok: boolean; path: string }>,
  getPath: () => ipcRenderer.invoke("testLog:path") as Promise<string>,
  getFriendFlowPath: () => ipcRenderer.invoke("testLog:friendFlowPath") as Promise<string>,
});
