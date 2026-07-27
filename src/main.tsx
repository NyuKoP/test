import { createRoot } from "react-dom/client";
import { BrowserRouter, HashRouter } from "./appRouter";
import "./index.css";
import App from "./app/App";
import { bindP2PConnectionStatusBridge } from "./store/useP2PStore";

const isE2E = Boolean((import.meta as { env?: { VITE_E2E?: string } }).env?.VITE_E2E);
if (isE2E) {
  const e2eStoragePrefix = "nkc-browser-e2e-secure-storage:";
  const e2eWindow = window as typeof window & {
    electron?: {
      secureStorage?: {
        isAvailable: () => Promise<boolean>;
        get: (key: string) => Promise<string | null>;
        set: (key: string, value: string) => Promise<boolean>;
        remove: (key: string) => Promise<boolean>;
      };
    };
  };
  if (!e2eWindow.electron?.secureStorage) {
    Object.defineProperty(e2eWindow, "electron", {
      configurable: true,
      value: {
        secureStorage: {
          isAvailable: async () => true,
          get: async (key: string) =>
            window.localStorage.getItem(`${e2eStoragePrefix}${key}`),
          set: async (key: string, value: string) => {
            window.localStorage.setItem(`${e2eStoragePrefix}${key}`, value);
            return true;
          },
          remove: async (key: string) => {
            window.localStorage.removeItem(`${e2eStoragePrefix}${key}`);
            return true;
          },
        },
      },
    });
  }
  const e2eEpochMs = new Date("2026-01-01T00:00:00Z").getTime();
  const realDateNow = Date.now.bind(Date);
  const realStartMs = realDateNow();
  Date.now = () => e2eEpochMs + (realDateNow() - realStartMs);
}

const root = document.getElementById("root");
const Router =
  typeof window !== "undefined" && window.location.protocol === "file:"
    ? HashRouter
    : BrowserRouter;

bindP2PConnectionStatusBridge();

if (root) {
  createRoot(root).render(
    <Router>
      <App />
    </Router>
  );
}
