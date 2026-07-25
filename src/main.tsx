import { createRoot } from "react-dom/client";
import { BrowserRouter, HashRouter } from "./appRouter";
import "./index.css";
import App from "./app/App";
import { bindP2PConnectionStatusBridge } from "./store/useP2PStore";

const isE2E = Boolean((import.meta as { env?: { VITE_E2E?: string } }).env?.VITE_E2E);
if (isE2E) {
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
