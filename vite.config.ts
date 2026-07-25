import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import electron from "vite-plugin-electron";

const nativeWorkerName = process.platform === "win32" ? "nkc-worker.exe" : "nkc-worker";
const nativeWorkerPath = path.resolve(__dirname, "native", "bin", nativeWorkerName);
const nativeWorkerSha256 = fs.existsSync(nativeWorkerPath)
  ? crypto.createHash("sha256").update(fs.readFileSync(nativeWorkerPath)).digest("hex")
  : "";

const electronMainBuild = {
  outDir: "dist-electron",
  sourcemap: true,
  emptyOutDir: false,
  lib: {
    entry: "src/main.ts",
    formats: ["cjs"],
  },
  rollupOptions: {
    external: ["electron", "electron-updater"],
    output: {
      format: "cjs" as const,
      entryFileNames: "[name].js",
    },
  },
} satisfies import("vite").BuildOptions;

const electronPreloadBuild = {
  outDir: "dist-electron",
  sourcemap: true,
  emptyOutDir: false,
  lib: {
    entry: "src/preload.ts",
    formats: ["cjs"],
  },
  rollupOptions: {
    external: ["electron"],
    output: {
      format: "cjs" as const,
      entryFileNames: "[name].js",
    },
  },
} satisfies import("vite").BuildOptions;

const clientManualChunks = (id: string) => {
  if (!id.includes("node_modules")) return undefined;
  if (id.includes("libsodium")) return "vendor-crypto";
  return "vendor";
};

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),

    electron([
      // =========================
      // main process
      // =========================
      {
        entry: "src/main.ts",
        onstart({ startup }) {
          if (process.env.NKC_E2E === "1") return;
          const env = { ...process.env };
          delete env.ELECTRON_RUN_AS_NODE;
          void startup(["."], { env });
        },
        vite: {
          define: {
            __NKC_NATIVE_WORKER_SHA256__: JSON.stringify(nativeWorkerSha256),
          },
          build: {
            ...electronMainBuild,
          },
        },
      },

      // =========================
      // preload process
      // =========================
      {
        entry: "src/preload.ts",
        vite: {
          build: {
            ...electronPreloadBuild,
          },
        },
      },
    ]),
  ],

  resolve: {
    alias: {
      "libsodium-wrappers-sumo": path.resolve(
        __dirname,
        "node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js"
      ),
      "libsodium-sumo": path.resolve(
        __dirname,
        "node_modules/libsodium-sumo/dist/modules-sumo/libsodium-sumo.js"
      ),
    },
  },

  optimizeDeps: {
    include: ["libsodium-wrappers-sumo", "libsodium-sumo"],
  },

  worker: {
    format: "es",
  },

  build: {
    target: "chrome150",
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks: clientManualChunks,
      },
    },
  },
});
