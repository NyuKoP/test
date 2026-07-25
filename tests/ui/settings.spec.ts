import { test, expect, type Page } from "@playwright/test";
import {
  disableAnimations,
  ensureOnboarded,
  ensureChatsList,
  openNetworkSettings,
} from "./helpers";

// NOTE: Electron Playwright launch is not supported by this Electron build
// (no --remote-debugging-port), so we run against the Vite dev server in browser mode.

const getStoredProxyUrl = async (page: Page) =>
  page.evaluate(() => {
    const raw = localStorage.getItem("netConfig.v1");
    if (!raw) return null;
    try {
      return (JSON.parse(raw) as { onionProxyUrl?: string }).onionProxyUrl ?? null;
    } catch {
      return null;
    }
  });

const createLargePngBuffer = (sizeBytes: number) => {
  const header = Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
  ]);
  if (sizeBytes <= header.length) return header;
  const padding = Buffer.alloc(sizeBytes - header.length);
  return Buffer.concat([header, padding]);
};

const clearProfileStore = async (page: Page) =>
  page.evaluate(async () => {
    const openRequest = indexedDB.open("nkc_vault");
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      openRequest.onsuccess = () => resolve(openRequest.result);
      openRequest.onerror = () => reject(openRequest.error);
    });

    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction("profiles", "readwrite");
        tx.objectStore("profiles").clear();
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  });

test.describe("Settings and media E2E", () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      const prefix = "nkc-settings-e2e-secure-storage:";
      Object.defineProperty(window, "electron", {
        configurable: true,
        value: {
          secureStorage: {
            isAvailable: async () => true,
            get: async (key: string) => localStorage.getItem(`${prefix}${key}`),
            set: async (key: string, value: string) => {
              localStorage.setItem(`${prefix}${key}`, value);
              return true;
            },
            remove: async (key: string) => {
              localStorage.removeItem(`${prefix}${key}`);
              return true;
            },
          },
        },
      });
    });
    await page.goto("/");
    await disableAnimations(page);
    await ensureOnboarded(page);
  });

  test("missing account profile returns to onboarding instead of a dead settings route", async ({
    page,
  }) => {
    await clearProfileStore(page);

    await page.reload();
    await expect(page.getByTestId("onboarding-screen")).toBeVisible();
    await page.goto("/settings");
    await expect(page.getByTestId("onboarding-screen")).toBeVisible();
  });

  test("proxy URL without port shows inline error and is not applied", async ({ page }) => {
    await openNetworkSettings(page);

    await page.getByTestId("network-mode-torOnion").check();
    const proxyInput = page.getByTestId("proxy-url-input");
    await expect(proxyInput).toBeVisible();

    const beforeUrl = await getStoredProxyUrl(page);
    await proxyInput.fill("socks5://127.0.0.1");

    await expect(page.getByTestId("proxy-url-error")).toBeVisible();
    const afterUrl = await getStoredProxyUrl(page);
    expect(afterUrl).toBe(beforeUrl);
  });

  test("shows Tor first as the recommended connection mode without changing the selection", async ({
    page,
  }) => {
    await openNetworkSettings(page);

    const tor = page.getByTestId("network-mode-torOnion");
    const direct = page.getByTestId("network-mode-directP2P");
    const torBox = await tor.boundingBox();
    const directBox = await direct.boundingBox();

    expect(torBox).not.toBeNull();
    expect(directBox).not.toBeNull();
    expect(torBox?.y ?? Number.POSITIVE_INFINITY).toBeLessThan(
      directBox?.y ?? Number.NEGATIVE_INFINITY
    );
    await expect(page.getByTestId("network-mode-tor-recommended")).toHaveText(/권장|Recommended/);
    await expect(page.getByTestId("network-mode-selfOnion")).toBeChecked();
    await expect(page.getByTestId("tor-auto-prepare")).toBeDisabled();

    await tor.check();
    await expect(page.getByTestId("tor-auto-prepare")).toBeEnabled();
    await expect(page.getByTestId("tor-auto-prepare")).toBeChecked();
    await page.getByTestId("tor-auto-prepare-control").click();
    await expect(page.getByTestId("tor-auto-prepare")).not.toBeChecked();
  });

  test("direct P2P switches only after save", async ({ page }) => {
    await openNetworkSettings(page);

    const effectiveMode = page.getByTestId("effective-mode-label");
    const initialLabel = (await effectiveMode.textContent())?.trim() ?? "";

    await page.getByTestId("network-mode-directP2P").click();
    await expect(effectiveMode).toHaveText(initialLabel);

    await page.getByRole("button", { name: "Save" }).click();
    await expect(effectiveMode).not.toHaveText(initialLabel);

    await page.getByTestId("network-mode-selfOnion").click();
    await expect(effectiveMode).not.toHaveText(initialLabel);
    await page.getByRole("button", { name: "Save" }).click();
    await expect(effectiveMode).toHaveText(initialLabel);
  });

  test("light and dark themes apply immediately after save", async ({ page }) => {
    await page.getByTestId("open-settings").click();
    await page.getByTestId("settings-theme-button").click();
    await page.getByTestId("theme-option-dark").click();
    await page.getByTestId("theme-save-button").click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

    await page.getByTestId("settings-theme-button").click();
    await page.getByTestId("theme-option-light").click();
    await page.getByTestId("theme-save-button").click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  });

  test("notification preferences use accessible sliding switches", async ({ page }) => {
    await page.evaluate(() => {
      type Prefs = {
        login: { autoStartEnabled: boolean; startInTray: boolean; closeToTray: boolean; closeToExit: boolean };
        background: { enabled: boolean; syncIntervalMinutes: 0 };
        notifications: { enabled: boolean; hideContent: boolean };
        deviceSync: { transportPolicy: "directOnly" };
      };
      type Patch = { [Key in keyof Prefs]?: Partial<Prefs[Key]> };
      let prefs: Prefs = {
        login: { autoStartEnabled: true, startInTray: false, closeToTray: true, closeToExit: false },
        background: { enabled: true, syncIntervalMinutes: 0 },
        notifications: { enabled: true, hideContent: true },
        deviceSync: { transportPolicy: "directOnly" },
      };
      const root = globalThis as typeof globalThis & {
        prefs?: { get: () => Promise<Prefs>; set: (patch: Patch) => Promise<Prefs> };
      };
      root.prefs = {
        get: async () => prefs,
        set: async (patch) => {
          prefs = {
            login: { ...prefs.login, ...(patch.login ?? {}) },
            background: { ...prefs.background, ...(patch.background ?? {}) },
            notifications: { ...prefs.notifications, ...(patch.notifications ?? {}) },
            deviceSync: { ...prefs.deviceSync, ...(patch.deviceSync ?? {}) },
          };
          return prefs;
        },
      };
    });
    await page.getByTestId("open-settings").click();
    await page.getByTestId("settings-notifications-button").click();

    const enabled = page.getByTestId("notifications-enabled-switch");
    const hideContent = page.getByTestId("notifications-hide-content-switch");
    const enabledTrack = page.getByTestId("notifications-enabled-switch-track");
    await expect(enabled).toHaveAttribute("role", "switch");
    await expect(enabled).toBeChecked();
    await expect(enabledTrack).toHaveCSS("background-color", "rgb(57, 127, 152)");

    await page.getByTestId("notifications-enabled-switch-control").click();
    await expect(enabled).not.toBeChecked();
    await expect(enabledTrack).toHaveCSS("background-color", "rgb(180, 192, 217)");
    await expect(hideContent).toBeDisabled();

    await page.getByTestId("notifications-enabled-switch-control").click();
    await expect(enabled).toBeChecked();
  });

  test("close behavior switches directly between tray and exit", async ({ page }) => {
    await page.evaluate(() => {
      type Prefs = {
        login: { autoStartEnabled: boolean; startInTray: boolean; closeToTray: boolean; closeToExit: boolean };
        background: { enabled: boolean; syncIntervalMinutes: 0 };
        notifications: { enabled: boolean; hideContent: boolean };
        deviceSync: { transportPolicy: "directOnly" };
      };
      type Patch = { [Key in keyof Prefs]?: Partial<Prefs[Key]> };
      let prefs: Prefs = {
        login: { autoStartEnabled: true, startInTray: false, closeToTray: true, closeToExit: false },
        background: { enabled: true, syncIntervalMinutes: 0 },
        notifications: { enabled: true, hideContent: true },
        deviceSync: { transportPolicy: "directOnly" },
      };
      const root = globalThis as typeof globalThis & {
        prefs?: { get: () => Promise<Prefs>; set: (patch: Patch) => Promise<Prefs> };
      };
      root.prefs = {
        get: async () => prefs,
        set: async (patch) => {
          prefs = {
            login: { ...prefs.login, ...(patch.login ?? {}) },
            background: { ...prefs.background, ...(patch.background ?? {}) },
            notifications: { ...prefs.notifications, ...(patch.notifications ?? {}) },
            deviceSync: { ...prefs.deviceSync, ...(patch.deviceSync ?? {}) },
          };
          if (patch.login?.closeToExit) {
            prefs.login.closeToTray = false;
            prefs.background.enabled = false;
          }
          if (patch.login?.closeToTray) prefs.login.closeToExit = false;
          return prefs;
        },
      };
    });

    await page.getByTestId("open-settings").click();
    await page.getByTestId("settings-login-button").click();

    const tray = page.getByTestId("login-close-to-tray-switch");
    const exit = page.getByTestId("login-close-to-exit-switch");
    await expect(tray).toBeChecked();
    await expect(exit).not.toBeChecked();
    await expect(exit).toBeEnabled();

    await page.getByTestId("login-close-to-exit-switch-control").click();
    await expect(exit).toBeChecked();
    await expect(tray).not.toBeChecked();
    await expect(tray).toBeEnabled();

    await page.getByTestId("login-close-to-tray-switch-control").click();
    await expect(tray).toBeChecked();
    await expect(exit).not.toBeChecked();
  });

  test("PIN lock switch opens the PIN editor with one click", async ({ page }) => {
    await page.getByTestId("open-settings").click();
    await page.getByTestId("settings-privacy-button").click();

    const pinSwitch = page.getByTestId("privacy-pin-lock-switch");
    await expect(pinSwitch).not.toBeChecked();
    await page.getByTestId("privacy-pin-lock-switch-control").click();
    await expect(pinSwitch).toBeChecked();
    await expect(page.getByPlaceholder(/4-8/)).toBeVisible();
  });

  test("sidebar tabs and quick theme selection persist", async ({ page }) => {
    await expect(page.getByTestId("sidebar-tabs")).toBeVisible();
    await page.getByRole("button", { name: "탭 숨기기" }).click();
    await expect(page.getByTestId("sidebar-tabs")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "탭 표시" })).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => localStorage.getItem("nkc.sidebar.tabsVisible")))
      .toBe("false");
    await page.getByRole("button", { name: "탭 표시" }).click();
    await expect(page.getByTestId("sidebar-tabs")).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => localStorage.getItem("nkc.sidebar.tabsVisible")))
      .toBe("true");

    const initialTheme = (await page.locator("html").getAttribute("data-theme")) ?? "light";
    const nextTheme = initialTheme === "dark" ? "light" : "dark";
    await page.getByTestId("theme-quick-toggle").click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", nextTheme);
    await expect.poll(() => page.evaluate(() => localStorage.getItem("nkc.theme"))).toBe(nextTheme);
    await expect(page.getByTestId("theme-quick-toggle")).toHaveAttribute(
      "aria-label",
      nextTheme === "dark" ? "라이트 모드로 전환" : "다크 모드로 전환"
    );

    await page.getByTestId("theme-quick-toggle").click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", initialTheme);
  });

  test("friend tab removes the conversation filter divider", async ({ page }) => {
    await ensureChatsList(page);
    await expect(page.getByTestId("conversation-filters")).toBeVisible();
    await page.getByTestId("list-mode-friends").click();
    await expect(page.getByTestId("conversation-filters")).toHaveCount(0);
    await expect(page.getByTestId("sidebar-search-region")).toHaveCSS("border-bottom-width", "0px");
    await expect(page.getByTestId("friends-section")).toHaveCSS("border-top-width", "0px");
  });

  test("conversation rows use NKC hover separation without dividers", async ({ page }) => {
    await ensureChatsList(page);
    const row = page.locator('[data-testid^="conversation-row-"][data-selected="false"]').first();
    await expect(row).toBeVisible();
    await expect(row).toHaveCSS("border-top-width", "0px");
    await expect(row).toHaveCSS("border-bottom-width", "0px");
    await expect(row).toHaveCSS("border-radius", "10px");
    await expect(row).toHaveCSS("min-height", "72px");

    const idleBackground = await row.evaluate((element) => getComputedStyle(element).backgroundColor);
    await row.hover();
    await expect
      .poll(() => row.evaluate((element) => getComputedStyle(element).backgroundColor))
      .not.toBe(idleBackground);

    const rowTestId = await row.getAttribute("data-testid");
    expect(rowTestId).toBeTruthy();
    await row.click();
    const selectedRow = page.getByTestId(rowTestId!);
    await expect(selectedRow).toHaveAttribute("aria-pressed", "true");
    await expect(selectedRow).toHaveCSS("background-color", "rgb(232, 238, 253)");
    await expect(selectedRow).not.toBeFocused();
  });

  test("large media send keeps UI responsive and reloads safely", async ({ page }) => {
    test.setTimeout(120_000);

    await ensureChatsList(page);
    const rows = page.locator('[data-testid^="conversation-row-"]');
    await expect(rows.first()).toBeVisible();

    const target = rows.first();
    const convId = await target.getAttribute("data-conversation-id");
    await target.click();

    const messageInput = page.getByTestId("chat-message-input");
    await expect(messageInput).toBeEditable();

    const mediaBubbles = page.getByTestId("media-message-bubble");
    const beforeCount = await mediaBubbles.count();

    const buffer = createLargePngBuffer(20 * 1024 * 1024);
    await page
      .getByTestId("chat-attach-input")
      .setInputFiles({ name: "large.png", mimeType: "image/png", buffer });

    await expect(page.getByTestId("attachment-preview")).toHaveCount(1);
    await expect(messageInput).toBeEditable();
    await messageInput.fill("still responsive");
    await expect(messageInput).toHaveValue("still responsive");
    await page.getByTestId("chat-send-button").click();

    await expect(mediaBubbles).toHaveCount(beforeCount + 1);
    await expect(mediaBubbles.nth(beforeCount)).toBeVisible();

    if (convId) {
      const fallback = rows.nth(1);
      await fallback.click();
      await page.locator(`[data-conversation-id="${convId}"]`).click();
      await expect(mediaBubbles.nth(beforeCount)).toBeVisible();
    }
  });
});
