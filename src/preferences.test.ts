import { describe, expect, it } from "vitest";
import {
  applyAppPrefsPatch,
  defaultAppPrefs,
  type AppPreferences,
} from "./preferences";

const createPrefs = (): AppPreferences => ({
  login: { ...defaultAppPrefs.login },
  background: { ...defaultAppPrefs.background },
  notifications: { ...defaultAppPrefs.notifications },
  deviceSync: { ...defaultAppPrefs.deviceSync },
});

describe("applyAppPrefsPatch", () => {
  it("switches directly from hide-to-tray to exit", () => {
    const next = applyAppPrefsPatch(createPrefs(), {
      login: { closeToExit: true },
    });

    expect(next.login.closeToExit).toBe(true);
    expect(next.login.closeToTray).toBe(false);
    expect(next.background.enabled).toBe(false);
  });

  it("switches directly from exit to hide-to-tray", () => {
    const current = applyAppPrefsPatch(createPrefs(), {
      login: { closeToExit: true },
    });
    const next = applyAppPrefsPatch(current, {
      login: { closeToTray: true },
    });

    expect(next.login.closeToTray).toBe(true);
    expect(next.login.closeToExit).toBe(false);
  });
});
