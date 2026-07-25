export type SyncIntervalMinutes = 0 | 1 | 3 | 5 | 10 | 15 | 20 | 25 | 30;
export type DeviceSyncTransportPolicy = "directOnly" | "followNetwork";

export type AppPreferences = {
  login: {
    autoStartEnabled: boolean;
    startInTray: boolean;
    closeToTray: boolean;
    closeToExit: boolean;
  };
  background: {
    enabled: boolean;
    syncIntervalMinutes: SyncIntervalMinutes;
  };
  notifications: {
    enabled: boolean;
    hideContent: boolean;
  };
  deviceSync: {
    transportPolicy: DeviceSyncTransportPolicy;
  };
};

export type AppPreferencesPatch = {
  login?: Partial<AppPreferences["login"]>;
  background?: Partial<AppPreferences["background"]>;
  notifications?: Partial<AppPreferences["notifications"]>;
  deviceSync?: Partial<AppPreferences["deviceSync"]>;
};

export const defaultAppPrefs: AppPreferences = {
  login: {
    autoStartEnabled: true,
    startInTray: false,
    closeToTray: true,
    closeToExit: false,
  },
  background: {
    enabled: true,
    syncIntervalMinutes: 0,
  },
  notifications: {
    enabled: true,
    hideContent: true,
  },
  deviceSync: {
    transportPolicy: "directOnly",
  },
};

const allowedIntervals: SyncIntervalMinutes[] = [0, 1, 3, 5, 10, 15, 20, 25, 30];

export const normalizePrefs = (input?: Partial<AppPreferences> | null): AppPreferences => {
  const merged: AppPreferences = {
    login: { ...defaultAppPrefs.login, ...(input?.login ?? {}) },
    background: { ...defaultAppPrefs.background, ...(input?.background ?? {}) },
    notifications: { ...defaultAppPrefs.notifications, ...(input?.notifications ?? {}) },
    deviceSync: { ...defaultAppPrefs.deviceSync, ...(input?.deviceSync ?? {}) },
  };

  if (!allowedIntervals.includes(merged.background.syncIntervalMinutes)) {
    merged.background.syncIntervalMinutes = defaultAppPrefs.background.syncIntervalMinutes;
  }

  if (merged.login.closeToExit) {
    merged.login.closeToTray = false;
    merged.background.enabled = false;
  }

  if (merged.login.closeToTray) {
    merged.login.closeToExit = false;
  }

  if (
    merged.deviceSync.transportPolicy !== "directOnly" &&
    merged.deviceSync.transportPolicy !== "followNetwork"
  ) {
    merged.deviceSync.transportPolicy = defaultAppPrefs.deviceSync.transportPolicy;
  }

  return merged;
};

export const applyAppPrefsPatch = (
  current: AppPreferences,
  patch: AppPreferencesPatch
): AppPreferences => {
  const next = {
    ...current,
    login: { ...current.login, ...(patch.login ?? {}) },
    background: { ...current.background, ...(patch.background ?? {}) },
    notifications: { ...current.notifications, ...(patch.notifications ?? {}) },
    deviceSync: { ...current.deviceSync, ...(patch.deviceSync ?? {}) },
  };

  if (patch.login?.closeToTray === true) {
    next.login.closeToExit = false;
  }
  if (patch.login?.closeToExit === true) {
    next.login.closeToTray = false;
  }

  return normalizePrefs(next);
};

type PrefsBridge = {
  get: () => Promise<AppPreferences>;
  set: (patch: AppPreferencesPatch) => Promise<AppPreferences>;
};

const getBridge = (): PrefsBridge | null => {
  const root = globalThis as typeof globalThis & { prefs?: PrefsBridge };
  return root.prefs ?? null;
};

export const getAppPrefs = async () => {
  const bridge = getBridge();
  if (!bridge) throw new Error("Preferences bridge unavailable");
  return bridge.get();
};

export const setAppPrefs = async (patch: AppPreferencesPatch) => {
  const bridge = getBridge();
  if (!bridge) throw new Error("Preferences bridge unavailable");
  return bridge.set(patch);
};
