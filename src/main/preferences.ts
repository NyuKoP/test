import fs from "node:fs/promises";
import path from "node:path";
import { app } from "electron";
import {
  applyAppPrefsPatch,
  defaultAppPrefs,
  normalizePrefs,
  type AppPreferences,
  type AppPreferencesPatch,
} from "../preferences";

const PREFS_FILENAME = "nkc_app_prefs_v1.json";

let cachedPrefs: AppPreferences | null = null;
let pendingWrite: Promise<void> = Promise.resolve();

const getPrefsPath = () => path.join(app.getPath("userData"), PREFS_FILENAME);

export const readAppPrefs = async (): Promise<AppPreferences> => {
  if (cachedPrefs) return cachedPrefs;
  try {
    const raw = await fs.readFile(getPrefsPath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<AppPreferences>;
    cachedPrefs = normalizePrefs(parsed);
  } catch {
    cachedPrefs = defaultAppPrefs;
  }
  return cachedPrefs;
};

const writePrefs = async (prefs: AppPreferences) => {
  cachedPrefs = prefs;
  const payload = JSON.stringify({ ...prefs, updatedAt: Date.now() });
  const target = getPrefsPath();
  const temporary = `${target}.${process.pid}.tmp`;
  const write = pendingWrite
    .catch(() => undefined)
    .then(async () => {
      await fs.writeFile(temporary, payload, { encoding: "utf8", mode: 0o600 });
      await fs.rename(temporary, target);
      await fs.chmod(target, 0o600).catch(() => undefined);
    });
  pendingWrite = write;
  await write;
};

export const setAppPrefs = async (patch: AppPreferencesPatch) => {
  const current = await readAppPrefs();
  const next = applyAppPrefsPatch(current, patch);
  await writePrefs(next);
  return next;
};
