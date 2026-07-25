import { app, safeStorage } from "electron";
import fs from "node:fs/promises";
import path from "node:path";

const SECRET_STORE_FILENAME = "secret-store.json";
const SECRET_STORE_EXACT_KEYS = new Set([
  "nkc_identity_priv_v1",
  "nkc_dh_priv_v1",
  "nkc_session_v1",
  "nkc_pin_v1",
  "nkc_pin_reset_v1",
]);
const SECRET_STORE_PREFIXES = [
  "nkc_friend_psk_v1:",
  "nkc_invite_used_v1:",
  "nkc_ratchet_v1:",
  "nkc_ratchet_v2:",
];
let pendingWrite: Promise<void> = Promise.resolve();

const isSecureStorageBackendAvailable = () => {
  if (!safeStorage.isEncryptionAvailable()) return false;
  if (process.platform !== "linux") return true;
  return safeStorage.getSelectedStorageBackend() !== "basic_text";
};

export const isAllowedSecretStoreKey = (key: unknown): key is string =>
  typeof key === "string" &&
  key.length > 0 &&
  key.length <= 256 &&
  (SECRET_STORE_EXACT_KEYS.has(key) ||
    SECRET_STORE_PREFIXES.some((prefix) => key.startsWith(prefix)));

const readSecretStore = async () => {
  const filePath = path.join(app.getPath("userData"), SECRET_STORE_FILENAME);
  try {
    const raw = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(raw) as Record<string, string>;
    if (!parsed || typeof parsed !== "object") return {};
    return parsed;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error) {
      const code = String((error as { code?: unknown }).code ?? "");
      if (code === "ENOENT") return {};
    }
    return {};
  }
};

const writeSecretStore = async (payload: Record<string, string>) => {
  const filePath = path.join(app.getPath("userData"), SECRET_STORE_FILENAME);
  const temporaryPath = `${filePath}.${process.pid}.tmp`;
  pendingWrite = pendingWrite.catch(() => undefined).then(async () => {
    await fs.writeFile(temporaryPath, JSON.stringify(payload), {
      encoding: "utf8",
      mode: 0o600,
    });
    await fs.rename(temporaryPath, filePath);
    await fs.chmod(filePath, 0o600).catch(() => undefined);
  });
  await pendingWrite;
};

export const saveKeyPair = async (key: string, value: string) => {
  if (!isAllowedSecretStoreKey(key) || typeof value !== "string") return false;
  if (!isSecureStorageBackendAvailable()) return false;
  const data = await readSecretStore();
  data[key] = safeStorage.encryptString(value).toString("base64");
  await writeSecretStore(data);
  return true;
};

export const loadKeyPair = async (key: string) => {
  if (!isAllowedSecretStoreKey(key)) return null;
  if (!isSecureStorageBackendAvailable()) return null;
  const data = await readSecretStore();
  const entry = data[key];
  if (!entry) return null;
  try {
    return safeStorage.decryptString(Buffer.from(entry, "base64"));
  } catch {
    return null;
  }
};

export const removeKeyPair = async (key: string) => {
  if (!isAllowedSecretStoreKey(key)) return false;
  if (!isSecureStorageBackendAvailable()) return false;
  const data = await readSecretStore();
  if (key in data) {
    delete data[key];
    await writeSecretStore(data);
  }
  return true;
};

export const isSecretStoreAvailable = () => isSecureStorageBackendAvailable();
