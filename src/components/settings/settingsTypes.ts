import type { LucideIcon } from "lucide-react";
import {
  Bell,
  Globe,
  HardDrive,
  KeyRound,
  Monitor,
  Palette,
  RefreshCw,
  Shield,
  Users,
} from "lucide-react";

export type LocalizedLabel = { ko: string; en: string };

export const themeOptions: { value: "dark" | "light"; label: LocalizedLabel }[] = [
  { value: "dark", label: { ko: "다크", en: "Dark" } },
  { value: "light", label: { ko: "라이트", en: "Light" } },
];

export type ConnectionChoice = "directP2P" | "selfOnion" | "torOnion";

export type SettingsView =
  | "main"
  | "notifications"
  | "privacy"
  | "privacyKeys"
  | "theme"
  | "friends"
  | "danger"
  | "network"
  | "help"
  | "login"
  | "storage"
  | "devices"
  | "updates";

export type SettingsRoute = {
  key:
    | "settings.notifications"
    | "settings.friends"
    | "settings.network"
    | "settings.devices"
    | "settings.privacy"
    | "settings.login"
    | "settings.theme"
    | "settings.storage"
    | "settings.updates";
  view: SettingsView;
  label: LocalizedLabel;
  testId?: string;
};

export const SETTINGS_ROUTES: SettingsRoute[] = [
  {
    key: "settings.notifications",
    view: "notifications",
    label: { ko: "알림", en: "Notifications" },
    testId: "settings-notifications-button",
  },
  { key: "settings.friends", view: "friends", label: { ko: "친구 관리", en: "Friend management" } },
  {
    key: "settings.network",
    view: "network",
    label: { ko: "네트워크 설정", en: "Network settings" },
    testId: "settings-network-button",
  },
  { key: "settings.devices", view: "devices", label: { ko: "기기/동기화", en: "Devices / Sync" } },
  {
    key: "settings.privacy",
    view: "privacy",
    label: { ko: "보안 / 개인정보", en: "Security / Privacy" },
    testId: "settings-privacy-button",
  },
  {
    key: "settings.login",
    view: "login",
    label: { ko: "로그인", en: "Login" },
    testId: "settings-login-button",
  },
  {
    key: "settings.theme",
    view: "theme",
    label: { ko: "테마", en: "Theme" },
    testId: "settings-theme-button",
  },
  { key: "settings.storage", view: "storage", label: { ko: "저장소 관리", en: "Storage management" } },
  { key: "settings.updates", view: "updates", label: { ko: "앱 업데이트", en: "App updates" } },
];

export const routeIconByView: Record<
  Exclude<SettingsView, "main" | "privacyKeys" | "danger" | "help">,
  LucideIcon
> = {
  notifications: Bell,
  friends: Users,
  network: Globe,
  devices: Monitor,
  privacy: Shield,
  login: KeyRound,
  theme: Palette,
  storage: HardDrive,
  updates: RefreshCw,
};
