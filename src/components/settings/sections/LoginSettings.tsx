import type {
  AppPreferences,
  AppPreferencesPatch,
  SyncIntervalMinutes,
} from "../../../preferences";
import SettingsBackHeader from "../SettingsBackHeader";
import ToggleSwitch from "../ToggleSwitch";

type Translate = (ko: string, en: string) => string;

type LoginSettingsProps = {
  t: Translate;
  onBack: () => void;
  appPrefs: AppPreferences;
  prefsDisabled: boolean;
  backgroundDisabled: boolean;
  onUpdateAppPrefs: (patch: AppPreferencesPatch) => void | Promise<void>;
  onManualSync: () => void;
};

export default function LoginSettings({
  t,
  onBack,
  appPrefs,
  prefsDisabled,
  backgroundDisabled,
  onUpdateAppPrefs,
  onManualSync,
}: LoginSettingsProps) {
  return (
    <div className="mt-6 grid gap-6">
      <SettingsBackHeader title={t("로그인", "Login")} backLabel={t("뒤로", "Back")} onBack={onBack} />
      <div className="text-xs text-nkc-muted">
        {t("앱 시작 및 실행 동작 설정", "Configure app startup and launch behavior.")}
      </div>
      <section className="rounded-nkc border border-nkc-border bg-nkc-panelMuted">
        <div className="border-b border-nkc-border px-4 py-3">
          <div className="text-sm font-semibold text-nkc-text">{t("시작", "Startup")}</div>
        </div>
        <div className="flex flex-col">
          <div className="flex items-center justify-between gap-4 border-b border-nkc-border px-4 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">
                {t("Windows 자동 시작", "Start with Windows")}
              </div>
              <div className="text-xs text-nkc-muted">
                {t(
                  "Windows 로그인 시 앱을 자동으로 실행합니다.",
                  "Launch automatically on Windows login."
                )}
              </div>
            </div>
            <ToggleSwitch
              label={t("Windows 자동 시작", "Start with Windows")}
              checked={appPrefs.login.autoStartEnabled}
              disabled={prefsDisabled}
              onChange={(checked) =>
                void onUpdateAppPrefs({
                  login: { autoStartEnabled: checked },
                })
              }
            />
          </div>

          <div className="flex items-center justify-between gap-4 border-b border-nkc-border px-4 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">
                {t("자동 시작 시 트레이에서 시작", "Start in tray on auto-start")}
              </div>
              <div className="text-xs text-nkc-muted">
                {t(
                  "Windows 자동 시작으로 실행될 때 창을 표시하지 않습니다.",
                  "Hide the window when launched by auto-start."
                )}
              </div>
            </div>
            <ToggleSwitch
              label={t("자동 시작 시 트레이에서 시작", "Start in tray on auto-start")}
              checked={appPrefs.login.startInTray}
              disabled={prefsDisabled}
              onChange={(checked) =>
                void onUpdateAppPrefs({
                  login: { startInTray: checked },
                })
              }
            />
          </div>

          <div className="flex items-center justify-between gap-4 border-b border-nkc-border px-4 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">
                {t("닫기(X) = 트레이로 숨김", "Close (X) = Hide to tray")}
              </div>
              <div className="text-xs text-nkc-muted">
                {t("창 닫기 시 앱을 종료하지 않습니다.", "Keep the app running in the tray.")}
              </div>
            </div>
            <ToggleSwitch
              label={t("닫기(X) = 트레이로 숨김", "Close (X) = Hide to tray")}
              checked={appPrefs.login.closeToTray}
              disabled={prefsDisabled}
              testId="login-close-to-tray-switch"
              onChange={(checked) =>
                void onUpdateAppPrefs({
                  login: { closeToTray: checked },
                })
              }
            />
          </div>

          <div className="flex items-center justify-between gap-4 border-b border-nkc-border px-4 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">
                {t("닫기(X) = 종료", "Close (X) = Exit")}
              </div>
              <div className="text-xs text-nkc-muted">
                {t("앱을 종료하고 백그라운드를 끕니다.", "Exit the app and disable background mode.")}
              </div>
            </div>
            <ToggleSwitch
              label={t("닫기(X) = 종료", "Close (X) = Exit")}
              checked={appPrefs.login.closeToExit}
              disabled={prefsDisabled}
              testId="login-close-to-exit-switch"
              onChange={(checked) =>
                void onUpdateAppPrefs({
                  login: { closeToExit: checked },
                })
              }
            />
          </div>

          <div className="flex items-center justify-between gap-4 border-b border-nkc-border px-4 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">
                {t("백그라운드 사용", "Background enabled")}
              </div>
              <div className="text-xs text-nkc-muted">
                {t(
                  "앱을 닫아도 메시지 수신과 동기화를 계속합니다.",
                  "Continue receiving and syncing even when the app is closed."
                )}
              </div>
            </div>
            <ToggleSwitch
              label={t("백그라운드 사용", "Background enabled")}
              checked={appPrefs.background.enabled}
              disabled={prefsDisabled || appPrefs.login.closeToExit}
              onChange={(checked) =>
                void onUpdateAppPrefs({
                  background: { enabled: checked },
                })
              }
            />
          </div>

          <div className="flex items-center justify-between gap-4 border-b border-nkc-border px-6 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">{t("주기적 동기화", "Periodic sync")}</div>
              <div className="text-xs text-nkc-muted">
                {t("백그라운드 동기화 간격", "Background sync interval")}
              </div>
            </div>
            <div className="flex flex-col items-end">
              <select
                value={appPrefs.background.syncIntervalMinutes}
                disabled={prefsDisabled || backgroundDisabled}
                onChange={(e) =>
                  void onUpdateAppPrefs({
                    background: {
                      syncIntervalMinutes: Number(e.target.value) as SyncIntervalMinutes,
                    },
                  })
                }
                className="rounded-nkc border border-nkc-border bg-nkc-panel px-2 py-1 text-xs text-nkc-text disabled:opacity-50"
              >
                <option value={0}>{t("Auto", "Auto")}</option>
                <option value={1}>1분</option>
                <option value={3}>3분</option>
                <option value={5}>5분</option>
                <option value={10}>10분</option>
                <option value={15}>15분</option>
                <option value={20}>20분</option>
                <option value={25}>25분</option>
                <option value={30}>30분</option>
              </select>
              {appPrefs.background.syncIntervalMinutes === 0 ? (
                <div className="mt-2 text-xs text-nkc-muted">
                  {t(
                    "상태에 따라 동기화 간격이 자동으로 조절됩니다.",
                    "Sync interval is adjusted automatically based on status."
                  )}
                </div>
              ) : null}
            </div>
          </div>

          <div className="flex items-center justify-between gap-4 px-6 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">{t("수동 동기화", "Manual sync")}</div>
              <div className="text-xs text-nkc-muted">
                {t("필요할 때 즉시 동기화합니다.", "Sync immediately when needed.")}
              </div>
            </div>
            <button
              type="button"
              onClick={onManualSync}
              disabled={prefsDisabled || backgroundDisabled}
              className="rounded-nkc border border-nkc-border px-3 py-2 text-xs text-nkc-text hover:bg-nkc-panelMuted disabled:opacity-50"
            >
              {t("지금 동기화", "Sync now")}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
