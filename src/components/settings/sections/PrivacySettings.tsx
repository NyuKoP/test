import { Lock } from "lucide-react";
import type { PrivacyPreferences } from "../../../security/preferences";
import SettingsBackHeader from "../SettingsBackHeader";
import ToggleSwitch from "../ToggleSwitch";

type Translate = (ko: string, en: string) => string;

type PrivacySettingsProps = {
  t: Translate;
  onBack: () => void;
  onOpenKeys: () => void;
  onLock: () => void;
  pinEnabled: boolean;
  pinAvailable: boolean;
  pinDraft: string;
  setPinDraft: (value: string) => void;
  pinError: string;
  onTogglePin: (next: boolean) => void | Promise<void>;
  onSetPin: () => void | Promise<void>;
  privacyPrefs: PrivacyPreferences;
  onUpdatePrivacy: (next: PrivacyPreferences) => void | Promise<void>;
};

export default function PrivacySettings({
  t,
  onBack,
  onOpenKeys,
  onLock,
  pinEnabled,
  pinAvailable,
  pinDraft,
  setPinDraft,
  pinError,
  onTogglePin,
  onSetPin,
  privacyPrefs,
  onUpdatePrivacy,
}: PrivacySettingsProps) {
  void onOpenKeys;
  return (
    <div className="mt-6 grid gap-6">
      <SettingsBackHeader
        title={t("보안 / 개인정보", "Security / Privacy")}
        backLabel={t("뒤로", "Back")}
        onBack={onBack}
      />

      <section className="rounded-nkc border border-nkc-border bg-nkc-panelMuted p-6">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-nkc-text">{t("보안", "Security")}</h3>
          <button
            type="button"
            onClick={onLock}
            className="flex items-center gap-2 rounded-nkc border border-nkc-border px-3 py-2 text-xs text-nkc-text hover:bg-nkc-panel"
          >
            <Lock size={14} />
            {t("잠그기", "Lock")}
          </button>
        </div>

        <div className="mt-4 grid gap-3">
          <div className="flex items-center justify-between text-sm text-nkc-text">
            <span>{t("PIN 잠금", "PIN lock")}</span>
            <ToggleSwitch
              label={t("PIN 잠금", "PIN lock")}
              checked={pinEnabled}
              disabled={!pinAvailable}
              testId="privacy-pin-lock-switch"
              onChange={(checked) => void onTogglePin(checked)}
            />
          </div>

          {!pinAvailable ? (
            <div className="text-xs text-nkc-muted">
              {t(
                "PIN lock is unavailable on this platform/build.",
                "PIN lock is unavailable on this platform/build."
              )}
            </div>
          ) : null}

          {pinEnabled ? (
            <div className="grid gap-2">
              <input
                type="password"
                inputMode="numeric"
                pattern="\\d*"
                maxLength={8}
                value={pinDraft}
                onChange={(e) => setPinDraft(e.target.value)}
                placeholder={t("4-8자리", "4-8 digits")}
                className="w-full rounded-nkc border border-nkc-border bg-nkc-panel px-3 py-2 text-sm text-nkc-text"
                disabled={!pinAvailable}
              />
              <button
                type="button"
                onClick={() => void onSetPin()}
                className="w-fit rounded-nkc bg-nkc-accent px-3 py-2 text-xs font-semibold text-nkc-accentText disabled:opacity-50"
                disabled={!pinDraft || !pinAvailable}
              >
                {t("PIN 설정", "Set PIN")}
              </button>
            </div>
          ) : null}

          {pinError ? <div className="text-xs text-red-300">{pinError}</div> : null}
        </div>
      </section>

      <section className="rounded-nkc border border-nkc-border bg-nkc-panelMuted">
        <div className="flex flex-col">
          <div className="flex items-center justify-between gap-4 border-b border-nkc-border px-4 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">{t("읽음 표시", "Read receipts")}</div>
              <div className="text-xs text-nkc-muted">
                {t("상대에게 읽음 상태를 공유합니다.", "Share read status with the other person.")}
              </div>
            </div>
            <ToggleSwitch
              label={t("읽음 표시", "Read receipts")}
              checked={privacyPrefs.readReceipts}
              onChange={(checked) =>
                void onUpdatePrivacy({ ...privacyPrefs, readReceipts: checked })
              }
            />
          </div>

          <div className="flex items-center justify-between gap-4 border-b border-nkc-border px-4 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">{t("입력 표시", "Typing indicator")}</div>
              <div className="text-xs text-nkc-muted">
                {t("상대에게 입력 중 상태를 표시합니다.", "Show typing status to the other person.")}
              </div>
            </div>
            <ToggleSwitch
              label={t("입력 표시", "Typing indicator")}
              checked={privacyPrefs.typingIndicator}
              onChange={(checked) =>
                void onUpdatePrivacy({ ...privacyPrefs, typingIndicator: checked })
              }
            />
          </div>

          <div className="flex items-center justify-between gap-4 px-4 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">{t("링크 미리보기", "Link preview")}</div>
              <div className="text-xs text-nkc-muted">{t("링크 카드 표시", "Show link card")}</div>
            </div>
            <ToggleSwitch
              label={t("링크 미리보기", "Link preview")}
              checked={privacyPrefs.linkPreviews}
              onChange={(checked) =>
                void onUpdatePrivacy({ ...privacyPrefs, linkPreviews: checked })
              }
            />
          </div>

          <div className="flex items-center justify-between gap-4 border-t border-nkc-border px-4 py-3">
            <div>
              <div className="text-sm font-medium text-nkc-text">
                {t("알 수 없는 요청 자동 거절", "Auto-reject unknown requests")}
              </div>
              <div className="text-xs text-nkc-muted">
                {t(
                  "검증되지 않은 신규 친구 요청을 자동으로 거절합니다.",
                  "Automatically reject unverified friend requests."
                )}
              </div>
            </div>
            <ToggleSwitch
              label={t("알 수 없는 요청 자동 거절", "Auto-reject unknown requests")}
              checked={privacyPrefs.autoRejectUnknownRequests}
              onChange={(checked) =>
                void onUpdatePrivacy({
                  ...privacyPrefs,
                  autoRejectUnknownRequests: checked,
                })
              }
            />
          </div>
        </div>
      </section>
    </div>
  );
}
