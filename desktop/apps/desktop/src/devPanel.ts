/** Scenario buttons for `vite dev` in a plain browser (MockBackend only; never mounted in Tauri). */
import { MockBackend } from "./api/mock";
import { sampleApproval, sampleSession } from "./api/samples";
import type { AppController } from "./controller";
import { h } from "./dom";

export function mountDevPanel(root: HTMLElement, mock: MockBackend, controller: AppController): void {
  let n = 0;
  const id = (): string => `ar_01929f1a-6c2e-7b3c-9e4d-${(++n).toString(16).padStart(12, "0")}`;
  const btn = (label: string, fn: () => void): HTMLButtonElement => h("button", { type: "button", class: "btn btn-small", onClick: fn }, label);
  root.append(
    h(
      "aside",
      { class: "dev-panel", "aria-label": "데모 시나리오" },
      h("strong", null, "데모 시나리오"),
      btn("승인(낮음)", () => mock.simulateApproval("low", id())),
      btn("승인(높음)", () => mock.simulateApproval("high", id())),
      btn("승인(매우 높음)", () => mock.simulateApproval("critical", id())),
      btn("Codex 승인(거부만)", () => mock.pushApproval(sampleApproval({ id: id(), level: "medium", origin: "codex.hook.cli", created_at: new Date().toISOString() }))),
      btn("휴대폰 연결 요청", () => {
        try {
          mock.simulatePairPending({ name: "Galaxy S25", platform: "android", model: "SM-S931" });
        } catch {
          controller.toast("info", "먼저 '기기 추가'에서 QR을 표시하세요.");
        }
      }),
      btn("세션 오류 상태", () => mock.pushSession(sampleSession({ state: "error", headline: "명령이 실패했어요 (exit 1)" }))),
    ),
  );
}
