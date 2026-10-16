/** SAS confirmation modal (security.md 4.2 step 6-8, 4.3; desktop.md section 6 "Pairing"). */
import type { AppController } from "../controller";
import { h } from "../dom";
import { SAS_APPROVE_DELAY_MS, SasGate, formatSas } from "../logic/sas";
import { safeText } from "../logic/sanitize";
import type { SasPrompt } from "../store";
import { openModal, type ModalHandle } from "./modal";

export class SasModal {
  readonly pairingId: string;
  private readonly handle: ModalHandle;
  private readonly timer: ReturnType<typeof setInterval>;
  private readonly approveBtn: HTMLButtonElement;
  private readonly rejectBtn: HTMLButtonElement;
  private readonly gate: SasGate;
  private readonly sasText: string | null;

  constructor(
    root: HTMLElement,
    private readonly prompt: SasPrompt,
    private readonly controller: AppController,
    private readonly clock: () => number,
  ) {
    this.pairingId = prompt.pairing_id;
    this.gate = new SasGate(prompt.shown_at_ms, prompt.confirm_timeout_ms, SAS_APPROVE_DELAY_MS);
    this.sasText = formatSas(prompt.sas);

    this.approveBtn = h("button", { type: "button", class: "btn btn-primary", disabled: true, "data-action": "sas-approve", onClick: () => void this.decide(true) }, "승인");
    this.rejectBtn = h("button", { type: "button", class: "btn btn-danger", "data-action": "sas-reject", onClick: () => void this.decide(false) }, "거절");

    const d = prompt.device;
    const deviceLine = [d.name, d.model, d.platform].filter((x): x is string => x !== null && x !== "").map((x) => safeText(x, 64)).join(" · ");

    const body = this.sasText
      ? [
          h("p", { class: "sas-question" }, "휴대폰에 표시된 숫자 ", h("strong", { class: "sas-digits", "data-sas": "1" }, this.sasText), " 와 같습니까?"),
        ]
      : [h("p", { class: "banner banner-bad" }, "연결 요청의 확인 숫자가 올바르지 않아요. [거절]을 눌러 주세요.")];

    this.handle = openModal(root, {
      title: "휴대폰을 연결할까요?",
      labelId: "sas-title",
      dismissable: false,
      body: [
        ...body,
        h("p", { class: "sas-device" }, "연결을 요청한 기기: ", h("strong", { "data-sas-device": "1" }, deviceLine || "이름 없는 기기")),
        h("p", { class: "hint" }, "숫자가 다르거나 휴대폰에 아직 숫자가 보이지 않으면 [거절]을 누르세요. 내가 하지 않은 연결 요청이라면 누군가 QR을 먼저 스캔했을 수 있어요."),
        h("p", { class: "hint", "data-sas-remaining": "1" }),
        h("div", { class: "modal-actions" }, this.rejectBtn, this.approveBtn),
      ],
    });

    // Initial focus on the safe choice: a stray Enter/Space rejects instead of approving.
    this.rejectBtn.focus();
    this.timer = setInterval(() => this.refresh(), 250);
    this.refresh();
  }

  private refresh(): void {
    const now = this.clock();
    const remainingEl = this.handle.el.querySelector("[data-sas-remaining]");
    const wait = this.gate.secondsUntilEnabled(now);
    const enabled = this.sasText !== null && this.gate.approveEnabled(now);
    this.approveBtn.disabled = !enabled;
    this.approveBtn.textContent = wait > 0 ? `승인 (${wait}초 뒤 활성)` : "승인";
    if (remainingEl) {
      const left = Math.max(0, Math.ceil((this.prompt.shown_at_ms + this.prompt.confirm_timeout_ms - now) / 1000));
      remainingEl.textContent = `${left}초 안에 선택하지 않으면 자동으로 거절돼요.`;
    }
  }

  private async decide(approve: boolean): Promise<void> {
    this.approveBtn.disabled = true;
    this.rejectBtn.disabled = true;
    const ok = await this.controller.confirmPairing(approve);
    if (!ok) {
      this.rejectBtn.disabled = false;
      this.refresh();
    }
  }

  close(): void {
    clearInterval(this.timer);
    this.handle.close();
  }
}
