/** Device revoke: the user must type the exact device name (security.md 10). */
import type { Device } from "../api/types";
import type { AppController } from "../controller";
import { h } from "../dom";
import { revokeNameMatches } from "../logic/revoke";
import { safeText } from "../logic/sanitize";
import { openModal } from "./modal";

export function openRevokeDialog(root: HTMLElement, device: Device, controller: AppController): void {
  const input = h("input", {
    type: "text",
    class: "input",
    autocomplete: "off",
    spellcheck: "false",
    "aria-label": "폐기할 기기 이름 입력",
    "data-fid": "revoke-input",
    "data-revoke-input": "1",
  });
  const confirm = h("button", { type: "button", class: "btn btn-danger", disabled: true, "data-action": "revoke-confirm" }, "폐기");
  const cancel = h("button", { type: "button", class: "btn", "data-action": "revoke-cancel" }, "취소");

  const modal = openModal(root, {
    title: "기기를 폐기할까요?",
    labelId: "revoke-title",
    dismissable: true,
    body: [
      h("p", null, "폐기하면 이 휴대폰은 즉시 연결이 끊기고, 다시 연결하려면 처음부터 페어링해야 해요. 되돌릴 수 없어요."),
      h("p", null, "계속하려면 기기 이름 ", h("strong", { "data-revoke-name": "1" }, safeText(device.name, 64)), " 을(를) 그대로 입력하세요."),
      input,
      h("div", { class: "modal-actions" }, cancel, confirm),
    ],
  });

  input.addEventListener("input", () => {
    confirm.disabled = !revokeNameMatches(device.name, input.value);
  });
  cancel.addEventListener("click", () => modal.close());
  confirm.addEventListener("click", () => {
    if (!revokeNameMatches(device.name, input.value)) return;
    confirm.disabled = true;
    void controller.revokeDevice(device, input.value).then((ok) => {
      if (ok) modal.close();
      else confirm.disabled = !revokeNameMatches(device.name, input.value);
    });
  });
  input.focus();
}
