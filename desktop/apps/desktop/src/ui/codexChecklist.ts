/** Codex hooks onboarding checklist (docs/desktop.md 6.1 item 4). Manual steps are persisted in settings. */
import type { CodexOnboardingStep } from "../api/types";
import { h } from "../dom";
import { CODEX_HOOKS_PATH } from "../integrations/codexDraft";
import { relativeKo } from "../logic/format";
import type { AppState } from "../store";
import { badge, button } from "./components";
import type { ViewCtx } from "./view";

async function copyText(ctx: ViewCtx, text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    ctx.controller.toast("success", "복사했어요.");
  } catch {
    ctx.controller.toast("error", "복사하지 못했어요. 직접 선택해서 복사해 주세요.");
  }
}

function manualStep(ctx: ViewCtx, step: CodexOnboardingStep, done: boolean, title: string, body: Array<Node | string>): HTMLElement {
  const box = h("input", { type: "checkbox", "data-codex-step": step, "data-fid": `codex-step-${step}` });
  box.checked = done;
  box.addEventListener("change", () => void ctx.controller.toggleCodexStep(step));
  return h("li", { class: `check check-stack ${done ? "check-ok" : "check-pending"}` }, h("label", { class: "check-label" }, box, " ", h("strong", null, title)), h("div", { class: "check-detail" }, ...body));
}

export function codexChecklist(state: AppState, ctx: ViewCtx): HTMLElement {
  const done = state.settings?.["onboarding.codex_steps_done"] ?? [];
  const lastCodex = state.status?.last_event_at.codex ?? null;
  // built by the daemon with the real hook program path and the current TTL (null until the first status arrives)
  const draft = state.hooks.codex?.codex_draft ?? null;
  const doctor = state.hooks.codex?.doctor_command ?? null;
  const mode = state.status?.codex_mode ?? "off";

  return h(
    "ol",
    { class: "checklist", "data-codex-checklist": "1" },
    manualStep(ctx, "hooks_json", done.includes("hooks_json"), "hooks.json 저장", [
      h("p", null, `아래 초안을 복사해 ${CODEX_HOOKS_PATH} 에 저장하세요.`),
      h("p", { class: "hint" }, "초안이에요: 최상위 구조는 Codex 확인(C6) 전까지 바뀔 수 있어요."),
      draft !== null
        ? h("details", null, h("summary", null, "hooks.json 초안 보기"), h("pre", { class: "code", "data-codex-draft": "1" }, draft))
        : h("p", { class: "hint" }, "초안을 불러오는 중이에요. 잠시 뒤에도 보이지 않으면 데몬 상태를 확인해 주세요."),
      button("초안 복사", () => (draft !== null ? void copyText(ctx, draft) : undefined), { fid: "codex-copy", disabled: draft === null }),
    ]),
    manualStep(ctx, "trust", done.includes("trust"), "Codex에서 hooks 신뢰(trust)", [
      h("p", null, "Codex 화면에서 /hooks 를 열어 AgentNest 항목을 trust 하세요. 신뢰하지 않은 훅은 실행되지 않아요."),
    ]),
    manualStep(ctx, "doctor", done.includes("doctor"), "연결 점검", [
      doctor !== null
        ? h("p", null, "터미널에서 ", h("code", { "data-codex-doctor": "1" }, doctor), " 를 실행해 PC 앱 연결과 토큰을 점검하세요.")
        : h("p", null, "훅 프로그램의 doctor 명령으로 PC 앱 연결과 토큰을 점검하세요. (경로를 불러오는 중이에요)"),
    ]),
    h(
      "li",
      { class: `check check-stack ${lastCodex !== null ? "check-ok" : "check-pending"}`, "data-codex-first-event": "1" },
      h("strong", null, lastCodex !== null ? "첫 이벤트를 받았어요" : "첫 이벤트 수신 확인"),
      h("div", { class: "check-detail" }, lastCodex !== null ? `마지막 수신: ${relativeKo(lastCodex, ctx.clock())}` : "Codex에서 명령을 하나 실행하면 여기에 표시돼요."),
    ),
    h(
      "li",
      { class: "check check-stack check-info" },
      h("strong", null, "상태"),
      h(
        "div",
        { class: "check-detail" },
        h("div", null, badge("Codex 승인: 관찰만", "muted"), " ", mode === "hooks" ? badge("리뷰 결과: 수집 불가 (hooks 모드)", "muted") : null),
        h("div", { class: "hint" }, "Codex 승인 연동은 확인(C6)이 끝나면 켜져요. 그 전에는 PC의 Codex 화면에서 직접 승인해요."),
      ),
    ),
  );
}
