import { h } from "../dom";
import { relativeKo } from "../logic/format";
import { badge, button, checkRow } from "../ui/components";
import { codexChecklist } from "../ui/codexChecklist";
import { simpleView } from "../ui/view";
import { diagnosticsChecks, networkReady } from "./diagnostics";

/** First-run checklist (docs/desktop.md 6.1). Each item shows a measured pass/fail. */
export const onboardingView = simpleView(
  (s) => [s.settings, s.diagnostics, s.diagnosticsBusy, s.status, s.hooks, s.devices],
  (s, ctx) => {
    const c = ctx.controller;
    const r1 = s.settings?.["risk.accepted"].includes("R1") === true;
    const net = networkReady(s.diagnostics);
    const hooks = s.status?.hooks_installed === true;
    const claudeSeen = s.status?.last_event_at.claude_code ?? null;
    const paired = s.devices.some((d) => d.revoked_at === null);
    const canPair = r1 && net;
    const linkOn = s.status?.link_enabled !== false;

    return [
      h("h2", null, "첫 실행 체크리스트"),
      h("p", { class: "hint" }, "휴대폰을 연결하려면 아래 순서대로 확인해 주세요. 항목은 실제 상태를 측정해서 표시해요."),
      h(
        "ol",
        { class: "checklist onboarding", "data-onboarding": "1" },
        checkRow(
          r1 ? true : null,
          "1. 수용된 위험 확인 (R1)",
          h(
            "div",
            null,
            h("p", null, "PC의 TLS 키·훅 토큰이 Windows 보호 저장소(DPAPI)가 아닌 사용자 전용 파일에 저장돼요. (후속 단계에서 개선 예정)"),
            r1 ? badge("확인했어요", "ok") : button("이해했어요", () => void c.acceptRiskR1(), { kind: "primary", fid: "ob-r1" }),
          ),
        ),
        checkRow(
          s.diagnostics === null ? null : net,
          "2. 네트워크·방화벽",
          h(
            "div",
            null,
            button(s.diagnosticsBusy ? "진단 중…" : "연결 진단 실행", () => void c.runDiagnostics(), { fid: "ob-diag", disabled: s.diagnosticsBusy }),
            s.diagnostics ? h("ul", { class: "checklist nested" }, ...diagnosticsChecks(s.diagnostics, ctx, linkOn)) : null,
          ),
        ),
        checkRow(
          hooks && claudeSeen !== null ? true : null,
          "3. Claude Code 훅 설치",
          h(
            "div",
            null,
            h("div", null, badge(hooks ? "훅 설치됨" : "훅 미설치", hooks ? "ok" : "warn"), " ", claudeSeen !== null ? `첫 이벤트 수신: ${relativeKo(claudeSeen, ctx.clock())}` : "아직 이벤트를 받지 못했어요."),
            button(hooks ? "다시 설치" : "설치", () => void c.hooksInstall("claude_code", "http"), { kind: "primary", fid: "ob-hooks" }),
            h("p", { class: "hint" }, "이 프로젝트에서 이벤트가 오지 않으면 Claude Code에서 폴더 신뢰(trust)를 수락해 주세요. 설치 후 Claude Code에서 아무 명령이나 실행하면 확인돼요."),
          ),
        ),
        h("li", { class: "check check-stack check-info", "data-onboarding-codex": "1" }, h("div", { class: "check-body" }, h("strong", null, "4. Codex hooks (Codex를 쓸 때만, 수동)"), h("div", { class: "check-detail" }, codexChecklist(s, ctx)))),
        checkRow(
          paired ? true : canPair ? null : false,
          "5. 기기 추가",
          canPair ? h("div", null, button("기기 추가로 이동", () => c.navigate("pairing"), { kind: "primary", fid: "ob-pair" })) : "1번과 2번이 모두 통과해야 기기를 추가할 수 있어요.",
        ),
      ),
      h("div", { class: "row" }, button("나중에 하기", () => c.navigate("status"), { fid: "ob-later" }), button("완료", () => void c.completeOnboarding(), { kind: "primary", disabled: !(r1 && net && hooks), fid: "ob-done" })),
    ];
  },
);
