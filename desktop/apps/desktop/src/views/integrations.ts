import type { HooksMode } from "../api/types";
import { h } from "../dom";
import { ADAPTER_STATUS_KO } from "../ko";
import { relativeKo } from "../logic/format";
import { safeText } from "../logic/sanitize";
import { badge, button, kv, section } from "../ui/components";
import { codexChecklist } from "../ui/codexChecklist";
import { simpleView, type ViewCtx } from "../ui/view";

/**
 * Effective-TTL warning (desktop.md section 6 "Integrations"): setting TTL > hook timeout - 30. Without installed hooks
 * the daemon reports a timeout of 0 (nothing to compare against), which must not turn into a negative "effective" TTL.
 */
export function ttlWarning(
  ttl: number | undefined,
  hookTimeoutS: number | undefined,
  hooksInstalled: boolean | undefined,
): { effective: number } | null {
  if (ttl === undefined || hookTimeoutS === undefined || hooksInstalled !== true || !(hookTimeoutS > 0)) return null;
  const effective = hookTimeoutS - 30;
  return ttl > effective ? { effective } : null;
}

export const integrationsView = (ctx: ViewCtx) => {
  let mode: HooksMode = "http";
  return simpleView(
    (s) => [s.status, s.settings, s.hooks, s.codexProbe, s.adapters],
    (s, c, rerender) => {
      const st = s.status;
      const claude = s.hooks.claude_code;
      const now = c.clock();
      const warn = ttlWarning(s.settings?.["approval.ttl_s"], st?.hook_timeout_s, st?.hooks_installed);
      const probe = s.codexProbe;
      const codexAdapter = s.adapters.codex;

      const modeSelect = h("select", { class: "input", "aria-label": "훅 방식", "data-fid": "hooks-mode" }, h("option", { value: "http" }, "HTTP (권장)"), h("option", { value: "cli" }, "CLI (대체)"));
      modeSelect.value = mode;
      modeSelect.addEventListener("change", () => {
        mode = modeSelect.value === "cli" ? "cli" : "http";
        rerender();
      });

      return [
        h("h2", null, "연동"),
        section(
          "Claude Code",
          kv([
            ["훅", badge(claude?.installed ? "설치됨" : "미설치", claude?.installed ? "ok" : "warn")],
            ["설정 파일", claude?.path ? safeText(claude.path, 160) : "-"],
            ["마지막 이벤트", relativeKo(st?.last_event_at.claude_code, now)],
          ]),
          warn
            ? h(
                "div",
                { class: "banner banner-warn", "data-ttl-warning": "1" },
                `승인 시간(${s.settings?.["approval.ttl_s"]}초)이 훅 제한시간보다 길어서 실제로는 ${warn.effective}초만 적용돼요. `,
                button("훅 재설치", () => void c.controller.hooksInstall("claude_code", "http"), { kind: "primary", fid: "hooks-reinstall" }),
              )
            : null,
          ...(claude?.warnings ?? []).map((w) => h("div", { class: "banner banner-warn" }, safeText(w, 200))),
          h("div", { class: "row" }, modeSelect, button(claude?.installed ? "다시 설치" : "설치", () => void c.controller.hooksInstall("claude_code", mode), { kind: "primary", fid: "hooks-install" }), button("제거", () => void c.controller.hooksUninstall("claude_code", mode), { fid: "hooks-uninstall" }), button("점검", () => void c.controller.refreshHooks("claude_code"), { fid: "hooks-check" })),
          h("p", { class: "hint" }, "설치 후 이 프로젝트에서 이벤트가 오지 않으면 Claude Code에서 폴더 신뢰(trust)를 수락해 주세요."),
        ),
        section(
          "Codex",
          kv([
            ["모드", st ? (st.codex_mode === "hooks" ? "hooks" : st.codex_mode === "off" ? "꺼짐" : "관찰 모드") : "-"],
            ["연결 상태", codexAdapter ? badge(ADAPTER_STATUS_KO[codexAdapter.status], codexAdapter.status === "connected" ? "ok" : "warn") : badge("정보 없음", "muted")],
            ["마지막 이벤트", relativeKo(st?.last_event_at.codex, now)],
          ]),
          h("div", { class: "row" }, button("소켓 진단", () => void c.controller.probeCodex(), { fid: "codex-probe" })),
          probe
            ? h(
                "div",
                { class: "hint", "data-codex-probe": "1" },
                probe.reachable ? "Codex에 연결할 수 있어요." : "Codex에 연결하지 못했어요.",
                ` 소켓: ${safeText(probe.socket_path, 160) || "-"} · 스레드 ${probe.threads}개`,
                probe.user_agent ? ` · ${safeText(probe.user_agent, 80)}` : "",
              )
            : null,
          h("h3", null, "Codex hooks 설정 (수동)"),
          h("p", { class: "hint" }, "설치기는 Codex 확인(C6) 전까지 꺼져 있어요. 아래 순서대로 직접 설정해 주세요."),
          codexChecklist(s, c),
        ),
      ];
    },
  )(ctx);
};
