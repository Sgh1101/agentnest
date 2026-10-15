import { h } from "../dom";
import { ADAPTER_STATUS_KO } from "../ko";
import { formatDateTime, relativeKo } from "../logic/format";
import { safeText } from "../logic/sanitize";
import { badge, button, empty, kv, section } from "../ui/components";
import { simpleView } from "../ui/view";
import { sessionCard } from "./sessions";

export const statusView = simpleView(
  (s) => [s.status, s.sessions, s.adapters, s.approvals.length, s.devices],
  (s, ctx) => {
    const st = s.status;
    const now = ctx.clock();
    if (st === null) {
      return [h("h2", null, "상태"), h("div", { class: "banner banner-bad" }, "PC 앱의 데몬 상태를 가져오지 못했어요. 앱을 다시 시작해 보세요.")];
    }
    const codexNeedsSetup = st.codex_mode === "hooks" && st.last_event_at.codex === null;
    const codexAdapter = s.adapters.codex;
    const active = s.sessions.filter((x) => !x.ended);

    return [
      h("h2", null, "상태"),
      section(
        "PC 앱",
        kv([
          ["데몬", badge(st.running ? "실행 중" : "멈춤", st.running ? "ok" : "bad")],
          ["훅 수신 포트", `127.0.0.1:${st.hook_port}`],
          ["휴대폰 연결 주소", st.link_enabled ? safeText(st.wss_addr, 80) || "-" : "연결 꺼짐"],
          ["PC 주소 목록", st.hosts.length > 0 ? st.hosts.map((x) => safeText(x, 64)).join(", ") : "-"],
          ["휴대폰 연결", badge(st.link_enabled ? "켜짐" : "꺼짐", st.link_enabled ? "ok" : "warn", { "data-link": st.link_enabled ? "on" : "off" })],
          ["원격 승인", badge(st.remote_approval_paused ? "일시정지" : "사용 중", st.remote_approval_paused ? "warn" : "ok")],
          ["온라인 휴대폰", `${st.devices_online}대`],
          ["인증서 만료", formatDateTime(st.cert_expires_at)],
        ]),
      ),
      section(
        "에이전트 연동",
        kv([
          [
            "Claude Code",
            h(
              "span",
              null,
              badge(st.hooks_installed ? "훅 설치됨" : "훅 미설치", st.hooks_installed ? "ok" : "warn"),
              " ",
              `마지막 이벤트: ${relativeKo(st.last_event_at.claude_code, now)}`,
            ),
          ],
          [
            "Codex",
            h(
              "span",
              null,
              badge(st.codex_mode === "hooks" ? "hooks 모드" : st.codex_mode === "off" ? "꺼짐" : "관찰 모드", "muted"),
              " ",
              codexAdapter ? badge(ADAPTER_STATUS_KO[codexAdapter.status], codexAdapter.status === "connected" ? "ok" : "warn") : null,
              " ",
              `마지막 이벤트: ${relativeKo(st.last_event_at.codex, now)}`,
              codexNeedsSetup ? h("span", null, " ", badge("Codex hooks 설정 필요", "warn", { "data-codex-setup": "1" })) : null,
            ),
          ],
        ]),
        h("div", { class: "row" }, button("연동 설정 열기", () => ctx.controller.navigate("integrations")), button("첫 실행 체크리스트 다시 열기", () => ctx.controller.navigate("onboarding"))),
      ),
      section(`활성 세션 (${active.length})`, active.length === 0 ? empty("지금 활동 중인 세션이 없어요.") : h("div", { class: "cards" }, ...active.map((x) => sessionCard(x, { nowMs: now })))),
      s.approvals.length > 0
        ? h("div", { class: "banner banner-warn" }, `승인 대기 ${s.approvals.length}건이 있어요. `, button("승인 화면으로", () => ctx.controller.navigate("approvals"), { kind: "primary" }))
        : null,
    ];
  },
);
