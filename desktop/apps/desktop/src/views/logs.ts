import { h } from "../dom";
import { safeText } from "../logic/sanitize";
import { button, empty } from "../ui/components";
import { simpleView } from "../ui/view";

export const logsView = simpleView(
  (s) => [s.logs],
  (s, ctx) => [
    h("h2", null, "로그"),
    h("p", { class: "hint" }, "최근 200줄이에요. 토큰·비밀번호는 지워진 상태로만 기록돼요."),
    h("div", { class: "row" }, button("새로고침", () => void ctx.controller.refreshLogs(), { fid: "logs-refresh" }), button("로그 폴더 열기", () => void ctx.controller.openLogsDir(), { fid: "logs-open" })),
    s.logs.length === 0 ? empty("표시할 로그가 없어요.") : h("pre", { class: "code logs", "data-logs": "1" }, s.logs.map((l) => safeText(l, 500)).join("\n")),
  ],
);
