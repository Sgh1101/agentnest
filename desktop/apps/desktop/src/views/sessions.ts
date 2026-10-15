import type { AgentEvent, AgentState, SessionState } from "../api/types";
import { h } from "../dom";
import { REMOTE_APPROVAL_KO, STATE_KO } from "../ko";
import { formatClock, relativeKo } from "../logic/format";
import { safeText } from "../logic/sanitize";
import { badge, button, empty, type Tone } from "../ui/components";
import { simpleView, type ViewCtx } from "../ui/view";

const STATE_TONE: Record<AgentState, Tone> = {
  idle: "muted",
  working: "info",
  writing_code: "info",
  reviewing: "info",
  testing: "info",
  awaiting_approval: "warn",
  awaiting_input: "warn",
  error: "bad",
  completed: "ok",
  disconnected: "muted",
};

export function reviewText(s: SessionState): string | null {
  const r = s.meta.review;
  if (r === null) return null;
  switch (r.state) {
    case "unavailable":
      return "리뷰 정보 없음 (hooks 모드)";
    case "running":
      return "리뷰 중";
    case "completed":
      return `리뷰 결과: P0 ${r.p0} · P1 ${r.p1}`;
    case "none":
      return null;
  }
}

export interface SessionCardOpts {
  nowMs: number;
  timeline?: { open: boolean; events: AgentEvent[] | undefined; toggle: () => void };
}

export function sessionCard(s: SessionState, opts: SessionCardOpts): HTMLElement {
  const lines: Array<HTMLElement | null> = [];
  lines.push(
    h(
      "div",
      { class: "card-meta" },
      badge(STATE_KO[s.state], STATE_TONE[s.state], { "data-state": s.state }),
      s.stale ? badge("오래된 정보", "muted") : null,
      s.pending_approval_ids.length > 0 ? badge(`승인 대기 ${s.pending_approval_ids.length}`, "warn") : null,
    ),
  );
  lines.push(h("div", { class: "session-headline", "data-headline": "1" }, safeText(s.headline, 200)));
  if (s.detail) lines.push(h("div", { class: "hint" }, safeText(s.detail, 200)));
  if (s.remote_approval !== "available") lines.push(h("div", { class: "hint" }, REMOTE_APPROVAL_KO[s.remote_approval]));
  const review = reviewText(s);
  if (review !== null) lines.push(h("div", { class: "hint" }, review));
  if (s.last_test !== null) {
    const t = s.last_test;
    lines.push(h("div", { class: "hint" }, `최근 테스트: ${t.status === "running" ? "실행 중" : t.status === "passed" ? "통과" : "실패"} (${relativeKo(t.at, opts.nowMs)})`));
  }
  lines.push(h("div", { class: "hint" }, `도구 ${s.counters.tools} · 파일 수정 ${s.counters.files_modified} · 명령 ${s.counters.commands} · 오류 ${s.counters.errors} · 마지막 활동 ${relativeKo(s.last_event_at, opts.nowMs)}`));

  const card = h(
    "article",
    { class: "card session", "data-session-key": s.session_key },
    h("header", { class: "card-head" }, h("div", { class: "card-who" }, h("strong", null, safeText(s.agent_label, 40)), " · ", safeText(s.project.name, 60), s.project.branch ? ` (${safeText(s.project.branch, 40)})` : "")),
    ...lines,
  );
  if (opts.timeline) {
    const tl = opts.timeline;
    card.append(button(tl.open ? "최근 활동 접기" : "최근 활동 보기", tl.toggle, { fid: `tl-${s.session_key}` }));
    if (tl.open) {
      card.append(
        tl.events === undefined
          ? h("p", { class: "hint" }, "불러오는 중…")
          : tl.events.length === 0
            ? h("p", { class: "hint" }, "기록이 없어요.")
            : h("ul", { class: "timeline" }, ...tl.events.map((e) => h("li", null, h("span", { class: "time" }, formatClock(e.ts)), " ", safeText(e.headline, 120)))),
      );
    }
  }
  return card;
}

export const sessionsView = (ctx: ViewCtx) => {
  const open = new Set<string>();
  const cache = new Map<string, AgentEvent[]>();
  return simpleView(
    (s) => [s.sessions],
    (s, c, rerender) => {
      const now = c.clock();
      const mk = (x: SessionState): HTMLElement =>
        sessionCard(x, {
          nowMs: now,
          timeline: {
            open: open.has(x.session_key),
            events: cache.get(x.session_key),
            toggle: () => {
              if (open.has(x.session_key)) open.delete(x.session_key);
              else {
                open.add(x.session_key);
                void c.controller.loadSessionEvents(x.session_key).then((ev) => {
                  cache.set(x.session_key, ev);
                  rerender();
                });
              }
              rerender();
            },
          },
        });
      const active = s.sessions.filter((x) => !x.ended);
      const ended = s.sessions.filter((x) => x.ended);
      return [
        h("h2", null, "세션"),
        active.length === 0 ? empty("지금 활동 중인 세션이 없어요.") : h("div", { class: "cards" }, ...active.map(mk)),
        ended.length > 0 ? h("details", { class: "ended" }, h("summary", null, `종료된 세션 (${ended.length})`), h("div", { class: "cards" }, ...ended.map(mk))) : null,
      ];
    },
  )(ctx);
};
