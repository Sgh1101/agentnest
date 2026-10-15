import { h } from "../dom";
import { OUTCOME_KO, RESOLVED_BY_KO } from "../ko";
import { formatClock } from "../logic/format";
import { safeText } from "../logic/sanitize";
import { ApprovalCard } from "../ui/approvalCard";
import { badge, empty, riskBadge } from "../ui/components";
import type { ViewFactory } from "../ui/view";
import type { ApprovalHistoryEntry } from "../api/types";

function historyList(history: readonly ApprovalHistoryEntry[]): HTMLElement {
  if (history.length === 0) return empty("아직 처리한 요청이 없어요.");
  return h(
    "ul",
    { class: "history", "data-history": "1" },
    ...history.map((e) =>
      h(
        "li",
        { "data-outcome": e.outcome },
        h("span", { class: "time" }, formatClock(e.resolved_at)),
        " ",
        badge(OUTCOME_KO[e.outcome], e.outcome === "allowed" ? "ok" : e.outcome === "expired" || e.outcome === "failed" ? "warn" : "muted"),
        " ",
        riskBadge(e.risk_level),
        " ",
        safeText(e.title, 80),
        h("span", { class: "hint" }, ` — ${RESOLVED_BY_KO[e.resolved_by]}${e.resolved_device_name ? ` (${safeText(e.resolved_device_name, 40)})` : ""}`),
      ),
    ),
  );
}

/**
 * Approvals page: one ApprovalCard per pending request, patched in place so holds, checkboxes
 * and focus survive store updates. History is rebuilt only when it changes.
 */
export const approvalsView: ViewFactory = (ctx) => {
  const el = h("div", { class: "view" });
  const title = h("h2", null, "승인");
  const note = h("p", { class: "hint" }, "여기서 허용·거부하는 것은 휴대폰과 같은 규칙을 거쳐요. 위험한 작업은 길게 눌러야 해요.");
  const list = h("div", { class: "cards", "data-approvals": "1" });
  const emptyEl = empty("지금 처리할 승인 요청이 없어요.");
  const historyTitle = h("h3", null, "최근 기록 (최대 50건)");
  const historyBox = h("div");
  el.append(title, note, list, emptyEl, historyTitle, historyBox);

  const cards = new Map<string, ApprovalCard>();
  let lastHistory: readonly ApprovalHistoryEntry[] | null = null;

  return {
    el,
    update(s) {
      const wanted = [...s.approvals].sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at));
      const ids = new Set(wanted.map((a) => a.request_id));
      for (const [id, card] of cards) {
        if (!ids.has(id)) {
          card.destroy();
          card.el.remove();
          cards.delete(id);
        }
      }
      for (const a of wanted) {
        const existing = cards.get(a.request_id);
        if (existing && existing.request.tool_input_sha256 === a.tool_input_sha256 && existing.request.risk.extra_confirmation === a.risk.extra_confirmation) {
          existing.update(a);
        } else {
          existing?.destroy();
          existing?.el.remove();
          cards.set(a.request_id, new ApprovalCard(a, ctx));
        }
      }
      // Keep DOM order = sorted order without rebuilding cards.
      wanted.forEach((a, i) => {
        const card = cards.get(a.request_id);
        if (card && list.children[i] !== card.el) list.insertBefore(card.el, list.children[i] ?? null);
      });
      title.textContent = `승인 (대기 ${wanted.length}건)`;
      emptyEl.hidden = wanted.length > 0;
      if (lastHistory !== s.history) {
        lastHistory = s.history;
        historyBox.replaceChildren(historyList(s.history));
      }
    },
    tick(nowMs) {
      for (const c of cards.values()) c.tick(nowMs);
    },
    destroy() {
      for (const c of cards.values()) c.destroy();
    },
  };
};
