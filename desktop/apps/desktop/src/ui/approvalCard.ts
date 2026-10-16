/**
 * Pending approval card with local Allow / Deny / "handle locally" (docs/desktop.md section 6).
 * The card is created once per request and patched in place, so a hold in progress or a ticked
 * checkbox survives unrelated store updates.
 */
import type { ApprovalDelivery, ApprovalPending, Decision } from "../api/types";
import { append, h, type Child } from "../dom";
import {
  HOLD_MS,
  decisionAvailability,
  denyMeansStop,
  isDenyOnlyCodex,
  isExpired,
  requiredGate,
  type CardUiState,
} from "../logic/approvalGate";
import { formatCountdown } from "../logic/format";
import { HoldGate } from "../logic/hold";
import { safeText, truncate, visualize } from "../logic/sanitize";
import { badge, riskBadge } from "./components";
import type { ViewCtx } from "./view";

const COMMAND_PREVIEW_CHARS = 300;
const MAX_PATHS_SHOWN = 5;

export function deliveryText(d: ApprovalDelivery): string {
  if (d.sent_to.length === 0) return "휴대폰에 보내지 않았어요 (PC에서 처리)";
  const parts = [`전송됨 (${d.sent_to.map((n) => safeText(n, 40)).join(", ")})`];
  if (d.acked) parts.push("휴대폰이 받음");
  if (d.seen) parts.push("열어봄");
  return parts.join(" · ");
}

export class ApprovalCard {
  readonly el: HTMLElement;
  private approval: ApprovalPending;
  private readonly ui: CardUiState = { reconfirmChecked: false, busy: false };
  private readonly buttons = new Map<Decision, HTMLButtonElement>();
  private readonly holds = new Map<Decision, HoldGate>();
  private handoffBtn!: HTMLButtonElement;
  private countdownEl!: HTMLElement;
  private deliveryEl!: HTMLElement;
  private expiredEl!: HTMLElement;
  private checkbox: HTMLInputElement | null = null;
  private gateHintEl!: HTMLElement;

  constructor(
    approval: ApprovalPending,
    private readonly ctx: ViewCtx,
  ) {
    this.approval = approval;
    this.el = h("article", { class: `card approval risk-${approval.risk.level}`, "data-request-id": approval.request_id });
    this.build();
    this.tick(this.ctx.clock());
  }

  private add(...children: Child[]): void {
    append(this.el, children);
  }

  get request(): ApprovalPending {
    return this.approval;
  }

  /** True while any hold-to-confirm press is in progress. */
  get holdActive(): boolean {
    return [...this.holds.values()].some((g) => g.active);
  }

  /** Update delivery info. A changed hash/risk for the same id means a different request: caller rebuilds. */
  update(a: ApprovalPending): void {
    this.approval = a;
    this.deliveryEl.textContent = deliveryText(a.delivery);
  }

  tick(nowMs: number): void {
    this.countdownEl.textContent = formatCountdown(Date.parse(this.approval.expires_at) - nowMs);
    this.refreshAvailability(nowMs);
  }

  destroy(): void {
    for (const g of this.holds.values()) g.cancel();
  }

  // ---------------------------------------------------------------------------

  private build(): void {
    const a = this.approval;
    const gate = requiredGate(a.risk);
    this.countdownEl = h("span", { class: "countdown", "data-countdown-until": String(Date.parse(a.expires_at)) });
    this.deliveryEl = h("div", { class: "delivery", "data-delivery": "1" }, deliveryText(a.delivery));
    this.expiredEl = h("div", { class: "banner banner-warn", hidden: true }, "시간이 지났어요. 에이전트의 로컬 화면에서 처리돼요.");

    const head = h(
      "header",
      { class: "card-head" },
      h("div", { class: "card-who" }, h("strong", null, safeText(a.agent_label, 40)), " · ", safeText(a.project.name, 60), a.project.branch ? ` (${safeText(a.project.branch, 40)})` : ""),
      h("div", { class: "card-meta" }, riskBadge(a.risk.level), h("span", { class: "time-left" }, "남은 시간 ", this.countdownEl)),
    );

    this.add(head, h("h3", { class: "card-title" }, safeText(a.title, 80)), h("div", { class: "tool" }, `도구: ${safeText(a.tool_name, 80)}`));

    // What will happen: command / paths / diff / mcp server. All as text nodes.
    const d = a.details;
    if (d.command !== null) {
      const full = d.command;
      this.add(
        h("div", { class: "label" }, "명령"),
        h("pre", { class: "code", "data-command-preview": "1" }, truncate(visualize(full), COMMAND_PREVIEW_CHARS)),
        full.length > COMMAND_PREVIEW_CHARS ? h("div", { class: "hint" }, `전체 ${full.length}자 중 일부만 보여요.`) : null,
        // Critical requests re-show the whole command below; for the rest, make the hidden tail reachable.
        full.length > COMMAND_PREVIEW_CHARS && gate !== "hold_and_reconfirm"
          ? h("details", { "data-command-expanded-block": "1" }, h("summary", null, "전체 명령 보기"), h("pre", { class: "code code-full", "data-command-expanded": "1" }, visualize(full)))
          : null,
      );
    }
    if (d.cwd_hint) this.add(h("div", { class: "hint", title: visualize(d.cwd_hint) }, `위치: ${safeText(d.cwd_hint, 120)}`));
    if (d.mcp_server) this.add(h("div", { class: "hint" }, `MCP 서버: ${safeText(d.mcp_server, 80)}`));
    if (d.file_paths.length > 0) {
      const shown = d.file_paths.slice(0, MAX_PATHS_SHOWN);
      const rest = d.file_paths.slice(MAX_PATHS_SHOWN);
      // `title` carries the full path for hover; the visible text is length-limited and wraps.
      const item = (p: string): HTMLElement => h("li", { title: visualize(p) }, safeText(p, 200));
      this.add(
        h("div", { class: "label" }, "대상 파일"),
        h(
          "ul",
          { class: "paths" },
          ...shown.map(item),
          rest.length > 0 ? h("li", { class: "paths-more" }, h("details", null, h("summary", { class: "hint" }, `외 ${rest.length}개 더 보기`), h("ul", { class: "paths" }, ...rest.map(item)))) : null,
        ),
      );
    }
    if (d.diff_preview) {
      this.add(h("details", null, h("summary", null, "변경 내용 미리보기"), h("pre", { class: "code" }, visualize(d.diff_preview))));
    }
    if (d.content_preview) {
      this.add(h("details", null, h("summary", null, "새 파일 내용 미리보기"), h("pre", { class: "code" }, visualize(d.content_preview))));
    }
    if (d.truncated) this.add(h("div", { class: "hint" }, "내용이 길어 일부만 보여요."));

    if (a.risk.reasons_ko.length > 0) {
      this.add(h("div", { class: "reasons-box" }, h("div", { class: "label" }, "위험하다고 본 이유"), h("ul", { class: "reasons" }, ...a.risk.reasons_ko.map((r) => h("li", null, safeText(r, 120))))));
    }

    // Critical: re-show the whole command and require an explicit "I checked" box (desktop.md section 6).
    if (gate === "hold_and_reconfirm") {
      const checkbox = h("input", { type: "checkbox", "data-reconfirm": "1", "data-fid": `reconfirm-${a.request_id}` });
      this.checkbox = checkbox;
      checkbox.addEventListener("change", () => {
        this.ui.reconfirmChecked = checkbox.checked;
        this.refreshAvailability(this.ctx.clock());
      });
      this.add(
        h(
          "div",
          { class: "reconfirm", "data-reconfirm-block": "1" },
          // A cut card never shows the whole command, so the label must not claim it does: say so and send the user to the
          // local prompt of the agent, which shows the real command.
          h("div", { class: "label" }, d.truncated ? "표시된 내용 다시 확인 (일부만 보여요)" : "전체 명령 다시 확인"),
          d.truncated
            ? h("div", { class: "hint", "data-truncated-warning": "1" }, "명령이 길어서 전부 보여드릴 수 없어요. 뒷부분을 확인할 수 없으니 허용하지 말고 PC의 에이전트 화면에서 직접 확인하세요.")
            : null,
          h("pre", { class: "code code-full", "data-command-full": "1" }, visualize(d.command ?? d.file_paths.join("\n"))),
          h("label", { class: "check-label" }, checkbox, " 내용을 확인했어요"),
        ),
      );
    }

    // purpose is agent-written and unverified: small, below command and risk (protocol.md 6.1).
    if (a.purpose) {
      this.add(h("p", { class: "purpose", "data-purpose": "1" }, h("span", { class: "purpose-label" }, "에이전트가 한 말 (검증 안 됨): "), safeText(a.purpose, 200)));
    }

    this.add(this.deliveryEl);
    if (isDenyOnlyCodex(a)) this.add(h("div", { class: "hint", "data-codex-note": "1" }, "거부만 가능 (Codex hooks는 작업을 멈출 수 없어요)"));
    if (denyMeansStop(a)) this.add(h("div", { class: "hint" }, "이 요청은 거부하면 작업이 중단돼요."));
    this.add(this.expiredEl);

    this.handoffBtn = h("button", { type: "button", class: "btn btn-decision", "data-action": "handoff", onClick: () => void this.handoff() }, "로컬로 처리");
    // Tab order: safe actions first, allow last and visually separated.
    const safe = h("div", { class: "actions-safe" }, this.handoffBtn);
    const actions = h("div", { class: "actions" }, safe);
    for (const dec of ["deny_and_stop", "deny", "allow"] as const) {
      if (!a.allowed_decisions.includes(dec)) continue;
      const btn = this.makeDecisionButton(dec);
      this.buttons.set(dec, btn);
      if (dec === "allow") actions.append(h("div", { class: "actions-allow" }, btn));
      else safe.append(btn);
    }
    this.gateHintEl = h("div", { class: "gate-hint", "data-gate-hint": "1", hidden: true }, "‘내용을 확인했어요’에 체크하면 허용 버튼을 길게 눌러 진행할 수 있어요.");
    this.add(actions, this.gateHintEl);
  }

  private label(dec: Decision, mode: "click" | "hold"): string {
    const base = dec === "allow" ? "허용" : dec === "deny" ? "거부" : denyMeansStop(this.approval) ? "거부 (작업 중단)" : "거부하고 중단";
    return mode === "hold" ? `${base} (길게 누르기)` : base;
  }

  private makeDecisionButton(dec: Decision): HTMLButtonElement {
    const av = decisionAvailability(this.approval, dec, this.ui, this.ctx.clock());
    const kind = dec === "allow" ? "btn-allow" : dec === "deny" ? "btn-deny" : "btn-deny-stop";
    const btn = h("button", { type: "button", class: `btn btn-decision ${kind}${av.mode === "hold" ? " btn-hold" : ""}`, "data-decision": dec, "data-mode": av.mode }, this.label(dec, av.mode));
    if (av.mode === "click") {
      btn.addEventListener("click", () => void this.perform(dec, false));
      return btn;
    }
    // Hold-to-confirm: pointer or keyboard press must last HOLD_MS; click alone does nothing.
    btn.style.setProperty("--hold-ms", `${HOLD_MS}ms`);
    const gate = new HoldGate(
      HOLD_MS,
      () => void this.perform(dec, true),
      (active) => btn.classList.toggle("holding", active),
    );
    this.holds.set(dec, gate);
    const startPointer = (e: Event): void => {
      if (e instanceof MouseEvent && e.button !== 0) return;
      if (btn.disabled) return;
      gate.start();
    };
    btn.addEventListener("pointerdown", startPointer);
    for (const t of ["pointerup", "pointerleave", "pointercancel", "blur"]) btn.addEventListener(t, () => gate.cancel());
    btn.addEventListener("keydown", (e) => {
      if ((e.key === " " || e.key === "Enter") && !e.repeat && !btn.disabled) {
        e.preventDefault();
        gate.start();
      }
    });
    btn.addEventListener("keyup", (e) => {
      if (e.key === " " || e.key === "Enter") gate.cancel();
    });
    btn.addEventListener("click", (e) => e.preventDefault());
    return btn;
  }

  private refreshAvailability(nowMs: number): void {
    const expired = isExpired(this.approval, nowMs);
    this.expiredEl.hidden = !expired;
    for (const [dec, btn] of this.buttons) {
      const av = decisionAvailability(this.approval, dec, this.ui, nowMs);
      btn.disabled = !av.enabled;
      if (!av.enabled) this.holds.get(dec)?.cancel();
      btn.title = av.blockedReason === "reconfirm" ? "아래 '내용을 확인했어요'를 먼저 체크하세요" : "";
    }
    this.handoffBtn.disabled = expired || this.ui.busy;
    // Say why Allow is greyed out instead of leaving it to a tooltip.
    const allow = this.buttons.get("allow");
    const reconfirmBlocked = allow !== undefined && !expired && decisionAvailability(this.approval, "allow", this.ui, nowMs).blockedReason === "reconfirm";
    this.gateHintEl.hidden = !reconfirmBlocked;
  }

  private async perform(dec: Decision, gatePassed: boolean): Promise<void> {
    const av = decisionAvailability(this.approval, dec, this.ui, this.ctx.clock());
    if (!av.enabled) return;
    this.ui.busy = true;
    this.refreshAvailability(this.ctx.clock());
    try {
      await this.ctx.controller.decide(this.approval, dec, gatePassed);
    } finally {
      this.ui.busy = false;
      this.refreshAvailability(this.ctx.clock());
    }
  }

  private async handoff(): Promise<void> {
    if (this.ui.busy) return;
    this.ui.busy = true;
    this.refreshAvailability(this.ctx.clock());
    try {
      await this.ctx.controller.handoffLocal(this.approval);
    } finally {
      this.ui.busy = false;
      this.refreshAvailability(this.ctx.clock());
    }
  }

  /** For tests: whether the reconfirm checkbox exists. */
  get reconfirmCheckbox(): HTMLInputElement | null {
    return this.checkbox;
  }
}

export function pendingBadge(count: number): HTMLElement | null {
  return count > 0 ? badge(String(count), "warn", { "data-pending-count": "1" }) : null;
}
