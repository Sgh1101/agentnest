import type { RiskLevel } from "../api/types";
import { h, type Child, type Props } from "../dom";
import { RISK_KO } from "../ko";

export type Tone = "ok" | "warn" | "bad" | "info" | "muted";

export function badge(text: string, tone: Tone = "muted", extra?: Props): HTMLSpanElement {
  return h("span", { class: `badge badge-${tone}`, ...extra }, text);
}

export function riskBadge(level: RiskLevel): HTMLSpanElement {
  const tone: Tone = level === "low" ? "ok" : level === "medium" ? "info" : level === "high" ? "warn" : "bad";
  return badge(RISK_KO[level], tone, { "data-risk": level });
}

export function button(label: string, onClick: () => void, opts: { kind?: "primary" | "danger" | "ghost"; disabled?: boolean; fid?: string; title?: string } = {}): HTMLButtonElement {
  return h(
    "button",
    {
      type: "button",
      class: `btn${opts.kind ? ` btn-${opts.kind}` : ""}`,
      disabled: opts.disabled === true ? true : undefined,
      "data-fid": opts.fid,
      title: opts.title,
      onClick: () => onClick(),
    },
    label,
  );
}

export function section(title: string, ...children: Child[]): HTMLElement {
  return h("section", { class: "panel" }, h("h2", null, title), ...children);
}

export function kv(rows: ReadonlyArray<readonly [string, Child]>): HTMLElement {
  const dl = h("dl", { class: "kv" });
  for (const [k, v] of rows) {
    dl.appendChild(h("dt", null, k));
    dl.appendChild(h("dd", null, v));
  }
  return dl;
}

export function empty(text: string): HTMLElement {
  return h("p", { class: "empty" }, text);
}

export function checkRow(ok: boolean | null, label: string, detail?: Child): HTMLElement {
  const mark = ok === null ? "○" : ok ? "✓" : "✗";
  const cls = ok === null ? "check check-pending" : ok ? "check check-ok" : "check check-bad";
  return h("li", { class: cls }, h("span", { class: "check-mark", "aria-hidden": "true" }, mark), h("div", { class: "check-body" }, h("strong", null, label), detail ? h("div", { class: "check-detail" }, detail) : null));
}

export function labelledInput(label: string, input: HTMLElement): HTMLElement {
  return h("label", { class: "field" }, h("span", null, label), input);
}
