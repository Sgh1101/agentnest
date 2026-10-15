/**
 * Local approval gating (docs/desktop.md section 6, security.md 6.2.1 step 8).
 *
 * The desktop is a second approve path, not a weaker one:
 *  - `low`/`medium` (extra_confirmation none): one click.
 *  - `high` (hold): the allow button must be held for 1.5 s.
 *  - `critical` (hold_and_reconfirm): full command re-shown + "I checked" box + hold.
 * Only after the gate is passed do we send `confirm_ack = true`; the Rust side re-validates.
 * Plain `deny` is never gated (safe direction). `deny_and_stop` follows `auth_required_for`
 * because the server applies step 8 to every decision in that list (security.md 6.2 step 8).
 */
import type { ApprovalRequest, DecideLocalArgs, Decision, ExtraConfirmation, RiskLevel } from "../api/types";

export const HOLD_MS = 1500;

const RANK: Record<ExtraConfirmation, number> = { none: 0, hold: 1, hold_and_reconfirm: 2 };

/** Minimum gate implied by the risk level, in case `extra_confirmation` is inconsistent. */
export function levelFloor(level: RiskLevel): ExtraConfirmation {
  switch (level) {
    case "low":
    case "medium":
      return "none";
    case "high":
      return "hold";
    case "critical":
      return "hold_and_reconfirm";
  }
}

/** The stronger of the server's `extra_confirmation` and the level floor (fail-closed). */
export function requiredGate(risk: ApprovalRequest["risk"]): ExtraConfirmation {
  const a = risk.extra_confirmation;
  const b = levelFloor(risk.level);
  return RANK[a] >= RANK[b] ? a : b;
}

export function isExpired(a: Pick<ApprovalRequest, "expires_at">, nowMs: number): boolean {
  const t = Date.parse(a.expires_at);
  // An unparseable expiry is treated as already expired (fail closed).
  return Number.isNaN(t) || nowMs >= t;
}

export function isGatedDecision(a: ApprovalRequest, d: Decision): boolean {
  if (requiredGate(a.risk) === "none") return false;
  if (d === "allow") return true;
  if (d === "deny_and_stop") return a.auth_required_for.includes("deny_and_stop");
  return false;
}

export interface CardUiState {
  reconfirmChecked: boolean;
  busy: boolean;
}

export type BlockedReason = "expired" | "busy" | "reconfirm" | "not_allowed" | null;

export interface DecisionAvailability {
  /** Whether the card shows this decision at all. */
  visible: boolean;
  enabled: boolean;
  /** `hold` = must be long-pressed for HOLD_MS; `click` = plain click. */
  mode: "click" | "hold";
  blockedReason: BlockedReason;
}

export function decisionAvailability(a: ApprovalRequest, d: Decision, ui: CardUiState, nowMs: number): DecisionAvailability {
  const visible = a.allowed_decisions.includes(d);
  const gated = isGatedDecision(a, d);
  const mode = gated ? "hold" : "click";
  if (!visible) return { visible, enabled: false, mode, blockedReason: "not_allowed" };
  if (isExpired(a, nowMs)) return { visible, enabled: false, mode, blockedReason: "expired" };
  if (ui.busy) return { visible, enabled: false, mode, blockedReason: "busy" };
  if (gated && requiredGate(a.risk) === "hold_and_reconfirm" && !ui.reconfirmChecked) {
    return { visible, enabled: false, mode, blockedReason: "reconfirm" };
  }
  return { visible, enabled: true, mode, blockedReason: null };
}

/**
 * Build the `approval_decide_local` arguments. `gatePassed` must be true for gated decisions
 * (hold completed, reconfirm checked); otherwise this throws instead of sending a weaker request.
 */
export function buildDecideArgs(a: ApprovalRequest, d: Decision, gatePassed: boolean, reason?: string): DecideLocalArgs {
  const gated = isGatedDecision(a, d);
  if (gated && !gatePassed) throw new Error("gate not passed");
  const args: DecideLocalArgs = {
    request_id: a.request_id,
    decision: d,
    tool_input_sha256: a.tool_input_sha256,
    confirm_ack: gated && gatePassed,
  };
  if (reason !== undefined) args.reason = reason;
  return args;
}

/**
 * Tray rule (desktop.md section 4), implemented in Rust; kept here as an executable spec:
 * handoff and "open approval window" always; inline allow/deny only for low/medium.
 */
export function trayInlineActions(level: RiskLevel): { handoff: true; openWindow: true; allow: boolean; deny: boolean } {
  const inline = level === "low" || level === "medium";
  return { handoff: true, openWindow: true, allow: inline, deny: inline };
}

/** When `deny` is not offered (Codex without decline) the card labels deny_and_stop as "deny = stop". */
export function denyMeansStop(a: ApprovalRequest): boolean {
  return !a.allowed_decisions.includes("deny") && a.allowed_decisions.includes("deny_and_stop");
}

/** Codex hooks cannot stop the agent: card says "deny only". */
export function isDenyOnlyCodex(a: ApprovalRequest): boolean {
  return a.origin === "codex.hook.cli";
}
