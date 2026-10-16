import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sampleApproval } from "../src/api/samples";
import { HOLD_MS, buildDecideArgs, decisionAvailability, isExpired, isGatedDecision, levelFloor, requiredGate, trayInlineActions } from "../src/logic/approvalGate";
import { HoldGate } from "../src/logic/hold";
import { SAS_APPROVE_DELAY_MS, SasGate, formatSas } from "../src/logic/sas";
import { revokeNameMatches } from "../src/logic/revoke";
import { hasSuspicious, safeText, truncate, visualize } from "../src/logic/sanitize";
import { T0, click, mountHarness, press, q, qa, release, settle, type Harness } from "./helpers";

const ui = { reconfirmChecked: false, busy: false };

describe("gate logic (pure)", () => {
  it("risk level floor: low/medium none, high hold, critical hold_and_reconfirm", () => {
    expect(levelFloor("low")).toBe("none");
    expect(levelFloor("medium")).toBe("none");
    expect(levelFloor("high")).toBe("hold");
    expect(levelFloor("critical")).toBe("hold_and_reconfirm");
  });

  it("requiredGate never goes below the level floor, even if the daemon says none", () => {
    expect(requiredGate({ level: "critical", reasons: [], reasons_ko: [], extra_confirmation: "none" })).toBe("hold_and_reconfirm");
    expect(requiredGate({ level: "high", reasons: [], reasons_ko: [], extra_confirmation: "none" })).toBe("hold");
    expect(requiredGate({ level: "low", reasons: [], reasons_ko: [], extra_confirmation: "hold" })).toBe("hold");
    expect(requiredGate({ level: "medium", reasons: [], reasons_ko: [], extra_confirmation: "none" })).toBe("none");
  });

  it("allow needs a hold for high/critical; deny never does", () => {
    const low = sampleApproval({ level: "low" });
    const high = sampleApproval({ level: "high" });
    const crit = sampleApproval({ level: "critical" });
    expect(isGatedDecision(low, "allow")).toBe(false);
    expect(isGatedDecision(high, "allow")).toBe(true);
    expect(isGatedDecision(crit, "allow")).toBe(true);
    expect(isGatedDecision(crit, "deny")).toBe(false);
    // deny_and_stop follows auth_required_for (the server applies step 8 to it)
    expect(isGatedDecision(high, "deny_and_stop")).toBe(true);
  });

  it("confirm_ack is true only after the gate passed; gated decisions cannot be built without it", () => {
    const high = sampleApproval({ level: "high" });
    expect(() => buildDecideArgs(high, "allow", false)).toThrow();
    expect(buildDecideArgs(high, "allow", true).confirm_ack).toBe(true);
    expect(buildDecideArgs(high, "deny", false).confirm_ack).toBe(false);
    const low = sampleApproval({ level: "low" });
    const args = buildDecideArgs(low, "allow", false);
    expect(args).toEqual({ request_id: low.request_id, decision: "allow", tool_input_sha256: low.tool_input_sha256, confirm_ack: false });
  });

  it("availability: critical allow needs the reconfirm box; expired/busy disable everything", () => {
    const crit = sampleApproval({ level: "critical", created_at: new Date(T0).toISOString() });
    expect(decisionAvailability(crit, "allow", ui, T0)).toMatchObject({ enabled: false, blockedReason: "reconfirm", mode: "hold" });
    expect(decisionAvailability(crit, "allow", { ...ui, reconfirmChecked: true }, T0).enabled).toBe(true);
    expect(decisionAvailability(crit, "deny", ui, T0).enabled).toBe(true);
    expect(decisionAvailability(crit, "deny", ui, T0 + 120_000)).toMatchObject({ enabled: false, blockedReason: "expired" });
    expect(decisionAvailability(crit, "deny", { ...ui, busy: true }, T0).blockedReason).toBe("busy");
    const codex = sampleApproval({ level: "low", origin: "codex.hook.cli" });
    expect(decisionAvailability(codex, "deny_and_stop", ui, T0).visible).toBe(false);
  });

  it("an unparseable expires_at counts as expired (fail closed)", () => {
    expect(isExpired({ expires_at: "garbage" }, T0)).toBe(true);
  });

  it("tray: inline allow/deny only for low/medium; handoff and open-window always", () => {
    expect(trayInlineActions("low")).toEqual({ handoff: true, openWindow: true, allow: true, deny: true });
    expect(trayInlineActions("medium").allow).toBe(true);
    expect(trayInlineActions("high")).toEqual({ handoff: true, openWindow: true, allow: false, deny: false });
    expect(trayInlineActions("critical").allow).toBe(false);
  });
});

describe("HoldGate / SasGate / helpers", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("HoldGate completes once after the duration and cancels on release", () => {
    const done = vi.fn();
    const g = new HoldGate(HOLD_MS, done);
    g.start();
    g.start();
    vi.advanceTimersByTime(HOLD_MS - 1);
    expect(done).not.toHaveBeenCalled();
    g.cancel();
    vi.advanceTimersByTime(10);
    expect(done).not.toHaveBeenCalled();
    g.start();
    vi.advanceTimersByTime(HOLD_MS);
    expect(done).toHaveBeenCalledTimes(1);
    expect(g.active).toBe(false);
  });

  it("HOLD_MS is 1.5 s and SAS delay is 2 s", () => {
    expect(HOLD_MS).toBe(1500);
    expect(SAS_APPROVE_DELAY_MS).toBe(2000);
  });

  it("SasGate enables approve exactly at 2 s and expires at the confirm timeout", () => {
    const g = new SasGate(1000, 60_000);
    expect(g.approveEnabled(1000)).toBe(false);
    expect(g.approveEnabled(2999)).toBe(false);
    expect(g.approveEnabled(3000)).toBe(true);
    expect(g.secondsUntilEnabled(1500)).toBe(2);
    expect(g.approveEnabled(61_000)).toBe(false);
    expect(g.expired(61_000)).toBe(true);
  });

  it("formatSas groups six digits and rejects anything else", () => {
    expect(formatSas("482915")).toBe("482 915");
    expect(formatSas("48291")).toBeNull();
    expect(formatSas("48291a")).toBeNull();
    expect(formatSas("4829150")).toBeNull();
  });

  it("revoke name must match exactly (case and whitespace sensitive)", () => {
    expect(revokeNameMatches("Pixel 9", "Pixel 9")).toBe(true);
    expect(revokeNameMatches("Pixel 9", "pixel 9")).toBe(false);
    expect(revokeNameMatches("Pixel 9", "Pixel 9 ")).toBe(false);
    expect(revokeNameMatches("", "")).toBe(false);
  });

  it("visualize also catches Hangul fillers, soft hyphen, braille blank, deprecated format and tag characters", () => {
    const cases: Array<[string, string]> = [
      ["\u3164", "⟦U+3164⟧"],
      ["\u115F", "⟦U+115F⟧"],
      ["\u1160", "⟦U+1160⟧"],
      ["\uFFA0", "⟦U+FFA0⟧"],
      ["\u00AD", "⟦U+00AD⟧"],
      ["\u2800", "⟦U+2800⟧"],
      ["\u206A", "⟦U+206A⟧"],
      ["\u206F", "⟦U+206F⟧"],
      ["\u2028", "⟦U+2028⟧"],
      ["\u180E", "⟦U+180E⟧"],
      [String.fromCodePoint(0xe0000), "⟦U+E0000⟧"],
      [String.fromCodePoint(0xe0041), "⟦U+E0041⟧"],
      [String.fromCodePoint(0xe007f), "⟦U+E007F⟧"],
    ];
    for (const [ch, shown] of cases) {
      const text = `ls${ch}-la`;
      expect(hasSuspicious(text), shown).toBe(true);
      expect(visualize(text), shown).toBe(`ls${shown}-la`);
    }
    // ordinary text, Korean, emoji, tab/newline and the neighbours of the ranges are left alone
    for (const ok of ["ls -la", "한글 명령", "😀 ok", "a\tb\nc", "\u2065", "\uFFA1", "\u3163", "\u2801", String.fromCodePoint(0xe0080)]) {
      expect(hasSuspicious(ok), JSON.stringify(ok)).toBe(false);
      expect(visualize(ok)).toBe(ok);
    }
  });

  it("visualize makes bidi/zero-width characters visible and truncate is surrogate-safe", () => {
    const evil = "rm -rf /‮ txt.exe​";
    expect(hasSuspicious(evil)).toBe(true);
    expect(visualize(evil)).toContain("⟦U+202E⟧");
    expect(visualize(evil)).toContain("⟦U+200B⟧");
    expect(visualize("a\nb\tc")).toBe("a\nb\tc");
    expect(truncate("😀😀😀😀", 3)).toBe("😀😀…");
    expect(safeText(null)).toBe("");
  });
});

describe("approval card (DOM)", () => {
  let h: Harness;

  beforeEach(async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
  });
  afterEach(() => {
    h.destroy();
    vi.useRealTimers();
  });

  async function open(...approvals: ReturnType<typeof sampleApproval>[]): Promise<void> {
    h = await mountHarness({ settings: { seed: true } });
    for (const a of approvals) h.mock?.pushApproval(a);
    await h.go("approvals");
  }
  const created = (): string => new Date(Date.now()).toISOString();
  const decideCalls = (): Array<Record<string, unknown>> => (h.mock?.calls ?? []).filter((c) => c.command === "approval_decide_local").map((c) => c.args);

  it("low risk: one click allows, confirm_ack=false", async () => {
    await open(sampleApproval({ id: "ar_low", level: "low", created_at: created() }));
    const allow = q<HTMLButtonElement>(h.root, "[data-request-id=ar_low] [data-decision=allow]");
    expect(allow.dataset["mode"]).toBe("click");
    click(allow);
    await settle();
    expect(decideCalls()).toHaveLength(1);
    expect(decideCalls()[0]).toMatchObject({ decision: "allow", confirm_ack: false });
    expect(h.store.get().approvals).toHaveLength(0);
    expect(h.store.get().history[0]?.outcome).toBe("allowed");
  });

  it("high risk: a click does nothing; 1.5 s hold sends confirm_ack=true; early release cancels", async () => {
    await open(sampleApproval({ id: "ar_high", level: "high", created_at: created() }));
    const allow = q<HTMLButtonElement>(h.root, "[data-request-id=ar_high] [data-decision=allow]");
    expect(allow.dataset["mode"]).toBe("hold");
    expect(allow.disabled).toBe(false);

    click(allow);
    await settle();
    expect(decideCalls()).toHaveLength(0);

    press(allow);
    vi.advanceTimersByTime(HOLD_MS - 1);
    release(allow);
    vi.advanceTimersByTime(50);
    await settle();
    expect(decideCalls()).toHaveLength(0);

    press(allow);
    await vi.advanceTimersByTimeAsync(HOLD_MS);
    await settle();
    expect(decideCalls()).toHaveLength(1);
    expect(decideCalls()[0]).toMatchObject({ decision: "allow", confirm_ack: true });
  });

  it("keyboard hold (Space) works the same way and keyup cancels", async () => {
    await open(sampleApproval({ id: "ar_kb", level: "high", created_at: created() }));
    const allow = q<HTMLButtonElement>(h.root, "[data-request-id=ar_kb] [data-decision=allow]");
    allow.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
    vi.advanceTimersByTime(500);
    allow.dispatchEvent(new KeyboardEvent("keyup", { key: " ", bubbles: true }));
    await vi.advanceTimersByTimeAsync(2000);
    expect(decideCalls()).toHaveLength(0);
    allow.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
    await vi.advanceTimersByTimeAsync(HOLD_MS);
    await settle();
    expect(decideCalls()[0]).toMatchObject({ decision: "allow", confirm_ack: true });
  });

  it("critical: full command re-shown, allow disabled until the box is checked, then needs the hold", async () => {
    const long = `rm -rf ${"/very/long/path/".repeat(40)}`;
    await open(sampleApproval({ id: "ar_crit", level: "critical", command: long, created_at: created() }));
    const card = q(h.root, "[data-request-id=ar_crit]");
    const preview = q(card, "[data-command-preview]").textContent ?? "";
    const full = q(card, "[data-command-full]").textContent ?? "";
    expect(preview.length).toBeLessThan(long.length);
    expect(full).toBe(long);

    const allow = q<HTMLButtonElement>(card, "[data-decision=allow]");
    expect(allow.disabled).toBe(true);
    press(allow);
    await vi.advanceTimersByTimeAsync(HOLD_MS + 100);
    expect(decideCalls()).toHaveLength(0);

    const box = q<HTMLInputElement>(card, "[data-reconfirm]");
    box.checked = true;
    box.dispatchEvent(new Event("change", { bubbles: true }));
    expect(allow.disabled).toBe(false);
    press(allow);
    await vi.advanceTimersByTimeAsync(HOLD_MS);
    await settle();
    expect(decideCalls()[0]).toMatchObject({ decision: "allow", confirm_ack: true });
  });

  it("deny and 'handle locally' are never gated, even for critical requests", async () => {
    await open(sampleApproval({ id: "ar_c1", level: "critical", created_at: created() }), sampleApproval({ id: "ar_c2", level: "critical", created_at: created() }));
    click(q(h.root, "[data-request-id=ar_c1] [data-decision=deny]"));
    click(q(h.root, "[data-request-id=ar_c2] [data-action=handoff]"));
    await settle();
    expect(decideCalls()).toHaveLength(1);
    expect(decideCalls()[0]).toMatchObject({ request_id: "ar_c1", decision: "deny", confirm_ack: false });
    expect(h.store.get().history.map((x) => x.outcome).sort()).toEqual(["denied", "handed_off_local"]);
  });

  it("Codex hooks origin: deny only, with the explanatory note", async () => {
    await open(sampleApproval({ id: "ar_cx", level: "low", origin: "codex.hook.cli", created_at: created() }));
    const card = q(h.root, "[data-request-id=ar_cx]");
    expect(card.querySelector("[data-decision=deny_and_stop]")).toBeNull();
    expect(card.querySelector("[data-decision=deny]")).not.toBeNull();
    expect(q(card, "[data-codex-note]").textContent).toContain("거부만 가능");
  });

  it("purpose is labelled unverified and sits below the command and risk reasons", async () => {
    await open(sampleApproval({ id: "ar_pu", level: "high", purpose: "안전한 정리 작업입니다", created_at: created() }));
    const card = q(h.root, "[data-request-id=ar_pu]");
    const purpose = q(card, "[data-purpose]");
    expect(purpose.textContent).toContain("에이전트가 한 말 (검증 안 됨)");
    expect(purpose.textContent).toContain("안전한 정리 작업입니다");
    const cmd = q(card, "[data-command-preview]");
    expect(cmd.compareDocumentPosition(purpose) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("delivery status and countdown render, and everything disables at expiry", async () => {
    await open(sampleApproval({ id: "ar_exp", level: "low", ttl_seconds: 60, created_at: created() }));
    const card = q(h.root, "[data-request-id=ar_exp]");
    expect(q(card, "[data-delivery]").textContent).toContain("휴대폰이 받음");
    expect(q(card, ".countdown").textContent).toBe("1:00");
    await vi.advanceTimersByTimeAsync(30_000);
    expect(q(card, ".countdown").textContent).toBe("0:30");
    await vi.advanceTimersByTimeAsync(31_000);
    expect(q<HTMLButtonElement>(card, "[data-decision=allow]").disabled).toBe(true);
    expect(q<HTMLButtonElement>(card, "[data-action=handoff]").disabled).toBe(true);
    expect(card.textContent).toContain("시간이 지났어요");
  });

  it("a hold in progress survives unrelated store updates (cards are patched, not rebuilt)", async () => {
    await open(sampleApproval({ id: "ar_stable", level: "high", created_at: created() }));
    const allow = q<HTMLButtonElement>(h.root, "[data-request-id=ar_stable] [data-decision=allow]");
    press(allow);
    await vi.advanceTimersByTimeAsync(500);
    h.mock?.pushSession({ ...(await h.mock.sessionsList())[0]!, headline: "다른 세션 변경" });
    h.mock?.emit({ kind: "approval", payload: { op: "delivery", request_id: "ar_stable", delivery: { sent_to: ["Pixel 9"], acked: true, seen: true } } });
    await vi.advanceTimersByTimeAsync(0);
    expect(q(h.root, "[data-request-id=ar_stable] [data-decision=allow]")).toBe(allow);
    await vi.advanceTimersByTimeAsync(HOLD_MS);
    await settle();
    expect(decideCalls()).toHaveLength(1);
  });

  it("server-side rejection is shown in Korean (hash echo mismatch) and the card is rebuilt for the changed request", async () => {
    await open(sampleApproval({ id: "ar_err", level: "low", created_at: created() }));
    const before = q(h.root, "[data-request-id=ar_err]");
    // The daemon now reports a different tool_input_sha256 for the same id (input swapped): card must be rebuilt.
    h.store.update((st) => ({ approvals: st.approvals.map((a) => ({ ...a, tool_input_sha256: "0".repeat(64) })) }));
    await settle();
    const after = q(h.root, "[data-request-id=ar_err]");
    expect(after).not.toBe(before);
    click(q(after, "[data-decision=allow]"));
    await settle();
    const toast = qa(h.root, "[data-toast=error]").map((t) => t.textContent ?? "");
    expect(toast.some((t) => t.includes("요청 내용이 바뀌어"))).toBe(true);
    // refreshed from the daemon: the genuine request is back
    expect(h.store.get().approvals[0]?.tool_input_sha256).not.toBe("0".repeat(64));
  });

  it("history lists outcome, actor and risk (max 50)", async () => {
    await open(sampleApproval({ id: "ar_hist", level: "low", created_at: created() }));
    click(q(h.root, "[data-request-id=ar_hist] [data-decision=deny]"));
    await settle();
    const li = q(h.root, "[data-history] li");
    expect(li.textContent).toContain("거부");
    expect(li.textContent).toContain("PC");
  });
});
