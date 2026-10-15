import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sampleApproval, sampleSession } from "../src/api/samples";
import { T0, click, mountHarness, q, qa, settle, type Harness } from "./helpers";

describe("views (Korean UI, measured status)", () => {
  let h: Harness;
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
  });
  afterEach(() => {
    h.destroy();
    vi.useRealTimers();
  });

  it("header shows daemon, hooks, link and ports; mock data is labelled", async () => {
    h = await mountHarness({ settings: { seed: true } });
    const header = q(h.root, "[data-header-status]").textContent ?? "";
    expect(header).toContain("데몬 실행 중");
    expect(header).toContain("Claude Code 훅 설치됨");
    expect(header).toContain("휴대폰 연결 켜짐");
    expect(header).toContain("127.0.0.1:47831");
    expect(header).toContain("192.168.0.10:47832");
    expect(header).toContain("데모 데이터");
  });

  it("header follows link disable and pause events", async () => {
    h = await mountHarness({ settings: { seed: true } });
    await h.controller.setLinkEnabled(false);
    await h.controller.setRemoteApprovalPaused(true);
    await settle();
    const header = q(h.root, "[data-header-status]").textContent ?? "";
    expect(header).toContain("휴대폰 연결 꺼짐");
    expect(header).toContain("원격 승인 일시정지");
    expect(header).not.toContain("연결 192.168");
  });

  it("status page: sessions with headline, state badge, Codex setup badge, approval banner", async () => {
    h = await mountHarness({ settings: { seed: true } });
    h.mock?.pushApproval(sampleApproval({ level: "low", created_at: new Date(T0).toISOString() }));
    await h.go("status");
    const text = h.root.textContent ?? "";
    expect(text).toContain("테스트를 돌리고 있어요 (cargo test -p core)");
    expect(text).toContain("Codex hooks 설정 필요");
    expect(text).toContain("승인 대기 1건");
    expect(q(h.root, "[data-nav=approvals] [data-pending-count]").textContent).toBe("1");
  });

  it("sessions page: Codex hooks-mode review text, ended sessions collapsed, timeline loads events", async () => {
    h = await mountHarness({ settings: { seed: true } });
    h.mock?.pushSession(sampleSession({ session_key: "claude_code:old", ended: true, headline: "끝난 세션" }));
    await h.go("sessions");
    expect(h.root.textContent).toContain("리뷰 정보 없음 (hooks 모드)");
    expect(q(h.root, "details.ended summary").textContent).toContain("종료된 세션 (1)");
    h.mock?.pushEvents([{ event_id: "e1", seq: 1, ts: new Date(T0).toISOString(), agent_kind: "claude_code", session_key: sampleSession().session_key, project: null, kind: "tool_started", category: "tool", severity: "info", headline: "도구를 쓰고 있어요", detail_ko: null, state_hint: null, redacted: false }]);
    click(q(h.root, `[data-fid="tl-${sampleSession().session_key}"]`));
    await settle();
    expect(h.root.textContent).toContain("도구를 쓰고 있어요");
  });

  it("diagnostics: public profile + missing firewall rule show Korean guidance and [규칙 만들기] runs the UAC command", async () => {
    h = await mountHarness({ settings: { seed: true } });
    h.mock?.setDiagnostics({ network_profile: "public", firewall: { rule_present: false, scoped_ok: false, block_rule_present: false }, last_preauth_attempt: null, self_connect_ok: true });
    await h.go("diagnostics");
    const text = q(h.root, "[data-diagnostics]").textContent ?? "";
    expect(text).toContain("'공용'이라 휴대폰이 연결하지 못해요");
    expect(text).toContain("방화벽 규칙이 없어요");
    expect(text).toContain("휴대폰이 PC에 닿지 못했어요");
    expect(text).toContain("192.168.0.10");
    click(q(h.root, "[data-fid=fw-create]"));
    await settle();
    expect((h.mock?.calls ?? []).some((c) => c.command === "firewall_rule_create")).toBe(true);
    expect(q(h.root, "[data-diagnostics]").textContent).toContain("개인 네트워크의 같은 서브넷");
  });

  it("diagnostics: a Windows block rule asks for cleanup first; link toggle button works", async () => {
    h = await mountHarness({ settings: { seed: true } });
    h.mock?.setDiagnostics({ firewall: { rule_present: false, scoped_ok: false, block_rule_present: true } });
    await h.go("diagnostics");
    expect(q(h.root, "[data-diagnostics]").textContent).toContain("'차단' 규칙");
    click(q(h.root, "[data-fid=diag-link]"));
    await settle();
    expect((h.mock?.calls ?? []).some((c) => c.command === "link_set_enabled" && c.args["enabled"] === false)).toBe(true);
  });

  it("onboarding: shown first on a fresh install, items measured, pairing blocked until 1 and 2 pass", async () => {
    h = await mountHarness({ settings: { settings: { "onboarding.completed": false, "risk.accepted": [] } } });
    expect(h.store.get().view).toBe("onboarding");
    await settle();
    const ob = q(h.root, "[data-onboarding]");
    expect(ob.textContent).toContain("1. 수용된 위험 확인 (R1)");
    expect(ob.textContent).toContain("1번과 2번이 모두 통과해야 기기를 추가할 수 있어요.");
    expect(q<HTMLButtonElement>(h.root, "[data-fid=ob-done]").disabled).toBe(true);
    click(q(h.root, "[data-fid=ob-r1]"));
    await settle();
    expect(h.store.get().settings?.["risk.accepted"]).toEqual(["R1"]);
    expect(h.root.querySelector("[data-fid=ob-pair]")).not.toBeNull();
    expect(q(h.root, "[data-onboarding-codex]").textContent).toContain("hooks.json");
  });

  it("onboarding: [완료] persists onboarding.completed once R1, network and hooks pass", async () => {
    h = await mountHarness({ settings: { seed: true, settings: { "onboarding.completed": false } } });
    await settle();
    const done = q<HTMLButtonElement>(h.root, "[data-fid=ob-done]");
    expect(done.disabled).toBe(false);
    click(done);
    await settle();
    expect(h.store.get().settings?.["onboarding.completed"]).toBe(true);
    expect(h.store.get().view).toBe("status");
  });

  it("settings: TTL above the hook timeout shows the effective-TTL warning and 1-click reinstall fixes it", async () => {
    h = await mountHarness({ settings: { seed: true } });
    await h.controller.setSetting("approval.ttl_s", 180);
    await h.go("settings");
    expect(q(h.root, "[data-ttl-warning]").textContent).toContain("120초");
    click(q(h.root, "[data-fid=set-reinstall]"));
    await settle();
    expect(h.root.querySelector("[data-ttl-warning]")).toBeNull();
    expect(h.store.get().status?.effective_ttl_s).toBe(180);
  });

  it("integrations: Claude install/uninstall; Codex checklist persists manual steps, copies the draft, flags missing first event", async () => {
    h = await mountHarness({ settings: { seed: true } });
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    await h.go("integrations");
    click(q(h.root, "[data-fid=hooks-uninstall]"));
    await settle();
    expect(h.store.get().status?.hooks_installed).toBe(false);
    click(q(h.root, "[data-fid=hooks-install]"));
    await settle();
    expect(h.store.get().status?.hooks_installed).toBe(true);

    const list = q(h.root, "[data-codex-checklist]");
    expect(list.textContent).toContain("초안이에요");
    expect(list.textContent).toContain("/hooks");
    expect(list.textContent).toContain("agentnest-hook doctor");
    expect(list.textContent).toContain("Codex 승인: 관찰만");
    expect(list.textContent).toContain("리뷰 결과: 수집 불가 (hooks 모드)");
    expect(q(list, "[data-codex-first-event]").className).toContain("check-pending");
    click(q(h.root, "[data-fid=codex-copy]"));
    await settle();
    expect(writeText).toHaveBeenCalledTimes(1);
    const copied = (writeText.mock.calls as unknown as string[][])[0]?.[0] ?? "";
    expect(JSON.parse(copied)).toHaveProperty("hooks.PermissionRequest");

    const step = q<HTMLInputElement>(h.root, "[data-codex-step=trust]");
    step.checked = true;
    step.dispatchEvent(new Event("change", { bubbles: true }));
    await settle();
    expect(h.store.get().settings?.["onboarding.codex_steps_done"]).toEqual(["trust"]);
    expect(q<HTMLInputElement>(h.root, "[data-codex-step=trust]").checked).toBe(true);

    h.mock?.setCodexEventSeen();
    await h.controller.refreshStatusQuiet();
    await settle();
    expect(q(h.root, "[data-codex-first-event]").className).toContain("check-ok");
  });

  it("logs page lists redacted lines and can open the folder", async () => {
    h = await mountHarness({ settings: { seed: true } });
    await h.go("logs");
    expect(q(h.root, "[data-logs]").textContent).toContain("mock daemon started");
    click(q(h.root, "[data-fid=logs-open]"));
    await settle();
    expect((h.mock?.calls ?? []).some((c) => c.command === "logs_open_dir")).toBe(true);
  });

  it("navigation covers all pages and marks the current one", async () => {
    h = await mountHarness({ settings: { seed: true } });
    const labels = qa(h.root, "[data-nav]").map((b) => b.getAttribute("data-nav"));
    expect(labels).toEqual(["status", "diagnostics", "pairing", "devices", "sessions", "approvals", "integrations", "settings", "logs"]);
    click(q(h.root, "[data-nav=devices]"));
    await settle();
    expect(q(h.root, "[data-nav=devices]").getAttribute("aria-current")).toBe("page");
  });
});
