import { describe, expect, it } from "vitest";
import { defaultSettings, sampleApproval, sampleDevice, sampleSession } from "../src/api/samples";
import type { DaemonStatus } from "../src/api/types";
import { MAX_HISTORY, MAX_RECENT_EVENTS, initialState, reduceDaemonEvent, type AppState } from "../src/store";

const STATUS: DaemonStatus = {
  running: true,
  hook_port: 47831,
  wss_addr: "x:1",
  hosts: [],
  link_enabled: true,
  cert_expires_at: null,
  spki_pin: "",
  hooks_installed: true,
  effective_ttl_s: 120,
  hook_timeout_s: 150,
  codex_mode: "hooks",
  sessions: 0,
  devices_online: 0,
  remote_approval_paused: false,
  last_event_at: { claude_code: null, codex: null },
};

function base(): AppState {
  return { ...initialState("mock"), status: STATUS, settings: defaultSettings() };
}

describe("reduceDaemonEvent", () => {
  it("upserts sessions by session_key", () => {
    const s1 = sampleSession();
    let st = { ...base(), ...reduceDaemonEvent(base(), { kind: "session_state", payload: s1 }, 0) };
    st = { ...st, ...reduceDaemonEvent(st, { kind: "session_state", payload: { ...s1, headline: "바뀜" } }, 0) };
    expect(st.sessions).toHaveLength(1);
    expect(st.sessions[0]?.headline).toBe("바뀜");
  });

  it("approval lifecycle: requested -> delivery -> resolved moves it into history with actor and device", () => {
    const a = sampleApproval({ id: "ar_1", level: "high" });
    let st: AppState = { ...base(), devices: [sampleDevice()] };
    st = { ...st, ...reduceDaemonEvent(st, { kind: "approval", payload: { op: "requested", approval: a } }, 0) };
    expect(st.approvals).toHaveLength(1);
    st = { ...st, ...reduceDaemonEvent(st, { kind: "approval", payload: { op: "delivery", request_id: "ar_1", delivery: { sent_to: ["Pixel 9"], acked: true, seen: true } } }, 0) };
    expect(st.approvals[0]?.delivery.seen).toBe(true);
    st = {
      ...st,
      ...reduceDaemonEvent(st, { kind: "approval", payload: { op: "resolved", resolved: { request_id: "ar_1", session_key: a.session_key, outcome: "allowed", resolved_by: "phone", resolved_device_id: sampleDevice().device_id, resolved_at: "2026-10-15T12:36:00Z", message_ko: "" } } }, 0),
    };
    expect(st.approvals).toHaveLength(0);
    expect(st.history[0]).toMatchObject({ request_id: "ar_1", outcome: "allowed", resolved_by: "phone", resolved_device_name: "Pixel 9", risk_level: "high" });
  });

  it("history is capped at 50 and events at 200", () => {
    let st = base();
    for (let i = 0; i < MAX_HISTORY + 5; i++) {
      st = { ...st, ...reduceDaemonEvent(st, { kind: "approval", payload: { op: "resolved", resolved: { request_id: `ar_${i}`, session_key: "k:x", outcome: "denied", resolved_by: "desktop", resolved_device_id: null, resolved_at: "2026-10-15T12:36:00Z", message_ko: "" } } }, 0) };
    }
    expect(st.history).toHaveLength(MAX_HISTORY);
    const ev = (i: number) => ({ event_id: `e${i}`, seq: i, ts: "2026-10-15T12:36:00Z", agent_kind: "codex" as const, session_key: "codex:x", project: null, kind: "k", category: "tool", severity: "info" as const, headline: "h", detail_ko: null, state_hint: null, redacted: false });
    st = { ...st, ...reduceDaemonEvent(st, { kind: "event", payload: Array.from({ length: MAX_RECENT_EVENTS + 10 }, (_v, i) => ev(i)) }, 0) };
    expect(st.recentEvents).toHaveLength(MAX_RECENT_EVENTS);
    expect(st.status?.last_event_at.codex).toBe("2026-10-15T12:36:00Z");
  });

  it("pairing: pending_sas replaces the QR with the SAS prompt; ended/completed clear everything and toast", () => {
    let st: AppState = { ...base(), pairing: { pairing_id: "p_1", qr_svg: "<svg/>", expires_at_ms: 1 } };
    st = { ...st, ...reduceDaemonEvent(st, { kind: "pairing", payload: { op: "pending_sas", pairing_id: "p_1", sas: "123456", device: { name: "n", platform: "android", model: null }, confirm_timeout_ms: 60_000 } }, 5000) };
    expect(st.pairing).toBeNull();
    expect(st.sas).toMatchObject({ pairing_id: "p_1", sas: "123456", shown_at_ms: 5000 });
    st = { ...st, ...reduceDaemonEvent(st, { kind: "pairing", payload: { op: "ended", pairing_id: "p_1", reason: "rejected" } }, 6000) };
    expect(st.sas).toBeNull();
    expect(st.toasts.at(-1)?.text).toContain("거절");
    st = { ...st, sas: { pairing_id: "p_2", sas: "1", device: { name: "n", platform: "", model: null }, confirm_timeout_ms: 1, shown_at_ms: 0 } };
    st = { ...st, ...reduceDaemonEvent(st, { kind: "pairing", payload: { op: "completed", pairing_id: "p_2", device_id: "dev_x" } }, 7000) };
    expect(st.sas).toBeNull();
  });

  it("link disabled drops QR and SAS prompt and updates the status flags", () => {
    let st: AppState = { ...base(), pairing: { pairing_id: "p", qr_svg: "<svg/>", expires_at_ms: 1 }, sas: { pairing_id: "p", sas: "123456", device: { name: "n", platform: "", model: null }, confirm_timeout_ms: 1, shown_at_ms: 0 } };
    st = { ...st, ...reduceDaemonEvent(st, { kind: "link", payload: { enabled: false, remote_approval_paused: true } }, 0) };
    expect(st.pairing).toBeNull();
    expect(st.sas).toBeNull();
    expect(st.status).toMatchObject({ link_enabled: false, remote_approval_paused: true });
  });

  it("device and adapter events", () => {
    let st = base();
    st = { ...st, ...reduceDaemonEvent(st, { kind: "device", payload: { op: "paired", device: sampleDevice() } }, 0) };
    st = { ...st, ...reduceDaemonEvent(st, { kind: "device", payload: { op: "revoked", device: sampleDevice({ revoked_at: "2026-10-15T00:00:00Z" }) } }, 0) };
    expect(st.devices).toHaveLength(1);
    expect(st.devices[0]?.revoked_at).not.toBeNull();
    st = { ...st, ...reduceDaemonEvent(st, { kind: "adapter", payload: { agent_kind: "codex", status: "degraded", mode: "hooks_cli", detail: null, updated_at: "2026-10-15T00:00:00Z" } }, 0) };
    expect(st.adapters.codex?.status).toBe("degraded");
  });
});
