import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { COMMANDS } from "../src/api/backend";
import { BackendError, messageKo, toBackendError } from "../src/api/errors";
import { parseDaemonEvent } from "../src/api/guards";
import { MockBackend } from "../src/api/mock";
import { defaultSettings, sampleApproval, sampleDevice, sampleSession } from "../src/api/samples";
import { TauriBackend, toIpcArgs, type AutostartApi, type InvokeFn, type ListenFn } from "../src/api/tauri";
import { DAEMON_EVENT_NAME, SETTING_KEYS } from "../src/api/types";
import { REPO_ROOT, T0 } from "./helpers";

const SETTINGS_WIRE = {
  "approval.ttl_s": 120,
  "approval.deny_requires_auth": false,
  "approval.critical_remote": "extra_confirmation",
  "approval.daemon_down_deny": false,
  "app.notifications": true,
  "app.log_level": "info",
  "onboarding.completed": true,
  "onboarding.codex_steps_done": [],
  "risk.accepted": ["R1"],
};

const STATUS_WIRE = {
  running: true,
  hook_port: 47831,
  wss_addr: "192.168.0.10:47832",
  hosts: ["192.168.0.10"],
  link_enabled: true,
  cert_expires_at: "2028-10-15T00:00:00.000Z",
  spki_pin: "sha256/abc",
  hooks_installed: true,
  effective_ttl_s: 120,
  hook_timeout_s: 150,
  codex_mode: "hooks",
  sessions: 1,
  devices_online: 1,
  remote_approval_paused: false,
  last_event_at: { claude_code: null, codex: null },
};

const DIAG_WIRE = {
  listener: { bound: true, addr: "192.168.0.10", port: 47832 },
  network_profile: "private",
  firewall: { rule_present: true, scoped_ok: true, block_rule_present: false },
  last_preauth_attempt: null,
  self_connect_ok: true,
  hosts: ["192.168.0.10"],
  hints_ko: [],
};

function fakeTauri(responses: Record<string, unknown> = {}) {
  const calls: Array<{ cmd: string; args: Record<string, unknown> | undefined }> = [];
  const invoke: InvokeFn = (cmd, args) => {
    calls.push({ cmd, args });
    const r = responses[cmd];
    if (r instanceof Error) return Promise.reject(r);
    if (typeof r === "function") return Promise.resolve((r as () => unknown)());
    return Promise.resolve(r === undefined ? null : r);
  };
  let handler: ((e: { payload: unknown }) => void) | null = null;
  const listen: ListenFn = (event, h) => {
    calls.push({ cmd: `listen:${event}`, args: undefined });
    handler = h;
    return Promise.resolve(() => {
      handler = null;
    });
  };
  const autostart = { enabled: false };
  const api: AutostartApi = {
    isEnabled: () => Promise.resolve(autostart.enabled),
    enable: () => {
      autostart.enabled = true;
      return Promise.resolve();
    },
    disable: () => {
      autostart.enabled = false;
      return Promise.resolve();
    },
  };
  return { calls, backend: new TauriBackend({ invoke, listen, autostart: api }), emit: (p: unknown) => handler?.({ payload: p }), autostart };
}

describe("COMMANDS match docs/desktop.md section 3", () => {
  it("every documented command has a binding with the exact name", () => {
    const md = readFileSync(join(REPO_ROOT, "docs", "desktop.md"), "utf8");
    const section3 = md.split("## 3. Tauri 커맨드·이벤트")[1]?.split("## 4.")[0] ?? "";
    const documented: string[] = [];
    for (const line of section3.split("\n")) {
      const m = /^\| ((?:`[a-z_]+`(?: \/ )?)+) \|/.exec(line);
      if (!m || m[1] === undefined) continue;
      let prev = "";
      for (const tok of m[1].matchAll(/`([a-z_]+)`/g)) {
        const name = tok[1] ?? "";
        // "`remote_approval_pause` / `_resume`" shorthand
        const full = name.startsWith("_") ? prev.replace(/_[a-z]+$/, "") + name : name;
        documented.push(full);
        prev = full;
      }
    }
    expect(documented.length).toBeGreaterThanOrEqual(22);
    const bound = new Set<string>(Object.values(COMMANDS));
    for (const name of documented) expect(bound.has(name), `${name} bound`).toBe(true);
  });

  it("event name and kinds", () => {
    expect(DAEMON_EVENT_NAME).toBe("daemon-event");
  });

  it("settings keys contain no forbidden field (security.md section 9)", () => {
    const forbidden = /^(auto_allow|allow_for_session|trust_all_certs|bind_hooks_all_interfaces|hook_bind_addr|disable_biometric|skip_auth_for|risk_overrides|risk_rules_path)/;
    for (const k of SETTING_KEYS) expect(k.split(".").pop() ?? "").not.toMatch(forbidden);
    expect(SETTING_KEYS.some((k) => /auto_allow|session|trust_all|biometric|override/.test(k))).toBe(false);
  });
});

describe("TauriBackend: exact command names, argument keys and parsing", () => {
  it("sends the documented commands with snake_case arguments (plus camelCase twins)", async () => {
    const { backend, calls } = fakeTauri({
      daemon_status: STATUS_WIRE,
      diagnostics_run: DIAG_WIRE,
      firewall_rule_create: { ok: true, elevated: true },
      firewall_rule_remove: { ok: true, elevated: true },
      pairing_start: { pairing_id: "p_1", qr_svg: "<svg xmlns='http://www.w3.org/2000/svg'/>", expires_at: "2026-10-15T12:37:00.000Z" },
      devices_list: [sampleDevice()],
      sessions_list: [sampleSession()],
      events_recent: [],
      approvals_pending: [sampleApproval()],
      approvals_history: [],
      hooks_install: { installed: true, path: "p", warnings: [], codex_draft: null, doctor_command: null },
      hooks_uninstall: { installed: false, path: null, warnings: [], codex_draft: null, doctor_command: null },
      hooks_status: { installed: true, path: "p", warnings: [], codex_draft: null, doctor_command: null },
      codex_probe: { socket_path: null, reachable: false, threads: 0 },
      settings_get: SETTINGS_WIRE,
      settings_set: SETTINGS_WIRE,
      logs_tail: ["a"],
    });
    expect((await backend.daemonStatus()).hook_port).toBe(47831);
    await backend.diagnosticsRun();
    await backend.firewallRuleCreate();
    await backend.firewallRuleRemove();
    await backend.linkSetEnabled(false);
    await backend.riskAccept("R1");
    await backend.pairingStart();
    await backend.pairingCancel("p_1");
    await backend.pairingConfirm("p_1", true);
    await backend.devicesList();
    await backend.deviceRevoke("dev_1", "Pixel 9");
    await backend.sessionsList();
    await backend.eventsRecent("claude_code:x", 20);
    await backend.eventsRecent(null, 5);
    await backend.approvalsPending();
    await backend.approvalsHistory(50);
    await backend.approvalHandoffLocal("ar_1");
    await backend.approvalDecideLocal({ request_id: "ar_1", decision: "allow", tool_input_sha256: "a".repeat(64), confirm_ack: true });
    await backend.approvalDecideLocal({ request_id: "ar_1", decision: "deny", tool_input_sha256: "a".repeat(64), confirm_ack: false, reason: "no" });
    await backend.remoteApprovalPause();
    await backend.remoteApprovalResume();
    await backend.hooksInstall({ agent: "claude_code", mode: "http" });
    await backend.hooksUninstall({ agent: "codex", mode: "cli" });
    await backend.hooksStatus({ agent: "claude_code", mode: "http" });
    await backend.codexProbe();
    await backend.settingsGet();
    await backend.settingsSet("approval.ttl_s", 90);
    await backend.logsOpenDir();
    await backend.logsTail(200);

    const byCmd = (c: string): Array<Record<string, unknown> | undefined> => calls.filter((x) => x.cmd === c).map((x) => x.args);
    expect(byCmd("link_set_enabled")[0]).toEqual({ enabled: false });
    expect(byCmd("risk_accept")[0]).toEqual({ risk_id: "R1", riskId: "R1" });
    expect(byCmd("pairing_cancel")[0]).toMatchObject({ pairing_id: "p_1" });
    expect(byCmd("pairing_confirm")[0]).toMatchObject({ pairing_id: "p_1", approve: true });
    expect(byCmd("device_revoke")[0]).toMatchObject({ device_id: "dev_1", name_typed: "Pixel 9" });
    expect(byCmd("events_recent")[0]).toMatchObject({ session_key: "claude_code:x", limit: 20 });
    expect(byCmd("events_recent")[1]).toEqual({ limit: 5 });
    expect(byCmd("approvals_history")[0]).toEqual({ limit: 50 });
    expect(byCmd("approval_handoff_local")[0]).toMatchObject({ request_id: "ar_1" });
    expect(byCmd("approval_decide_local")[0]).toMatchObject({ request_id: "ar_1", decision: "allow", tool_input_sha256: "a".repeat(64), confirm_ack: true });
    expect(byCmd("approval_decide_local")[0]).not.toHaveProperty("reason");
    expect(byCmd("approval_decide_local")[1]).toMatchObject({ decision: "deny", confirm_ack: false, reason: "no" });
    expect(byCmd("hooks_install")[0]).toEqual({ agent: "claude_code", mode: "http" });
    expect(byCmd("hooks_uninstall")[0]).toEqual({ agent: "codex", mode: "cli" });
    expect(byCmd("settings_set")[0]).toEqual({ key: "approval.ttl_s", value: 90 });
    expect(byCmd("logs_tail")[0]).toEqual({ limit: 200 });
    for (const c of ["daemon_status", "diagnostics_run", "firewall_rule_create", "firewall_rule_remove", "pairing_start", "devices_list", "sessions_list", "approvals_pending", "remote_approval_pause", "remote_approval_resume", "codex_probe", "settings_get", "logs_open_dir"]) {
      expect(byCmd(c)[0], c).toBeUndefined();
    }
  });

  it("toIpcArgs adds camelCase twins only for multi-word keys", () => {
    expect(toIpcArgs({ request_id: "x", limit: 1 })).toEqual({ request_id: "x", requestId: "x", limit: 1 });
  });

  it("app.autostart is handled through the autostart plugin, not the Rust settings store", async () => {
    const t = fakeTauri({ settings_get: SETTINGS_WIRE, settings_set: SETTINGS_WIRE });
    expect((await t.backend.settingsGet())["app.autostart"]).toBe(false);
    const after = await t.backend.settingsSet("app.autostart", true);
    expect(after["app.autostart"]).toBe(true);
    expect(t.calls.some((c) => c.cmd === "settings_set")).toBe(false);
  });

  it("rejects with normalised BackendError codes", async () => {
    expect(toBackendError({ code: "EXPIRED", message: "x" }).code).toBe("EXPIRED");
    expect(toBackendError("ALREADY_RESOLVED").code).toBe("ALREADY_RESOLVED");
    expect(toBackendError("some free text").code).toBe("INTERNAL");
    expect(toBackendError(new Error("boom")).code).toBe("INTERNAL");
    const failing = fakeTauri({ approval_handoff_local: new BackendError("UNKNOWN_REQUEST") });
    await expect(failing.backend.approvalHandoffLocal("ar_x")).rejects.toMatchObject({ code: "UNKNOWN_REQUEST" });
  });

  it("onEvent parses daemon-event, drops malformed and unknown events", async () => {
    const t = fakeTauri();
    const seen: string[] = [];
    const un = await t.backend.onEvent((e) => seen.push(e.kind));
    t.emit({ kind: "link", payload: { enabled: false, remote_approval_paused: true } });
    t.emit({ kind: "link", payload: { enabled: "nope" } });
    t.emit({ kind: "future_kind", payload: {} });
    t.emit("garbage");
    t.emit({ kind: "session_state", payload: sampleSession() });
    expect(seen).toEqual(["link", "session_state"]);
    expect(t.calls.some((c) => c.cmd === "listen:daemon-event")).toBe(true);
    un();
  });

  it("messageKo never echoes arbitrary daemon text", () => {
    expect(messageKo("EXPIRED")).toContain("시간");
    expect(messageKo("<script>alert(1)</script>")).not.toContain("script");
  });
});

describe("daemon-event payload shapes", () => {
  it("parses every kind", () => {
    const device = sampleDevice();
    const ap = sampleApproval();
    const cases: unknown[] = [
      { kind: "event", payload: [{ event_id: "e", seq: 1, ts: "2026-10-15T00:00:00Z", agent_kind: "claude_code", session_key: "claude_code:x", kind: "tool_started", category: "tool", severity: "info", summary: { headline: "도구" }, detail: {}, source: { channel: "claude_code.hook.http" }, redacted: false }] },
      { kind: "session_state", payload: sampleSession() },
      { kind: "approval", payload: { op: "requested", approval: ap } },
      { kind: "approval", payload: { op: "delivery", request_id: ap.request_id, delivery: { sent_to: ["a"], acked: true, seen: false } } },
      { kind: "approval", payload: { op: "resolved", resolved: { request_id: ap.request_id, session_key: ap.session_key, outcome: "allowed", resolved_by: "phone", resolved_device_id: device.device_id, resolved_at: "2026-10-15T00:00:00Z", message_ko: "허용했어요." } } },
      { kind: "device", payload: { op: "paired", device } },
      { kind: "pairing", payload: { op: "pending_sas", pairing_id: "p_1", sas: "482915", device: { name: "Pixel", platform: "android", model: null }, confirm_timeout_ms: 60000 } },
      { kind: "pairing", payload: { op: "completed", pairing_id: "p_1", device_id: device.device_id } },
      { kind: "pairing", payload: { op: "ended", pairing_id: "p_1", reason: "expired" } },
      { kind: "adapter", payload: { agent_kind: "codex", status: "connected", mode: "hooks_cli", updated_at: "2026-10-15T00:00:00Z" } },
      { kind: "link", payload: { enabled: true, remote_approval_paused: false } },
      { kind: "resync", payload: { missed: 12 } },
    ];
    for (const c of cases) expect(parseDaemonEvent(c), JSON.stringify(c).slice(0, 60)).not.toBeNull();
    expect(parseDaemonEvent({ kind: "resync", payload: { missed: 12 } })).toEqual({ kind: "resync", payload: { missed: 12 } });
    expect(() => parseDaemonEvent({ kind: "resync", payload: "nope" })).toThrow();
    // single event (not array) is tolerated
    const single = parseDaemonEvent({ kind: "event", payload: (cases[0] as { payload: unknown[] }).payload[0] });
    expect(single?.kind === "event" && single.payload.length).toBe(1);
  });
});

describe("MockBackend enforces the same server-side rules (security.md 6.2.1)", () => {
  function setup() {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    const mock = new MockBackend({ now: () => Date.now() });
    return mock;
  }
  const afterEach = (): void => {
    vi.useRealTimers();
  };

  it("decide: UNKNOWN_REQUEST / INPUT_HASH_MISMATCH / EXPIRED / NOT_ALLOWED / EXTRA_CONFIRMATION_REQUIRED / ALREADY_RESOLVED", async () => {
    const mock = setup();
    const a = sampleApproval({ id: "ar_a", level: "high", created_at: new Date(T0).toISOString() });
    mock.pushApproval(a);
    const base = { request_id: "ar_a", decision: "allow" as const, tool_input_sha256: a.tool_input_sha256, confirm_ack: true };
    await expect(mock.approvalDecideLocal({ ...base, request_id: "ar_zzz" })).rejects.toMatchObject({ code: "UNKNOWN_REQUEST" });
    await expect(mock.approvalDecideLocal({ ...base, tool_input_sha256: "0".repeat(64) })).rejects.toMatchObject({ code: "INPUT_HASH_MISMATCH" });
    await expect(mock.approvalDecideLocal({ ...base, confirm_ack: false })).rejects.toMatchObject({ code: "EXTRA_CONFIRMATION_REQUIRED" });
    // deny is exempt from extra confirmation
    const b = sampleApproval({ id: "ar_b", level: "critical", created_at: new Date(T0).toISOString() });
    mock.pushApproval(b);
    await expect(mock.approvalDecideLocal({ request_id: "ar_b", decision: "deny", tool_input_sha256: b.tool_input_sha256, confirm_ack: false })).resolves.toBeUndefined();
    const c = sampleApproval({ id: "ar_c", level: "low", origin: "codex.hook.cli", created_at: new Date(T0).toISOString() });
    mock.pushApproval(c);
    await expect(mock.approvalDecideLocal({ request_id: "ar_c", decision: "deny_and_stop", tool_input_sha256: c.tool_input_sha256, confirm_ack: false })).rejects.toMatchObject({ code: "NOT_ALLOWED" });
    await expect(mock.approvalDecideLocal({ ...base })).resolves.toBeUndefined();
    await expect(mock.approvalDecideLocal({ ...base })).rejects.toMatchObject({ code: "ALREADY_RESOLVED" });
    vi.setSystemTime(T0 + 121_000);
    const d = sampleApproval({ id: "ar_d", level: "low", created_at: new Date(T0).toISOString() });
    mock.pushApproval(d);
    await expect(mock.approvalDecideLocal({ request_id: "ar_d", decision: "allow", tool_input_sha256: d.tool_input_sha256, confirm_ack: false })).rejects.toMatchObject({ code: "EXPIRED" });
    afterEach();
  });

  it("handoff is always allowed regardless of risk; desktop decisions work while remote approval is paused", async () => {
    const mock = setup();
    const a = sampleApproval({ id: "ar_h", level: "critical", created_at: new Date(T0).toISOString() });
    mock.pushApproval(a);
    await mock.remoteApprovalPause();
    await expect(mock.approvalHandoffLocal("ar_h")).resolves.toBeUndefined();
    expect((await mock.approvalsHistory(5))[0]?.outcome).toBe("handed_off_local");
    const b = sampleApproval({ id: "ar_p", level: "low", created_at: new Date(T0).toISOString() });
    mock.pushApproval(b);
    await expect(mock.approvalDecideLocal({ request_id: "ar_p", decision: "allow", tool_input_sha256: b.tool_input_sha256, confirm_ack: false })).resolves.toBeUndefined();
    afterEach();
  });

  it("pairing: RISK_NOT_ACCEPTED -> accepted -> BUSY -> confirm needs pending SAS", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    const mock = new MockBackend({ now: () => Date.now(), settings: { "risk.accepted": [] } });
    await expect(mock.pairingStart()).rejects.toMatchObject({ code: "RISK_NOT_ACCEPTED" });
    await mock.riskAccept("R1");
    const p = await mock.pairingStart();
    await expect(mock.pairingStart()).rejects.toMatchObject({ code: "PAIRING_BUSY" });
    await expect(mock.pairingConfirm(p.pairing_id, true)).rejects.toMatchObject({ code: "PAIRING_NOT_PENDING" });
    expect(p.qr_svg.startsWith("<svg")).toBe(true);
    expect(Date.parse(p.expires_at) - T0).toBe(120_000);
    afterEach();
  });

  it("device_revoke needs the exact name", async () => {
    const mock = new MockBackend({ seed: true });
    const [d] = await mock.devicesList();
    if (!d) throw new Error("seed");
    await expect(mock.deviceRevoke(d.device_id, "pixel 9")).rejects.toMatchObject({ code: "NAME_MISMATCH" });
    await expect(mock.deviceRevoke(d.device_id, d.name)).resolves.toBeUndefined();
    expect((await mock.devicesList())[0]?.revoked_at).not.toBeNull();
  });

  it("settings_set: whitelist + ranges (TTL 60-180 only)", async () => {
    const mock = new MockBackend();
    await expect(mock.settingsSet("approval.ttl_s", 180)).resolves.toBeDefined();
    await expect(mock.settingsSet("approval.ttl_s", 60)).resolves.toBeDefined();
    await expect(mock.settingsSet("approval.ttl_s", 181)).rejects.toMatchObject({ code: "INVALID_SETTING" });
    await expect(mock.settingsSet("approval.ttl_s", 59)).rejects.toMatchObject({ code: "INVALID_SETTING" });
    await expect(mock.settingsSet("approval.ttl_s", 90.5)).rejects.toMatchObject({ code: "INVALID_SETTING" });
    const loose = mock as unknown as { settingsSet(k: string, v: unknown): Promise<unknown> };
    for (const k of ["auto_allow_low", "allow_for_session", "trust_all_certs", "hook_bind_addr", "disable_biometric", "risk_overrides", "risk.accepted"]) {
      await expect(loose.settingsSet(k, true)).rejects.toMatchObject({ code: "UNKNOWN_SETTING" });
    }
    expect(Object.keys(await mock.settingsGet()).sort()).toEqual([...SETTING_KEYS].sort());
    expect(defaultSettings()["approval.ttl_s"]).toBe(120);
  });

  it("hooks reinstall aligns hook timeout with TTL + 30 (effective TTL fix)", async () => {
    const mock = new MockBackend({ seed: true });
    await mock.settingsSet("approval.ttl_s", 180);
    expect((await mock.daemonStatus()).effective_ttl_s).toBe(120);
    await mock.hooksInstall({ agent: "claude_code", mode: "http" });
    expect((await mock.daemonStatus()).effective_ttl_s).toBe(180);
  });
});
