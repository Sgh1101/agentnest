/**
 * In-memory Backend used by `vite dev` (plain browser) and by tests.
 *
 * It mimics the server-side rules of the Rust shell closely enough that the UI contract
 * (error codes, gating, ordering) can be tested without Tauri:
 *  - approval_decide_local: UNKNOWN_REQUEST / ALREADY_RESOLVED / INPUT_HASH_MISMATCH / EXPIRED /
 *    NOT_ALLOWED / EXTRA_CONFIRMATION_REQUIRED (security.md 6.2.1)
 *  - pairing_start: RISK_NOT_ACCEPTED / LINK_DISABLED / PAIRING_BUSY; pairing_confirm needs a pending SAS
 *  - device_revoke: NAME_MISMATCH unless the exact device name is passed
 *  - settings_set: whitelist + range validation (security.md 9)
 */
import type { Backend } from "./backend";
import { COMMANDS } from "./backend";
import { BackendError } from "./errors";
import { defaultSettings, sampleApproval, sampleDevice, sampleSession } from "./samples";
import {
  SETTING_KEYS,
  TTL_MAX_S,
  TTL_MIN_S,
  type AgentEvent,
  type ApprovalHistoryEntry,
  type ApprovalOutcome,
  type ApprovalPending,
  type CodexProbe,
  type DaemonEvent,
  type DaemonStatus,
  type DecideLocalArgs,
  type Device,
  type DiagnosticsReport,
  type FirewallResult,
  type HooksArgs,
  type HooksStatus,
  type PairingDevice,
  type PairingStartResult,
  type RiskId,
  type SessionState,
  type Settings,
  type WritableSettingKey,
} from "./types";

export interface MockOptions {
  now?: () => number;
  settings?: Partial<Settings>;
  /** Pre-populate sessions/devices/approvals/diagnostics for `vite dev`. */
  seed?: boolean;
}

export interface MockCall {
  command: string;
  args: Record<string, unknown>;
}

interface ActivePairing {
  pairing_id: string;
  expires_at_ms: number;
  pending: { sas: string; device: PairingDevice } | null;
}

const PAIRING_TTL_MS = 120_000;
const CLAUDE_HOOK_TIMEOUT_DEFAULT_S = 150;

function fakeQrSvg(seed: number): string {
  const n = 25;
  const cell = 8;
  let s = seed >>> 0 || 1;
  const rects: string[] = [];
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
      const finder = (x < 7 && y < 7) || (x >= n - 7 && y < 7) || (x < 7 && y >= n - 7);
      if (finder ? (x % 6 === 0 || y % 6 === 0 || (x % 6 >= 2 && x % 6 <= 4 && y % 6 >= 2 && y % 6 <= 4)) : s >>> 31 === 1) {
        rects.push(`<rect x="${x * cell}" y="${y * cell}" width="${cell}" height="${cell}"/>`);
      }
    }
  }
  const size = n * cell;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="${size}" height="${size}" fill="#fff"/><g fill="#000">${rects.join("")}</g></svg>`;
}

export class MockBackend implements Backend {
  readonly kind = "mock" as const;
  /** Every command invocation, in order (for contract tests). */
  readonly calls: MockCall[] = [];

  private readonly now: () => number;
  private readonly handlers = new Set<(e: DaemonEvent) => void>();
  private settings: Settings;
  private sessions: SessionState[] = [];
  private approvals: ApprovalPending[] = [];
  private resolvedIds = new Set<string>();
  private history: ApprovalHistoryEntry[] = [];
  private devices: Device[] = [];
  private events: AgentEvent[] = [];
  private logs: string[] = ["[info] mock daemon started"];
  private pairing: ActivePairing | null = null;
  private pairingCounter = 0;
  private linkEnabled = true;
  private paused = false;
  private claudeHooksInstalled = false;
  private hookTimeoutS = CLAUDE_HOOK_TIMEOUT_DEFAULT_S;
  private lastEventAt: DaemonStatus["last_event_at"] = { claude_code: null, codex: null };
  private diagnostics: DiagnosticsReport = {
    listener: { bound: true, addr: "192.168.0.10", port: 47832 },
    network_profile: "private",
    firewall: { rule_present: true, scoped_ok: true, block_rule_present: false },
    last_preauth_attempt: null,
    self_connect_ok: true,
    hosts: ["192.168.0.10"],
    hints_ko: [],
  };

  constructor(opts: MockOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.settings = defaultSettings(opts.settings);
    if (opts.seed === true) this.seed();
  }

  // ----- test / dev-panel controls -----------------------------------------

  private seed(): void {
    this.claudeHooksInstalled = true;
    this.sessions = [
      sampleSession(),
      sampleSession({
        session_key: "codex:thr_01HZX3Q9N4K7",
        agent_kind: "codex",
        agent_label: "Codex",
        state: "awaiting_approval",
        headline: "허락을 기다리고 있어요: 파일 1개를 바꾸려고 해요",
        meta: { title: null, model: null, review: { p0: 0, p1: 0, state: "unavailable" } },
      }),
    ];
    this.devices = [sampleDevice()];
    this.lastEventAt = { claude_code: new Date(this.now() - 30_000).toISOString(), codex: null };
  }

  /** Push a daemon event to subscribers (tests and dev panel). */
  emit(event: DaemonEvent): void {
    for (const h of [...this.handlers]) h(event);
  }

  pushSession(session: SessionState): void {
    this.sessions = [...this.sessions.filter((s) => s.session_key !== session.session_key), session];
    this.emit({ kind: "session_state", payload: session });
  }

  pushApproval(approval: ApprovalPending): void {
    this.approvals = [...this.approvals.filter((a) => a.request_id !== approval.request_id), approval];
    this.emit({ kind: "approval", payload: { op: "requested", approval } });
  }

  pushEvents(events: AgentEvent[]): void {
    this.events.push(...events);
    this.emit({ kind: "event", payload: events });
  }

  setDiagnostics(patch: Partial<DiagnosticsReport>): void {
    this.diagnostics = { ...this.diagnostics, ...patch };
  }

  setCodexEventSeen(): void {
    this.lastEventAt = { ...this.lastEventAt, codex: new Date(this.now()).toISOString() };
  }

  setDevices(devices: Device[]): void {
    this.devices = devices;
  }

  /** The phone sent a valid `pair` proof: the daemon enters PairPending and shows the SAS modal. */
  simulatePairPending(device: PairingDevice, sas = "482915", confirmTimeoutMs = 60_000): void {
    const p = this.pairing;
    if (p === null) throw new BackendError("PAIRING_NOT_FOUND");
    p.pending = { sas, device };
    this.emit({ kind: "pairing", payload: { op: "pending_sas", pairing_id: p.pairing_id, sas, device, confirm_timeout_ms: confirmTimeoutMs } });
  }

  /** Dev helper: a high-risk approval for the dev panel. */
  simulateApproval(level: ApprovalPending["risk"]["level"], id: string): void {
    this.pushApproval(sampleApproval({ id, level, created_at: new Date(this.now()).toISOString() }));
  }

  // ----- helpers ------------------------------------------------------------

  private rec(command: string, args: Record<string, unknown> = {}): void {
    this.calls.push({ command, args });
  }

  private effectiveTtl(): number {
    return Math.min(this.settings["approval.ttl_s"], this.hookTimeoutS - 30);
  }

  private resolve(a: ApprovalPending, outcome: ApprovalOutcome, message: string): void {
    this.approvals = this.approvals.filter((x) => x.request_id !== a.request_id);
    this.resolvedIds.add(a.request_id);
    const at = new Date(this.now()).toISOString();
    const entry: ApprovalHistoryEntry = {
      request_id: a.request_id,
      title: a.title,
      tool_name: a.tool_name,
      risk_level: a.risk.level,
      outcome,
      resolved_by: "desktop",
      resolved_device_name: null,
      resolved_at: at,
    };
    this.history = [entry, ...this.history].slice(0, 50);
    this.emit({
      kind: "approval",
      payload: { op: "resolved", resolved: { request_id: a.request_id, session_key: a.session_key, outcome, resolved_by: "desktop", resolved_device_id: null, resolved_at: at, message_ko: message } },
    });
  }

  // ----- Backend ------------------------------------------------------------

  daemonStatus(): Promise<DaemonStatus> {
    this.rec(COMMANDS.daemonStatus);
    return Promise.resolve({
      running: true,
      hook_port: 47831,
      wss_addr: this.linkEnabled ? "192.168.0.10:47832" : "",
      hosts: this.linkEnabled ? ["192.168.0.10"] : [],
      link_enabled: this.linkEnabled,
      cert_expires_at: "2028-10-15T00:00:00.000Z",
      spki_pin: "sha256/glLmKAo9gdGvAGIYNxNEvncjE6SNAheIa/dX4bFINbU=",
      hooks_installed: this.claudeHooksInstalled,
      effective_ttl_s: this.effectiveTtl(),
      hook_timeout_s: this.hookTimeoutS,
      codex_mode: "hooks",
      sessions: this.sessions.length,
      devices_online: this.devices.filter((d) => d.online && d.revoked_at === null).length,
      remote_approval_paused: this.paused,
      last_event_at: { ...this.lastEventAt },
    });
  }

  diagnosticsRun(): Promise<DiagnosticsReport> {
    this.rec(COMMANDS.diagnosticsRun);
    return Promise.resolve(structuredClone(this.diagnostics));
  }

  firewallRuleCreate(): Promise<FirewallResult> {
    this.rec(COMMANDS.firewallRuleCreate);
    this.diagnostics = { ...this.diagnostics, firewall: { rule_present: true, scoped_ok: true, block_rule_present: false } };
    return Promise.resolve({ ok: true, elevated: true, error: null });
  }

  firewallRuleRemove(): Promise<FirewallResult> {
    this.rec(COMMANDS.firewallRuleRemove);
    this.diagnostics = { ...this.diagnostics, firewall: { ...this.diagnostics.firewall, rule_present: false, scoped_ok: false } };
    return Promise.resolve({ ok: true, elevated: true, error: null });
  }

  linkSetEnabled(enabled: boolean): Promise<void> {
    this.rec(COMMANDS.linkSetEnabled, { enabled });
    this.linkEnabled = enabled;
    if (!enabled) {
      if (this.pairing !== null) {
        const id = this.pairing.pairing_id;
        this.pairing = null;
        this.emit({ kind: "pairing", payload: { op: "ended", pairing_id: id, reason: "link_disabled" } });
      }
      for (const a of [...this.approvals]) this.resolve(a, "handed_off_local", "PC에서 처리하도록 넘겼어요.");
      this.devices = this.devices.map((d) => ({ ...d, online: false }));
    }
    this.emit({ kind: "link", payload: { enabled, remote_approval_paused: this.paused } });
    return Promise.resolve();
  }

  riskAccept(riskId: RiskId): Promise<void> {
    this.rec(COMMANDS.riskAccept, { risk_id: riskId });
    if (riskId !== "R1") return Promise.reject(new BackendError("INVALID_SETTING"));
    this.settings = { ...this.settings, "risk.accepted": ["R1"] };
    return Promise.resolve();
  }

  pairingStart(): Promise<PairingStartResult> {
    this.rec(COMMANDS.pairingStart);
    if (!this.settings["risk.accepted"].includes("R1")) return Promise.reject(new BackendError("RISK_NOT_ACCEPTED"));
    if (!this.linkEnabled) return Promise.reject(new BackendError("LINK_DISABLED"));
    if (this.pairing !== null && this.now() >= this.pairing.expires_at_ms) this.pairing = null; // lazily expire the old one
    if (this.pairing !== null) return Promise.reject(new BackendError("PAIRING_BUSY"));
    this.pairingCounter += 1;
    const pairing_id = `p_${this.pairingCounter.toString(16).padStart(16, "0")}`;
    const expires = this.now() + PAIRING_TTL_MS;
    this.pairing = { pairing_id, expires_at_ms: expires, pending: null };
    return Promise.resolve({ pairing_id, qr_svg: fakeQrSvg(this.pairingCounter * 7919), expires_at: new Date(expires).toISOString() });
  }

  pairingCancel(pairingId: string): Promise<void> {
    this.rec(COMMANDS.pairingCancel, { pairing_id: pairingId });
    if (this.pairing === null || this.pairing.pairing_id !== pairingId) return Promise.reject(new BackendError("PAIRING_NOT_FOUND"));
    this.pairing = null;
    this.emit({ kind: "pairing", payload: { op: "ended", pairing_id: pairingId, reason: "cancelled" } });
    return Promise.resolve();
  }

  pairingConfirm(pairingId: string, approve: boolean): Promise<void> {
    this.rec(COMMANDS.pairingConfirm, { pairing_id: pairingId, approve });
    const p = this.pairing;
    if (p === null || p.pairing_id !== pairingId || p.pending === null) return Promise.reject(new BackendError("PAIRING_NOT_PENDING"));
    const pending = p.pending;
    this.pairing = null;
    if (!approve) {
      this.emit({ kind: "pairing", payload: { op: "ended", pairing_id: pairingId, reason: "rejected" } });
      return Promise.resolve();
    }
    const device = sampleDevice({
      device_id: `dev_${this.pairingCounter.toString(16).padStart(32, "0")}`,
      name: pending.device.name,
      platform: pending.device.platform,
      model: pending.device.model,
      paired_at: new Date(this.now()).toISOString(),
      last_seen_at: new Date(this.now()).toISOString(),
    });
    this.devices = [...this.devices, device];
    this.emit({ kind: "device", payload: { op: "paired", device } });
    this.emit({ kind: "pairing", payload: { op: "completed", pairing_id: pairingId, device_id: device.device_id } });
    return Promise.resolve();
  }

  devicesList(): Promise<Device[]> {
    this.rec(COMMANDS.devicesList);
    return Promise.resolve(structuredClone(this.devices));
  }

  deviceRevoke(deviceId: string, nameTyped: string): Promise<void> {
    this.rec(COMMANDS.deviceRevoke, { device_id: deviceId, name_typed: nameTyped });
    const d = this.devices.find((x) => x.device_id === deviceId && x.revoked_at === null);
    if (d === undefined) return Promise.reject(new BackendError("DEVICE_NOT_FOUND"));
    if (nameTyped !== d.name) return Promise.reject(new BackendError("NAME_MISMATCH"));
    const revoked: Device = { ...d, online: false, revoked_at: new Date(this.now()).toISOString() };
    this.devices = this.devices.map((x) => (x.device_id === deviceId ? revoked : x));
    this.emit({ kind: "device", payload: { op: "revoked", device: revoked } });
    return Promise.resolve();
  }

  sessionsList(): Promise<SessionState[]> {
    this.rec(COMMANDS.sessionsList);
    return Promise.resolve(structuredClone(this.sessions));
  }

  eventsRecent(sessionKey: string | null, limit: number): Promise<AgentEvent[]> {
    this.rec(COMMANDS.eventsRecent, sessionKey === null ? { limit } : { session_key: sessionKey, limit });
    const list = sessionKey === null ? this.events : this.events.filter((e) => e.session_key === sessionKey);
    return Promise.resolve(structuredClone(list.slice(-limit)));
  }

  approvalsPending(): Promise<ApprovalPending[]> {
    this.rec(COMMANDS.approvalsPending);
    return Promise.resolve(structuredClone(this.approvals));
  }

  approvalsHistory(limit: number): Promise<ApprovalHistoryEntry[]> {
    this.rec(COMMANDS.approvalsHistory, { limit });
    return Promise.resolve(structuredClone(this.history.slice(0, limit)));
  }

  approvalHandoffLocal(requestId: string): Promise<void> {
    this.rec(COMMANDS.approvalHandoffLocal, { request_id: requestId });
    const a = this.approvals.find((x) => x.request_id === requestId);
    if (a === undefined) return Promise.reject(new BackendError(this.resolvedIds.has(requestId) ? "ALREADY_RESOLVED" : "UNKNOWN_REQUEST"));
    // Handing off is always allowed regardless of risk: it creates no decision.
    this.resolve(a, "handed_off_local", "PC에서 직접 처리하도록 넘겼어요.");
    return Promise.resolve();
  }

  approvalDecideLocal(args: DecideLocalArgs): Promise<void> {
    this.rec(COMMANDS.approvalDecideLocal, { ...args });
    const a = this.approvals.find((x) => x.request_id === args.request_id);
    if (a === undefined) return Promise.reject(new BackendError(this.resolvedIds.has(args.request_id) ? "ALREADY_RESOLVED" : "UNKNOWN_REQUEST"));
    if (args.tool_input_sha256 !== a.tool_input_sha256) return Promise.reject(new BackendError("INPUT_HASH_MISMATCH"));
    if (this.now() >= Date.parse(a.expires_at)) {
      this.resolve(a, "expired", "요청 시간이 지나 PC에서 직접 처리하도록 넘겼어요.");
      return Promise.reject(new BackendError("EXPIRED"));
    }
    if (!a.allowed_decisions.includes(args.decision)) return Promise.reject(new BackendError("NOT_ALLOWED"));
    const allowFamily = args.decision === "allow" || (args.decision === "deny_and_stop" && a.auth_required_for.includes("deny_and_stop"));
    if (allowFamily && a.risk.extra_confirmation !== "none" && args.confirm_ack !== true) {
      return Promise.reject(new BackendError("EXTRA_CONFIRMATION_REQUIRED"));
    }
    // Remote-approval pause never blocks the desktop path (security.md 6.2.1 step 9: n/a).
    if (args.decision === "allow") this.resolve(a, "allowed", "허용했어요.");
    else if (args.decision === "deny") this.resolve(a, "denied", "거부했어요.");
    else this.resolve(a, "denied_and_stopped", "거부하고 작업을 멈췄어요.");
    return Promise.resolve();
  }

  remoteApprovalPause(): Promise<void> {
    this.rec(COMMANDS.remoteApprovalPause);
    this.paused = true;
    this.emit({ kind: "link", payload: { enabled: this.linkEnabled, remote_approval_paused: true } });
    return Promise.resolve();
  }

  remoteApprovalResume(): Promise<void> {
    this.rec(COMMANDS.remoteApprovalResume);
    this.paused = false;
    this.emit({ kind: "link", payload: { enabled: this.linkEnabled, remote_approval_paused: false } });
    return Promise.resolve();
  }

  hooksInstall(args: HooksArgs): Promise<HooksStatus> {
    this.rec(COMMANDS.hooksInstall, { ...args });
    if (args.agent === "codex") {
      return Promise.resolve({ installed: false, path: null, warnings: ["Codex hooks 설치기는 아직 꺼져 있어요. 안내에 따라 직접 설치해 주세요."] });
    }
    this.claudeHooksInstalled = true;
    this.hookTimeoutS = this.settings["approval.ttl_s"] + 30;
    return Promise.resolve({ installed: true, path: "C:\\Users\\me\\.claude\\settings.json", warnings: [] });
  }

  hooksUninstall(args: HooksArgs): Promise<HooksStatus> {
    this.rec(COMMANDS.hooksUninstall, { ...args });
    if (args.agent === "claude_code") this.claudeHooksInstalled = false;
    return Promise.resolve({ installed: false, path: null, warnings: [] });
  }

  hooksStatus(args: HooksArgs): Promise<HooksStatus> {
    this.rec(COMMANDS.hooksStatus, { ...args });
    if (args.agent === "codex") return Promise.resolve({ installed: false, path: null, warnings: ["Codex hooks는 수동 설치예요."] });
    return Promise.resolve({
      installed: this.claudeHooksInstalled,
      path: this.claudeHooksInstalled ? "C:\\Users\\me\\.claude\\settings.json" : null,
      warnings: [],
    });
  }

  codexProbe(): Promise<CodexProbe> {
    this.rec(COMMANDS.codexProbe);
    return Promise.resolve({ socket_path: null, reachable: false, user_agent: null, threads: 0 });
  }

  settingsGet(): Promise<Settings> {
    this.rec(COMMANDS.settingsGet);
    return Promise.resolve(structuredClone(this.settings));
  }

  settingsSet<K extends WritableSettingKey>(key: K, value: Settings[K]): Promise<Settings> {
    this.rec(COMMANDS.settingsSet, { key, value });
    const k: string = key;
    if (!(SETTING_KEYS as readonly string[]).includes(k) || k === "risk.accepted") return Promise.reject(new BackendError("UNKNOWN_SETTING"));
    const v: unknown = value;
    const next: Settings = { ...this.settings };
    switch (k) {
      case "approval.ttl_s":
        if (typeof v !== "number" || !Number.isInteger(v) || v < TTL_MIN_S || v > TTL_MAX_S) return Promise.reject(new BackendError("INVALID_SETTING"));
        next["approval.ttl_s"] = v;
        break;
      case "approval.deny_requires_auth":
      case "approval.daemon_down_deny":
      case "app.notifications":
      case "app.autostart":
      case "onboarding.completed":
        if (typeof v !== "boolean") return Promise.reject(new BackendError("INVALID_SETTING"));
        next[k] = v;
        break;
      case "approval.critical_remote":
        if (v !== "extra_confirmation" && v !== "local_only") return Promise.reject(new BackendError("INVALID_SETTING"));
        next[k] = v;
        break;
      case "app.log_level":
        if (v !== "error" && v !== "warn" && v !== "info" && v !== "debug") return Promise.reject(new BackendError("INVALID_SETTING"));
        next[k] = v;
        break;
      case "onboarding.codex_steps_done": {
        const ok = Array.isArray(v) && v.every((s) => s === "hooks_json" || s === "trust" || s === "doctor");
        if (!ok) return Promise.reject(new BackendError("INVALID_SETTING"));
        next[k] = [...(v as Settings["onboarding.codex_steps_done"])];
        break;
      }
      default:
        return Promise.reject(new BackendError("UNKNOWN_SETTING"));
    }
    this.settings = next;
    return Promise.resolve(structuredClone(this.settings));
  }

  logsOpenDir(): Promise<void> {
    this.rec(COMMANDS.logsOpenDir);
    return Promise.resolve();
  }

  logsTail(limit: number): Promise<string[]> {
    this.rec(COMMANDS.logsTail, { limit });
    return Promise.resolve(this.logs.slice(-limit));
  }

  onEvent(handler: (event: DaemonEvent) => void): Promise<() => void> {
    this.handlers.add(handler);
    return Promise.resolve(() => {
      this.handlers.delete(handler);
    });
  }
}
