/** Application controller: the only place that calls the Backend and mutates the store. */
import { messageKo, toBackendError } from "./api/errors";
import type { Backend } from "./api/backend";
import { ContractError } from "./api/guards";
import {
  TTL_MAX_S,
  TTL_MIN_S,
  type AgentEvent,
  type AgentKind,
  type ApprovalPending,
  type CodexOnboardingStep,
  type Decision,
  type Device,
  type HooksAgent,
  type HooksMode,
  type Settings,
  type WritableSettingKey,
} from "./api/types";
import { buildDecideArgs } from "./logic/approvalGate";
import { revokeNameMatches } from "./logic/revoke";
import { SAS_APPROVE_DELAY_MS, SasGate, formatSas } from "./logic/sas";
import { reduceDaemonEvent, withToast, type Store, type ViewId } from "./store";

export class AppController {
  private unlisten: (() => void) | null = null;

  constructor(
    readonly backend: Backend,
    readonly store: Store,
    readonly clock: () => number = () => Date.now(),
  ) {}

  // ----- lifecycle ----------------------------------------------------------

  async init(): Promise<void> {
    // Subscribe first so nothing that happens during the initial fetch is lost.
    this.unlisten = await this.backend.onEvent((ev) => {
      this.store.update((s) => reduceDaemonEvent(s, ev, this.clock()));
      if (ev.kind === "device" || ev.kind === "pairing") void this.refreshStatusQuiet();
      // the pump lost events (possibly an approval request): re-read everything it could have carried
      if (ev.kind === "resync") void this.refreshAll();
    });
    await this.refreshAll();
    const s = this.store.get().settings;
    const onboarding = s !== null && !s["onboarding.completed"];
    this.store.set({ ready: true, view: onboarding ? "onboarding" : "status" });
    if (onboarding) void this.runDiagnostics();
  }

  dispose(): void {
    this.unlisten?.();
    this.unlisten = null;
  }

  navigate(view: ViewId): void {
    this.store.set({ view });
    if (view === "logs") void this.refreshLogs();
    // events can be missed (window hidden, pump lag): a fresh read when the approvals page opens
    if (view === "approvals") void this.refreshApprovals();
    if (view === "diagnostics" && this.store.get().diagnostics === null) void this.runDiagnostics();
  }

  toast(kind: "info" | "success" | "error", text: string): void {
    this.store.update((s) => withToast(s, kind, text));
  }

  dismissToast(id: number): void {
    this.store.update((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
  }

  /** Run a user action; report failures in Korean without ever showing raw daemon text. */
  private async guard<T>(fn: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; code: string }> {
    try {
      return { ok: true, value: await fn() };
    } catch (e) {
      const code = e instanceof ContractError ? "CONTRACT" : toBackendError(e).code;
      this.toast("error", messageKo(code));
      return { ok: false, code };
    }
  }

  // ----- refresh ------------------------------------------------------------

  async refreshAll(): Promise<void> {
    await Promise.all([
      this.refreshStatusQuiet(),
      this.refreshSettings(),
      this.refreshSessions(),
      this.refreshApprovals(),
      this.refreshDevices(),
      this.refreshHooks("claude_code"),
      this.refreshHooks("codex"),
    ]);
  }

  async refreshStatusQuiet(): Promise<void> {
    try {
      this.store.set({ status: await this.backend.daemonStatus() });
    } catch {
      this.store.set({ status: null });
    }
  }

  async refreshSettings(): Promise<void> {
    try {
      this.store.set({ settings: await this.backend.settingsGet() });
    } catch {
      /* keep the previous settings */
    }
  }

  async refreshSessions(): Promise<void> {
    try {
      this.store.set({ sessions: await this.backend.sessionsList() });
    } catch {
      /* ignore: events keep the list fresh */
    }
  }

  async refreshApprovals(): Promise<void> {
    // Independent fetches: a failing history call must not hide pending approvals (or vice versa).
    await Promise.all([
      this.backend.approvalsPending().then(
        (approvals) => this.store.set({ approvals }),
        () => undefined,
      ),
      this.backend.approvalsHistory(50).then(
        (history) => this.store.set({ history }),
        () => undefined,
      ),
    ]);
  }

  async refreshDevices(): Promise<void> {
    try {
      this.store.set({ devices: await this.backend.devicesList() });
    } catch {
      /* ignore */
    }
  }

  async refreshHooks(agent: HooksAgent): Promise<void> {
    try {
      const st = await this.backend.hooksStatus({ agent, mode: "http" });
      this.store.update((s) => ({ hooks: { ...s.hooks, [agent]: st } }));
    } catch {
      /* ignore */
    }
  }

  async refreshLogs(): Promise<void> {
    try {
      this.store.set({ logs: await this.backend.logsTail(200) });
    } catch {
      /* ignore */
    }
  }

  async loadSessionEvents(sessionKey: string): Promise<AgentEvent[]> {
    const r = await this.guard(() => this.backend.eventsRecent(sessionKey, 20));
    return r.ok ? r.value : [];
  }

  // ----- diagnostics / firewall --------------------------------------------

  async runDiagnostics(): Promise<void> {
    this.store.set({ diagnosticsBusy: true });
    const r = await this.guard(() => this.backend.diagnosticsRun());
    this.store.set({ diagnosticsBusy: false, ...(r.ok ? { diagnostics: r.value } : {}) });
  }

  async firewallCreate(): Promise<void> {
    const r = await this.guard(() => this.backend.firewallRuleCreate());
    if (r.ok) {
      this.toast(r.value.ok ? "success" : "error", r.value.ok ? "방화벽 규칙을 만들었어요." : "방화벽 규칙을 만들지 못했어요. 관리자 권한 확인(UAC)을 허용했는지 확인해 주세요.");
      await this.runDiagnostics();
    }
  }

  async firewallRemove(): Promise<void> {
    const r = await this.guard(() => this.backend.firewallRuleRemove());
    if (r.ok) {
      this.toast(r.value.ok ? "success" : "error", r.value.ok ? "방화벽 규칙을 제거했어요." : "방화벽 규칙을 제거하지 못했어요.");
      await this.runDiagnostics();
    }
  }

  // ----- link / pause / risk ------------------------------------------------

  async setLinkEnabled(enabled: boolean): Promise<boolean> {
    const r = await this.guard(() => this.backend.linkSetEnabled(enabled));
    await this.refreshStatusQuiet();
    if (r.ok) this.toast("info", enabled ? "휴대폰 연결을 켰어요." : "휴대폰 연결을 껐어요. 보류 중인 승인은 PC에서 처리하도록 넘겼어요.");
    return r.ok;
  }

  async setRemoteApprovalPaused(paused: boolean): Promise<boolean> {
    const r = await this.guard(() => (paused ? this.backend.remoteApprovalPause() : this.backend.remoteApprovalResume()));
    await this.refreshStatusQuiet();
    return r.ok;
  }

  async acceptRiskR1(): Promise<boolean> {
    const r = await this.guard(() => this.backend.riskAccept("R1"));
    await this.refreshSettings();
    return r.ok;
  }

  // ----- pairing ------------------------------------------------------------

  async startPairing(): Promise<boolean> {
    const r = await this.guard(() => this.backend.pairingStart());
    if (!r.ok) return false;
    const exp = Date.parse(r.value.expires_at);
    this.store.set({
      pairing: {
        pairing_id: r.value.pairing_id,
        qr_svg: r.value.qr_svg,
        expires_at_ms: Number.isNaN(exp) ? this.clock() : exp,
      },
    });
    return true;
  }

  async cancelPairing(): Promise<void> {
    const p = this.store.get().pairing;
    // Drop the QR first: it must never outlive the user's cancel click.
    this.store.set({ pairing: null });
    if (p === null) return;
    await this.guard(() => this.backend.pairingCancel(p.pairing_id));
  }

  /**
   * SAS modal decision. Approving is refused here (not only in the button state) unless the
   * SAS is a well-formed 6-digit string, the 2 s delay has passed and the confirm window is open.
   */
  async confirmPairing(approve: boolean): Promise<boolean> {
    const sas = this.store.get().sas;
    if (sas === null) return false;
    if (approve) {
      const gate = new SasGate(sas.shown_at_ms, sas.confirm_timeout_ms, SAS_APPROVE_DELAY_MS);
      if (formatSas(sas.sas) === null || !gate.approveEnabled(this.clock())) return false;
    }
    const r = await this.guard(() => this.backend.pairingConfirm(sas.pairing_id, approve));
    if (r.ok || (!r.ok && r.code === "PAIRING_NOT_PENDING")) {
      this.store.update((s) => (s.sas !== null && s.sas.pairing_id === sas.pairing_id ? { sas: null } : {}));
    }
    await Promise.all([this.refreshDevices(), this.refreshStatusQuiet()]);
    return r.ok;
  }

  /** Called every second by the shell. Fail-closed expiry of QR and SAS prompts. */
  tick(): void {
    const now = this.clock();
    const s = this.store.get();
    if (s.pairing !== null && now >= s.pairing.expires_at_ms) {
      this.store.set({ pairing: null, ...withToast(s, "info", "QR 시간이 지나 기기 추가가 끝났어요.") });
    }
    const sas = this.store.get().sas;
    if (sas !== null && new SasGate(sas.shown_at_ms, sas.confirm_timeout_ms).expired(now)) {
      // Never leave an approvable prompt around: reject (best effort) and close.
      void this.confirmPairing(false);
    }
  }

  // ----- devices ------------------------------------------------------------

  async revokeDevice(device: Device, typedName: string): Promise<boolean> {
    // Mirrors the server rule; the Rust side re-checks name_typed.
    if (!revokeNameMatches(device.name, typedName)) {
      this.toast("error", messageKo("NAME_MISMATCH"));
      return false;
    }
    const r = await this.guard(() => this.backend.deviceRevoke(device.device_id, typedName));
    await Promise.all([this.refreshDevices(), this.refreshStatusQuiet()]);
    if (r.ok) this.toast("success", "기기를 폐기했어요. 이 휴대폰은 다시 페어링해야 연결돼요.");
    return r.ok;
  }

  // ----- approvals ----------------------------------------------------------

  async decide(approval: ApprovalPending, decision: Decision, gatePassed: boolean): Promise<boolean> {
    const args = buildDecideArgs(approval, decision, gatePassed);
    const r = await this.guard(() => this.backend.approvalDecideLocal(args));
    if (!r.ok) await this.refreshApprovals();
    else this.toast("success", decision === "allow" ? "허용했어요." : "거부했어요.");
    return r.ok;
  }

  async handoffLocal(approval: ApprovalPending): Promise<boolean> {
    const r = await this.guard(() => this.backend.approvalHandoffLocal(approval.request_id));
    if (!r.ok) await this.refreshApprovals();
    else this.toast("info", "에이전트의 로컬 화면에서 직접 처리해 주세요.");
    return r.ok;
  }

  // ----- settings / integrations -------------------------------------------

  async setSetting<K extends WritableSettingKey>(key: K, value: Settings[K]): Promise<boolean> {
    if (key === "approval.ttl_s") {
      const n = Number(value);
      if (!Number.isInteger(n) || n < TTL_MIN_S || n > TTL_MAX_S) {
        this.toast("error", messageKo("INVALID_SETTING"));
        return false;
      }
    }
    const r = await this.guard(() => this.backend.settingsSet(key, value));
    if (r.ok) this.store.set({ settings: r.value });
    else await this.refreshSettings();
    await this.refreshStatusQuiet();
    // the Codex hooks.json draft carries the PermissionRequest timeout (TTL + 30)
    if (r.ok && key === "approval.ttl_s") await this.refreshHooks("codex");
    return r.ok;
  }

  async toggleCodexStep(step: CodexOnboardingStep): Promise<void> {
    const cur = this.store.get().settings?.["onboarding.codex_steps_done"] ?? [];
    const next = cur.includes(step) ? cur.filter((s) => s !== step) : [...cur, step];
    await this.setSetting("onboarding.codex_steps_done", next);
  }

  async completeOnboarding(): Promise<void> {
    if (await this.setSetting("onboarding.completed", true)) this.navigate("status");
  }

  async hooksInstall(agent: HooksAgent, mode: HooksMode): Promise<boolean> {
    const r = await this.guard(() => this.backend.hooksInstall({ agent, mode }));
    if (r.ok) {
      this.store.update((s) => ({ hooks: { ...s.hooks, [agent]: r.value } }));
      this.toast(r.value.installed ? "success" : "info", r.value.installed ? "훅을 설치했어요." : "안내에 따라 직접 설치해 주세요.");
    }
    await this.refreshStatusQuiet();
    return r.ok;
  }

  async hooksUninstall(agent: HooksAgent, mode: HooksMode): Promise<boolean> {
    const r = await this.guard(() => this.backend.hooksUninstall({ agent, mode }));
    if (r.ok) {
      this.store.update((s) => ({ hooks: { ...s.hooks, [agent]: r.value } }));
      this.toast("info", "훅을 제거했어요.");
    }
    await this.refreshStatusQuiet();
    return r.ok;
  }

  async probeCodex(): Promise<void> {
    const r = await this.guard(() => this.backend.codexProbe());
    if (r.ok) this.store.set({ codexProbe: r.value });
  }

  async openLogsDir(): Promise<void> {
    await this.guard(() => this.backend.logsOpenDir());
  }

  // ----- misc ----------------------------------------------------------------

  agentSeen(kind: AgentKind): string | null {
    const last = this.store.get().status?.last_event_at;
    if (last === undefined) return null;
    if (kind === "claude_code") return last.claude_code;
    if (kind === "codex") return last.codex;
    return null;
  }
}

