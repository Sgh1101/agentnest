import type {
  AgentEvent,
  ApprovalHistoryEntry,
  ApprovalPending,
  CodexProbe,
  DaemonEvent,
  DaemonStatus,
  DecideLocalArgs,
  Device,
  DiagnosticsReport,
  FirewallResult,
  HooksArgs,
  HooksStatus,
  PairingStartResult,
  RiskId,
  SessionState,
  Settings,
  WritableSettingKey,
} from "./types";

/**
 * Typed surface over the Tauri commands of docs/desktop.md section 3.
 * `TauriBackend` talks to the Rust shell; `MockBackend` runs everything in memory.
 */
export interface Backend {
  readonly kind: "tauri" | "mock";

  daemonStatus(): Promise<DaemonStatus>;
  diagnosticsRun(): Promise<DiagnosticsReport>;
  firewallRuleCreate(): Promise<FirewallResult>;
  firewallRuleRemove(): Promise<FirewallResult>;
  linkSetEnabled(enabled: boolean): Promise<void>;
  riskAccept(riskId: RiskId): Promise<void>;

  pairingStart(): Promise<PairingStartResult>;
  pairingCancel(pairingId: string): Promise<void>;
  pairingConfirm(pairingId: string, approve: boolean): Promise<void>;

  devicesList(): Promise<Device[]>;
  deviceRevoke(deviceId: string, nameTyped: string): Promise<void>;

  sessionsList(): Promise<SessionState[]>;
  eventsRecent(sessionKey: string | null, limit: number): Promise<AgentEvent[]>;

  approvalsPending(): Promise<ApprovalPending[]>;
  approvalsHistory(limit: number): Promise<ApprovalHistoryEntry[]>;
  approvalHandoffLocal(requestId: string): Promise<void>;
  approvalDecideLocal(args: DecideLocalArgs): Promise<void>;
  remoteApprovalPause(): Promise<void>;
  remoteApprovalResume(): Promise<void>;

  hooksInstall(args: HooksArgs): Promise<HooksStatus>;
  hooksUninstall(args: HooksArgs): Promise<HooksStatus>;
  hooksStatus(args: HooksArgs): Promise<HooksStatus>;
  codexProbe(): Promise<CodexProbe>;

  settingsGet(): Promise<Settings>;
  settingsSet<K extends WritableSettingKey>(key: K, value: Settings[K]): Promise<Settings>;

  logsOpenDir(): Promise<void>;
  logsTail(limit: number): Promise<string[]>;

  /** Subscribe to `daemon-event`. Resolves to an unsubscribe function. */
  onEvent(handler: (event: DaemonEvent) => void): Promise<() => void>;
}

/** Exact Tauri command names (docs/desktop.md section 3 + 3.1 additions). */
export const COMMANDS = {
  daemonStatus: "daemon_status",
  diagnosticsRun: "diagnostics_run",
  firewallRuleCreate: "firewall_rule_create",
  firewallRuleRemove: "firewall_rule_remove",
  linkSetEnabled: "link_set_enabled",
  riskAccept: "risk_accept",
  pairingStart: "pairing_start",
  pairingCancel: "pairing_cancel",
  pairingConfirm: "pairing_confirm",
  devicesList: "devices_list",
  deviceRevoke: "device_revoke",
  sessionsList: "sessions_list",
  eventsRecent: "events_recent",
  approvalsPending: "approvals_pending",
  approvalsHistory: "approvals_history",
  approvalHandoffLocal: "approval_handoff_local",
  approvalDecideLocal: "approval_decide_local",
  remoteApprovalPause: "remote_approval_pause",
  remoteApprovalResume: "remote_approval_resume",
  hooksInstall: "hooks_install",
  hooksUninstall: "hooks_uninstall",
  hooksStatus: "hooks_status",
  codexProbe: "codex_probe",
  settingsGet: "settings_get",
  settingsSet: "settings_set",
  logsOpenDir: "logs_open_dir",
  logsTail: "logs_tail",
} as const;
