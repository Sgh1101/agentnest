/**
 * Hand-written TypeScript mirror of the daemon payloads.
 *
 * Ground truth: protocol/schema (JSON Schema) + docs/protocol.md + docs/desktop.md section 3.
 * `guards.ts` turns untrusted `unknown` values into these types field by field
 * (unknown fields are dropped, unknown enum values map to the fail-safe value).
 *
 * Deliberately absent: `nonce_b64` (a security.md 8.1 secret type) and the raw
 * `detail` object of AgentEvent. The UI never needs them, so it never holds them.
 */

export type Timestamp = string;

export const AGENT_KINDS = ["claude_code", "codex", "gemini_cli", "opencode", "other"] as const;
export type AgentKind = (typeof AGENT_KINDS)[number];

export const AGENT_STATES = [
  "idle",
  "working",
  "writing_code",
  "reviewing",
  "testing",
  "awaiting_approval",
  "awaiting_input",
  "error",
  "completed",
  "disconnected",
] as const;
export type AgentState = (typeof AGENT_STATES)[number];

export const RISK_LEVELS = ["low", "medium", "high", "critical"] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const EXTRA_CONFIRMATIONS = ["none", "hold", "hold_and_reconfirm"] as const;
export type ExtraConfirmation = (typeof EXTRA_CONFIRMATIONS)[number];

export const DECISIONS = ["allow", "deny", "deny_and_stop"] as const;
export type Decision = (typeof DECISIONS)[number];

export const REMOTE_APPROVALS = ["available", "unavailable", "paused", "unknown"] as const;
export type RemoteApproval = (typeof REMOTE_APPROVALS)[number];

export const SOURCE_CHANNELS = [
  "claude_code.hook.http",
  "claude_code.hook.cli",
  "claude_code.statusline",
  "codex.hook.cli",
  "codex.app_server",
  "codex.rollout",
  "codex.exec_json",
] as const;
export type SourceChannel = (typeof SOURCE_CHANNELS)[number];

export const SEVERITIES = ["debug", "info", "notice", "warning", "error"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const ADAPTER_STATUS_KINDS = ["connected", "degraded", "disconnected", "not_configured"] as const;
export type AdapterStatusKind = (typeof ADAPTER_STATUS_KINDS)[number];

export const ADAPTER_MODES = ["hooks_http", "hooks_cli", "daemon_observer", "rollout_tail", "none"] as const;
export type AdapterMode = (typeof ADAPTER_MODES)[number];

export const APPROVAL_OUTCOMES = [
  "allowed",
  "denied",
  "denied_and_stopped",
  "expired",
  "handed_off_local",
  "superseded",
  "failed",
] as const;
/** `handled` is UI-only: protocol.md section 10 says an unknown outcome is shown as "처리됨". */
export type ApprovalOutcome = (typeof APPROVAL_OUTCOMES)[number] | "handled";

export const RESOLVED_BYS = ["phone", "desktop", "timeout", "agent", "system"] as const;
/** `unknown` is UI-only (unknown value from a newer daemon). */
export type ResolvedBy = (typeof RESOLVED_BYS)[number] | "unknown";

export const DETAILS_KINDS = [
  "command",
  "file_write",
  "file_edit",
  "file_read",
  "mcp_tool",
  "web",
  "agent",
  "file_change",
  "permissions",
  "other",
] as const;
export type DetailsKind = (typeof DETAILS_KINDS)[number];

export interface ProjectRef {
  project_key: string;
  name: string;
  path_hint: string | null;
  repo: string | null;
  branch: string | null;
}

/** Normalised event (protocol.md 5.1). `detail` is intentionally not mirrored. */
export interface AgentEvent {
  event_id: string;
  seq: number;
  ts: Timestamp;
  agent_kind: AgentKind;
  session_key: string;
  project: ProjectRef | null;
  kind: string;
  category: string;
  severity: Severity;
  headline: string;
  detail_ko: string | null;
  state_hint: AgentState | null;
  redacted: boolean;
}

export interface SessionTurn {
  active: boolean;
  started_at: Timestamp | null;
  completed_at: Timestamp | null;
  prompt_preview: string | null;
}

export interface SessionCounters {
  tools: number;
  files_modified: number;
  commands: number;
  tests: number;
  errors: number;
}

export interface SessionReview {
  p0: number;
  p1: number;
  state: "none" | "running" | "completed" | "unavailable";
}

export interface SessionMeta {
  title: string | null;
  model: string | null;
  review: SessionReview | null;
}

export interface SessionLastTest {
  status: "running" | "passed" | "failed";
  at: Timestamp;
}

/** protocol.md 5.3 (subset the desktop renders). */
export interface SessionState {
  session_key: string;
  agent_kind: AgentKind;
  agent_label: string;
  project: ProjectRef;
  state: AgentState;
  state_since: Timestamp;
  headline: string;
  detail: string | null;
  started_at: Timestamp;
  turn: SessionTurn;
  permission_mode: string | null;
  remote_approval: RemoteApproval;
  pending_approval_ids: string[];
  counters: SessionCounters;
  last_test: SessionLastTest | null;
  meta: SessionMeta;
  last_event_at: Timestamp;
  ended: boolean;
  stale: boolean;
}

export interface Risk {
  level: RiskLevel;
  reasons: string[];
  reasons_ko: string[];
  extra_confirmation: ExtraConfirmation;
}

export interface ApprovalDetails {
  kind: DetailsKind;
  command: string | null;
  cwd_hint: string | null;
  file_paths: string[];
  diff_preview: string | null;
  content_preview: string | null;
  mcp_server: string | null;
  reason: string | null;
  truncated: boolean;
  permission_suggestions_count: number | null;
}

/** protocol.md 6.1 without `nonce_b64`. */
export interface ApprovalRequest {
  request_id: string;
  session_key: string;
  agent_kind: AgentKind;
  agent_label: string;
  project: ProjectRef;
  origin: SourceChannel;
  created_at: Timestamp;
  expires_at: Timestamp;
  ttl_seconds: number;
  tool_name: string;
  title: string;
  /** Agent-controlled, unverified text. Always rendered with the "unverified" label. */
  purpose: string | null;
  details: ApprovalDetails;
  tool_input_sha256: string;
  risk: Risk;
  allowed_decisions: Decision[];
  auth_required_for: Decision[];
  permission_mode: string | null;
  local_prompt: "unknown" | "visible" | "hidden";
}

/** `approvals_pending` row: delivery status "sent / phone received / opened". */
export interface ApprovalDelivery {
  sent_to: string[];
  acked: boolean;
  seen: boolean;
}

export interface ApprovalPending extends ApprovalRequest {
  delivery: ApprovalDelivery;
}

/** protocol.md 4.12 `approval_resolved` payload. */
export interface ApprovalResolved {
  request_id: string;
  session_key: string;
  outcome: ApprovalOutcome;
  resolved_by: ResolvedBy;
  resolved_device_id: string | null;
  resolved_at: Timestamp;
  message_ko: string;
}

/** `approvals_history` row (contract addition, see docs/desktop.md 3.1). */
export interface ApprovalHistoryEntry {
  request_id: string;
  title: string;
  tool_name: string;
  risk_level: RiskLevel;
  outcome: ApprovalOutcome;
  resolved_by: ResolvedBy;
  resolved_device_name: string | null;
  resolved_at: Timestamp;
}

export interface AdapterStatus {
  agent_kind: AgentKind;
  status: AdapterStatusKind;
  mode: AdapterMode;
  detail: string | null;
  updated_at: Timestamp;
}

// ---------------------------------------------------------------------------
// Tauri command payloads (docs/desktop.md section 3)
// ---------------------------------------------------------------------------

export type CodexMode = "hooks" | "daemon_observer" | "off";

export interface DaemonStatus {
  running: boolean;
  hook_port: number;
  wss_addr: string;
  hosts: string[];
  link_enabled: boolean;
  cert_expires_at: Timestamp | null;
  /** Public key fingerprint (not a secret). */
  spki_pin: string;
  hooks_installed: boolean;
  effective_ttl_s: number;
  hook_timeout_s: number;
  codex_mode: CodexMode;
  sessions: number;
  devices_online: number;
  /** Contract addition: tray "remote approval pause" state. */
  remote_approval_paused: boolean;
  /** Contract addition: last event per agent (null = never). */
  last_event_at: { claude_code: Timestamp | null; codex: Timestamp | null };
}

export type NetworkProfile = "private" | "public" | "domain" | "unknown";

export interface DiagnosticsReport {
  listener: { bound: boolean; addr: string | null; port: number | null };
  network_profile: NetworkProfile;
  firewall: { rule_present: boolean; scoped_ok: boolean; block_rule_present: boolean };
  last_preauth_attempt: { at: Timestamp; ip_masked: string } | null;
  self_connect_ok: boolean;
  hosts: string[];
  hints_ko: string[];
}

export interface FirewallResult {
  ok: boolean;
  elevated: boolean;
  error: string | null;
}

export interface PairingStartResult {
  pairing_id: string;
  /** SVG markup produced by the daemon. Never inserted as markup (see ui/qr.ts). */
  qr_svg: string;
  expires_at: Timestamp;
}

export interface Device {
  device_id: string;
  name: string;
  platform: string;
  model: string | null;
  paired_at: Timestamp;
  last_seen_at: Timestamp | null;
  online: boolean;
  revoked_at: Timestamp | null;
}

export type HooksAgent = "claude_code" | "codex";
export type HooksMode = "http" | "cli";

export interface HooksArgs {
  agent: HooksAgent;
  mode: HooksMode;
}

export interface HooksStatus {
  installed: boolean;
  path: string | null;
  warnings: string[];
}

export interface CodexProbe {
  socket_path: string | null;
  reachable: boolean;
  user_agent: string | null;
  threads: number;
}

export interface DecideLocalArgs {
  request_id: string;
  decision: Decision;
  tool_input_sha256: string;
  confirm_ack: boolean;
  reason?: string;
}

export type RiskId = "R1";
export type LogLevel = "error" | "warn" | "info" | "debug";
export type CriticalRemote = "extra_confirmation" | "local_only";
export type CodexOnboardingStep = "hooks_json" | "trust" | "doctor";

/**
 * Whitelisted settings (security.md section 9: only strengthening settings exist).
 * Forbidden keys (auto_allow_*, allow_for_session, trust_all_certs, ...) are not representable.
 */
export interface Settings {
  "approval.ttl_s": number;
  "approval.deny_requires_auth": boolean;
  "approval.critical_remote": CriticalRemote;
  "approval.daemon_down_deny": boolean;
  "app.notifications": boolean;
  "app.log_level": LogLevel;
  "app.autostart": boolean;
  "onboarding.completed": boolean;
  "onboarding.codex_steps_done": CodexOnboardingStep[];
  "risk.accepted": RiskId[];
}

export type SettingKey = keyof Settings;

export const SETTING_KEYS: readonly SettingKey[] = [
  "approval.ttl_s",
  "approval.deny_requires_auth",
  "approval.critical_remote",
  "approval.daemon_down_deny",
  "app.notifications",
  "app.log_level",
  "app.autostart",
  "onboarding.completed",
  "onboarding.codex_steps_done",
  "risk.accepted",
] as const;

/** Settings the UI may write through `settings_set` (`risk.accepted` goes through `risk_accept`). */
export type WritableSettingKey = Exclude<SettingKey, "risk.accepted">;

export const TTL_MIN_S = 60;
export const TTL_MAX_S = 180;

// ---------------------------------------------------------------------------
// Tauri event `daemon-event` payloads (docs/desktop.md section 3 + 3.1)
// ---------------------------------------------------------------------------

export type PairingEndReason = "expired" | "cancelled" | "rejected" | "failed" | "timeout" | "link_disabled";

export interface PairingDevice {
  name: string;
  platform: string;
  model: string | null;
}

export type PairingEvent =
  | {
      op: "pending_sas";
      pairing_id: string;
      /** 6-digit short authentication string; displayed for visual comparison only. */
      sas: string;
      device: PairingDevice;
      confirm_timeout_ms: number;
    }
  | { op: "completed"; pairing_id: string; device_id: string }
  | { op: "ended"; pairing_id: string; reason: PairingEndReason };

export type ApprovalEvent =
  | { op: "requested"; approval: ApprovalPending }
  | { op: "delivery"; request_id: string; delivery: ApprovalDelivery }
  | { op: "resolved"; resolved: ApprovalResolved };

export interface DeviceEvent {
  op: "paired" | "online" | "offline" | "revoked" | "updated";
  device: Device;
}

export interface LinkEvent {
  enabled: boolean;
  remote_approval_paused: boolean;
}

export type DaemonEvent =
  | { kind: "event"; payload: AgentEvent[] }
  | { kind: "session_state"; payload: SessionState }
  | { kind: "approval"; payload: ApprovalEvent }
  | { kind: "device"; payload: DeviceEvent }
  | { kind: "pairing"; payload: PairingEvent }
  | { kind: "adapter"; payload: AdapterStatus }
  | { kind: "link"; payload: LinkEvent };

export const DAEMON_EVENT_NAME = "daemon-event";
