/**
 * Runtime guards: turn untrusted `unknown` values (daemon JSON) into typed objects.
 *
 * Rules:
 *  - Output objects are rebuilt field by field, so unknown fields (including anything
 *    secret-looking a buggy daemon might add) never reach the UI.
 *  - Missing required fields throw `ContractError`.
 *  - Unknown enum values map to the fail-safe value (protocol.md section 10): unknown
 *    risk -> high, unknown extra_confirmation -> hold_and_reconfirm, unknown state -> working,
 *    unknown decisions are dropped.
 */
import {
  ADAPTER_MODES,
  ADAPTER_STATUS_KINDS,
  AGENT_KINDS,
  AGENT_STATES,
  APPROVAL_OUTCOMES,
  DECISIONS,
  DETAILS_KINDS,
  EXTRA_CONFIRMATIONS,
  REMOTE_APPROVALS,
  RESOLVED_BYS,
  RISK_LEVELS,
  SEVERITIES,
  SOURCE_CHANNELS,
  TTL_MAX_S,
  TTL_MIN_S,
  type AdapterStatus,
  type AgentEvent,
  type AgentKind,
  type AgentState,
  type ApprovalDelivery,
  type ApprovalDetails,
  type ApprovalEvent,
  type ApprovalHistoryEntry,
  type ApprovalOutcome,
  type ApprovalPending,
  type ApprovalRequest,
  type ApprovalResolved,
  type CodexMode,
  type CodexOnboardingStep,
  type CodexProbe,
  type DaemonEvent,
  type DaemonStatus,
  type Decision,
  type Device,
  type DeviceEvent,
  type DiagnosticsReport,
  type FirewallResult,
  type HooksStatus,
  type LinkEvent,
  type NetworkProfile,
  type PairingEndReason,
  type PairingEvent,
  type PairingStartResult,
  type ProjectRef,
  type ResolvedBy,
  type Risk,
  type RiskId,
  type SessionState,
  type Settings,
} from "./types";

export class ContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContractError";
  }
}

type Rec = Record<string, unknown>;

export function isRecord(v: unknown): v is Rec {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function rec(v: unknown, path: string): Rec {
  if (!isRecord(v)) throw new ContractError(`${path}: expected object`);
  return v;
}

function reqStr(r: Rec, key: string, path: string): string {
  const v = r[key];
  if (typeof v !== "string") throw new ContractError(`${path}.${key}: expected string`);
  return v;
}

function optStr(r: Rec, key: string): string | null {
  const v = r[key];
  return typeof v === "string" ? v : null;
}

function reqNum(r: Rec, key: string, path: string): number {
  const v = r[key];
  if (typeof v !== "number" || !Number.isFinite(v)) throw new ContractError(`${path}.${key}: expected number`);
  return v;
}

function optNum(r: Rec, key: string): number | null {
  const v = r[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function reqBool(r: Rec, key: string, path: string): boolean {
  const v = r[key];
  if (typeof v !== "boolean") throw new ContractError(`${path}.${key}: expected boolean`);
  return v;
}

function boolOr(r: Rec, key: string, dflt: boolean): boolean {
  const v = r[key];
  return typeof v === "boolean" ? v : dflt;
}

function strArray(v: unknown, max = 256): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const item of v) {
    if (typeof item === "string") out.push(item);
    if (out.length >= max) break;
  }
  return out;
}

function enumOr<T extends string>(values: readonly T[], v: unknown, fallback: T): T {
  return typeof v === "string" && (values as readonly string[]).includes(v) ? (v as T) : fallback;
}

function enumStrict<T extends string>(values: readonly T[], v: unknown, path: string): T {
  if (typeof v === "string" && (values as readonly string[]).includes(v)) return v as T;
  throw new ContractError(`${path}: unexpected value`);
}

// ---------------------------------------------------------------------------
// Protocol models
// ---------------------------------------------------------------------------

export function parseProject(v: unknown, path = "project"): ProjectRef {
  const r = rec(v, path);
  return {
    project_key: reqStr(r, "project_key", path),
    name: reqStr(r, "name", path),
    path_hint: optStr(r, "path_hint"),
    repo: optStr(r, "repo"),
    branch: optStr(r, "branch"),
  };
}

export function parseAgentEvent(v: unknown): AgentEvent {
  const path = "event";
  const r = rec(v, path);
  const summary = rec(r["summary"], `${path}.summary`);
  const hint = r["state_hint"];
  return {
    event_id: reqStr(r, "event_id", path),
    seq: reqNum(r, "seq", path),
    ts: reqStr(r, "ts", path),
    agent_kind: enumOr(AGENT_KINDS, r["agent_kind"], "other"),
    session_key: reqStr(r, "session_key", path),
    project: isRecord(r["project"]) ? parseProject(r["project"], `${path}.project`) : null,
    kind: reqStr(r, "kind", path),
    category: reqStr(r, "category", path),
    severity: enumOr(SEVERITIES, r["severity"], "info"),
    headline: reqStr(summary, "headline", `${path}.summary`),
    detail_ko: optStr(summary, "detail"),
    state_hint: typeof hint === "string" ? enumOr<AgentState>(AGENT_STATES, hint, "working") : null,
    redacted: boolOr(r, "redacted", false),
  };
}

export function parseSessionState(v: unknown): SessionState {
  const path = "session_state";
  const r = rec(v, path);
  const turn = rec(r["turn"], `${path}.turn`);
  // Missing counters default to 0 (readers are lenient here; see protocol/examples/invalid/_index.json).
  const counters = isRecord(r["counters"]) ? r["counters"] : {};
  const metaRaw = isRecord(r["meta"]) ? r["meta"] : {};
  const reviewRaw = isRecord(metaRaw["review"]) ? metaRaw["review"] : null;
  const lastTestRaw = isRecord(r["last_test"]) ? r["last_test"] : null;
  return {
    session_key: reqStr(r, "session_key", path),
    agent_kind: enumOr(AGENT_KINDS, r["agent_kind"], "other"),
    agent_label: reqStr(r, "agent_label", path),
    project: parseProject(r["project"], `${path}.project`),
    // Unknown states render as "working" (protocol.md section 10).
    state: enumOr(AGENT_STATES, r["state"], "working"),
    state_since: reqStr(r, "state_since", path),
    headline: reqStr(r, "headline", path),
    detail: optStr(r, "detail"),
    started_at: reqStr(r, "started_at", path),
    turn: {
      active: reqBool(turn, "active", `${path}.turn`),
      started_at: optStr(turn, "started_at"),
      completed_at: optStr(turn, "completed_at"),
      prompt_preview: optStr(turn, "prompt_preview"),
    },
    permission_mode: optStr(r, "permission_mode"),
    // Unknown remote_approval renders as "unavailable" (protocol.md section 10).
    remote_approval: enumOr(REMOTE_APPROVALS, r["remote_approval"], "unavailable"),
    pending_approval_ids: strArray(r["pending_approval_ids"], 64),
    counters: {
      tools: optNum(counters, "tools") ?? 0,
      files_modified: optNum(counters, "files_modified") ?? 0,
      commands: optNum(counters, "commands") ?? 0,
      tests: optNum(counters, "tests") ?? 0,
      errors: optNum(counters, "errors") ?? 0,
    },
    last_test: lastTestRaw
      ? {
          status: enumOr(["running", "passed", "failed"] as const, lastTestRaw["status"], "running"),
          at: reqStr(lastTestRaw, "at", `${path}.last_test`),
        }
      : null,
    meta: {
      title: optStr(metaRaw, "title"),
      model: optStr(metaRaw, "model"),
      review: reviewRaw
        ? {
            p0: optNum(reviewRaw, "p0") ?? 0,
            p1: optNum(reviewRaw, "p1") ?? 0,
            // Unknown review state is "unavailable" (protocol.md 5.3).
            state: enumOr(["none", "running", "completed", "unavailable"] as const, reviewRaw["state"], "unavailable"),
          }
        : null,
    },
    last_event_at: reqStr(r, "last_event_at", path),
    ended: reqBool(r, "ended", path),
    stale: boolOr(r, "stale", false),
  };
}

export function parseRisk(v: unknown, path = "risk"): Risk {
  const r = rec(v, path);
  return {
    // Unknown level -> high (never lower; protocol.md section 10), unknown extra_confirmation -> strongest gate.
    level: enumOr(RISK_LEVELS, r["level"], "high"),
    reasons: strArray(r["reasons"], 16),
    reasons_ko: strArray(r["reasons_ko"], 16),
    extra_confirmation: enumOr(EXTRA_CONFIRMATIONS, r["extra_confirmation"], "hold_and_reconfirm"),
  };
}

function parseDetails(v: unknown, path: string): ApprovalDetails {
  const r = rec(v, path);
  return {
    kind: enumOr(DETAILS_KINDS, r["kind"], "other"),
    command: optStr(r, "command"),
    cwd_hint: optStr(r, "cwd_hint"),
    file_paths: strArray(r["file_paths"], 50),
    diff_preview: optStr(r, "diff_preview"),
    content_preview: optStr(r, "content_preview"),
    mcp_server: optStr(r, "mcp_server"),
    reason: optStr(r, "reason"),
    // Missing flag means "possibly truncated" -> fail towards showing the warning.
    truncated: boolOr(r, "truncated", true),
    permission_suggestions_count: optNum(r, "permission_suggestions_count"),
  };
}

function parseDecisions(v: unknown): Decision[] {
  const out: Decision[] = [];
  if (Array.isArray(v)) {
    for (const d of v) {
      if (typeof d === "string" && (DECISIONS as readonly string[]).includes(d) && !out.includes(d as Decision)) {
        out.push(d as Decision);
      }
    }
  }
  return out;
}

/** protocol.md 6.1. `nonce_b64` and any unknown field are dropped. */
export function parseApprovalRequest(v: unknown): ApprovalRequest {
  const path = "approval";
  const r = rec(v, path);
  const origin = enumStrict(SOURCE_CHANNELS, r["origin"], `${path}.origin`);
  let allowed = parseDecisions(r["allowed_decisions"]);
  // Codex hooks cannot stop the agent: never offer deny_and_stop (protocol.md 6.1).
  if (origin === "codex.hook.cli") allowed = allowed.filter((d) => d !== "deny_and_stop");
  const sha = reqStr(r, "tool_input_sha256", path);
  if (!/^[0-9a-f]{64}$/.test(sha)) throw new ContractError(`${path}.tool_input_sha256: expected lowercase hex sha256`);
  return {
    request_id: reqStr(r, "request_id", path),
    session_key: reqStr(r, "session_key", path),
    agent_kind: enumOr(AGENT_KINDS, r["agent_kind"], "other"),
    agent_label: reqStr(r, "agent_label", path),
    project: parseProject(r["project"], `${path}.project`),
    origin,
    created_at: reqStr(r, "created_at", path),
    expires_at: reqStr(r, "expires_at", path),
    ttl_seconds: reqNum(r, "ttl_seconds", path),
    tool_name: reqStr(r, "tool_name", path),
    title: reqStr(r, "title", path),
    purpose: optStr(r, "purpose"),
    details: parseDetails(r["details"], `${path}.details`),
    tool_input_sha256: sha,
    risk: parseRisk(r["risk"], `${path}.risk`),
    allowed_decisions: allowed,
    auth_required_for: parseDecisions(r["auth_required_for"]),
    permission_mode: optStr(r, "permission_mode"),
    local_prompt: enumOr(["unknown", "visible", "hidden"] as const, r["local_prompt"], "unknown"),
  };
}

export function parseDelivery(v: unknown): ApprovalDelivery {
  const r = isRecord(v) ? v : {};
  return {
    sent_to: strArray(r["sent_to"], 16),
    acked: boolOr(r, "acked", false),
    seen: boolOr(r, "seen", false),
  };
}

export function parseApprovalPending(v: unknown): ApprovalPending {
  const r = rec(v, "approval");
  return { ...parseApprovalRequest(v), delivery: parseDelivery(r["delivery"]) };
}

export function parseApprovalResolved(v: unknown): ApprovalResolved {
  const path = "approval_resolved";
  const r = rec(v, path);
  return {
    request_id: reqStr(r, "request_id", path),
    session_key: reqStr(r, "session_key", path),
    outcome: enumOr<ApprovalOutcome>(APPROVAL_OUTCOMES, r["outcome"], "handled"),
    resolved_by: enumOr<ResolvedBy>(RESOLVED_BYS, r["resolved_by"], "unknown"),
    resolved_device_id: optStr(r, "resolved_device_id"),
    resolved_at: reqStr(r, "resolved_at", path),
    message_ko: optStr(r, "message_ko") ?? "",
  };
}

export function parseHistoryEntry(v: unknown): ApprovalHistoryEntry {
  const path = "history";
  const r = rec(v, path);
  return {
    request_id: reqStr(r, "request_id", path),
    title: reqStr(r, "title", path),
    tool_name: reqStr(r, "tool_name", path),
    risk_level: enumOr(RISK_LEVELS, r["risk_level"], "high"),
    outcome: enumOr<ApprovalOutcome>(APPROVAL_OUTCOMES, r["outcome"], "handled"),
    resolved_by: enumOr<ResolvedBy>(RESOLVED_BYS, r["resolved_by"], "unknown"),
    resolved_device_name: optStr(r, "resolved_device_name"),
    resolved_at: reqStr(r, "resolved_at", path),
  };
}

export function parseAdapterStatus(v: unknown): AdapterStatus {
  const path = "adapter_status";
  const r = rec(v, path);
  return {
    agent_kind: enumOr(AGENT_KINDS, r["agent_kind"], "other"),
    status: enumOr(ADAPTER_STATUS_KINDS, r["status"], "degraded"),
    mode: enumOr(ADAPTER_MODES, r["mode"], "none"),
    detail: optStr(r, "detail"),
    updated_at: reqStr(r, "updated_at", path),
  };
}

// ---------------------------------------------------------------------------
// Command results
// ---------------------------------------------------------------------------

export function parseDaemonStatus(v: unknown): DaemonStatus {
  const path = "daemon_status";
  const r = rec(v, path);
  const last = isRecord(r["last_event_at"]) ? r["last_event_at"] : {};
  return {
    running: reqBool(r, "running", path),
    hook_port: reqNum(r, "hook_port", path),
    wss_addr: reqStr(r, "wss_addr", path),
    hosts: strArray(r["hosts"], 16),
    link_enabled: reqBool(r, "link_enabled", path),
    cert_expires_at: optStr(r, "cert_expires_at"),
    spki_pin: optStr(r, "spki_pin") ?? "",
    hooks_installed: reqBool(r, "hooks_installed", path),
    effective_ttl_s: reqNum(r, "effective_ttl_s", path),
    hook_timeout_s: reqNum(r, "hook_timeout_s", path),
    codex_mode: enumOr<CodexMode>(["hooks", "daemon_observer", "off"], r["codex_mode"], "off"),
    sessions: optNum(r, "sessions") ?? 0,
    devices_online: optNum(r, "devices_online") ?? 0,
    remote_approval_paused: boolOr(r, "remote_approval_paused", false),
    last_event_at: { claude_code: optStr(last, "claude_code"), codex: optStr(last, "codex") },
  };
}

export function parseDiagnostics(v: unknown): DiagnosticsReport {
  const path = "diagnostics";
  const r = rec(v, path);
  const listener = rec(r["listener"], `${path}.listener`);
  const fw = rec(r["firewall"], `${path}.firewall`);
  const pre = isRecord(r["last_preauth_attempt"]) ? r["last_preauth_attempt"] : null;
  return {
    listener: {
      bound: reqBool(listener, "bound", `${path}.listener`),
      addr: optStr(listener, "addr"),
      port: optNum(listener, "port"),
    },
    network_profile: enumOr<NetworkProfile>(["private", "public", "domain", "unknown"], r["network_profile"], "unknown"),
    firewall: {
      rule_present: reqBool(fw, "rule_present", `${path}.firewall`),
      scoped_ok: reqBool(fw, "scoped_ok", `${path}.firewall`),
      block_rule_present: reqBool(fw, "block_rule_present", `${path}.firewall`),
    },
    last_preauth_attempt: pre ? { at: reqStr(pre, "at", path), ip_masked: reqStr(pre, "ip_masked", path) } : null,
    self_connect_ok: reqBool(r, "self_connect_ok", path),
    hosts: strArray(r["hosts"], 16),
    hints_ko: strArray(r["hints_ko"], 16),
  };
}

export function parseFirewallResult(v: unknown): FirewallResult {
  const r = rec(v, "firewall_result");
  return { ok: reqBool(r, "ok", "firewall_result"), elevated: boolOr(r, "elevated", false), error: optStr(r, "error") };
}

export function parsePairingStart(v: unknown): PairingStartResult {
  const path = "pairing_start";
  const r = rec(v, path);
  return {
    pairing_id: reqStr(r, "pairing_id", path),
    qr_svg: reqStr(r, "qr_svg", path),
    expires_at: reqStr(r, "expires_at", path),
  };
}

export function parseDevice(v: unknown): Device {
  const path = "device";
  const r = rec(v, path);
  return {
    device_id: reqStr(r, "device_id", path),
    name: reqStr(r, "name", path),
    platform: optStr(r, "platform") ?? "",
    model: optStr(r, "model"),
    paired_at: reqStr(r, "paired_at", path),
    last_seen_at: optStr(r, "last_seen_at"),
    online: boolOr(r, "online", false),
    revoked_at: optStr(r, "revoked_at"),
  };
}

export function parseHooksStatus(v: unknown): HooksStatus {
  const r = rec(v, "hooks_status");
  return { installed: reqBool(r, "installed", "hooks_status"), path: optStr(r, "path"), warnings: strArray(r["warnings"], 16) };
}

export function parseCodexProbe(v: unknown): CodexProbe {
  const r = rec(v, "codex_probe");
  return {
    socket_path: optStr(r, "socket_path"),
    reachable: reqBool(r, "reachable", "codex_probe"),
    user_agent: optStr(r, "user_agent"),
    threads: optNum(r, "threads") ?? 0,
  };
}

const CODEX_STEPS: readonly CodexOnboardingStep[] = ["hooks_json", "trust", "doctor"];

export function parseSettings(v: unknown): Settings {
  const path = "settings";
  const r = rec(v, path);
  const ttl = reqNum(r, "approval.ttl_s", path);
  const accepted: RiskId[] = Array.isArray(r["risk.accepted"]) && (r["risk.accepted"] as unknown[]).includes("R1") ? ["R1"] : [];
  const steps = Array.isArray(r["onboarding.codex_steps_done"])
    ? (r["onboarding.codex_steps_done"] as unknown[]).filter((s): s is CodexOnboardingStep =>
        typeof s === "string" && (CODEX_STEPS as readonly string[]).includes(s),
      )
    : [];
  return {
    // An out-of-range TTL from the daemon is clamped for display; the UI never offers more than 180.
    "approval.ttl_s": Math.min(TTL_MAX_S, Math.max(TTL_MIN_S, Math.round(ttl))),
    "approval.deny_requires_auth": boolOr(r, "approval.deny_requires_auth", false),
    "approval.critical_remote": r["approval.critical_remote"] === "local_only" ? "local_only" : "extra_confirmation",
    "approval.daemon_down_deny": boolOr(r, "approval.daemon_down_deny", false),
    "app.notifications": boolOr(r, "app.notifications", true),
    "app.log_level": enumOr(["error", "warn", "info", "debug"] as const, r["app.log_level"], "info"),
    "app.autostart": boolOr(r, "app.autostart", false),
    "onboarding.completed": boolOr(r, "onboarding.completed", false),
    "onboarding.codex_steps_done": steps,
    "risk.accepted": accepted,
  };
}

/**
 * Parse a list but drop elements that violate the contract instead of failing the whole list
 * (one malformed row must not hide every other pending approval or device). Dropped rows are
 * counted, never logged with content.
 */
export function parseListLenient<T>(v: unknown, item: (x: unknown) => T, path: string): T[] {
  if (!Array.isArray(v)) throw new ContractError(`${path}: expected array`);
  const out: T[] = [];
  for (const x of v) {
    try {
      out.push(item(x));
    } catch {
      /* skip */
    }
  }
  return out;
}

export function parseList<T>(v: unknown, item: (x: unknown) => T, path: string): T[] {
  if (!Array.isArray(v)) throw new ContractError(`${path}: expected array`);
  return v.map((x) => item(x));
}

export function parseStringList(v: unknown, path: string): string[] {
  if (!Array.isArray(v)) throw new ContractError(`${path}: expected array`);
  return strArray(v, 1000);
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

const PAIRING_END_REASONS: readonly PairingEndReason[] = [
  "expired",
  "cancelled",
  "rejected",
  "failed",
  "timeout",
  "link_disabled",
];

function parsePairingEvent(v: unknown): PairingEvent {
  const r = rec(v, "pairing_event");
  const op = r["op"];
  const pairing_id = reqStr(r, "pairing_id", "pairing_event");
  if (op === "pending_sas") {
    const dev = rec(r["device"], "pairing_event.device");
    return {
      op,
      pairing_id,
      sas: reqStr(r, "sas", "pairing_event"),
      device: {
        name: reqStr(dev, "name", "pairing_event.device"),
        platform: optStr(dev, "platform") ?? "",
        model: optStr(dev, "model"),
      },
      confirm_timeout_ms: optNum(r, "confirm_timeout_ms") ?? 60_000,
    };
  }
  if (op === "completed") return { op, pairing_id, device_id: reqStr(r, "device_id", "pairing_event") };
  if (op === "ended") return { op, pairing_id, reason: enumOr(PAIRING_END_REASONS, r["reason"], "failed") };
  throw new ContractError("pairing_event.op: unexpected value");
}

function parseApprovalEvent(v: unknown): ApprovalEvent {
  const r = rec(v, "approval_event");
  const op = r["op"];
  if (op === "requested") return { op, approval: parseApprovalPending(r["approval"]) };
  if (op === "delivery") return { op, request_id: reqStr(r, "request_id", "approval_event"), delivery: parseDelivery(r["delivery"]) };
  if (op === "resolved") return { op, resolved: parseApprovalResolved(r["resolved"]) };
  throw new ContractError("approval_event.op: unexpected value");
}

function parseDeviceEvent(v: unknown): DeviceEvent {
  const r = rec(v, "device_event");
  return {
    op: enumOr(["paired", "online", "offline", "revoked", "updated"] as const, r["op"], "updated"),
    device: parseDevice(r["device"]),
  };
}

function parseLinkEvent(v: unknown): LinkEvent {
  const r = rec(v, "link_event");
  return { enabled: reqBool(r, "enabled", "link_event"), remote_approval_paused: boolOr(r, "remote_approval_paused", false) };
}

/**
 * Parse a raw `daemon-event` message. Returns null for unknown kinds (forward compatibility:
 * ignore, never crash) and throws ContractError for malformed known kinds.
 */
export function parseDaemonEvent(v: unknown): DaemonEvent | null {
  const r = rec(v, "daemon-event");
  const kind = r["kind"];
  const payload = r["payload"];
  switch (kind) {
    case "event": {
      const list = Array.isArray(payload) ? payload : [payload];
      return { kind, payload: list.map((e) => parseAgentEvent(e)) };
    }
    case "session_state":
      return { kind, payload: parseSessionState(payload) };
    case "approval":
      return { kind, payload: parseApprovalEvent(payload) };
    case "device":
      return { kind, payload: parseDeviceEvent(payload) };
    case "pairing":
      return { kind, payload: parsePairingEvent(payload) };
    case "adapter":
      return { kind, payload: parseAdapterStatus(payload) };
    case "link":
      return { kind, payload: parseLinkEvent(payload) };
    default:
      return null;
  }
}

export function isAgentKind(v: unknown): v is AgentKind {
  return typeof v === "string" && (AGENT_KINDS as readonly string[]).includes(v);
}
