/** Deterministic sample payloads for MockBackend, the dev panel and tests. */
import type {
  ApprovalPending,
  Device,
  ExtraConfirmation,
  ProjectRef,
  RiskLevel,
  SessionState,
  Settings,
} from "./types";

export const SAMPLE_PROJECT: ProjectRef = {
  project_key: "c:/dev/agentnest",
  name: "agentnest",
  path_hint: "…\\dev\\agentnest",
  repo: "owner/agentnest",
  branch: "feat/pairing",
};

export function sampleSession(over: Partial<SessionState> = {}): SessionState {
  return {
    session_key: "claude_code:7f1e2d3c-4b5a-4c6d-8e7f-0a1b2c3d4e5f",
    agent_kind: "claude_code",
    agent_label: "Claude Code",
    project: SAMPLE_PROJECT,
    state: "testing",
    state_since: "2026-10-15T12:34:50.000Z",
    headline: "테스트를 돌리고 있어요 (cargo test -p core)",
    detail: "Run core tests.",
    started_at: "2026-10-15T11:02:10.000Z",
    turn: { active: true, started_at: "2026-10-15T12:30:01.000Z", completed_at: null, prompt_preview: "페어링 토큰 만료 테스트 추가해줘" },
    permission_mode: "default",
    remote_approval: "available",
    pending_approval_ids: [],
    counters: { tools: 42, files_modified: 3, commands: 7, tests: 2, errors: 1 },
    last_test: { status: "running", at: "2026-10-15T12:34:50.000Z" },
    meta: { title: "훅 수집기 구현", model: "claude-opus-5", review: null },
    last_event_at: "2026-10-15T12:34:55.000Z",
    ended: false,
    stale: false,
    ...over,
  };
}

const LEVEL_GATE: Record<RiskLevel, ExtraConfirmation> = {
  low: "none",
  medium: "none",
  high: "hold",
  critical: "hold_and_reconfirm",
};

export interface ApprovalSampleOptions {
  id?: string;
  level?: RiskLevel;
  extra?: ExtraConfirmation;
  command?: string;
  created_at?: string;
  ttl_seconds?: number;
  origin?: ApprovalPending["origin"];
  purpose?: string | null;
}

/** Build an ApprovalPending. `created_at` is ISO; expiry = created_at + ttl_seconds. */
export function sampleApproval(opts: ApprovalSampleOptions = {}): ApprovalPending {
  const level = opts.level ?? "high";
  const created = opts.created_at ?? "2026-10-15T12:35:00.000Z";
  const ttl = opts.ttl_seconds ?? 120;
  const expires = new Date(Date.parse(created) + ttl * 1000).toISOString();
  const origin = opts.origin ?? "claude_code.hook.http";
  const codex = origin === "codex.hook.cli";
  return {
    request_id: opts.id ?? "ar_01929f1a-6c2e-7b3c-9e4d-00000000001a",
    session_key: codex ? "codex:thr_01HZX3Q9N4K7" : "claude_code:7f1e2d3c-4b5a-4c6d-8e7f-0a1b2c3d4e5f",
    agent_kind: codex ? "codex" : "claude_code",
    agent_label: codex ? "Codex" : "Claude Code",
    project: SAMPLE_PROJECT,
    origin,
    created_at: created,
    expires_at: expires,
    ttl_seconds: ttl,
    tool_name: "Bash",
    title: "명령을 실행하려고 해요",
    purpose: opts.purpose === undefined ? "node_modules 폴더를 지우고 다시 설치합니다." : opts.purpose,
    details: {
      kind: "command",
      command: opts.command ?? "rm -rf node_modules && pnpm install",
      cwd_hint: "…\\apps\\desktop",
      file_paths: ["desktop/apps/desktop/node_modules"],
      diff_preview: null,
      content_preview: null,
      mcp_server: null,
      reason: null,
      truncated: false,
      permission_suggestions_count: 1,
    },
    tool_input_sha256: "940519b4cf559666e1068256e714a63ef4b8df29e78fc02b9b75079bbeae4032",
    risk: {
      level,
      reasons: level === "high" ? ["recursive_delete"] : [],
      reasons_ko: level === "high" ? ["폴더를 통째로 지우는 명령이에요"] : level === "critical" ? ["되돌릴 수 없는 명령이에요"] : [],
      extra_confirmation: opts.extra ?? LEVEL_GATE[level],
    },
    allowed_decisions: codex ? ["allow", "deny"] : ["allow", "deny", "deny_and_stop"],
    auth_required_for: codex ? ["allow"] : ["allow", "deny_and_stop"],
    permission_mode: "default",
    local_prompt: "unknown",
    delivery: { sent_to: ["Pixel 9"], acked: true, seen: false },
  };
}

export function sampleDevice(over: Partial<Device> = {}): Device {
  return {
    device_id: "dev_8a1f3c5e7b9d2f4a6c8e0a1b3d5f7092",
    name: "Pixel 9",
    platform: "android",
    model: "Pixel 9",
    paired_at: "2026-10-14T08:00:00.000Z",
    last_seen_at: "2026-10-15T12:30:00.000Z",
    online: true,
    revoked_at: null,
    ...over,
  };
}

export function defaultSettings(over: Partial<Settings> = {}): Settings {
  return {
    "approval.ttl_s": 120,
    "approval.deny_requires_auth": false,
    "approval.critical_remote": "extra_confirmation",
    "approval.daemon_down_deny": false,
    "app.notifications": true,
    "app.log_level": "info",
    "app.autostart": false,
    "onboarding.completed": true,
    "onboarding.codex_steps_done": [],
    "risk.accepted": ["R1"],
    ...over,
  };
}
