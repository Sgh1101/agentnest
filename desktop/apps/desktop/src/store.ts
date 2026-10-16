/** Small observable state store + pure reducer for `daemon-event` messages. */
import type {
  AdapterStatus,
  AgentEvent,
  AgentKind,
  ApprovalHistoryEntry,
  ApprovalPending,
  CodexProbe,
  DaemonEvent,
  DaemonStatus,
  Device,
  DiagnosticsReport,
  HooksAgent,
  HooksStatus,
  PairingDevice,
  SessionState,
  Settings,
} from "./api/types";
import { PAIRING_END_KO } from "./ko";

export type ViewId =
  | "status"
  | "diagnostics"
  | "pairing"
  | "devices"
  | "sessions"
  | "approvals"
  | "integrations"
  | "settings"
  | "logs"
  | "onboarding";

export const VIEW_ORDER: readonly ViewId[] = [
  "status",
  "diagnostics",
  "pairing",
  "devices",
  "sessions",
  "approvals",
  "integrations",
  "settings",
  "logs",
];

export interface PairingActive {
  pairing_id: string;
  /** Held only while pairing mode is active; dropped on every end path. */
  qr_svg: string;
  expires_at_ms: number;
}

export interface SasPrompt {
  pairing_id: string;
  sas: string;
  device: PairingDevice;
  confirm_timeout_ms: number;
  shown_at_ms: number;
}

export type ToastKind = "info" | "success" | "error";
export interface Toast {
  id: number;
  kind: ToastKind;
  text: string;
}

export interface AppState {
  view: ViewId;
  backendKind: "tauri" | "mock";
  ready: boolean;
  status: DaemonStatus | null;
  settings: Settings | null;
  sessions: SessionState[];
  approvals: ApprovalPending[];
  history: ApprovalHistoryEntry[];
  devices: Device[];
  diagnostics: DiagnosticsReport | null;
  diagnosticsBusy: boolean;
  adapters: Partial<Record<AgentKind, AdapterStatus>>;
  hooks: Partial<Record<HooksAgent, HooksStatus>>;
  codexProbe: CodexProbe | null;
  pairing: PairingActive | null;
  sas: SasPrompt | null;
  logs: string[];
  recentEvents: AgentEvent[];
  toasts: Toast[];
  toastSeq: number;
}

export const MAX_RECENT_EVENTS = 200;
export const MAX_HISTORY = 50;

export function initialState(backendKind: "tauri" | "mock" = "mock"): AppState {
  return {
    view: "status",
    backendKind,
    ready: false,
    status: null,
    settings: null,
    sessions: [],
    approvals: [],
    history: [],
    devices: [],
    diagnostics: null,
    diagnosticsBusy: false,
    adapters: {},
    hooks: {},
    codexProbe: null,
    pairing: null,
    sas: null,
    logs: [],
    recentEvents: [],
    toasts: [],
    toastSeq: 0,
  };
}

export interface Store {
  get(): AppState;
  set(patch: Partial<AppState>): void;
  update(fn: (s: AppState) => Partial<AppState>): void;
  subscribe(fn: (s: AppState) => void): () => void;
}

export function createStore(initial: AppState): Store {
  let state = initial;
  const subs = new Set<(s: AppState) => void>();
  const notify = (): void => {
    for (const fn of [...subs]) fn(state);
  };
  return {
    get: () => state,
    set(patch) {
      state = { ...state, ...patch };
      notify();
    },
    update(fn) {
      state = { ...state, ...fn(state) };
      notify();
    },
    subscribe(fn) {
      subs.add(fn);
      return () => {
        subs.delete(fn);
      };
    },
  };
}

export function withToast(state: AppState, kind: ToastKind, text: string): Pick<AppState, "toasts" | "toastSeq"> {
  const id = state.toastSeq + 1;
  return { toastSeq: id, toasts: [...state.toasts, { id, kind, text }].slice(-4) };
}

function upsertBy<T>(list: readonly T[], item: T, same: (a: T) => boolean): T[] {
  const idx = list.findIndex(same);
  if (idx < 0) return [...list, item];
  const copy = [...list];
  copy[idx] = item;
  return copy;
}

/** Pure reducer: returns the state patch for one daemon event. */
export function reduceDaemonEvent(state: AppState, ev: DaemonEvent, nowMs: number): Partial<AppState> {
  switch (ev.kind) {
    case "event": {
      const recentEvents = [...state.recentEvents, ...ev.payload].slice(-MAX_RECENT_EVENTS);
      let status = state.status;
      if (status !== null) {
        const last = { ...status.last_event_at };
        for (const e of ev.payload) {
          if (e.agent_kind === "claude_code") last.claude_code = e.ts;
          if (e.agent_kind === "codex") last.codex = e.ts;
        }
        status = { ...status, last_event_at: last };
      }
      return { recentEvents, status };
    }
    case "session_state":
      return { sessions: upsertBy(state.sessions, ev.payload, (s) => s.session_key === ev.payload.session_key) };
    case "approval": {
      const p = ev.payload;
      if (p.op === "requested") {
        return { approvals: upsertBy(state.approvals, p.approval, (a) => a.request_id === p.approval.request_id) };
      }
      if (p.op === "delivery") {
        return { approvals: state.approvals.map((a) => (a.request_id === p.request_id ? { ...a, delivery: p.delivery } : a)) };
      }
      const known = state.approvals.find((a) => a.request_id === p.resolved.request_id);
      const device = state.devices.find((d) => d.device_id === p.resolved.resolved_device_id);
      const entry: ApprovalHistoryEntry = {
        request_id: p.resolved.request_id,
        title: known?.title ?? "승인 요청",
        tool_name: known?.tool_name ?? "",
        risk_level: known?.risk.level ?? "high",
        outcome: p.resolved.outcome,
        resolved_by: p.resolved.resolved_by,
        resolved_device_name: device?.name ?? null,
        resolved_at: p.resolved.resolved_at,
      };
      return {
        approvals: state.approvals.filter((a) => a.request_id !== p.resolved.request_id),
        history: [entry, ...state.history.filter((h) => h.request_id !== entry.request_id)].slice(0, MAX_HISTORY),
      };
    }
    case "device":
      return { devices: upsertBy(state.devices, ev.payload.device, (d) => d.device_id === ev.payload.device.device_id) };
    case "adapter":
      return { adapters: { ...state.adapters, [ev.payload.agent_kind]: ev.payload } };
    case "resync":
      // handled by the controller (it re-reads approvals, sessions, devices and status); nothing to derive here
      return {};
    case "link": {
      const patch: Partial<AppState> = {};
      if (state.status !== null) {
        patch.status = { ...state.status, link_enabled: ev.payload.enabled, remote_approval_paused: ev.payload.remote_approval_paused };
      }
      if (!ev.payload.enabled) {
        patch.pairing = null;
        patch.sas = null;
      }
      return patch;
    }
    case "pairing": {
      const p = ev.payload;
      if (p.op === "pending_sas") {
        // The QR is no longer needed once a phone has connected: stop showing it immediately.
        return {
          pairing: null,
          sas: { pairing_id: p.pairing_id, sas: p.sas, device: p.device, confirm_timeout_ms: p.confirm_timeout_ms, shown_at_ms: nowMs },
        };
      }
      if (p.op === "completed") {
        return { pairing: null, sas: null, ...withToast(state, "success", "기기를 추가했어요.") };
      }
      return { pairing: null, sas: null, ...withToast(state, "info", PAIRING_END_KO[p.reason]) };
    }
  }
}
