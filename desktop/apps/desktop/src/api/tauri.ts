import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";
import { disable as autostartDisable, enable as autostartEnable, isEnabled as autostartIsEnabled } from "@tauri-apps/plugin-autostart";
import type { Backend } from "./backend";
import { COMMANDS } from "./backend";
import { toBackendError } from "./errors";
import {
  ContractError,
  parseAgentEvent,
  parseApprovalPending,
  parseCodexProbe,
  parseDaemonEvent,
  parseDaemonStatus,
  parseDevice,
  parseDiagnostics,
  parseFirewallResult,
  parseHistoryEntry,
  parseHooksStatus,
  parseListLenient,
  parsePairingStart,
  parseSessionState,
  parseSettings,
  parseStringList,
} from "./guards";
import { DAEMON_EVENT_NAME, type DaemonEvent, type Settings, type WritableSettingKey } from "./types";

export type InvokeFn = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;
export type ListenFn = (event: string, handler: (e: { payload: unknown }) => void) => Promise<() => void>;

export interface AutostartApi {
  isEnabled(): Promise<boolean>;
  enable(): Promise<void>;
  disable(): Promise<void>;
}

export interface TauriDeps {
  invoke: InvokeFn;
  listen: ListenFn;
  autostart: AutostartApi;
}

function defaultDeps(): TauriDeps {
  return {
    invoke: (cmd, args) => tauriInvoke(cmd, args),
    listen: (event, handler) => tauriListen<unknown>(event, handler),
    autostart: { isEnabled: autostartIsEnabled, enable: autostartEnable, disable: autostartDisable },
  };
}

/** True when running inside the Tauri webview (vs. a plain browser / vitest). */
export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/**
 * Tauri turns JS argument keys from camelCase into the Rust snake_case parameter names
 * unless the command opts out with `rename_all = "snake_case"`. The documented contract uses
 * snake_case names, so we send both spellings; Tauri ignores keys a command does not declare.
 */
export function toIpcArgs(args: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    out[k] = v;
    const camel = k.replace(/_([a-z])/g, (_m, c: string) => c.toUpperCase());
    if (camel !== k) out[camel] = v;
  }
  return out;
}

export class TauriBackend implements Backend {
  readonly kind = "tauri" as const;
  private readonly deps: TauriDeps;

  constructor(deps?: Partial<TauriDeps>) {
    this.deps = { ...defaultDeps(), ...deps };
  }

  private async call(cmd: string, args?: Record<string, unknown>): Promise<unknown> {
    try {
      return await this.deps.invoke(cmd, args === undefined ? undefined : toIpcArgs(args));
    } catch (e) {
      if (e instanceof ContractError) throw e;
      throw toBackendError(e);
    }
  }

  async daemonStatus() {
    return parseDaemonStatus(await this.call(COMMANDS.daemonStatus));
  }
  async diagnosticsRun() {
    return parseDiagnostics(await this.call(COMMANDS.diagnosticsRun));
  }
  async firewallRuleCreate() {
    return parseFirewallResult(await this.call(COMMANDS.firewallRuleCreate));
  }
  async firewallRuleRemove() {
    return parseFirewallResult(await this.call(COMMANDS.firewallRuleRemove));
  }
  async linkSetEnabled(enabled: boolean) {
    await this.call(COMMANDS.linkSetEnabled, { enabled });
  }
  async riskAccept(riskId: "R1") {
    await this.call(COMMANDS.riskAccept, { risk_id: riskId });
  }

  async pairingStart() {
    return parsePairingStart(await this.call(COMMANDS.pairingStart));
  }
  async pairingCancel(pairingId: string) {
    await this.call(COMMANDS.pairingCancel, { pairing_id: pairingId });
  }
  async pairingConfirm(pairingId: string, approve: boolean) {
    await this.call(COMMANDS.pairingConfirm, { pairing_id: pairingId, approve });
  }

  async devicesList() {
    return parseListLenient(await this.call(COMMANDS.devicesList), parseDevice, "devices_list");
  }
  async deviceRevoke(deviceId: string, nameTyped: string) {
    await this.call(COMMANDS.deviceRevoke, { device_id: deviceId, name_typed: nameTyped });
  }

  async sessionsList() {
    return parseListLenient(await this.call(COMMANDS.sessionsList), parseSessionState, "sessions_list");
  }
  async eventsRecent(sessionKey: string | null, limit: number) {
    const args: Record<string, unknown> = { limit };
    if (sessionKey !== null) args["session_key"] = sessionKey;
    return parseListLenient(await this.call(COMMANDS.eventsRecent, args), parseAgentEvent, "events_recent");
  }

  async approvalsPending() {
    return parseListLenient(await this.call(COMMANDS.approvalsPending), parseApprovalPending, "approvals_pending");
  }
  async approvalsHistory(limit: number) {
    return parseListLenient(await this.call(COMMANDS.approvalsHistory, { limit }), parseHistoryEntry, "approvals_history");
  }
  async approvalHandoffLocal(requestId: string) {
    await this.call(COMMANDS.approvalHandoffLocal, { request_id: requestId });
  }
  async approvalDecideLocal(args: Parameters<Backend["approvalDecideLocal"]>[0]) {
    const payload: Record<string, unknown> = {
      request_id: args.request_id,
      decision: args.decision,
      tool_input_sha256: args.tool_input_sha256,
      confirm_ack: args.confirm_ack,
    };
    if (args.reason !== undefined) payload["reason"] = args.reason;
    await this.call(COMMANDS.approvalDecideLocal, payload);
  }
  async remoteApprovalPause() {
    await this.call(COMMANDS.remoteApprovalPause);
  }
  async remoteApprovalResume() {
    await this.call(COMMANDS.remoteApprovalResume);
  }

  async hooksInstall(args: Parameters<Backend["hooksInstall"]>[0]) {
    return parseHooksStatus(await this.call(COMMANDS.hooksInstall, { agent: args.agent, mode: args.mode }));
  }
  async hooksUninstall(args: Parameters<Backend["hooksUninstall"]>[0]) {
    return parseHooksStatus(await this.call(COMMANDS.hooksUninstall, { agent: args.agent, mode: args.mode }));
  }
  async hooksStatus(args: Parameters<Backend["hooksStatus"]>[0]) {
    return parseHooksStatus(await this.call(COMMANDS.hooksStatus, { agent: args.agent, mode: args.mode }));
  }
  async codexProbe() {
    return parseCodexProbe(await this.call(COMMANDS.codexProbe));
  }

  private async autostartValue(): Promise<boolean> {
    try {
      return await this.deps.autostart.isEnabled();
    } catch {
      return false;
    }
  }

  async settingsGet(): Promise<Settings> {
    const rust = parseSettings(await this.call(COMMANDS.settingsGet));
    // `app.autostart` is owned by tauri-plugin-autostart (JS side), not by the Rust settings store.
    return { ...rust, "app.autostart": await this.autostartValue() };
  }

  async settingsSet<K extends WritableSettingKey>(key: K, value: Settings[K]): Promise<Settings> {
    if (key === "app.autostart") {
      try {
        if (value === true) await this.deps.autostart.enable();
        else await this.deps.autostart.disable();
      } catch (e) {
        throw toBackendError(e);
      }
      return this.settingsGet();
    }
    const rust = parseSettings(await this.call(COMMANDS.settingsSet, { key, value }));
    return { ...rust, "app.autostart": await this.autostartValue() };
  }

  async logsOpenDir() {
    await this.call(COMMANDS.logsOpenDir);
  }
  async logsTail(limit: number) {
    return parseStringList(await this.call(COMMANDS.logsTail, { limit }), "logs_tail");
  }

  async onEvent(handler: (event: DaemonEvent) => void): Promise<() => void> {
    return this.deps.listen(DAEMON_EVENT_NAME, (e) => {
      let parsed: DaemonEvent | null;
      try {
        parsed = parseDaemonEvent(e.payload);
      } catch {
        // A malformed event must not crash the UI or be acted on. Drop it.
        return;
      }
      if (parsed !== null) handler(parsed);
    });
  }
}
