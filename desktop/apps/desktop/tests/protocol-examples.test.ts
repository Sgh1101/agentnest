import { describe, expect, it } from "vitest";
import {
  ContractError,
  parseAdapterStatus,
  parseAgentEvent,
  parseApprovalRequest,
  parseApprovalResolved,
  parseListLenient,
  parseSessionState,
} from "../src/api/guards";
import { listJson, readJson } from "./helpers";

function payloadOf(file: unknown): unknown {
  return (file as { payload: unknown }).payload;
}

describe("protocol/examples/model: bare payload examples parse", () => {
  for (const f of listJson("protocol", "examples", "model")) {
    if (f.startsWith("agent_event.")) {
      it(`${f} -> AgentEvent`, () => {
        const ev = parseAgentEvent(readJson("protocol", "examples", "model", f));
        expect(ev.headline.length).toBeGreaterThan(0);
        expect(ev.session_key).toMatch(/:/);
      });
    } else if (f.startsWith("session_state.")) {
      it(`${f} -> SessionState`, () => {
        const s = parseSessionState(readJson("protocol", "examples", "model", f));
        expect(s.counters.tools).toBeGreaterThanOrEqual(0);
        expect(["working", "idle", "testing", "awaiting_approval", "awaiting_input", "error", "completed", "disconnected", "writing_code", "reviewing"]).toContain(s.state);
      });
    } else if (f.startsWith("approval_request.")) {
      it(`${f} -> ApprovalRequest (no nonce kept)`, () => {
        const raw = readJson("protocol", "examples", "model", f) as { nonce_b64: string };
        const a = parseApprovalRequest(raw);
        expect(a.tool_input_sha256).toMatch(/^[0-9a-f]{64}$/);
        expect(JSON.stringify(a)).not.toContain(raw.nonce_b64);
        expect("nonce_b64" in a).toBe(false);
      });
    }
  }
});

describe("protocol/examples: wire envelopes carry parseable payloads", () => {
  it("session_state.*.json", () => {
    for (const f of listJson("protocol", "examples").filter((x) => x.startsWith("session_state."))) {
      expect(() => parseSessionState(payloadOf(readJson("protocol", "examples", f)))).not.toThrow();
    }
  });
  it("approval_request.*.json", () => {
    const files = listJson("protocol", "examples").filter((x) => x.startsWith("approval_request."));
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const a = parseApprovalRequest(payloadOf(readJson("protocol", "examples", f)));
      if (a.origin === "codex.hook.cli") expect(a.allowed_decisions).not.toContain("deny_and_stop");
    }
  });
  it("approval_resolved.*.json", () => {
    for (const f of listJson("protocol", "examples").filter((x) => x.startsWith("approval_resolved."))) {
      const r = parseApprovalResolved(payloadOf(readJson("protocol", "examples", f)));
      expect(r.request_id).toMatch(/^ar_/);
    }
  });
  it("adapter_status.*.json", () => {
    for (const f of listJson("protocol", "examples").filter((x) => x.startsWith("adapter_status."))) {
      expect(parseAdapterStatus(payloadOf(readJson("protocol", "examples", f))).updated_at).toMatch(/Z$/);
    }
  });
  it("event.*.json", () => {
    for (const f of listJson("protocol", "examples").filter((x) => /^event\.\d/.test(x))) {
      expect(parseAgentEvent(payloadOf(readJson("protocol", "examples", f))).seq).toBeGreaterThanOrEqual(0);
    }
  });
});

describe("forward compatibility (protocol.md section 10)", () => {
  it("unknown risk level -> high, unknown extra_confirmation -> strongest gate, unknown details.kind -> other", () => {
    const a = parseApprovalRequest(payloadOf(readJson("protocol", "examples", "forward_compat", "approval_request.unknown_enums.json")));
    expect(a.risk.level).toBe("high");
    expect(a.details.kind).toBe("other");
  });
  it("unknown extra_confirmation maps to hold_and_reconfirm", () => {
    const raw = payloadOf(readJson("protocol", "examples", "approval_request.1.json")) as { risk: { extra_confirmation: string } };
    raw.risk.extra_confirmation = "telepathy";
    expect(parseApprovalRequest(raw).risk.extra_confirmation).toBe("hold_and_reconfirm");
  });
  it("unknown session state -> working, unknown remote_approval -> unavailable", () => {
    const s = parseSessionState(payloadOf(readJson("protocol", "examples", "forward_compat", "session_state.unknown_enums.json")));
    expect(s.state).toBe("working");
    expect(s.remote_approval).toBe("unavailable");
  });
  it("unknown outcome/resolved_by are shown as handled/unknown, never as allowed", () => {
    const r = parseApprovalResolved(payloadOf(readJson("protocol", "examples", "forward_compat", "approval_resolved.unknown_enums.json")));
    expect(r.outcome).toBe("handled");
    expect(r.resolved_by).toBe("unknown");
  });
  it("unknown event enums fall back without throwing", () => {
    const e = parseAgentEvent(payloadOf(readJson("protocol", "examples", "forward_compat", "event.unknown_enums.json")));
    expect(e.agent_kind).toBe("other");
    expect(e.severity).toBe("info");
  });
  it("unknown decision values are dropped (no button)", () => {
    const raw = payloadOf(readJson("protocol", "examples", "approval_request.1.json")) as { allowed_decisions: string[] };
    raw.allowed_decisions = ["allow", "allow_for_session", "deny"];
    expect(parseApprovalRequest(raw).allowed_decisions).toEqual(["allow", "deny"]);
  });
});

describe("contract violations are rejected", () => {
  it("missing expires_at / tool_input_sha256 / bad hash", () => {
    for (const n of [4, 8]) {
      const file = readJson("protocol", "examples", "invalid", `approval_request.${n}.json`);
      expect(() => parseApprovalRequest(payloadOf(file))).toThrow(ContractError);
    }
    const ok = payloadOf(readJson("protocol", "examples", "approval_request.1.json")) as Record<string, unknown>;
    expect(() => parseApprovalRequest({ ...ok, tool_input_sha256: "ABC" })).toThrow(ContractError);
  });
  it("Codex hooks origin never keeps deny_and_stop even if the daemon sends it", () => {
    const ok = payloadOf(readJson("protocol", "examples", "approval_request.1.json")) as Record<string, unknown>;
    const a = parseApprovalRequest({ ...ok, origin: "codex.hook.cli", allowed_decisions: ["allow", "deny", "deny_and_stop"] });
    expect(a.allowed_decisions).toEqual(["allow", "deny"]);
  });
  it("lenient lists drop only the malformed row", () => {
    const ok = payloadOf(readJson("protocol", "examples", "approval_request.1.json"));
    const list = parseListLenient([ok, { request_id: "x" }, ok], parseApprovalRequest, "approvals");
    expect(list).toHaveLength(2);
  });
  it("session_state with missing counters defaults them to 0 (protocol examples/invalid note)", () => {
    const raw = payloadOf(readJson("protocol", "examples", "invalid", "session_state.1.json"));
    const s = parseSessionState(raw);
    expect(s.counters).toEqual({ tools: 0, files_modified: 0, commands: 0, tests: 0, errors: 0 });
  });
});
