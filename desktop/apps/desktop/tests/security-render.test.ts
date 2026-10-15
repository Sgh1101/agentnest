import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TauriBackend, type InvokeFn } from "../src/api/tauri";
import { SETTING_KEYS } from "../src/api/types";
import { sampleApproval, sampleDevice, sampleSession } from "../src/api/samples";
import { qrImageSrc } from "../src/ui/qr";
import { APP_ROOT, T0, click, mountHarness, q, qa, settle, type Harness } from "./helpers";
import type { ViewId } from "../src/store";

const EVIL = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>"><svg onload=window.__xss=3>';
const ALL_VIEWS: ViewId[] = ["status", "diagnostics", "pairing", "devices", "sessions", "approvals", "integrations", "settings", "logs", "onboarding"];

const SETTINGS_WIRE = {
  "approval.ttl_s": 120,
  "approval.deny_requires_auth": false,
  "approval.critical_remote": "extra_confirmation",
  "approval.daemon_down_deny": false,
  "app.notifications": true,
  "app.log_level": "info",
  "onboarding.completed": false,
  "onboarding.codex_steps_done": [],
  "risk.accepted": [],
};

function statusWire(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    running: true,
    hook_port: 47831,
    wss_addr: "192.168.0.10:47832",
    hosts: ["192.168.0.10"],
    link_enabled: true,
    cert_expires_at: "2028-10-15T00:00:00.000Z",
    spki_pin: "sha256/glLmKAo9gdGvAGIYNxNEvncjE6SNAheIa/dX4bFINbU=",
    hooks_installed: true,
    effective_ttl_s: 120,
    hook_timeout_s: 150,
    codex_mode: "hooks",
    sessions: 1,
    devices_online: 1,
    remote_approval_paused: false,
    last_event_at: { claude_code: null, codex: null },
    ...extra,
  };
}

function fakeBackend(responses: Record<string, unknown>): TauriBackend {
  const invoke: InvokeFn = (cmd) => {
    const r = responses[cmd];
    return Promise.resolve(r === undefined ? null : structuredClone(r));
  };
  return new TauriBackend({
    invoke,
    listen: () => Promise.resolve(() => undefined),
    autostart: { isEnabled: () => Promise.resolve(false), enable: () => Promise.resolve(), disable: () => Promise.resolve() },
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(T0);
  delete (window as unknown as Record<string, unknown>)["__xss"];
});
afterEach(() => vi.useRealTimers());

describe("XSS: every daemon-provided string is rendered as text", () => {
  let h: Harness;
  afterEach(() => h.destroy());

  it("renders hostile strings in all views without creating elements or running script", async () => {
    const approval = sampleApproval({ id: "ar_x", level: "critical", command: EVIL, purpose: EVIL, created_at: new Date(T0).toISOString() });
    approval.agent_label = EVIL;
    approval.title = EVIL;
    approval.tool_name = EVIL;
    approval.project = { ...approval.project, name: EVIL, branch: EVIL };
    approval.details.cwd_hint = EVIL;
    approval.details.file_paths = [EVIL];
    approval.details.diff_preview = EVIL;
    approval.details.content_preview = EVIL;
    approval.details.mcp_server = EVIL;
    approval.risk.reasons_ko = [EVIL];
    approval.delivery.sent_to = [EVIL];
    const session = sampleSession({ agent_label: EVIL, headline: EVIL, detail: EVIL, project: { ...approval.project } });
    session.meta.title = EVIL;
    const device = sampleDevice({ name: EVIL, model: EVIL, platform: EVIL });

    const backend = fakeBackend({
      daemon_status: statusWire({ wss_addr: EVIL, hosts: [EVIL], spki_pin: EVIL }),
      diagnostics_run: {
        listener: { bound: true, addr: EVIL, port: 1 },
        network_profile: "private",
        firewall: { rule_present: true, scoped_ok: true, block_rule_present: false },
        last_preauth_attempt: { at: "2026-10-15T12:00:00Z", ip_masked: EVIL },
        self_connect_ok: true,
        hosts: [EVIL],
        hints_ko: [EVIL],
      },
      sessions_list: [session],
      approvals_pending: [approval],
      approvals_history: [{ request_id: "ar_h", title: EVIL, tool_name: EVIL, risk_level: "low", outcome: "allowed", resolved_by: "phone", resolved_device_name: EVIL, resolved_at: "2026-10-15T12:00:00Z" }],
      devices_list: [device],
      events_recent: [{ event_id: "e", seq: 1, ts: "2026-10-15T12:00:00Z", agent_kind: "claude_code", session_key: session.session_key, kind: "k", category: "tool", severity: "info", summary: { headline: EVIL }, redacted: false }],
      hooks_status: { installed: true, path: EVIL, warnings: [EVIL] },
      codex_probe: { socket_path: EVIL, reachable: true, user_agent: EVIL, threads: 1 },
      settings_get: SETTINGS_WIRE,
      logs_tail: [EVIL],
    });
    h = await mountHarness({ backend });
    h.store.set({ codexProbe: { socket_path: EVIL, reachable: true, user_agent: EVIL, threads: 1 }, adapters: { codex: { agent_kind: "codex", status: "connected", mode: "hooks_cli", detail: EVIL, updated_at: "2026-10-15T12:00:00Z" } } });
    h.store.set({ sas: { pairing_id: "p_1", sas: "482915", device: { name: EVIL, platform: EVIL, model: EVIL }, confirm_timeout_ms: 60_000, shown_at_ms: Date.now() } });

    for (const v of ALL_VIEWS) {
      await h.go(v);
      const bad = h.root.querySelectorAll("img, script, iframe, object, embed, svg, [onerror], [onload], [onclick]");
      // the only <img> allowed would be the QR, which is not active here
      expect(bad.length, `view ${v}`).toBe(0);
    }
    expect((window as unknown as Record<string, unknown>)["__xss"]).toBeUndefined();

    // the hostile text is visible as literal text where it belongs
    await h.go("approvals");
    expect(q(h.root, "[data-command-preview]").textContent).toBe(EVIL);
    expect(q(h.root, "[data-command-full]").textContent).toBe(EVIL);
    expect(q(h.root, "[data-purpose]").textContent).toContain(EVIL.slice(0, 40));
    await h.go("sessions");
    expect(q(h.root, "[data-headline]").textContent).toBe(EVIL.length > 200 ? EVIL.slice(0, 199) + "…" : EVIL);
    await h.go("logs");
    expect(q(h.root, "[data-logs]").textContent).toBe(EVIL);
  });

  it("QR markup is validated: scripts/foreignObject/event handlers are refused, benign SVG becomes a data: <img>", () => {
    expect(qrImageSrc("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>")).toBeNull();
    expect(qrImageSrc("<svg xmlns='http://www.w3.org/2000/svg' onload='x()'/>")).toBeNull();
    expect(qrImageSrc("<svg><foreignObject/></svg>")).toBeNull();
    expect(qrImageSrc("<div>not svg</div>")).toBeNull();
    expect(qrImageSrc("")).toBeNull();
    expect(qrImageSrc("<svg xmlns='http://www.w3.org/2000/svg'><rect width='1' height='1'/></svg>")).toMatch(/^data:image\/svg\+xml;base64,/);
    expect(qrImageSrc(`<svg>${"a".repeat(300_000)}</svg>`)).toBeNull();
  });

  it("hostile QR from the daemon never reaches the DOM as markup", async () => {
    const backend = fakeBackend({
      daemon_status: statusWire(),
      settings_get: { ...SETTINGS_WIRE, "onboarding.completed": true, "risk.accepted": ["R1"] },
      pairing_start: { pairing_id: "p_1", qr_svg: "<svg xmlns='http://www.w3.org/2000/svg'><script>window.__xss=9</script></svg>", expires_at: new Date(T0 + 120_000).toISOString() },
    });
    h = await mountHarness({ backend, view: "pairing" });
    click(q(h.root, "[data-fid=pairing-start]"));
    await settle();
    expect(h.root.querySelector("img[data-qr]")).toBeNull();
    expect(h.root.querySelector("script")).toBeNull();
    expect(h.root.textContent).toContain("QR을 표시하지 못했어요");
    expect((window as unknown as Record<string, unknown>)["__xss"]).toBeUndefined();
  });

  it("bidi overrides in commands are shown as visible markers", async () => {
    const a = sampleApproval({ id: "ar_b", level: "low", command: "echo safe ‮ gnp.exe", created_at: new Date(T0).toISOString() });
    const backend = fakeBackend({ daemon_status: statusWire(), settings_get: { ...SETTINGS_WIRE, "onboarding.completed": true }, approvals_pending: [a] });
    h = await mountHarness({ backend, view: "approvals" });
    expect(q(h.root, "[data-command-preview]").textContent).toContain("⟦U+202E⟧");
    expect(q(h.root, "[data-command-preview]").textContent).not.toContain("‮");
  });
});

describe("no secrets are rendered or kept in state", () => {
  let h: Harness;
  afterEach(() => h.destroy());

  const SECRETS = ["an_hk_SUPERSECRETHOOKTOKEN", "PAIRING_SECRET_VALUE_XYZ", "DEVICE_TOKEN_VALUE_XYZ", "NONCE_VALUE_Kq2hYm9zZ3FwdHZ4eXoxMg==", "-----BEGIN PRIVATE KEY-----TLSKEY", "TOKEN_HASH_VALUE_XYZ"];

  it("extra secret-looking fields from a buggy daemon are dropped by the guards and never displayed", async () => {
    const approval = { ...sampleApproval({ id: "ar_s", level: "high", created_at: new Date(T0).toISOString() }), nonce_b64: SECRETS[3], hook_token: SECRETS[0] };
    const backend = fakeBackend({
      daemon_status: statusWire({ hook_token: SECRETS[0], pairing_secret: SECRETS[1], tls_key_pem: SECRETS[4] }),
      settings_get: { ...SETTINGS_WIRE, hook_token: SECRETS[0] },
      devices_list: [{ ...sampleDevice(), device_token: SECRETS[2], token_hash: SECRETS[5], pubkey_spki_der: "AAAA" }],
      sessions_list: [{ ...sampleSession(), hook_token: SECRETS[0] }],
      approvals_pending: [approval],
      pairing_start: { pairing_id: "p_1", qr_svg: "<svg xmlns='http://www.w3.org/2000/svg'><rect width='1' height='1'/></svg>", expires_at: new Date(T0 + 120_000).toISOString(), pairing_secret: SECRETS[1] },
    });
    h = await mountHarness({ backend });
    h.store.set({ settings: { ...h.store.get().settings!, "risk.accepted": ["R1"] } });
    await h.go("pairing");
    click(q(h.root, "[data-fid=pairing-start]"));
    await settle();
    expect(h.root.querySelector("img[data-qr]")).not.toBeNull();
    for (const v of ALL_VIEWS) {
      await h.go(v);
      const text = h.root.textContent ?? "";
      const html = h.root.innerHTML;
      for (const s of SECRETS) {
        expect(text.includes(s), `${v}: text has secret`).toBe(false);
        expect(html.includes(s), `${v}: html has secret`).toBe(false);
      }
    }
    const dump = JSON.stringify(h.store.get());
    for (const s of SECRETS) expect(dump.includes(s), "store holds secret").toBe(false);
  });
});

describe("forbidden settings do not exist (security.md section 9)", () => {
  let h: Harness;
  afterEach(() => h.destroy());

  it("the settings page exposes only whitelisted controls; TTL is capped to 60-180", async () => {
    h = await mountHarness({ view: "settings", settings: { seed: true } });
    const keys = qa(h.root, "[data-key]").map((e) => e.getAttribute("data-key"));
    const allowed = new Set<string>([...SETTING_KEYS, "link.enabled", "remote_approval_paused"]);
    expect(keys.length).toBeGreaterThanOrEqual(7);
    for (const k of keys) expect(allowed.has(k ?? ""), String(k)).toBe(true);
    const text = (h.root.textContent ?? "").toLowerCase();
    for (const word of ["auto_allow", "allow_for_session", "trust_all", "bind_addr", "disable_biometric", "risk_override"]) expect(text).not.toContain(word);
    for (const word of ["자동 허용", "세션 동안 허용", "항상 허용", "생체 인증 끄기", "인증서 검증 끄기"]) expect(h.root.textContent ?? "").not.toContain(word);

    const slider = q<HTMLInputElement>(h.root, "[data-key='approval.ttl_s']");
    expect(slider.min).toBe("60");
    expect(slider.max).toBe("180");
    slider.value = "999";
    slider.dispatchEvent(new Event("change", { bubbles: true }));
    await settle();
    const sent = (h.mock?.calls ?? []).filter((c) => c.command === "settings_set");
    expect(sent.length).toBe(1);
    expect(Number(sent[0]?.args["value"])).toBeLessThanOrEqual(180);
    expect(Number(sent[0]?.args["value"])).toBeGreaterThanOrEqual(60);
    expect(await h.controller.setSetting("approval.ttl_s", 181)).toBe(false);
    expect(await h.controller.setSetting("approval.ttl_s", 59)).toBe(false);
    expect((h.mock?.calls ?? []).filter((c) => c.command === "settings_set").length).toBe(1);
  });
});

function walk(dir: string, out: string[] = []): string[] {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

describe("source scan (guards against regressions)", () => {
  const files = walk(join(APP_ROOT, "src"));

  it("no raw HTML sinks anywhere in src/", () => {
    expect(files.length).toBeGreaterThan(20);
    for (const f of files) {
      const code = stripComments(readFileSync(f, "utf8"));
      expect(code, f).not.toMatch(/\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function\s*\(|dangerouslySet|\.srcdoc/);
    }
  });

  it("no explicit `any` in src/ or tests/", () => {
    for (const f of [...files, ...walk(join(APP_ROOT, "tests"))]) {
      const code = stripComments(readFileSync(f, "utf8")).replace(/"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g, '""');
      expect(code, f).not.toMatch(/:\s*any\b|<any>|\bas any\b|\bany\[\]|Array<any>|Record<string,\s*any>/);
    }
  });

  it("API layer is the only place that imports @tauri-apps", () => {
    for (const f of files) {
      if (f.includes(join("src", "api"))) continue;
      expect(readFileSync(f, "utf8"), f).not.toMatch(/@tauri-apps\//);
    }
  });
});
