/**
 * Settings page. Only the whitelisted, strengthening-only settings of security.md section 9 exist
 * here: there is no control for auto-allow, allow-for-session, TLS trust, hook bind address,
 * biometric bypass, risk overrides or TTL above 180 s.
 */
import type { CriticalRemote, LogLevel, Settings, WritableSettingKey } from "../api/types";
import { TTL_MAX_S, TTL_MIN_S } from "../api/types";
import type { AppController } from "../controller";
import { h, type Child } from "../dom";
import { badge, button, section } from "../ui/components";
import { simpleView } from "../ui/view";
import { ttlWarning } from "./integrations";

function row(label: string, desc: string, control: Child, id: string): HTMLElement {
  return h("div", { class: "setting", "data-setting": id }, h("div", { class: "setting-text" }, h("strong", null, label), h("div", { class: "hint" }, desc)), h("div", { class: "setting-control" }, control));
}

function toggle<K extends WritableSettingKey>(c: AppController, key: K, checked: boolean, label: string): HTMLElement {
  const box = h("input", { type: "checkbox", "data-fid": `set-${key}`, "data-key": key, "aria-label": label });
  box.checked = checked;
  box.addEventListener("change", () => void c.setSetting(key, box.checked as Settings[K]));
  return box;
}

export const settingsView = simpleView(
  // Primitive status fields only: unrelated daemon events must not rebuild the page mid-drag.
  (s) => [s.settings, s.status?.link_enabled, s.status?.remote_approval_paused, s.status?.hook_timeout_s],
  (s, ctx) => {
    const set = s.settings;
    const st = s.status;
    const c = ctx.controller;
    if (set === null) return [h("h2", null, "설정"), h("p", { class: "empty" }, "설정을 불러오지 못했어요.")];

    const ttl = set["approval.ttl_s"];
    const out = h("output", { "data-ttl-output": "1" }, `${ttl}초`);
    const slider = h("input", { type: "range", min: TTL_MIN_S, max: TTL_MAX_S, step: 10, value: ttl, "data-fid": "set-ttl", "data-key": "approval.ttl_s", "aria-label": "승인 제한시간(초)" });
    slider.addEventListener("input", () => {
      out.textContent = `${slider.value}초`;
    });
    slider.addEventListener("change", () => void c.setSetting("approval.ttl_s", Number(slider.value)));
    const warn = ttlWarning(ttl, st?.hook_timeout_s);

    const critical = h("select", { class: "input", "data-fid": "set-critical", "data-key": "approval.critical_remote", "aria-label": "매우 높은 위험 요청의 원격 승인" }, h("option", { value: "extra_confirmation" }, "추가 확인 후 원격 승인 허용"), h("option", { value: "local_only" }, "PC에서만 처리"));
    critical.value = set["approval.critical_remote"];
    critical.addEventListener("change", () => void c.setSetting("approval.critical_remote", critical.value as CriticalRemote));

    const level = h("select", { class: "input", "data-fid": "set-loglevel", "data-key": "app.log_level", "aria-label": "로그 수준" }, ...(["error", "warn", "info", "debug"] as const).map((l) => h("option", { value: l }, l)));
    level.value = set["app.log_level"];
    level.addEventListener("change", () => void c.setSetting("app.log_level", level.value as LogLevel));

    const linkBox = h("input", { type: "checkbox", "data-fid": "set-link", "data-key": "link.enabled", "aria-label": "휴대폰 연결" });
    linkBox.checked = st?.link_enabled ?? false;
    linkBox.addEventListener("change", () => void c.setLinkEnabled(linkBox.checked));
    const pauseBox = h("input", { type: "checkbox", "data-fid": "set-pause", "data-key": "remote_approval_paused", "aria-label": "원격 승인 일시정지" });
    pauseBox.checked = st?.remote_approval_paused ?? false;
    pauseBox.addEventListener("change", () => void c.setRemoteApprovalPaused(pauseBox.checked));

    const r1 = set["risk.accepted"].includes("R1");

    return [
      h("h2", null, "설정"),
      section(
        "승인",
        row("승인 제한시간", `요청이 이 시간 안에 처리되지 않으면 PC에서 직접 처리하도록 넘어가요 (${TTL_MIN_S}~${TTL_MAX_S}초).`, h("span", null, slider, " ", out), "approval.ttl_s"),
        warn
          ? h("div", { class: "banner banner-warn", "data-ttl-warning": "1" }, `훅 제한시간 때문에 실제 적용 시간은 ${warn.effective}초예요. `, button("훅 재설치", () => void c.hooksInstall("claude_code", "http"), { fid: "set-reinstall" }))
          : null,
        row("거부에도 인증 요구", "켜면 휴대폰에서 거부할 때도 생체/기기 잠금 인증이 필요해요. 이 설정은 PC에서만 바꿀 수 있어요.", toggle(c, "approval.deny_requires_auth", set["approval.deny_requires_auth"], "거부에도 인증 요구"), "approval.deny_requires_auth"),
        row("매우 높은 위험 요청", "가장 위험한 요청을 휴대폰에서 허용할 수 있게 할지 정해요.", critical, "approval.critical_remote"),
        row("데몬이 꺼져 있으면 차단", "켜면 PC 앱이 응답하지 않을 때 에이전트의 도구 실행을 막아요. 에이전트가 멈출 수 있어요.", toggle(c, "approval.daemon_down_deny", set["approval.daemon_down_deny"], "데몬이 꺼져 있으면 차단"), "approval.daemon_down_deny"),
      ),
      section(
        "연결",
        row("휴대폰 연결", "끄면 휴대폰 연결을 위한 포트를 닫아요. 보류 중인 승인은 PC에서 처리하도록 넘어가요.", linkBox, "link.enabled"),
        row("원격 승인 일시정지", "켜 두면 휴대폰에서는 승인할 수 없어요. PC에서는 계속 처리할 수 있어요.", pauseBox, "remote_approval_paused"),
        row("수용된 위험(R1)", "PC의 TLS 키·훅 토큰이 Windows 보호 저장소가 아닌 사용자 전용 파일에 저장돼요(후속 단계에서 개선).", r1 ? badge("확인함", "ok") : button("이해했어요", () => void c.acceptRiskR1(), { kind: "primary", fid: "set-r1" }), "risk.accepted"),
      ),
      section(
        "앱",
        row("Windows 시작 시 자동 실행", "로그인하면 트레이에서 조용히 시작해요.", toggle(c, "app.autostart", set["app.autostart"], "자동 시작"), "app.autostart"),
        row("알림", "승인 요청, 연결 상태 알림을 보여줘요(승인 요청은 제목만 표시해요).", toggle(c, "app.notifications", set["app.notifications"], "알림"), "app.notifications"),
        row("로그 수준", "문제를 찾을 때만 올리세요. 어떤 수준에서도 토큰·비밀은 기록되지 않아요.", level, "app.log_level"),
        row("로그 폴더", "로그 파일이 있는 폴더를 열어요.", button("폴더 열기", () => void c.openLogsDir(), { fid: "set-logs" }), "logs"),
      ),
    ];
  },
);
