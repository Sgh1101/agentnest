import type { DiagnosticsReport } from "../api/types";
import { h } from "../dom";
import { NETWORK_PROFILE_KO } from "../ko";
import { relativeKo } from "../logic/format";
import { safeText } from "../logic/sanitize";
import { button, checkRow } from "../ui/components";
import { simpleView, type ViewCtx } from "../ui/view";

/** Pass/fail evaluation shared with the onboarding checklist (item 2). */
export function networkReady(d: DiagnosticsReport | null): boolean {
  return d !== null && d.listener.bound && d.network_profile === "private" && d.firewall.rule_present && d.firewall.scoped_ok && !d.firewall.block_rule_present;
}

export function diagnosticsChecks(d: DiagnosticsReport, ctx: ViewCtx, linkEnabled: boolean): HTMLElement[] {
  const now = ctx.clock();
  const rows: HTMLElement[] = [];

  rows.push(
    checkRow(
      d.listener.bound,
      "휴대폰 연결 리스너",
      d.listener.bound
        ? `${safeText(d.listener.addr, 64) || "-"}:${d.listener.port ?? "-"} 에서 기다리고 있어요.`
        : linkEnabled
          ? "리스너가 켜지지 않았어요. 앱을 다시 시작하거나 다른 프로그램이 같은 포트를 쓰는지 확인해 주세요."
          : "휴대폰 연결이 꺼져 있어서 리스너도 닫혀 있어요.",
    ),
  );

  const profileOk = d.network_profile === "private";
  rows.push(
    checkRow(
      profileOk,
      `네트워크 프로필: ${NETWORK_PROFILE_KO[d.network_profile]}`,
      d.network_profile === "public"
        ? "이 네트워크가 '공용'이라 휴대폰이 연결하지 못해요. Windows 설정 → 네트워크 → 속성에서 '개인'으로 바꿔 주세요. 공용 Wi-Fi라면 휴대폰 연결을 끄세요."
        : d.network_profile === "private"
          ? "집·사무실 같은 개인 네트워크예요."
          : "네트워크 종류를 확인하지 못했어요. Windows 설정에서 '개인'인지 확인해 주세요.",
    ),
  );

  const fw = d.firewall;
  const fwDetail: Array<HTMLElement | string> = [];
  let fwOk: boolean | null;
  if (fw.block_rule_present) {
    fwOk = false;
    fwDetail.push("Windows가 만든 '차단' 규칙이 있어요. 아래 [방화벽 규칙 제거]로 정리한 뒤 [규칙 만들기]를 눌러 주세요.");
  } else if (!fw.rule_present) {
    fwOk = false;
    fwDetail.push("방화벽 규칙이 없어요. [규칙 만들기]를 누르면 Windows 관리자 권한 확인(UAC) 창이 떠요. AgentNest는 평소에는 관리자 권한 없이 실행돼요.");
  } else if (!fw.scoped_ok) {
    fwOk = false;
    fwDetail.push("규칙은 있지만 범위가 예상과 달라요(개인 네트워크 + 같은 서브넷이어야 해요). [규칙 만들기]로 다시 만들어 주세요.");
  } else {
    fwOk = true;
    fwDetail.push("개인 네트워크의 같은 서브넷에서만 이 앱의 연결 포트가 열려 있어요.");
  }
  if (!fw.rule_present || !fw.scoped_ok || fw.block_rule_present) fwDetail.push(h("div", null, button("규칙 만들기 (UAC)", () => void ctx.controller.firewallCreate(), { kind: "primary", fid: "fw-create" })));
  rows.push(checkRow(fwOk, "방화벽 규칙", h("div", null, ...fwDetail)));

  rows.push(
    d.last_preauth_attempt
      ? checkRow(true, "마지막 휴대폰 접속 시도", `${relativeKo(d.last_preauth_attempt.at, now)} · ${safeText(d.last_preauth_attempt.ip_masked, 40)}`)
      : checkRow(false, "마지막 휴대폰 접속 시도", "휴대폰이 PC에 닿지 못했어요. 휴대폰과 PC가 같은 Wi-Fi인지, 방화벽·네트워크 프로필이 위와 같은지 확인해 주세요."),
  );

  rows.push(checkRow(d.self_connect_ok, "셀프 접속 테스트", d.self_connect_ok ? "PC가 자기 주소로 연결하는 데는 성공했어요. (방화벽은 이 테스트로 걸러지지 않아요.)" : "PC가 자기 주소로도 연결하지 못했어요. 리스너 상태를 확인해 주세요."));

  rows.push(
    checkRow(
      d.hosts.length > 0 ? null : false,
      "현재 PC 주소 목록",
      d.hosts.length > 0
        ? h("div", null, h("code", null, d.hosts.map((x) => safeText(x, 64)).join(", ")), h("div", { class: "hint" }, "PC 주소가 바뀌어 휴대폰이 연결하지 못하면, 휴대폰 앱에서 'IP 직접 입력'으로 위 주소를 넣으세요."))
        : "사용할 수 있는 PC 주소가 없어요. 네트워크 연결을 확인해 주세요.",
    ),
  );

  for (const hint of d.hints_ko) rows.push(h("li", { class: "check check-info" }, h("div", { class: "check-body" }, safeText(hint, 200))));
  return rows;
}

export const diagnosticsView = simpleView(
  (s) => [s.diagnostics, s.diagnosticsBusy, s.status?.link_enabled],
  (s, ctx) => {
    const linkOn = s.status?.link_enabled !== false;
    return [
      h("h2", null, "연결 진단"),
      h("p", { class: "hint" }, "휴대폰이 PC에 연결되지 않을 때 가장 먼저 확인하는 화면이에요. 비밀 값은 표시하지 않아요."),
      h(
        "div",
        { class: "row" },
        button(s.diagnosticsBusy ? "진단 중…" : "다시 진단", () => void ctx.controller.runDiagnostics(), { kind: "primary", disabled: s.diagnosticsBusy, fid: "diag-run" }),
        button("방화벽 규칙 제거", () => void ctx.controller.firewallRemove(), { fid: "fw-remove" }),
        button(linkOn ? "휴대폰 연결 끊기" : "휴대폰 연결 켜기", () => void ctx.controller.setLinkEnabled(!linkOn), { kind: linkOn ? "danger" : "primary", fid: "diag-link" }),
      ),
      s.diagnostics === null ? h("p", { class: "empty" }, s.diagnosticsBusy ? "진단하고 있어요…" : "아직 진단하지 않았어요.") : h("ul", { class: "checklist", "data-diagnostics": "1" }, ...diagnosticsChecks(s.diagnostics, ctx, linkOn)),
    ];
  },
);
