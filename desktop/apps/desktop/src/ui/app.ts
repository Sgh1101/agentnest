/** Application shell: header, navigation, active view, toasts, modals, 1 s tick. */
import type { AppController } from "../controller";
import { clear, h } from "../dom";
import { formatCountdown } from "../logic/format";
import { VIEW_ORDER, type AppState, type ViewId } from "../store";
import { devicesView } from "../views/devices";
import { diagnosticsView } from "../views/diagnostics";
import { integrationsView } from "../views/integrations";
import { logsView } from "../views/logs";
import { onboardingView } from "../views/onboarding";
import { pairingView } from "../views/pairing";
import { approvalsView } from "../views/approvals";
import { sessionsView } from "../views/sessions";
import { settingsView } from "../views/settings";
import { statusView } from "../views/status";
import { badge } from "./components";
import { SasModal } from "./sasModal";
import type { ViewCtx, ViewFactory, ViewInstance } from "./view";

const NAV_LABEL: Record<ViewId, string> = {
  status: "상태",
  diagnostics: "연결 진단",
  pairing: "기기 추가",
  devices: "기기",
  sessions: "세션",
  approvals: "승인",
  integrations: "연동",
  settings: "설정",
  logs: "로그",
  onboarding: "첫 실행",
};

const FACTORIES: Record<ViewId, ViewFactory> = {
  status: statusView,
  diagnostics: diagnosticsView,
  pairing: pairingView,
  devices: devicesView,
  sessions: sessionsView,
  approvals: approvalsView,
  integrations: integrationsView,
  settings: settingsView,
  logs: logsView,
  onboarding: onboardingView,
};

export interface AppHandle {
  /** Render synchronously (tests). */
  flush(): void;
  destroy(): void;
}

function headerChips(s: AppState): HTMLElement {
  const st = s.status;
  if (st === null) return h("div", { class: "chips" }, badge("데몬 상태를 알 수 없어요", "bad"));
  return h(
    "div",
    { class: "chips", "data-header-status": "1" },
    badge(st.running ? "데몬 실행 중" : "데몬 멈춤", st.running ? "ok" : "bad"),
    badge(st.hooks_installed ? "Claude Code 훅 설치됨" : "Claude Code 훅 미설치", st.hooks_installed ? "ok" : "warn"),
    badge(st.link_enabled ? "휴대폰 연결 켜짐" : "휴대폰 연결 꺼짐", st.link_enabled ? "ok" : "warn"),
    st.remote_approval_paused ? badge("원격 승인 일시정지", "warn") : null,
    h("span", { class: "ports" }, `훅 127.0.0.1:${st.hook_port}`, st.link_enabled && st.wss_addr ? ` · 연결 ${st.wss_addr}` : ""),
    s.backendKind === "mock" ? badge("데모 데이터", "info") : null,
  );
}

export function mountApp(root: HTMLElement, controller: AppController, clock: () => number = () => Date.now()): AppHandle {
  const store = controller.store;
  const header = h("header", { class: "app-header" });
  const nav = h("nav", { class: "nav", "aria-label": "메뉴" });
  const main = h("main", { class: "main" });
  const toasts = h("div", { class: "toasts", role: "status", "aria-live": "polite" });
  const modalRoot = h("div", { class: "modal-root" });
  root.append(h("div", { class: "app" }, header, h("div", { class: "layout" }, nav, main)), toasts, modalRoot);

  const ctx: ViewCtx = { controller, clock, modalRoot };
  let currentId: ViewId | null = null;
  let current: ViewInstance | null = null;
  let sasModal: SasModal | null = null;
  let scheduled = false;
  let destroyed = false;
  let lastNavKey = "";
  let lastHeaderKey: unknown[] = [];

  const render = (): void => {
    scheduled = false;
    if (destroyed) return;
    const s = store.get();

    // header (rebuilt only when the displayed slices change)
    const hk = [s.status?.running, s.status?.hooks_installed, s.status?.link_enabled, s.status?.remote_approval_paused, s.status?.hook_port, s.status?.wss_addr, s.backendKind];
    if (hk.length !== lastHeaderKey.length || hk.some((v, i) => !Object.is(v, lastHeaderKey[i]))) {
      lastHeaderKey = hk;
      clear(header);
      header.append(h("h1", { class: "brand" }, "AgentNest"), headerChips(s));
    }

    // navigation
    const navKey = `${s.view}|${s.approvals.length}|${s.settings?.["onboarding.completed"]}`;
    if (navKey !== lastNavKey) {
      lastNavKey = navKey;
      clear(nav);
      const ids: ViewId[] = s.settings?.["onboarding.completed"] === false ? ["onboarding", ...VIEW_ORDER] : [...VIEW_ORDER];
      for (const id of ids) {
        nav.append(
          h(
            "button",
            { type: "button", class: `nav-item${id === s.view ? " active" : ""}`, "data-nav": id, "aria-current": id === s.view ? "page" : undefined, onClick: () => controller.navigate(id) },
            NAV_LABEL[id],
            id === "approvals" && s.approvals.length > 0 ? h("span", { class: "badge badge-warn", "data-pending-count": "1" }, String(s.approvals.length)) : null,
          ),
        );
      }
    }

    // active view
    if (currentId !== s.view || current === null) {
      current?.destroy?.();
      clear(main);
      currentId = s.view;
      current = FACTORIES[s.view](ctx);
      main.append(current.el);
    }
    current.update(s);

    // toasts
    clear(toasts);
    for (const t of s.toasts) {
      toasts.append(h("div", { class: `toast toast-${t.kind}`, "data-toast": t.kind }, h("span", null, t.text), h("button", { type: "button", class: "toast-x", "aria-label": "닫기", onClick: () => controller.dismissToast(t.id) }, "×")));
    }

    // SAS modal
    if (s.sas !== null && (sasModal === null || sasModal.pairingId !== s.sas.pairing_id)) {
      sasModal?.close();
      sasModal = new SasModal(modalRoot, s.sas, controller, clock);
    } else if (s.sas === null && sasModal !== null) {
      sasModal.close();
      sasModal = null;
    }
  };

  const schedule = (): void => {
    if (scheduled || destroyed) return;
    scheduled = true;
    queueMicrotask(render);
  };

  const unsub = store.subscribe(schedule);

  const tickTimer = setInterval(() => {
    const now = clock();
    controller.tick();
    current?.tick?.(now);
    for (const el of Array.from(root.querySelectorAll<HTMLElement>("[data-countdown-until]"))) {
      const until = Number(el.getAttribute("data-countdown-until"));
      if (Number.isFinite(until)) el.textContent = formatCountdown(until - now);
    }
  }, 1000);

  render();

  return {
    flush: render,
    destroy() {
      destroyed = true;
      clearInterval(tickTimer);
      unsub();
      current?.destroy?.();
      sasModal?.close();
      clear(root);
    },
  };
}
