import { h } from "../dom";
import { formatCountdown } from "../logic/format";
import { button } from "../ui/components";
import { qrImage } from "../ui/qr";
import { simpleView } from "../ui/view";

/** Pairing page. The QR is rendered only while `state.pairing` (pairing mode) is active. */
export const pairingView = simpleView(
  (s) => [s.pairing, s.settings?.["risk.accepted"], s.status?.link_enabled, s.sas],
  (s, ctx) => {
    const accepted = s.settings?.["risk.accepted"].includes("R1") === true;
    const linkOn = s.status?.link_enabled !== false;
    const out: Array<HTMLElement | null> = [h("h2", null, "기기 추가")];

    if (!accepted) {
      out.push(
        h("div", { class: "banner banner-warn" }, "기기를 추가하기 전에 '수용된 위험'을 먼저 확인해야 해요. ", button("체크리스트 열기", () => ctx.controller.navigate("onboarding"))),
      );
    }
    if (!linkOn) {
      out.push(h("div", { class: "banner banner-warn" }, "휴대폰 연결이 꺼져 있어요. 설정에서 연결을 켠 뒤 기기를 추가할 수 있어요."));
    }

    if (s.sas !== null) {
      out.push(h("div", { class: "banner banner-info" }, "휴대폰이 연결을 요청했어요. 열려 있는 확인 창에서 숫자를 비교해 주세요."));
      return out;
    }

    const p = s.pairing;
    if (p === null) {
      out.push(
        h("p", null, "같은 Wi-Fi에서 AgentNest 앱 → 설정 → PC 연결 → QR 스캔 순서로 진행해요."),
        h("div", null, button("기기 추가 (QR 표시)", () => void ctx.controller.startPairing(), { kind: "primary", disabled: !accepted || !linkOn, fid: "pairing-start" })),
      );
      return out;
    }

    const img = qrImage(p.qr_svg);
    out.push(
      h(
        "div",
        { class: "qr-box", "data-pairing-active": "1" },
        img ?? h("div", { class: "banner banner-bad" }, "QR을 표시하지 못했어요. 취소하고 다시 시도해 주세요."),
        h("p", null, "남은 시간 ", h("strong", { "data-countdown-until": String(p.expires_at_ms) }, formatCountdown(p.expires_at_ms - ctx.clock()))),
        h("p", { class: "hint" }, "같은 Wi-Fi에서 AgentNest 앱 → 설정 → PC 연결 → QR 스캔. 이 QR은 한 번만, 짧은 시간 동안만 쓸 수 있어요. 다른 사람이 보지 못하게 해 주세요."),
        button("취소", () => void ctx.controller.cancelPairing(), { fid: "pairing-cancel" }),
      ),
    );
    return out;
  },
);
