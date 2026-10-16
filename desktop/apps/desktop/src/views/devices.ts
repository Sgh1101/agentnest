import { h } from "../dom";
import { formatDateTime, relativeKo } from "../logic/format";
import { safeText } from "../logic/sanitize";
import { badge, button, empty } from "../ui/components";
import { openRevokeDialog } from "../ui/revokeDialog";
import { simpleView } from "../ui/view";

export const devicesView = simpleView(
  (s) => [s.devices],
  (s, ctx) => {
    const now = ctx.clock();
    const active = s.devices.filter((d) => d.revoked_at === null);
    const revoked = s.devices.filter((d) => d.revoked_at !== null);
    const row = (d: (typeof s.devices)[number]): HTMLElement =>
      h(
        "tr",
        { "data-device-id": d.device_id },
        h("td", null, h("strong", null, safeText(d.name, 64))),
        h("td", { "data-label": "모델" }, safeText([d.model, d.platform].filter((x): x is string => !!x).join(" · "), 80)),
        h("td", { "data-label": "연결한 날" }, formatDateTime(d.paired_at)),
        h("td", { "data-label": "마지막 접속" }, d.revoked_at === null ? relativeKo(d.last_seen_at, now) : "-"),
        h("td", { "data-label": "상태" }, d.revoked_at !== null ? badge("폐기됨", "muted") : badge(d.online ? "온라인" : "오프라인", d.online ? "ok" : "muted")),
        h("td", null, d.revoked_at === null ? button("폐기", () => openRevokeDialog(ctx.modalRoot, d, ctx.controller), { kind: "danger", fid: `revoke-${d.device_id}` }) : null),
      );
    const table = (rows: typeof s.devices): HTMLElement =>
      h("table", { class: "table" }, h("thead", null, h("tr", null, ...["이름", "모델", "연결한 날", "마지막 접속", "상태", ""].map((c) => h("th", null, c)))), h("tbody", null, ...rows.map(row)));
    return [
      h("h2", null, "기기"),
      active.length === 0 ? empty("연결된 휴대폰이 없어요. '기기 추가'에서 연결해 보세요.") : table(active),
      revoked.length > 0 ? h("details", null, h("summary", null, `폐기한 기기 (${revoked.length})`), table(revoked)) : null,
    ];
  },
);
