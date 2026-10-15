/** Korean time / countdown formatting. */

export function formatCountdown(msLeft: number): string {
  const total = Math.max(0, Math.ceil(msLeft / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export function formatClock(iso: string | null | undefined): string {
  if (iso === null || iso === undefined) return "-";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "-";
  return new Intl.DateTimeFormat("ko-KR", { hour: "numeric", minute: "2-digit", second: "2-digit" }).format(new Date(t));
}

export function formatDateTime(iso: string | null | undefined): string {
  if (iso === null || iso === undefined) return "-";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "-";
  return new Intl.DateTimeFormat("ko-KR", { year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(t));
}

export function relativeKo(iso: string | null | undefined, nowMs: number): string {
  if (iso === null || iso === undefined) return "기록 없음";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "기록 없음";
  const sec = Math.round((nowMs - t) / 1000);
  if (sec < 10) return "방금 전";
  if (sec < 60) return `${sec}초 전`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}분 전`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}시간 전`;
  return `${Math.round(hr / 24)}일 전`;
}
