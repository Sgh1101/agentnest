/** Errors surfaced by Tauri commands (and by MockBackend, which mimics them). */

export class BackendError extends Error {
  readonly code: string;

  constructor(code: string, message?: string) {
    super(message ?? code);
    this.name = "BackendError";
    this.code = code;
  }
}

/** Korean user-facing text per error code. Daemon-provided free text is never shown. */
const MESSAGES_KO: Readonly<Record<string, string>> = {
  UNKNOWN_REQUEST: "PC에 없는 요청이에요. 이미 끝난 요청일 수 있어요.",
  ALREADY_RESOLVED: "이미 처리된 요청이에요.",
  INPUT_HASH_MISMATCH: "요청 내용이 바뀌어 적용하지 않았어요(보안). 목록을 새로 확인해 주세요.",
  EXPIRED: "요청 시간이 지나 PC에서 직접 처리하도록 넘겼어요.",
  NOT_ALLOWED: "이 요청에는 쓸 수 없는 결정이에요.",
  EXTRA_CONFIRMATION_REQUIRED: "위험한 작업이라 추가 확인이 필요해요.",
  RISK_NOT_ACCEPTED: "먼저 '수용된 위험'을 확인해야 기기를 추가할 수 있어요.",
  PAIRING_BUSY: "이미 진행 중인 기기 추가가 있어요. 끝내거나 취소한 뒤 다시 시도해 주세요.",
  PAIRING_NOT_FOUND: "진행 중인 기기 추가를 찾을 수 없어요.",
  PAIRING_NOT_PENDING: "지금은 승인할 수 있는 연결 요청이 없어요.",
  LINK_DISABLED: "휴대폰 연결이 꺼져 있어요. 먼저 연결을 켜 주세요.",
  NAME_MISMATCH: "입력한 이름이 기기 이름과 달라요.",
  DEVICE_NOT_FOUND: "찾을 수 없는 기기예요.",
  INVALID_SETTING: "허용되지 않는 설정 값이에요.",
  UNKNOWN_SETTING: "알 수 없는 설정이에요.",
  DAEMON_NOT_RUNNING: "데몬이 실행 중이 아니에요.",
  ELEVATION_DENIED: "관리자 권한 확인(UAC)이 취소됐어요.",
  CONTRACT: "PC 앱에서 예상하지 못한 응답이 왔어요.",
  INTERNAL: "내부 오류가 발생했어요.",
};

export function messageKo(code: string): string {
  const known = MESSAGES_KO[code];
  if (known !== undefined) return known;
  const safe = /^[A-Z0-9_]{1,64}$/.test(code) ? code : "UNKNOWN";
  return `알 수 없는 오류가 발생했어요 (코드: ${safe}).`;
}

/**
 * Normalise whatever `invoke` rejected with. The Rust shell should reject with
 * `{ code: "UPPER_SNAKE", message?: string }`; plain strings are also accepted.
 */
export function toBackendError(e: unknown): BackendError {
  if (e instanceof BackendError) return e;
  if (typeof e === "string") return new BackendError(/^[A-Z0-9_]{1,64}$/.test(e) ? e : "INTERNAL", e);
  if (typeof e === "object" && e !== null) {
    const o = e as Record<string, unknown>;
    const code = typeof o["code"] === "string" ? o["code"] : "INTERNAL";
    const message = typeof o["message"] === "string" ? o["message"] : undefined;
    return new BackendError(code, message);
  }
  if (e instanceof Error) return new BackendError("INTERNAL", e.message);
  return new BackendError("INTERNAL");
}
