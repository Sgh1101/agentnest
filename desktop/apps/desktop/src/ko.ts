/** Korean UI labels shared by several views. */
import type {
  AdapterStatusKind,
  AgentState,
  ApprovalOutcome,
  NetworkProfile,
  PairingEndReason,
  RemoteApproval,
  ResolvedBy,
  RiskLevel,
} from "./api/types";

export const STATE_KO: Record<AgentState, string> = {
  idle: "대기 중",
  working: "작업 중",
  writing_code: "코드 작성 중",
  reviewing: "리뷰 중",
  testing: "테스트 중",
  awaiting_approval: "승인 대기",
  awaiting_input: "입력 대기",
  error: "오류",
  completed: "완료",
  disconnected: "연결 끊김",
};

export const RISK_KO: Record<RiskLevel, string> = {
  low: "위험 낮음",
  medium: "위험 보통",
  high: "위험 높음",
  critical: "위험 매우 높음",
};

export const OUTCOME_KO: Record<ApprovalOutcome, string> = {
  allowed: "허용",
  denied: "거부",
  denied_and_stopped: "거부 후 중단",
  expired: "시간 만료",
  handed_off_local: "로컬로 넘김",
  superseded: "대체됨",
  failed: "실패",
  handled: "처리됨",
};

export const RESOLVED_BY_KO: Record<ResolvedBy, string> = {
  phone: "휴대폰",
  desktop: "PC",
  timeout: "시간 초과",
  agent: "에이전트",
  system: "시스템",
  unknown: "알 수 없음",
};

export const REMOTE_APPROVAL_KO: Record<RemoteApproval, string> = {
  available: "원격 승인 가능",
  unavailable: "원격 승인 불가 (이 세션은 PC에서만 처리)",
  paused: "원격 승인 일시정지",
  unknown: "원격 승인 상태를 알 수 없어요 (PC에서 처리)",
};

export const NETWORK_PROFILE_KO: Record<NetworkProfile, string> = {
  private: "개인(Private)",
  public: "공용(Public)",
  domain: "도메인(Domain)",
  unknown: "알 수 없음",
};

export const ADAPTER_STATUS_KO: Record<AdapterStatusKind, string> = {
  connected: "연결됨",
  degraded: "불안정",
  disconnected: "연결 안 됨",
  not_configured: "설정 안 됨",
};

export const PAIRING_END_KO: Record<PairingEndReason, string> = {
  expired: "QR 시간이 지나 기기 추가가 끝났어요.",
  cancelled: "기기 추가를 취소했어요.",
  rejected: "연결 요청을 거절했어요.",
  failed: "기기 추가에 실패했어요. 다시 시도해 주세요.",
  timeout: "확인 시간이 지나 연결 요청을 거절했어요.",
  link_disabled: "휴대폰 연결이 꺼져 기기 추가를 끝냈어요.",
};
