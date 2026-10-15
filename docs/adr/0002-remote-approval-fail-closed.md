# ADR-0002 원격 승인은 fail-closed: 결정 없음 = 로컬 위임, allow는 한 곳에서만

- 상태: 승인됨 (2026-10-15)
- 관련: `docs/security.md` §2 I4/I5/I11/I12, §6, §7; `docs/integrations/claude-code.md` §6–§8; `docs/integrations/codex.md` §6

## 맥락

PRD §6: "승인 요청은 세션·요청 ID에 연결", "만료되면 실행하지 않음", "연결 실패 시 자동 승인하지 않음", "무조건 승인 모드 미제공". Claude Code 리서치(v2.1.300)로 확인된 사실: `PermissionRequest` 훅은 결정이 없으면 로컬 다이얼로그로 넘어가고(프롬프트 없는 세션은 거부), HTTP 훅의 2xx 빈 본문이 "결정 없음"이며, `onFailure:"block"`은 모든 데몬 장애를 거부로 바꾼다. 입력에 `tool_use_id`가 없다. Codex app-server에는 승인 타임아웃이 없고, hooks `PermissionRequest` 출력에 `interrupt`/`updatedInput`/`updatedPermissions`가 있으면 결정이 폐기되며, `PreToolUse` 훅은 `ask`를 거부한다. 심사는 세 제안 모두 자동 allow가 없다고 평가하면서도, 290초 TTL, 스키마에 예약된 `allow_for_session`, 데스크톱의 두 번째 allow 경로, "결정 없음 = 로컬 다이얼로그"의 과잉 일반화를 결함으로 꼽았다.

## 결정

1. **허용 응답은 `Broker::apply_decision`의 성공 분기 한 곳에서만 만들어진다.** `ApprovalReply`는 내부 enum이 비공개인 불투명 구조체이고 허용 값은 `ApprovalReply::allow(ApplyProof)`로만 생성되며 `ApplyProof::mint()`는 그 분기에서만 호출된다(응답자는 `ReplyKind` 읽기 뷰로 번역만). 데스크톱 허용 버튼도 같은 전이(actor=desktop, 감사, `security.md` §6.2.1의 필수 단계 + `high`/`critical`은 `confirm_ack`)를 지나며 트레이는 `high`/`critical` 허용을 제공하지 않는다. 강제: `compile_fail` doctest + CI의 `ApplyProof::mint` 호출 위치 1곳 grep(이전의 `ApprovalReply::Allow` grep은 enum variant가 공개라 달성 불가였다).
2. **결정 없음의 단일 표현**: Claude Code에는 2xx 빈 본문, Codex에는 무응답(hooks는 빈 stdout). 온라인 기기 0·TTL 만료·폰 끊김(10초 유예)·검증 실패·내부 오류·데몬 재시작(시작 시 pending→expired)·알 수 없는 값·분류기 오류 전부 이 경로다. 문서는 "프롬프트가 있는 세션이면 로컬 다이얼로그, 없으면 거부 — 어느 쪽도 allow 아님"으로 서술한다.
3. **바인딩·검증**: `request_id + session_key + nonce + tool_input_sha256`(PC만 계산, 폰은 에코), `decided_at` 창, 고정 순서 9단계를 **상태 변경 전에** 수행하고, 적용은 `UPDATE … WHERE status='pending' AND expires_at > now` 단일 조건부 전이로 한 번만.
4. **TTL 기본 120초(60~180)**, 훅 `timeout = TTL + 30`(데몬이 항상 먼저 응답). 300초급 창은 채택하지 않는다.
5. **범위 확장 결정은 존재하지 않는다**: `allow_for_session`, `updatedPermissions`/`updatedInput`, `acceptForSession`/amendment류는 v1 스키마·어댑터·설정에 없다("예약 후 거부"도 금지). Codex hooks 출처에서는 `deny_and_stop`이 `allowed_decisions`에서 제외되고 카드에 "거부만 가능"을 표시한다(사후 조용한 강등 금지). Codex `PreToolUse`에는 결정을 출력하지 않는다.
6. `onFailure`는 `continue`. `block`은 "데몬 다운 시 거부" 옵트인 설정으로만.
7. `critical`은 원격 승인 **가능**하되 길게 누르기 + 재확인 시트(명령 전체 재표시 + 체크) + 생체 프롬프트(설정으로 `local_only` 강화만 가능). `setConfirmationRequired`는 수동 생체(얼굴·홍채)에만 닿는 시스템 힌트라 지문 기기에서는 효과가 없으므로 보안 통제로 세지 않는다 — 실제 게이트는 길게 누르기·재확인 시트이고 서버는 `extra_confirmation.completed`와 `authenticated_at` 신선도(≤60초)를 검사한다(둘 다 Phase 3 서명 전까지는 폰의 주장). `deny`는 기본 인증 없음, `deny_and_stop`은 allow와 같은 게이트.
8. 위험 규칙은 코드 상수. 분류 실패 → `critical`. 알 수 없는 위험 등급은 폰에서 `high`.
9. 데스크톱 '로컬로 처리' 버튼(즉시 빈 2xx)과 '폰 없음 → 즉시 204' 규칙으로, 훅 보류 중 터미널 다이얼로그 표시 여부(미검증)와 무관하게 사용자가 막히지 않는다.
10. `approval_resolved`는 `delivery`(전달)와 `observed_result`(실행 관찰, 60초 상관 창)를 분리해 PRD §9 "실제 처리 결과 확인"을 "전달됨"으로 과장하지 않는다.

## 결과

- (+) 모든 실패 경로가 한 타입(`abandon`)으로 수렴해 리뷰·테스트 가능. PRD Phase 3 "중복 실행 없음"을 Phase 1 프로토콜에서 선반영(재생 시 만료 승인 치환, 멱등 결정).
- (+) 사용자는 PC 앞에서도 폰에서도 막히지 않는다(로컬 처리·로컬 결정·즉시 폴백).
- (−) `critical`을 원격에서 허용하므로 UX 게이트(재확인 시트)가 보안 경계의 일부가 된다 — 테스트로 강제. 
- (−) 120초 TTL은 폰을 꺼내 인증하기에 빠듯할 수 있다(설정 60~180, 사용자 테스트 후 조정).
- (−) Codex hooks 경로에서 "거부하고 멈추기"가 불가능하다(파서 제약) — `allowed_decisions`에서 제외하고 카드에 "거부만 가능" 표시.
- 대안 기각: 데몬 다운 시 자동 거부 기본값(PC에서조차 승인 불가), 데스크톱 전용 별도 allow 경로(A3 혼동 표면), `critical` 원격 금지(PRD §3.D "추가 확인"과 충돌), 290초 TTL(터미널 5분 점유·재생 창 확대).
