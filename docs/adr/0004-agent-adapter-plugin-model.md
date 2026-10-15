# ADR-0004 에이전트 어댑터 플러그인 모델과 Codex 관찰 모드

- 상태: 승인됨 (2026-10-15)
- 관련: `docs/integrations/codex.md` §2–§6, `docs/integrations/claude-code.md`, `docs/protocol.md` §5

## 맥락

PRD 핵심 원칙 "AI 연결을 플러그인 방식으로 확장"과 Phase 4(Gemini CLI, OpenCode, 로컬 AI). Claude Code는 HTTP 훅(검증)으로, Codex는 app-server JSON-RPC(메서드·결정 직렬화 검증)와 hooks(핸들러 스키마 검증, 파일 형식 미검증)로 붙는다. 공유 데몬 소켓에 제3자가 접속해 TUI 스레드의 승인 요청을 받는 동작은 소스 구조에서 **추론**만 되었고, Codex hooks에는 `http` 타입이 없어 CLI가 필수다. 심사는 (1) 미검증 소켓 모드를 1차로 두는 것, (2) 관찰 대상이 없는 `spawn_stdio`를 기본으로 두는 것, (3) Codex `PreToolUse`에 Claude식 `ask`를 흘리는 것을 결함으로 꼽았고, `RawObservation`/`ApprovalResponder` 추상화와 `native_ids` 보존·`observed_result` 상관을 그래프트 대상으로 꼽았다.

## 결정

1. **`agentnest-adapter-api`**(경량 크레이트): `AgentAdapter`(kind/label/capabilities/start/ingest_hook/health), `AdapterCapabilities`, `RawObservation`(Event / ApprovalOpened / ApprovalClosedByAgent / ApprovalOutcomeObserved / SessionMeta / Health), `NativeBinding`, `ApprovalResponder`(respond / abandon), 불투명 `ApprovalReply`/`ApplyProof`/`ReplyKind`. **어댑터는 결정을 만들지 못한다** — 브로커의 `ApprovalReply`(`ReplyKind` 뷰)를 각 프로토콜의 allow/accept, deny/decline(+interrupt→cancel), abandon→무응답으로 번역만 한다.
2. `AgentEvent.source.native_ids`에 원본 식별자(`tool_use_id`, `prompt_id`, `thread_id`, `turn_id`, `item_id`, `rpc_id`)를 보존하고, 이후 관찰 이벤트와 상관시켜 `approval_resolved.observed_result`를 갱신한다. 한국어 요약은 어댑터가 아니라 core의 `summarize::ko`가 만든다.
3. **Codex Phase 1 기본 = hooks(B)**: `agentnest-hook codex` command 훅으로 관찰; `PermissionRequest` 응답은 Phase 0 C6(결정 없음 → 로컬 프롬프트 폴백) 확인 후 활성, 그 전엔 관찰만. `PreToolUse`에는 어떤 결정도 출력하지 않는다. hooks.json 설치기는 C6 확정 전엔 안내만.
4. **공유 데몬 소켓 구독(A)은 feature flag `codex-daemon-observer`(기본 off) + `// UNVERIFIED (Phase 0)`**. C1~C4 통과 시 승인 채널로 승격하고 B의 `PermissionRequest`는 빈 stdout(이중 카드 금지). `thread/resume`에 정책 override 없음(`excludeTurns` 파라미터는 [추정] — C5 스키마 스냅샷 확인 전까지 선택), `optOutNotificationMethods`로 델타 차단, `availableDecisions` 교집합, 만료 시 무응답.
5. `spawn_stdio`는 Phase 1에서 연결성 프로브·스키마 스냅샷에만 쓰고 Phase 2(`review/start`, 작업 지시)에서 기본이 된다. rollout 테일링은 flag off, Phase 2 백필 전용. `notify`는 채택하지 않는다. `codex remote-control`은 설계 근거로 인용하지 않는다.
6. 모든 외부 API 가정은 `protocol/fixtures/`의 실제 페이로드 스냅샷과 `codex app-server generate-json-schema` 스냅샷으로 고정해 버전 드리프트를 테스트로 감지한다.
7. `adapter-mock`(dev feature)이 픽스처 JSONL을 재생해 SDK 없는 빌드박스에서 폰·데스크톱 E2E를 가능하게 한다.

## 결과

- (+) 새 에이전트는 트레이트 구현 + 정규화 매핑 표 + 픽스처로 추가된다. 승인 안전성은 어댑터와 무관하게 브로커가 보장한다.
- (+) 검증된 경로만 기본 빌드에 들어가고, 추정 경로는 flag·주석·Phase 0 항목으로 추적된다.
- (−) Phase 1 Codex 원격 승인은 C6 또는 C1~C4 결과에 달려 있어 "Codex 상태 표시"는 확실하지만 "Codex 승인"은 조건부다 — PRD §9 "지원되는 승인 요청"으로 수용.
- (−) Codex hooks 경로는 사용자가 `/hooks`에서 trust해야 하므로 온보딩이 필요하다(데스크톱 첫 실행 체크리스트 `desktop.md` §6.1), `deny_and_stop`을 표현할 수 없어 `allowed_decisions`에서 제외한다, hooks `tool_name`·`tool_use_id`는 미검증이라 Codex 전용 매핑 표(UNVERIFIED, C10)를 둔다.
- (−) **Codex 리뷰 결과(P0/P1)는 Phase 1 best-effort·선택 기능**이다 — hooks 기본 모드에서는 수집되지 않으며(`meta.review.state=unavailable`, 폰에 "리뷰 정보 없음 (hooks 모드)"), 모드 A(C1·C2) 또는 C7 픽스처로 입증된 경로에서만 켠다(`integrations/codex.md` §8).
