# AgentNest 설계 문서 색인

읽는 순서: `prd.md` → `architecture.md` → `protocol.md` → `security.md` → 연동(`integrations/`) → 플랫폼(`android.md`, `desktop.md`) → `storage.md` → `character.md` → `testing-and-ci.md` → `phase0-checklist.md` → `adr/`.

규칙: **코드와 문서가 어긋나면 문서를 먼저 고치고 코드를 맞춘다.** 프로토콜 변경은 `protocol/schema` → `protocol.md` → Rust → Kotlin → 예제/테스트 순으로 함께 바꾼다. `security.md`의 규칙은 협상 대상이 아니며 위반은 Codex 리뷰 P0다.

| 문서 | 내용 |
| --- | --- |
| [`prd.md`](prd.md) | 제품 요구사항(기준 문서). 우선순위 P0 > P1 > P2 > P3 |
| [`architecture.md`](architecture.md) | 시스템 개요, 핵심 결정 10가지, 모노레포 레이아웃, 컴포넌트 책임, 데이터 흐름, 빌드박스 제약·CI 매트릭스, 핀 고정 버전, Phase 범위 |
| [`protocol.md`](protocol.md) | 와이어 프로토콜 v1: 봉투, 메시지별 JSON·필드 표, `AgentEvent`/`SessionState`/`ApprovalRequest`, `AgentState` 전이표·캐릭터 매핑, 한국어 요약 템플릿, 하트비트·ack·재동기화, 오류·종료 코드, 전방 호환 규칙 |
| [`security.md`](security.md) | 위협 모델(A1~A5), 불변식 I1~I12(→ 테스트·Codex P0 추적), TLS/SPKI 핀, **Windows 방화벽·주소 변경·링크 비활성(§3)**, 페어링(HMAC+SAS(폰 로컬 계산)+PC 확인), 수용된 위험(R1), 토큰 수명주기, 승인 바인딩·9단계 검증·재생 방지, **fail-closed 표**, 레댁션 3-싱크, 금지 설정 필드, 폐기 절차 |
| [`integrations/claude-code.md`](integrations/claude-code.md) | HTTP 훅 settings.json, 훅 바이너리 계약, 수집 API, 정규화 표, 원격 승인 시퀀스·타임아웃, 위험 분류 규칙(코드 상수), Phase 0 A-시리즈 |
| [`integrations/codex.md`](integrations/codex.md) | 검증됨 vs 추정 표, 어댑터 API, 관찰 모드(hooks 기본 / 데몬 소켓 flag), app-server 흐름, hooks 응답 규칙, 승인 매핑, 리뷰 수집, Phase 0 C-시리즈 |
| [`android.md`](android.md) | 모듈·버전, 홈 3층·승인 상세 화면, FGS·재연결 상태기계, Keystore·생체 게이트·QR, 알림 채널, 권한, core 테스트 |
| [`desktop.md`](desktop.md) | Tauri 2 구조·플러그인, 커맨드/이벤트, 트레이, `tauri.conf.json`/capabilities, Phase 1 UI(SAS 모달·로컬로 처리·기기 폐기), 빌드 |
| [`storage.md`](storage.md) | SQLite DDL(M001~M005), 핵심 쿼리 규약(조건부 전이·재생 치환), 보존 정책 |
| [`character.md`](character.md) | 콩이 mood 열거형, 우선순위·히스테리시스, Compose Canvas 모션 스펙·성능 예산, 설정 토글·접근성 |
| [`testing-and-ci.md`](testing-and-ci.md) | 계층별 테스트(불변식 ↔ 테스트), CI 워크플로, Codex 리뷰 P0/P1 범위 |
| [`phase0-checklist.md`](phase0-checklist.md) | Phase 0 검증 항목(A/C/P 시리즈, 통과 기준·대안), Phase 0 통과 조건, Phase 1 수용 기준 ↔ PRD §9 |
| [`adr/0001-transport-and-pairing.md`](adr/0001-transport-and-pairing.md) | 핀 고정 WSS + HMAC 소지 증명 + SAS/PC 확인, 토큰은 Phase 1·서명은 Phase 3 |
| [`adr/0002-remote-approval-fail-closed.md`](adr/0002-remote-approval-fail-closed.md) | 결정 없음 = 로컬 위임, Allow 단일 경로, TTL 120, 범위 확장 결정 부재 |
| [`adr/0003-monorepo-and-build-constraints.md`](adr/0003-monorepo-and-build-constraints.md) | 4 크레이트 + Tauri 셸 제외, ring 단일 백엔드, Android core/app 분리 |
| [`adr/0004-agent-adapter-plugin-model.md`](adr/0004-agent-adapter-plugin-model.md) | 어댑터 API, Codex hooks 기본·데몬 소켓 flag |
| [`adr/0005-character-rendering.md`](adr/0005-character-rendering.md) | PC 상태 파생 + 폰 mood 집계, Compose Canvas |

신뢰도 표기(모든 문서 공통): **[검증]** 1차 자료·실측 / **[추정]** 구조·문맥 추론 / **검증 필요 (Phase 0)** 미확인 외부 API — 코드에서는 `// UNVERIFIED (Phase 0)` + feature flag(기본 off).
