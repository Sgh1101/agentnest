# AgentNest — Claude Code 작업 지침

이 저장소는 **AgentNest**(Windows PC의 AI 코딩 에이전트들을 Android 앱에서 통합 관제하는 플랫폼)의 모노레포다.
역할 분담: **Claude Code = 구현**, **Codex = 리뷰**(`AGENTS.md` 참고), **GitHub Actions = 자동 검증**, **사용자 = 최종 승인**.

## 먼저 읽을 문서

- `docs/prd.md` — 제품 요구사항(기준 문서). 우선순위 P0 > P1 > P2 > P3.
- `docs/architecture.md` — 모노레포 구조, 컴포넌트 책임, 빌드 제약.
- `docs/protocol.md` — PC↔폰 와이어 프로토콜 v1, AgentEvent / AgentState / ApprovalRequest 정의. **코드와 문서가 어긋나면 문서를 먼저 고치고 코드를 맞춘다.**
- `docs/security.md` — 페어링, 승인 바인딩, fail-closed 규칙. 이 문서의 규칙은 협상 대상이 아니다.
- `docs/integrations/claude-code.md`, `docs/integrations/codex.md` — 에이전트 연동 계약(검증 여부 표시 포함).

## 저장소 구조

```
docs/            설계 문서, ADR
protocol/        JSON Schema + 예제 메시지 (언어 중립적 단일 진실 공급원)
desktop/         Cargo 워크스페이스
  crates/agentnest-protocol   serde 타입 (protocol/schema 와 1:1)
  crates/agentnest-adapter-api 에이전트 어댑터 트레이트·RawObservation·불투명 ApprovalReply (의존성 최소, ADR-0003/0004)
  crates/agentnest-core       수집기·정규화·저장소·승인 브로커·페어링·WSS 서버
  crates/agentnest-hook       Claude Code 훅이 호출하는 소형 CLI
  crates/agentnest-shell-api  Tauri 없이 테스트되는 셸 로직(커맨드 계약·DTO·이벤트 매핑·설정·진단·방화벽·트레이 모델)
  apps/desktop                Tauri 2 셸(src-tauri = 얇은 글루) + Vite/TS 프런트엔드
android/
  core/                       순수 Kotlin JVM 모듈 (프로토콜 모델, 상태 매핑, 재연결 로직) — SDK 없이 테스트 가능
  app/                        Jetpack Compose 앱
.github/workflows/           CI
```

## 빌드·테스트 명령

```bash
# Rust (Linux에서도 동작: Tauri 셸은 default-members 에서 제외)
cd desktop && cargo fmt --all --check && cargo clippy --workspace --exclude agentnest-desktop --all-targets -- -D warnings && cargo test --workspace --exclude agentnest-desktop
# Tauri 셸 타입 검사 (webkit2gtk 없는 리눅스 박스에서도 가능: clang + mingw-w64 헤더 필요, docs/testing-and-ci.md 2.1)
cd desktop && tools/prepare-hook-sidecar.sh --placeholder x86_64-pc-windows-msvc && CC_x86_64_pc_windows_msvc=$PWD/tools/cc-msvc-check.sh AR_x86_64_pc_windows_msvc=llvm-ar cargo check -p agentnest-desktop --target x86_64-pc-windows-msvc
# 프런트엔드
cd desktop/apps/desktop && pnpm install --frozen-lockfile && pnpm typecheck && pnpm test
# Android 순수 모듈 (SDK 불필요)
cd android && ./gradlew :core:test
# Android 앱 (SDK 필요 — CI 또는 로컬 Android Studio)
cd android && ./gradlew :app:assembleDebug
```

## 코딩 규칙

- **언어**: 문서·커밋 메시지 본문·UI 문구는 한국어. 코드 식별자·코드 주석·로그 메시지는 영어.
- **프로토콜 변경**은 반드시 `protocol/schema` → `docs/protocol.md` → Rust 타입 → Kotlin 타입 → 예제/테스트 순으로 함께 바꾼다. 하나만 바꾼 PR은 받지 않는다.
- **보안 불변식**(위반 금지):
  - 승인 요청은 `request_id` + `session_id` 에 바인딩되고 `expires_at` 이후에는 어떤 결정도 적용하지 않는다.
  - 타임아웃·연결 끊김·검증 실패·알 수 없는 상태는 **항상 "ask"(로컬 프롬프트로 위임) 또는 deny** 로 귀결된다. 어떤 경로도 자동 allow 로 가지 않는다.
  - 로그에 토큰, 비밀번호, 인증서 개인키, 파일 본문 전체를 남기지 않는다. 명령/파일 경로는 길이를 제한해 기록한다.
  - 페어링 토큰은 1회용·단기 만료, 디바이스 토큰은 폐기 가능해야 한다.
- **Rust**: `clippy -D warnings` 통과, `unwrap()` 은 테스트 코드에서만. 에러는 `thiserror` 타입으로. 공개 API 에는 doc comment.
- **Kotlin**: `android/core` 에는 Android 의존성을 넣지 않는다(JVM 전용: OkHttp·`java.security`·`javax.crypto` 는 허용 — WS 클라이언트·핀닝·HMAC 은 `core`). Keystore·BiometricPrompt·알림·서비스·UI 는 `app` 에만.
- **TypeScript**: `strict: true`, `any` 금지.
- **테스트**: 새 메시지 타입·상태 전이·위험 분류 규칙에는 반드시 단위 테스트를 붙인다. 예제 JSON(`protocol/examples`)은 Rust 와 Kotlin 양쪽에서 라운드트립 테스트한다.
- **검증 안 된 외부 API 형태**(예: Codex app-server 메서드명)는 코드에서 `// UNVERIFIED (Phase 0)` 주석과 feature flag 뒤에 둔다.

## PR 규칙

- 브랜치 → PR → Codex 리뷰(P0/P1 지적) → Claude Code 수정 → CI 녹색 → 사용자 머지.
- PR 설명에 "변경 요약 / 보안 영향 / 테스트 방법 / 문서 변경" 네 항목을 쓴다.
- 커밋 메시지에 모델 식별자를 넣지 않는다.
