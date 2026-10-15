# 테스트 전략·CI·Codex 리뷰 범위

- 상태: 확정(리드 종합본) — 2026-10-15
- 원칙: (1) **Rust와 Kotlin이 같은 픽스처 파일을 읽는다**(`protocol/examples`, `protocol/fixtures`, `protocol/vectors`) — 한쪽만 통과하면 CI 실패. (2) 보안 불변식(`security.md` §2)마다 **이름 붙은 테스트**가 있다. (3) 새 메시지 타입·상태 전이·위험 규칙·요약 템플릿에는 테스트가 없으면 머지되지 않는다(CLAUDE.md).

---

## 1. 계층별 테스트

| 계층 | 테스트 | 도구 |
| --- | --- | --- |
| `protocol/schema` | 모든 `examples/**/*.json`이 스키마에 유효, `examples/invalid/**`는 반드시 거부(`decision.allow_for_session`, `v:2`, 음수 `seq`, `nonce_b64` 누락, 바이너리 프레임 표현 등), 스키마 자체가 draft 2020-12 메타스키마에 유효 | Rust `jsonschema 0.58.6`(default-features=false) 테스트가 디렉터리 순회 |
| `agentnest-protocol` | 예제 라운드트립(deserialize → serialize → 동일 JSON), 알 수 없는 필드 무시, 알 수 없는 enum → `Unknown`; `canonical`: `protocol/vectors/pair.json`(바이트열·HMAC·SAS), `tool_input_sha256` canonical JSON 케이스(키 순서·유니코드·숫자) | `cargo test` |
| `agentnest-adapter-api` | 타입 수준: `ApprovalReply`에 `Allow` 생성 함수가 공개되지 않음(브로커만 생성) | 컴파일 테스트(`trybuild` 미사용 — doc-test `compile_fail`) |
| `agentnest-core::adapters::claude_code` | 훅 픽스처(`protocol/fixtures/claude-code/hooks/*.json`) → `AgentEvent` 골든(스냅샷 파일), `PermissionRequest` 응답 JSON이 출력 스키마와 일치하고 `updatedInput`/`updatedPermissions` 부재, `PreToolUse` 응답은 `ask` 또는 빈 본문만, 절단·마스킹, settings.json 병합 골든(기존 훅 보존, `onFailure` 부재/옵트인) | `cargo test` |
| `agentnest-core::adapters::codex` | 인프로세스 가짜 app-server(`tokio::io::duplex`, 픽스처 JSONL 재생)로 핸드셰이크·구독·`requestApproval` → 응답 직렬화(`"accept"`/`"decline"`/`"cancel"` 문자열만), `serverRequest/resolved` → superseded, 만료 시 0바이트; 생성 스키마 스냅샷 적합성; hooks 정규화 골든; `/v1/hooks/codex` `PreToolUse`가 항상 204; hooks `PermissionRequest` 출력에 `interrupt`/`updatedInput`/`updatedPermissions` 부재; `[P0]` 텍스트 파서 | `cargo test`(flag 포함 빌드도 테스트) |
| `agentnest-core::summarize` | `protocol/fixtures/summaries_ko.json` 전수, `headline ≤ 40`/`detail ≤ 200` 상한, `{cmd60}` 마스킹 | `cargo test` |
| `agentnest-core::risk` | `protocol/fixtures/risk_cases.json` 전수(규칙당 양성·음성 ≥2, ≥80케이스), Windows 백슬래시·대소문자, 세그먼트 분리, 정규식 패닉 주입 → `critical`, 외부 파일 로드 코드 부재(grep) | `cargo test` |
| `agentnest-core::state` | `protocol/fixtures/state_transitions.json` 전수, 타이머(`tokio::time::pause`), `mood_priority.json`(focus) | `cargo test` |
| `agentnest-core::approvals` | **I4**: 9단계 각각을 단독으로 실패시키는 테스트 9개 + 전부 통과 1개; 재전송(같은 decision 2회 → 멱등), 교차 바인딩(다른 요청의 nonce/해시), 만료 경계, `decided_at` 창, 동시 결정 2건 → 1건만, 데몬 재시작 시 pending→expired, 폰 끊김 10초 유예 후 handoff, 데스크톱 로컬 결정이 같은 전이를 통과, `observed_result` 상관(60초 창); **I5**: TTL 만료·연결 끊김·기기 0대·패닉 경로 각각이 `abandon`을 호출하고 `Allow`가 되는 경로가 없음 + **grep 테스트** `ApprovalReply::Allow` 생성 위치 1곳 | `cargo test` + in-memory sqlite |
| `agentnest-core::http` | axum `tower::ServiceExt::oneshot`: 토큰 누락/불일치 401, `Origin` 403, 1 MiB 초과 413, 관찰 이벤트 204 응답 시간 < 10 ms, `PermissionRequest` 홀드 → 결정 → 200 JSON, 홀드 중 TTL → 204, 홀드 중 클라이언트 끊김 → superseded(DropGuard) | `cargo test` |
| `agentnest-core::link` | tokio-tungstenite 0.30 클라이언트 + rcgen 임시 인증서(ring): **I1** 인증 전 `ack`/`decision`/`ping` → 4001 & 아무 상태도 안 나감, 5초 초과 → 4001, 챌린지 재사용 거부; pair HMAC 실패 3회 → 소각, SAS 벡터, PC 거절 → 미등록; hello/resync/ack/replay(만료 승인 치환), 링버퍼 초과 → snapshot, 4009 대체, 레이트리밋, **I6** 폐기 → 4003 + kick + 보류 결정 무효 | `cargo test` |
| `agentnest-core::redact` | 모든 비밀 뉴타입 × 모든 이벤트 종류에서 포맷된 로그에 테스트 비밀 바이트 0회, `detail_json ≤ 8 KiB`, `tool_input.content` 미영속, `redact_cases.json` | `cargo test` |
| `agentnest-core::store` | `MIGRATIONS.validate()`, 보존 정책, `approvals_dedupe_idx`, 조건부 UPDATE 원자성, 트랜잭션 패닉 롤백 | `tempfile` DB |
| `agentnest-core::config` | 금지 필드(`security.md` §9)가 있는 설정 파일 → 시작 거부; 범위 밖 TTL 거부 | `cargo test` |
| `agentnest-hook` | 데몬 없음 → exit 0 + 빈 stdout; 응답 패스스루; stdout 오염 없음; 32 KiB 절단; `/codex` 응답의 `permissionDecision` 폐기 | `std::process::Command` + 로컬 axum |
| Tauri 셸 | `cargo check -p agentnest-desktop --target x86_64-pc-windows-msvc`(Linux), `tauri build`(windows-latest). 커맨드 인자 직렬화는 core 수준 테스트 | CI |
| 프런트(TS) | vitest: 상태 스토어 리듀서, QR 카운트다운, 승인 카드 렌더, `protocol/examples` 파싱(`types.ts` 검증) | `pnpm test` |
| `android/core` | `android.md` §7 표 전부(라운드트립·벡터·`NestReducer`·`MoodResolver`·`LinkStateMachine`·`DecisionValidator`·핀닝 4케이스) | `./gradlew :core:test` |
| `android/app` | `:app:testDebugUnitTest`(알림 빌더, 딥링크), `:app:lintDebug`(FGS 타입·권한·`allowBackup`) | CI |
| E2E(수동) | `adapter-mock` 픽스처 재생 → 폰 화면/알림; 실제 Claude Code/Codex로 `phase0-checklist.md` | Phase 0/1 |

---

## 2. CI 매트릭스 (`.github/workflows/`)

| 워크플로 / 잡 | 러너 | 단계 | 트리거 |
| --- | --- | --- | --- |
| `rust.yml` | ubuntu-24.04 | `actions/checkout@v7` → `dtolnay/rust-toolchain@1.97.0`(rustfmt, clippy) → `Swatinem/rust-cache@v2`(`workspaces: "desktop -> target"`) → `cargo fmt --all --check` → `cargo clippy --workspace --exclude agentnest-desktop --all-targets -- -D warnings` → `cargo test --workspace --exclude agentnest-desktop` → `cargo test -p agentnest-core --features codex-daemon-observer,codex-rollout`(flag 코드도 컴파일·테스트) → `sudo apt-get install -y llvm` + `rustup target add x86_64-pc-windows-msvc` → `cargo check -p agentnest-desktop --target x86_64-pc-windows-msvc` → `cargo tree -i aws-lc-rs` 결과가 비어 있는지 → `grep -rn "ApprovalReply::Allow" desktop/crates \| grep -v test` 가 1줄인지 | push / PR |
| `desktop-windows.yml` | windows-latest | `actions/checkout@v7` → `pnpm/action-setup@v4`(10) → `actions/setup-node@v4`(22, cache pnpm) → `dtolnay/rust-toolchain@1.97.0` → `Swatinem/rust-cache@v2` → `pnpm install --frozen-lockfile` → `pnpm typecheck && pnpm test` → `tauri-apps/tauri-action@v1`(`projectPath: desktop/apps/desktop`, `uploadWorkflowArtifacts: true`, `args: --target x86_64-pc-windows-msvc`) → `cargo test -p agentnest-core`(Windows 경로 규칙·ACL·(Phase 3) DPAPI 테스트는 여기서만) | push main / PR / 주 1회 |
| `android.yml` | ubuntu-latest | job `core-jvm`: `actions/checkout@v7` → `actions/setup-java@v6`(temurin 17) → `gradle/actions/setup-gradle@v6` → `./gradlew :core:test --no-daemon --console=plain`(`env ANDROID_HOME=""`로 `:app` 제외). job `app-android`: 동일 + `./gradlew :app:assembleDebug :app:testDebugUnitTest :app:lintDebug` → `actions/upload-artifact@v4`(APK) | push / PR |
| `release-desktop.yml` | windows-latest | 태그 `desktop-v*` → `tauri-action@v1` `tagName: desktop-v__VERSION__`, `releaseDraft: true` | 태그 |

- `protocol/**` 변경은 `paths` 필터 없이 `rust.yml`과 `android.yml` **둘 다** 실행된다(공용 픽스처).
- 브랜치 보호: 3개 워크플로 녹색 + Codex 리뷰 통과 + 사용자 머지(CLAUDE.md PR 규칙). PR 설명 4항목(변경 요약 / 보안 영향 / 테스트 방법 / 문서 변경).
- 빌드박스(Linux)에서 로컬로 통과해야 하는 것: `rust.yml` 전부, `android.yml` `core-jvm`, `desktop-windows.yml`의 typecheck/test.

---

## 3. Codex 리뷰 범위 (AGENTS.md 보강 개요)

### P0 — 머지 차단

1. `ApprovalReply::Allow` / Claude `behavior:"allow"` / Codex `"accept"`가 `apply_decision` 성공 분기 밖에서 생성되는 코드(데스크톱 로컬 결정 포함 — 같은 전이를 지나야 함).
2. `security.md` §6.2 9단계 중 생략·순서 변경·단축 평가(예: 상태 변경 후 검증), 조건부 UPDATE 없이 `approvals.status`를 쓰는 코드.
3. `decision`/`hello`/`pair` 바인딩에서 nonce/챌린지/`tool_input_sha256`이 빠지거나 재사용 가능한 구조; 만료 후 적용; 멱등 위반.
4. WSS 외 수신 경로, `0.0.0.0`/인터페이스 전체 바인드, trust-all TrustManager, 핀 검증 완화, 평문 ws 폴백, 인증 전 출력, `ping` 인증 전 허용.
5. 비밀 타입이 `Debug`/로그/DB/폰 전송에 노출되는 경로; 원시 훅 본문·`tool_input.content`·stdout 전체 영속; 알림 본문에 명령 전문.
6. `AppConfig`에 `security.md` §9 금지 필드 추가, 위험 규칙 완화·외부 파일 로드, 분류 실패가 `critical` 아닌 값으로.
7. 범위 확장 결정(`allow_for_session`, `updatedPermissions`, `updatedInput`, `acceptForSession`, execpolicy/network amendment, Codex hooks `interrupt`)이 스키마·응답·설정 어디에든 등장; Codex `PreToolUse`에 `permissionDecision` 출력; `onFailure:"block"` 기본값.
8. `// UNVERIFIED (Phase 0)` 코드가 feature flag 없이 기본 경로에 들어옴(Codex 데몬 소켓, hooks.json 설치, rollout, Nav3, DPAPI, code-scanner 버전).
9. 폐기(`revoked_at`)를 무시하는 조회(메모리 캐시 불일치 포함).
10. `docs/security.md` fail-closed 표(§7)와 어긋나는 동작.

### P1 — 기능 오류

스키마↔Rust↔Kotlin 불일치, 전이표/mood 테이블과 리듀서 불일치, 재동기화에서 만료·종결 승인이 되살아나는 경로, `dedupe_key` 누락, 픽스처 미갱신, 새 메시지/규칙/템플릿에 테스트 없음, 재연결 백오프 무한 루프, FGS 타입/권한 누락, headline 길이 상한 위반, 오프라인에서 결정 버튼 활성화, 결정 큐잉.

### 리뷰 입력

PR diff + `docs/security.md`(불변식·fail-closed 표) + `docs/protocol.md` + 변경된 픽스처. 보고 형식은 AGENTS.md 유지(`[P0] <파일:라인> 요약 / 근거 / 재현 / 수정 제안`).
