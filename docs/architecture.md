# AgentNest 아키텍처 (Phase 0 + Phase 1 확정본)

- 상태: **확정(리드 종합본)** — 2026-10-15
- 입력: `docs/prd.md`, 설계 제안 3종(보안 우선 / 연동 충실도 / 제품 UX), 심사 결과, 리서치 4종(`claude-code-hooks`, `codex-app-server`, `tauri2-desktop`, `android-stack`)
- 신뢰도 표기 규칙(모든 설계 문서 공통)
  - **[검증]** 공식 문서 원문·소스 코드·레지스트리·빌드박스 실측으로 확인
  - **[추정]** 소스 구조나 문서 문맥에서 추론(실동작 미확인)
  - **검증 필요 (Phase 0)** 확인하지 못한 외부 API 형태. 코드에서는 `// UNVERIFIED (Phase 0)` 주석 + feature flag(기본 off) 뒤에 둔다
- 관련 문서: `protocol.md`(와이어 프로토콜), `security.md`(위협 모델·불변식), `integrations/*.md`, `android.md`, `desktop.md`, `storage.md`, `character.md`, `testing-and-ci.md`, `phase0-checklist.md`, `adr/`

---

## 1. 한 장 요약

```text
┌──────────────────────────── Windows PC ────────────────────────────┐   ┌──────── Android ────────┐
│ Claude Code CLI ──http hook──▶ 127.0.0.1:47831 ┐                    │   │ LinkService (FGS)       │
│ Codex TUI/CLI ───command hook(agentnest-hook)─▶ │ agentnest-core    │   │  ├ OkHttp WSS(SPKI 핀)  │
│ Codex app-server 소켓 ──(flag, UNVERIFIED)────▶ │  ├ adapters       │   │  ├ NestReducer(core)    │
│                                                 │  ├ normalize/ko   │   │  └ 알림 채널 5종        │
│  Tauri 2 셸(트레이·설정·페어링·승인 로컬 처리)   │  ├ risk(상수)     │   │ UI: 홈(3층)·승인센터   │
│   └ invoke/emit ◀──────────────────────────────▶│  ├ broker(승인)   │◀WSS│ 콩이(Compose Canvas)   │
│                                                 │  ├ state(파생)    │ :47832                     │
│  SQLite(%LOCALAPPDATA%\AgentNest\agentnest.db)  │  ├ store(sqlite)  │   │ Keystore(AES-GCM 래핑)  │
│                                                 │  └ link(WSS)      │   │ BiometricPrompt         │
└────────────────────────────────────────────────────────────────────┘   └─────────────────────────┘
```

핵심 결정 10가지:

| # | 결정 | 근거 / 출처 |
| --- | --- | --- |
| 1 | Claude Code 수집·승인은 **`type: "http"` 훅**이 1차, `agentnest-hook` CLI는 폴백 | HTTP 훅은 stdin JSON과 동일 본문을 POST하고 응답 본문을 출력 JSON으로 해석 [검증 v2.1.63+]. 셸·Git Bash 의존 없음 |
| 2 | 훅 인증 토큰은 **사용자 settings.json에 리터럴 헤더**로 기록 | `allowedEnvVars` 방식은 환경변수가 없는 프로세스에서 빈 문자열로 치환되어 모든 훅이 401 → 조용히 이벤트 유실 [검증: 미나열 변수는 빈 문자열]. 사용자 파일은 이미 사용자 전용 |
| 3 | 원격 승인 = `PermissionRequest` 훅 1개(matcher 생략). 데몬은 HTTP 요청을 **열어둔 채** 폰 결정을 기다리고, **결정 없음 = 2xx 빈 본문** | exit 2 무시, 결정은 `hookSpecificOutput.decision`으로만, `onFailure` 기본 `continue` [검증]. 빈 본문 = "프롬프트가 있는 세션이면 로컬 다이얼로그, 없는 세션(-p·백그라운드 서브에이전트)이면 거부" [검증] — 어느 쪽도 allow가 아니다 |
| 4 | 허용 응답(Claude `behavior:"allow"`, Codex `accept`)은 **불투명 타입**으로만 만들 수 있다: `ApprovalReply::allow(ApplyProof)`이고 `ApplyProof::mint()`는 **`apply_decision` 성공 분기 한 곳에서만** 호출된다(응답자는 `ReplyKind` 읽기 뷰만 봄). 타임아웃·끊김·재시작·검증 실패·패닉·알 수 없는 상태는 전부 "결정 없음" | PRD §6, `security.md` 불변식 I5. `compile_fail` doctest + `ApplyProof::mint` 호출 위치 grep으로 강제 |
| 5 | 승인 TTL 기본 **120초**(설정 60~180), 훅 `timeout = TTL + 30`. 데몬이 항상 Claude Code보다 먼저 응답한다 | 재생/정체 창 최소화. 300초급 TTL은 터미널을 5분 묶을 수 있어 제외 |
| 6 | 페어링 = QR 비밀 **소지 증명(HMAC)** + **PC 화면 SAS 확인** + 폰 EC 공개키 등록. 접속 인증은 Phase 1에선 디바이스 토큰(Keystore 래핑), 결정 ECDSA 서명은 Phase 3 | QR 촬영 공격(A4) 방어는 Phase 1 필수; 서명은 비용 대비 Phase 3 |
| 7 | 위험 분류 규칙은 **코드 상수**(외부 파일 로드 금지), 분류 실패 → `critical`, `critical`도 원격 승인 **가능**하되 길게 누르기 + 재확인 시트 + 생체 프롬프트(`setConfirmationRequired`는 수동 생체 힌트일 뿐 게이트로 세지 않음) | PRD §3.D "추가 확인"(금지 아님). 완화 불가, 강화만 가능 |
| 8 | Codex는 Phase 1 기본 **hooks(command 훅 + `agentnest-hook codex`) 관찰**, 공유 데몬 소켓 구독·승인은 feature flag `codex-daemon-observer`(기본 off, `// UNVERIFIED (Phase 0)`) | 소켓 경로·메서드·결정 직렬화는 [검증], 제3자 연결로 승인 요청을 받는지는 [추정] |
| 9 | 한국어 요약(`headline ≤ 40자`, `detail ≤ 200자`, 도구별 `title`)은 **PC의 결정적 템플릿**(`agentnest-core::summarize::ko`)이 만들고 폰은 렌더링만 한다 | PRD §1 "쉬운 언어". 골든 픽스처 `protocol/fixtures/summaries_ko.json` |
| 10 | 원시 훅 본문은 **디스크에 저장하지 않는다**. 저장·전송되는 것은 바운드(8 KiB)·마스킹된 `detail`뿐 | PRD §6, CLAUDE.md "파일 본문 전체 금지" |

---

## 2. 빌드박스 제약(확정 사실) [검증: `build-constraints-verified.md`, 리서치 실측]

| 항목 | 사실 | 결과 |
| --- | --- | --- |
| Linux 빌드박스 | Rust 1.97.0, Node 22.22 + pnpm 10.28, Java 21, Gradle 8.14.3(전역) | 저장소 루트 `rust-toolchain.toml` `channel = "1.97.0"`; Android는 wrapper 9.7.1 강제 |
| webkit2gtk 없음 | Tauri 셸을 호스트 타깃으로 빌드·check 불가 | `default-members`에서 셸 제외. 셸은 `cargo check -p agentnest-desktop --target x86_64-pc-windows-msvc`(llvm-rc 존재, 성공 실측) |
| Android SDK 없음, `dl.google.com` 차단 | AGP 해석 불가 | `android/core`(순수 JVM)만 로컬 검증, `:app`은 조건부 include → CI(ubuntu-latest)에서만 |
| 도달 가능 | crates.io, npm, Maven Central, plugins.gradle.org, services.gradle.org, code.claude.com, raw.githubusercontent.com | 의존성 해석 가능 |
| windows-latest | Windows Server 2025 + VS2026, Rust 1.98.1, WiX 3.14.1, **NSIS·NASM 없음** | NSIS는 tauri-bundler가 자동 다운로드; rustls 프로바이더는 **ring**으로 통일(aws-lc-rs는 NASM 필요) |

로컬 검증 명령(CLAUDE.md와 동일; 전부 녹색이어야 PR):

```bash
cd desktop && cargo fmt --all --check && cargo clippy --workspace --exclude agentnest-desktop --all-targets -- -D warnings && cargo test --workspace --exclude agentnest-desktop
cd desktop && cargo check -p agentnest-desktop --target x86_64-pc-windows-msvc
cd desktop/apps/desktop && pnpm install --frozen-lockfile && pnpm typecheck && pnpm test
cd android && ./gradlew :core:test
```

---

## 3. 모노레포 레이아웃

```text
agentnest/
├── CLAUDE.md / AGENTS.md / README.md / .editorconfig / .gitignore
├── rust-toolchain.toml                     # channel = "1.97.0"
├── docs/                                   # 이 문서들 (README.md가 색인)
├── protocol/                               # 언어 중립 단일 진실 공급원
│   ├── schema/                             # JSON Schema draft 2020-12
│   │   ├── envelope.schema.json
│   │   ├── c2s/{pair,hello,ack,ping,snapshot_request,decision,approval_seen,unpair}.schema.json
│   │   ├── s2c/{challenge,pair_pending,pair_result,welcome,snapshot,event,session_state,
│   │   │        approval_request,approval_resolved,decision_result,adapter_status,pong,error,bye}.schema.json
│   │   ├── model/{agent_event,agent_state,approval_request,session_state,project_ref,risk}.schema.json
│   │   └── qr/pairing_payload.schema.json
│   ├── examples/                           # 타입당 ≥1개 유효 예시 + invalid/ (반드시 거부)
│   ├── vectors/                            # pair 소지 증명·SAS·tool_input_sha256 테스트 벡터(Rust·Kotlin 동일 결과)
│   ├── fixtures/
│   │   ├── claude-code/hooks/*.json        # 훅 페이로드(문서 예시 → Phase 0 실캡처로 교체, 마스킹)
│   │   ├── claude-code/statusline/*.json
│   │   ├── codex/app-server/*.jsonl        # initialize…turn/completed, 승인 요청/응답 시퀀스
│   │   ├── codex/app-server/schema/        # `codex app-server generate-json-schema` 스냅샷(드리프트 감지)
│   │   ├── codex/hooks/*.json
│   │   ├── summaries_ko.json               # 입력 → 기대 {title, headline, detail}
│   │   ├── risk_cases.json                 # 명령/경로 → 기대 등급 (규칙당 양성·음성 ≥2)
│   │   ├── state_transitions.json          # 이벤트 시퀀스 → 기대 AgentState (Rust·Kotlin 공용)
│   │   ├── mood_priority.json              # 세션 상태 집합 + 링크 상태 → 기대 mood (Rust·Kotlin 공용)
│   │   └── redact_cases.json
│   └── tables/                             # (없음) 위험 규칙은 코드 상수 — 외부 테이블 금지
├── desktop/                                # Cargo 워크스페이스
│   ├── Cargo.toml                          # default-members = 순수 크레이트 4개
│   ├── crates/
│   │   ├── agentnest-protocol/             # serde 타입(스키마와 1:1) + 스키마 적합성·라운드트립 테스트
│   │   ├── agentnest-adapter-api/          # AgentAdapter 트레이트, RawObservation, ApprovalResponder (의존성 최소)
│   │   ├── agentnest-core/                 # 데몬: http(훅 수집)·adapters·normalize·summarize·risk·state·approvals·store·auth·link(WSS)·redact
│   │   └── agentnest-hook/                 # CLI: stdin JSON → 로컬 데몬 POST → stdout (Codex 훅 필수, Claude Code 폴백)
│   └── apps/desktop/
│       ├── package.json / vite.config.ts / tsconfig.json / src/ / dist/index.html(더미, check용 커밋)
│       └── src-tauri/                      # tauri 2.12.4 (tray-icon), tauri-build 2.7.3, icons/icon.ico, capabilities/default.json
├── android/
│   ├── settings.gradle.kts                 # :core 항상, :app 은 SDK 있을 때만 include
│   ├── build.gradle.kts                    # kotlin.jvm / compose / serialization apply false (AGP 선언 금지)
│   ├── gradle/libs.versions.toml, gradle/wrapper/ (9.7.1)
│   ├── core/                               # kotlin("jvm"): 프로토콜 모델·NestReducer·MoodResolver·LinkStateMachine·DecisionValidator·SpkiPinTrustManager·Canonical/HMAC
│   └── app/                                # Compose 앱 (CI 전용)
└── .github/workflows/{rust.yml, desktop-windows.yml, android.yml, release-desktop.yml}
```

> CLAUDE.md의 저장소 구조에 `agentnest-adapter-api`를 반영했다(ADR-0003, 문서 우선 규칙에 따라 이 문서가 기준). 크레이트 목록은 CLAUDE.md·README·이 문서가 항상 같아야 한다.

### 3.1 Cargo 워크스페이스 (`desktop/Cargo.toml`)

```toml
[workspace]
resolver = "2"
members = [
  "crates/agentnest-protocol",
  "crates/agentnest-adapter-api",
  "crates/agentnest-core",
  "crates/agentnest-hook",
  "apps/desktop/src-tauri",
]
default-members = [
  "crates/agentnest-protocol",
  "crates/agentnest-adapter-api",
  "crates/agentnest-core",
  "crates/agentnest-hook",
]

[workspace.package]
edition = "2021"
rust-version = "1.90"          # Tauri 2.12.x MSRV [검증]
license = "MIT"

[workspace.dependencies]
serde = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.154"
tokio = { version = "1.53.3", features = ["rt-multi-thread", "macros", "sync", "net", "time", "signal", "process", "io-util", "fs"] }
axum = { version = "0.8.9", features = ["ws", "json", "macros"] }
axum-server = { version = "0.8.0", features = ["tls-rustls-no-provider"] }
rustls = { version = "0.23.46", default-features = false, features = ["ring", "std", "tls12", "logging"] }
tokio-rustls = { version = "0.26.6", default-features = false, features = ["ring", "tls12", "logging"] }
# 테스트 클라이언트 전용(dev-dependency). 기본 feature(`connect`·`handshake`)에는 TLS가 없고 TLS feature(`rustls-tls-*`)는 webpki/native 루트를 끌어온다 [검증: crates.io feature 표, 2026-10-15].
# 핀 검증 테스트는 커스텀 `ServerCertVerifier`가 필요하므로 `tokio-rustls`(위, ring)로 직접 TLS 핸드셰이크 후 그 스트림에 `tokio_tungstenite::client_async`를 쓴다.
tokio-tungstenite = { version = "0.30.0", default-features = false, features = ["handshake"] }   # `client_async` 사용 — 컴파일 확인은 구현 시 [추정]
ring = "0.17.14"               # HMAC-SHA256, SHA-256, SystemRandom, (Phase 3) ECDSA 검증
rcgen = "0.14.10"              # 기본 feature(ring) — 자가서명 인증서
subtle = "2.6.1"
zeroize = "1.9.1"
rusqlite = { version = "0.40.2", features = ["bundled"] }
rusqlite_migration = "2.6.0"
qrcode = { version = "0.14.1", default-features = false, features = ["svg"] }
jsonschema = { version = "0.58.6", default-features = false }
uuid = { version = "1.28.0", features = ["v4", "v7", "serde"] }
chrono = { version = "0.4.45", features = ["serde", "clock"] }
time = "0.3.55"                # rcgen not_before/not_after (OffsetDateTime)
base64 = "0.23.1"              # API 마찰 시 0.22 라인으로 핀 가능
hex = "0.4.3"
regex = "1.13.1"               # crates.io 2026-07-15 [검증]
thiserror = "2.0.21"
anyhow = "1.0.104"
tracing = "0.1.44"
tracing-subscriber = { version = "0.3.23", features = ["env-filter", "fmt", "json"] }
tracing-appender = "0.2.5"
futures-util = "0.3.34"
directories = "6.0.0"
local-ip-address = "0.6.13"
clap = { version = "4.6.7", features = ["derive"] }
# 훅 CLI는 http://127.0.0.1 에만 말한다 → TLS 불필요. ureq 3.4.2 기본 feature = `rustls`+`gzip`(rustls·ring·webpki-roots 유입)이라 끈다 [검증: crates.io, 2026-10-15].
ureq = { version = "3.4.2", default-features = false, features = ["json"] }   # (대안: TcpStream HTTP/1.1 직접 구현)
tempfile = "3.27.0"
```

- 암호 백엔드는 **ring 하나**: rustls(ring), rcgen(기본 ring), HMAC/SHA-256/CSPRNG도 `ring`. `sha2`/`hmac`/`rand` RustCrypto 크레이트는 넣지 않는다(중복 백엔드 금지). **`aws-lc-rs`가 의존 그래프에 없어야 한다 — CI 검사는 종료 코드를 반전해야 한다**: 패키지가 그래프에 없으면 `cargo tree -i aws-lc-rs`는 "did not match any packages" 오류로 **비정상 종료**하므로 `! cargo tree --workspace --target all -i aws-lc-rs 2>/dev/null`로 쓰고(`cargo tree --workspace` 자체가 성공함을 먼저 확인해 다른 오류로 인한 거짓 통과를 막는다), 사람이 읽는 출력이 '비어 있음'이라고 가정하지 않는다.
- `rustls::crypto::ring::default_provider().install_default()`를 데몬 시작 시 1회 호출(함수 경로는 관례 [추정] → 컴파일 시점 확인).
- `async-trait`는 쓰지 않는다. 트레이트 비동기 메서드는 `BoxFuture`(`futures-util`) 반환으로 통일(버전 미검증 크레이트 회피).
- Windows DPAPI(`windows` 0.62.2, feature `Win32_Security_Cryptography`)는 **Phase 0 항목 P0-21**(함수 소속 모듈 미확인 — 검증 필요 (Phase 0)). Phase 1은 파일 ACL(사용자 전용)로 시작한다.

### 3.2 의존 방향

```text
agentnest-protocol ◀── agentnest-adapter-api ◀── agentnest-core ◀── agentnest-desktop(src-tauri)
agentnest-protocol ◀── agentnest-hook
```

`agentnest-adapter-api`는 `protocol`, `serde`, `serde_json`, `futures-util`, `tokio(sync)`만 의존한다. `agentnest-core`는 Tauri를 모른다: `Daemon::start(config) -> DaemonHandle{events: broadcast::Receiver<DaemonEvent>, cmds: mpsc::Sender<DaemonCommand>}`.

### 3.3 `agentnest-core` 모듈 구조

```text
crates/agentnest-core/src/
├── lib.rs / daemon.rs      Daemon::start/run/shutdown, 포트 선택(47831 충돌 시 47833~47840 + 훅 재설치)
├── config.rs               AppConfig (금지 필드 없음 — security.md §9), 설정 파일 스키마
├── identity/               ServerIdentity: rcgen 키쌍(재사용) + 인증서 재발급, SPKI SHA-256, keywrap(ACL / cfg(windows) DPAPI 후보)
├── http/                   axum Router(127.0.0.1): POST /v1/hooks/{claude-code,codex}, POST /v1/statusline/claude-code, GET /v1/health, GET /v1/daemon
├── link/                   WSS 서버(axum ws + axum-server rustls): 핸드셰이크 상태기계, seq/ack/replay, 레이트리밋, 하트비트
├── auth/                   pairing(HMAC 소지 증명·SAS·PC 확인), devices(토큰 해시, 폐기), challenge
├── adapters/               Registry + feature 게이트: claude_code(HTTP 훅 정규화·PermissionRequest 홀드), codex/{hooks, daemon_observer(flag), rollout(flag), review}, mock(dev)
├── normalize/              RawObservation → AgentEvent 공통 후처리(경로 정규화·프로젝트 해석·마스킹·상한·dedupe_key)
├── summarize/ko.rs         결정적 한국어 템플릿 (title/headline/detail)
├── risk/                   분류기(코드 상수 규칙), command_class 토크나이저
├── state/                  SessionReducer(전이표), timers, focus(다중 세션 우선순위)
├── approvals/              Broker(단일 전이 경로), Validator(9단계), Correlator(observed_result), DropGuard
├── store/                  rusqlite 워커(단일 writer), migrations, retention
├── redact.rs               비밀 뉴타입(Debug → "<redacted>", zeroize), 3-싱크 정책, 패턴 마스킹
└── audit.rs                approval_audit / audit_log 기록
```

---

## 4. 컴포넌트 책임

| 컴포넌트 | 책임 | 하지 않는 것 |
| --- | --- | --- |
| `agentnest-protocol` | 와이어 타입(serde, `#[serde(default)]`, 알 수 없는 필드 무시, 알 수 없는 enum → `Unknown(String)`), 스키마 적합성 테스트, canonical 바이트열·`tool_input_sha256` 계산 | 네트워크·저장 |
| `agentnest-adapter-api` | `AgentAdapter`, `AdapterCapabilities`, `RawObservation`, `ApprovalResponder`, `NativeBinding` | 결정 생성(어댑터는 번역만) |
| `agentnest-core` | 수집·정규화·요약·위험 분류·상태 파생·승인 브로커·저장·페어링·WSS·레댁션 | UI, 캐릭터 렌더링 |
| `agentnest-hook` | stdin JSON → 데몬 POST → stdout 패스스루, 항상 exit 0 | 결정 생성, 입력 가공(32 KiB 초과 문자열 절단만) |
| `agentnest-desktop`(Tauri) | 트레이, 페어링 QR + SAS 확인 모달, 기기 폐기, 훅 설치, 승인 로컬 처리/로컬 결정, 설정 | 캐릭터, 폰 대체 모니터링 |
| `android/core` | 프로토콜 모델, `NestReducer`, `MoodResolver`, `LinkStateMachine`, `DecisionValidator`, 핀닝 TLS, HMAC/canonical | Android API |
| `android/app` | FGS 링크 서비스, 알림, Keystore 토큰 보관, 생체 게이트, QR 스캔, Compose UI, 콩이 | 상태 파생 로직(core에 위임) |

---

## 5. 데이터 흐름

### 5.1 상태 이벤트 (PRD §5 데이터 흐름 1~5)

```text
Claude Code ──POST /v1/hooks/claude-code (X-AgentNest-Token)──▶ http::hooks
  1. 토큰 상수시간 비교, Origin/Sec-Fetch-Site 거부, 1 MiB 상한
  2. dedupe_key = sha256(session_id | hook_event_name | tool_use_id ?? sha256(body)) — 2초 창 중복 무시
  3. adapters::claude_code::normalize(hook) → Vec<RawObservation::Event(AgentEvent)>   (순수 함수, 골든 테스트)
  4. normalize::post: 경로 정규화 → 프로젝트 해석 → redact(마스킹·상한) → summarize::ko(headline/detail)
  5. state::SessionReducer.reduce(prev, event) → session_state 변경?
  6. store: events INSERT, sessions UPSERT, stream INSERT(seq)
  7. link: 온라인 기기 전체에 event{seq} / session_state{seq} 브로드캐스트 ──WSS──▶ 폰 NestReducer → 콩이/홈
  8. 204 응답 (목표 < 10 ms; 1~7 중 3 이후는 큐에서 비동기)
```

### 5.2 원격 승인 (PRD §5 데이터 흐름 6~7) — 상세는 `integrations/claude-code.md` §6, `security.md` §6

```text
PermissionRequest(HTTP 열림, timeout=TTL+30)
  → risk::classify → summarize::ko → request_id/nonce/tool_input_sha256/expires_at(now+TTL)
  → approvals INSERT(pending) [같은 (session, agent_id, tool, hash)가 2초 안이면 중복 훅 → 카드 1장, 아니면 별도 카드]
  → 온라인 인증 기기 0 ⇒ 즉시 204 (handed_off_local, resolved_by=system)
  → approval_request{seq} 전송, ack 대기(5s×3), 데스크톱 "휴대폰이 받음"
  → decision 수신 → Validator 9단계(상태 변경 전) → 단일 UPDATE … WHERE status='pending' AND expires_at>now
  → ApprovalReply::allow(ApplyProof) | ::deny(..) → responder.respond → 200 JSON / Codex {"id","result":{"decision":…}}
  → approval_resolved{delivery, observed_result=unknown} → 60초 상관 창 내 PreToolUse/PostToolUse 관찰 → observed_result 갱신 재전송
그 외 모든 경로(만료·끊김·재시작·검증 실패·패닉) ⇒ 빈 2xx / Codex 무응답
```

### 5.3 재연결·재동기화

`hello.last_seq` → `welcome.resync{mode: replay|snapshot}` → `stream` 테이블(`max(48h, 10,000행)` + 크기 상한)에서 재생. 재생 시 만료된 `approval_request`는 보내지 않고 `approval_resolved{expired}`로 대체. 폰은 `snapshot`을 받으면 `sessions`·`pending_approvals`를 **교체**한다(병합 아님). 상세: `protocol.md` §8.

---

## 6. 핀 고정 버전 (리서치 2026-10-15 조회 기준)

### 6.1 Rust / 데스크톱 [검증: crates.io, npm]

| 패키지 | 버전 | 비고 |
| --- | --- | --- |
| tauri / tauri-build / tauri-cli | 2.12.4 / 2.7.3 / 2.12.3 | MSRV 1.90. 3.0.0-alpha 사용 금지 |
| tauri-plugin-single-instance / notification / autostart / opener / store / log | 2.5.4 / 2.7.0 / 2.7.0 / 2.7.2 / 2.5.0 / 2.10.1 | single-instance는 **첫 번째 등록**. `tauri-plugin-shell` 미사용 |
| @tauri-apps/api / cli | 2.12.4 / 2.12.3 | |
| vite / typescript / vitest | 8.3.4 / ~5.9.3 / 5.0.4 | TS 7·vite 8 호환 문제 시 vite ^7.3.7 |
| tokio / axum / axum-server / rustls / tokio-rustls / tokio-tungstenite | 1.53.3 / 0.8.9 / 0.8.0 / 0.23.46 / 0.26.6 / 0.30.0 | ring 프로바이더 |
| rcgen / ring / subtle / zeroize / regex | 0.14.10 / 0.17.14 / 2.6.1 / 1.9.1 / 1.13.1 | |
| rusqlite / rusqlite_migration | 0.40.2(bundled, SQLite 3.53.2) / 2.6.0 | |
| qrcode / jsonschema / uuid / chrono / time | 0.14.1(svg) / 0.58.6(no default) / 1.28.0 / 0.4.45 / 0.3.55 | |
| clap / ureq / local-ip-address / directories | 4.6.7 / 3.4.2 / 0.6.13 / 6.0.0 | |
| windows (DPAPI 후보) | 0.62.2 | feature 키 존재 [검증], `CryptProtectData` 소속 모듈 — 검증 필요 (Phase 0) |

### 6.2 Android [검증: developer.android.com, Maven Central, kotlinlang]

| 항목 | 버전 | 비고 |
| --- | --- | --- |
| Gradle wrapper / AGP / Kotlin | 9.7.1 / 9.3.3 / 2.4.21 | AGP 9 built-in Kotlin → `org.jetbrains.kotlin.android` 미적용 |
| Compose BOM / activity / lifecycle / core / datastore | 2026.09.00 / 1.13.0 / 2.11.0 / 1.19.1 / 1.2.1 | |
| biometric | 1.1.0 | `BiometricPrompt(FragmentActivity…)` |
| OkHttp / okhttp-tls / mockwebserver3-junit5 | 5.5.0 | WS 클라이언트·핀닝은 `android/core`(JVM)에 |
| kotlinx-serialization-json / coroutines | 1.11.0 / 1.11.0 | |
| play-services-code-scanner | 16.1.0 | **검증 필요 (Phase 0)** — `QrScanner` 인터페이스 뒤에 격리, zxing 4.3.0 폴백 |
| compileSdk / targetSdk / minSdk / JDK(CI) | 36 / 36 / 26 / 17 | targetSdk 37은 `ACCESS_LOCAL_NETWORK` 대응 후 |
| Navigation 3 | **미사용** | API 미검증 → Phase 1은 sealed class + BackHandler 수동 내비게이션 |

---

## 7. CI 매트릭스 (상세: `testing-and-ci.md`)

| 워크플로 / 잡 | 러너 | 핵심 단계 |
| --- | --- | --- |
| `rust.yml` | ubuntu-24.04 | `dtolnay/rust-toolchain@1.97.0` + `Swatinem/rust-cache@v2` → fmt → clippy(default-members) → test → `apt-get install llvm` + msvc 타깃 `cargo check -p agentnest-desktop` → `! cargo tree --workspace --target all -i aws-lc-rs`(종료 코드 반전: 없으면 오류로 종료하는 것이 정상) + `ApplyProof::mint` 호출 1곳 grep |
| `desktop-windows.yml` | windows-latest | pnpm 10 / node 22 / rust 1.97.0 → `pnpm typecheck && pnpm test` → `tauri-apps/tauri-action@v1`(`projectPath: desktop/apps/desktop`, `uploadWorkflowArtifacts: true`) → `cargo test -p agentnest-core`(Windows 경로·ACL 테스트) |
| `android.yml` | ubuntu-latest | `actions/checkout@v7`, `setup-java@v6`(temurin 17), `gradle/actions/setup-gradle@v6` → job A `:core:test`(`ANDROID_HOME=""`) / job B `:app:assembleDebug :app:testDebugUnitTest :app:lintDebug` → APK 아티팩트 |
| `release-desktop.yml` | windows-latest | 태그 `desktop-v*` → `tauri-action@v1` `releaseDraft: true` |

액션 태그는 리서치에서 존재 확인된 것만: `actions/checkout@v7`, `actions/setup-node@v4`, `pnpm/action-setup@v4`, `Swatinem/rust-cache@v2`, `dtolnay/rust-toolchain@1.97.0`, `actions/setup-java@v6`, `gradle/actions/setup-gradle@v6`, `tauri-apps/tauri-action@v1`, `actions/upload-artifact@v4`.

---

## 8. Phase 범위

| Phase | 포함 | 제외 |
| --- | --- | --- |
| 0 | `phase0-checklist.md` 전 항목(실기 캡처 → 픽스처) | UI 완성도 |
| 1 | 페어링(SAS, 폰 로컬 계산), Windows 방화벽·네트워크 프로필 안내, Claude Code 훅 수집·원격 승인, Codex hooks 관찰(+ flag 뒤 데몬 소켓), 콩이 **9 mood**(`blink_slow`, `typing`, `magnifier`, `tools`, `raise_hand`, `flustered`, `celebrate`, `sleepy`, `worried` — PRD 8 상태 + 링크 끊김 2종 분리), 홈 3층, 승인센터·승인 기록, 알림 **5채널**(`approvals`/`alerts`/`completions`/`link`/`security`), 재연결·재동기화·이벤트 이력 조회(`events_request`), 데스크톱 트레이·로컬 처리·연결 진단·링크 비활성 | GitHub/PR, LLM 요약, 외부망, 결정 서명, rollout 백필, `review/start` |
| 2 | GitHub API, PR/CI, 타임라인·일일 요약, AI 비서, Codex `review/start`·`codex exec review`, rollout 백필 | — |
| 3 | 외부망(릴레이/VPN), 결정 ECDSA 서명(Keystore EC, 페어링 때 이미 공개키 등록), DPAPI 키 래핑, Doze 테스트 | — |
| 4 | 워치, 멀티 PC, Gemini CLI/OpenCode 어댑터, 외부 프로세스 어댑터 | — |

**PRD 매핑 주의 — Codex 리뷰 결과**: PRD §2 P0 "Codex 세션 및 리뷰 상태"·§3.B(P0/P1 문제, 대상 PR, 권고) 중 Phase 1 기본 빌드(hooks)가 약속하는 것은 **세션 상태**다. **리뷰 결과(P0/P1)는 best-effort·선택 기능**으로, 소스가 입증된 경로(모드 A의 `/review` 관찰 = C1·C2, 또는 C7 픽스처로 형식이 입증된 `codex exec review`/`Stop` 텍스트 파서)에서만 켜지며 그 밖에서는 폰이 "리뷰 정보 없음 (hooks 모드)"를 표시한다(`session_state.meta.review.state=unavailable`, `adapter_status.detail`). 근거·게이트는 `integrations/codex.md` §8, 검증은 `phase0-checklist.md` §5.
