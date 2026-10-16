# Phase 0 검증 체크리스트 · Phase 1 수용 기준

- 상태: 확정(리드 종합본) — 2026-10-15
- 목적(PRD §7 Phase 0): "Claude Code와 Codex가 발생시킨 실제 이벤트를 PC에서 식별할 수 있어야 한다." 각 항목은 결과를 **실제 페이로드 캡처**(`protocol/fixtures/`, 민감값 마스킹)로 남기고 이 문서에 통과/실패와 날짜를 기록한다.
- ★ = **Phase 1 착수 게이트** 항목(통과 전 Phase 1 착수 금지). **같은 대안 군에 ★가 여러 개면 "그중 하나 이상의 대안이 통과"하면 그 군은 충족**이다(Codex: `★C1+★C2` **또는** `★C6`). 실패 시 대안이 명시된 항목은 대안을 채택하고 해당 설계 문서를 갱신한다. PRD §7의 'Phase 0 통과 조건'(§4.1)은 ★ 전체(§4.2)보다 좁은 부분집합이다.
- A-시리즈 목록·★ 표시는 `integrations/claude-code.md` §9와 항상 같아야 한다(이 문서가 범례의 규범).
- 환경: Windows 11 + Claude Code v2.1.300 + Codex rust-v0.162.x + 갤럭시(Android 16) + Linux 빌드박스 + GitHub Actions.

---

## 1. Claude Code (A-시리즈) — `integrations/claude-code.md`

| # | 항목 | 방법 | 통과 기준 | 실패 시 대안 |
| --- | --- | --- | --- | --- |
| ★A1 | 사용자 settings.json HTTP 훅 수집 | 최소 데몬(axum 204)로 터미널 세션 진행 | 16개 이벤트(SessionStart…SessionEnd) 각 1회 이상 캡처, 터미널에 `hook error` 없음, 원본 50건 → 픽스처 | CLI 폴백(exec form) |
| ★A2 | `PermissionRequest` 보류 중 **로컬 다이얼로그 표시 여부** | 데몬이 120초 홀드 후 204 | (a) 다이얼로그가 훅 종료 후에만 뜨는지 (b) 동시에 뜨는지 기록 → `local_prompt` 값 확정; 로컬 결정 시 HTTP 연결이 끊기는지(`superseded` 경로) | (a)면 "폰 없음 → 즉시 204" + 데스크톱 '로컬로 처리' 버튼이 필수(이미 설계); (b)면 UX 문구만 조정 |
| ★A3 | 훅 `timeout` 상한 | `timeout: 150`, `600`, `3600` | 경고/오류 없이 동작하는 최대값 기록 | 상한에 맞춰 `approval.ttl_s` 범위 축소 |
| ★A4 | 데몬 미실행 시 `hook error` 소음 | 데몬 종료 후 10분 작업 | transcript/UI 알림 빈도 기록 → 허용 가능 여부 판단 | "데몬 종료 시 AgentNest 훅 항목 제거" 옵션 기본 on |
| A5 | 비정상 종료 시 `SessionEnd` | 터미널 강제 종료 | 수신 여부 기록 | 미수신이면 dead 타이머(45분/30분) 유지 |
| A6 | Git Bash 없는 Windows | Git for Windows 제거 후 실행 | `PowerShell` 도구명, 백슬래시 절대경로 캡처 → 정규화기 픽스처 | — |
| A7 | `allow` 후 PreToolUse/PostToolUse 상관 | 동일 도구 10회 | 60초 창 내 `tool_name + sha256(tool_input)` 매칭 ≥ 90% | 창/키 조정, 불일치 시 `unknown` 유지 |
| A8 | auto/acceptEdits에서 PreToolUse `ask` 강제 | critical 명령 | `PermissionRequest`(또는 로컬 프롬프트) 유발 확인 | `force_ask_on_critical` 기본 off |
| A9 | statusLine 채널 | `agentnest-hook statusline` 설치 | `session_name`(AI 제목)·`cost`·`pr` 캡처 | 선택 기능 유지 |
| A10 | 사용자+프로젝트 settings 중복 정의 | 두 파일에 같은 훅 | 호출 횟수 기록, dedupe 동작 확인 | — |
| A11 | `UserPromptSubmit` 자동 턴 휴리스틱 | `/loop`, 백그라운드 서브에이전트 보고 | `auto_turn_suspect` 오탐/미탐률 기록 | 필드 제거(모두 "지시"로 표시) |
| ★A12 | 원격 `allow`/`deny` 적용 | 폰 대신 데몬 콘솔에서 결정 주입 | transcript에 "Allowed by PermissionRequest hook"; deny 시 Claude가 사유 수신; `interrupt:true` 시 중단 | — |
| A13 | `permission_mode`별 `PermissionRequest` 발생 | default/acceptEdits/plan/auto/dontAsk/bypass 각 1회 | 배지 규칙 확정 | — |
| A14 | 병렬 서브에이전트의 같은 명령 `PermissionRequest`에 `agent_id`가 실리는지, user+project 중복 호출 간격 | 같은 명령을 두 서브에이전트가 동시에 시도 + 두 settings에 같은 훅 | `agent_id` 유무·간격 기록 → 카드 병합 키(`agent_id`)·2초 창 확정 | `agent_id`가 없으면 병합 창 0(병합 안 함, 보수적) |
| A15 | `SessionStart`을 HTTP 훅으로 받을 수 있는가 | 같은 설정에 `SessionStart` HTTP 훅과 command 훅을 함께 두고 `claude -p` 실행 | HTTP 훅이 호출되는지/건너뛰는지 기록 → 설치기 규칙 확정 | 건너뛰면 `SessionStart`만 command 훅(`agentnest-hook claude-code`) |


### 1.1 실행 결과 (2026-10-16, Claude Code **2.1.301**, 리눅스 서버 `claude -p` 비대화형)

방법: 임시 설정(`--settings` + `--setting-sources project`)으로 모든 훅을 로컬 HTTP 캡처 서버에 연결하고 실제 `claude -p`를 실행 → 본문을 `protocol/fixtures/claude-code/captured/`에 마스킹해 보관(`desktop/crates/agentnest-core/tests/claude_code_captured.rs`가 정규화·수집기·승인 브로커로 재현). 실제 CLI → 설치기가 만든 설정 → 실제 수집기(+실제 `agentnest-hook`) 종단 테스트는 `AGENTNEST_REAL_CLAUDE=1 AGENTNEST_HOOK_BIN=<agentnest-hook> cargo test -p agentnest-core --test claude_code_captured -- --ignored`. **측정하지 못한 것**: 대화형 TUI(폴더 trust·로컬 다이얼로그·`Notification`), Windows(PowerShell·백슬래시), statusLine, 비정상 종료.

| # | 결과 | 근거·남은 일 |
| --- | --- | --- |
| ★A1 | **부분** | 16개 중 10개 캡처(`SessionStart`·`UserPromptSubmit`·`PreToolUse`·`PermissionRequest`·`PostToolUse`·`PostToolUseFailure`·`SubagentStart`·`SubagentStop`·`Stop`·`SessionEnd`), 28건 → 픽스처. **미캡처: `PermissionDenied`·`Notification`·`StopFailure`·`TaskCreated`·`TaskCompleted`·`PostCompact`**(대화형·특수 조건 필요), 원본 50건 미달, 터미널 `hook error` 소음은 TUI에서 확인 못 함. `SessionStart`는 HTTP로 오지 않음(A15) |
| ★A2 | 미검증 | 로컬 다이얼로그 동시 표시는 대화형 TUI 필요. 참고: `-p`에서는 훅이 결정하지 않으면(204) 곧바로 거부 |
| ★A3 | **부분** | 단위=초 확인(`timeout:5` + 8초 지연 → `cancelled`, 응답 폐기·거부), `600`·`3600`은 경고 없이 수용되고 8초 지연 응답이 적용됨. 스키마에 상한 없음. 600초·3600초를 **끝까지** 기다리는지는 미측정 |
| ★A4 | **부분** | 데몬 없음(`ECONNREFUSED`) = 비차단 `outcome: error`, 작업 계속(`-p`). 대화형 UI의 알림 빈도는 미측정 |
| A5, A6, A8, A9, A10 | 미검증 | 비정상 종료·Windows·auto 강제 ask·statusLine·settings 중복은 이번에 측정하지 않음 |
| A7 | **부분** | 실제 `PermissionRequest.tool_input`의 정규화 해시가 같은 호출의 `PreToolUse`·`PostToolUse` 이벤트의 해시와 일치(Bash·Write). 10회 반복 매칭률·거부 후 상관은 미측정(거부되면 `PostToolUse*`/`PermissionDenied`가 오지 않음) |
| A11 | **부분** | `<task-notification>` 알림 턴은 `auto_turn_suspect=true`, 일반 프롬프트는 `false`. `/loop`·예약 작업은 미측정. 2.1.301 `-p` 본문에는 `UserPromptSubmit.source`가 없음(Claude Code 스키마에는 선택 필드로 존재) |
| ★A12 | **부분** | `-p`에서 `allow` → 명령 실행, `deny`+`message` → 원문 그대로 Claude에 전달·미실행, `deny`+`interrupt:true` → 턴 중단(메시지는 미전달), 결정 없음(204) → 거부. 종단 테스트로 재현. 대화형 transcript의 "Allowed by PermissionRequest hook" 문구는 미확인 |
| A13 | **부분** | `default`에서만 `PermissionRequest` 관측; `acceptEdits`(Write)·`auto`(Bash)·`dontAsk`·`plan`에서는 발생 안 함. `bypassPermissions`는 미측정(root 세션) |
| A14 | **부분** | 서브에이전트 안 `PermissionRequest`에 `agent_id`·`agent_type` 실림(메인 스레드는 없음). 병렬 동시 호출 간격·user+project 중복은 미측정 |
| A15 | **통과** | `SessionStart` HTTP 훅은 호출되지 않고 같은 설정의 command 훅만 호출됨(Claude Code 로그: "HTTP hooks are not supported for SessionStart"). → 설치기에서 `SessionStart`만 command 훅으로 고정(`COMMAND_ONLY_EVENTS`) |

---

## 2. Codex (C-시리즈) — `integrations/codex.md`

> 대안 군: **(★C1 + ★C2)**(공유 데몬 소켓 구독·승인) **또는 ★C6**(hooks). 둘 중 하나 이상이 통과하면 Codex 군은 충족이다. C10(실페이로드)은 C6를 채택하는 경우 hooks 정규화기 작성의 선행 조건이다.

| # | 항목 | 방법 | 통과 기준 | 실패 시 대안 |
| --- | --- | --- | --- | --- |
| ★C1 | 공유 데몬 소켓 존재(Windows AF_UNIX) | 사용자가 `codex`(TUI)만 실행 → `%USERPROFILE%\.codex\app-server-control\` 확인 → AgentNest `initialize` | 소켓 파일 존재 + `userAgent` 캡처 | 모드 A 폐기, hooks(B)만 |
| ★C2 | 제3 연결 구독·승인 수신 | 소형 Rust 클라이언트 `thread/list` → `thread/resume{threadId}`(`excludeTurns` 지원 여부도 확인 — [추정]) | TUI 스레드의 `item/*`·`thread/status/changed`·**`requestApproval`** 수신, 폰(콘솔) `accept` 시 TUI 진행 | 모드 A 폐기 |
| C3 | 첫 응답 승리 + `serverRequest/resolved` | TUI와 AgentNest 동시 대기, 한쪽 응답 | 다른 쪽에 `serverRequest/resolved`, 중복 실행 없음, 레이스(폰 accept 직후 TUI decline) 결과 기록 | 카드 취소 로직 조정 |
| C4 | 소켓 인증/권한 | 비상승·상승 프로세스 각각 접속 | 토큰 요구 여부, `ensure_non_elevated_peer` 결과 | 필요 설정 문서화 |
| C5 | 스키마 스냅샷 | `codex app-server generate-json-schema` | `protocol/fixtures/codex/app-server/schema/` 커밋, 드리프트 테스트 통과 | — |
| ★C6 | hooks 설정 파일 형식·trust·폴백 | `~/.codex/hooks.json` 작성 후 `/hooks` | 최상위 구조(`hooks` 키 유무)·matcher 필드·`commandWindows` 선택 규칙 확정; trust 절차 캡처; `agentnest-hook codex` 호출 확인; `PermissionRequest` 빈 stdout 시 **로컬 프롬프트 폴백** 확인; `max_permission_request_timeout` 키·값 | 폴백 미확인이면 hooks `PermissionRequest`는 **관찰만** 유지(Codex 원격 승인은 모드 A 또는 Phase 2) |
| C7 | 리뷰 출력 | `codex exec review --json --output-schema` + TUI `/review` | 실제 출력 캡처; `exitedReviewMode.review` 텍스트 형식 → `[P0]` 파서 픽스처 | 텍스트 파서만 |
| C8 | `thread/list` 소스·정책 노출 | `sourceKinds` 생략/명시 비교; `thread/resume` 응답·`config/read` | TUI 세션 포함 여부; `approvalPolicy`/`sandbox` 노출 여부(위험 배지) | `sourceKinds` 명시 / 배지 생략 |
| C9 | A+B 동시 사용 시 이중 카드 | hooks + 데몬 소켓 동시 활성 | hooks allow가 app-server 승인 요청을 생략하는지 | 한 채널만 활성 |
| C10 | **hooks 실페이로드 캡처** | Codex에서 셸 명령·패치 적용(`apply_patch` 류)·MCP 도구·웹 검색 각각으로 `PreToolUse`/`PermissionRequest`/`PostToolUse` 유발 | `tool_name` 실제 값, 이벤트별 `tool_use_id` 유무(리서치상 `PermissionRequest`에는 없음)를 캡처(마스킹) → `protocol/fixtures/codex/hooks/`; `codex.md` §5.3 Codex 전용 매핑 표를 실값으로 교체 | 미지 이름은 `working` 유지, 상관은 `sha256(tool_input)` |

---

## 3. 플랫폼·보안 (P-시리즈)

| # | 항목 | 방법 | 통과 기준 |
| --- | --- | --- | --- |
| ★P1 | windows-latest(VS2026) `tauri build` | `desktop-windows.yml` 1회 | NSIS `-setup.exe` 산출, 설치본에서 토스트에 앱 이름/아이콘, 트레이 4단계 교체 |
| ★P2 | 빌드박스 로컬 | `cargo test`(default-members), `cargo check -p agentnest-desktop --target x86_64-pc-windows-msvc`(심 환경변수 포함, `testing-and-ci.md` 2.1), `pnpm typecheck && pnpm test`, `./gradlew :core:test` | 전부 녹색(리서치 실측과 동일) |
| ★P3 | Android CI | `android.yml` | `:core:test` + `:app:assembleDebug` 녹색; `./gradlew :app:dependencies`로 `play-services-code-scanner` 최신 버전 확인·확정; AGP built-in Kotlin이 KGP 2.4.21을 쓰는지 로그 확인 |
| ★P4 | WSS + SPKI 핀 실기 | Windows 데몬(rcgen+ring) ↔ 갤럭시 OkHttp | (a) 핀 일치 → 연결, (b) 다른 키 → 실패, (c) 같은 키 재발급(SAN 변경) → 재페어링 없이 연결, (d) IP 변경 후 재연결(주소 갱신 경로의 상세·한계는 **P16**) |
| P5 | 페어링 UX | QR → SAS → PC 승인 | 폰·PC SAS 일치, 거절 시 미등록, 촬영 QR로 먼저 보낸 `pair`가 PC 모달 거절로 차단됨, 120초 만료·3회 실패 소각 |
| P6 | axum 보류 핸들러 drop | 클라이언트가 연결을 끊음 | `DropGuard`가 호출되어 `superseded` 기록(hyper 취소 동작 [추정] 확인) |
| P7 | 생체 게이트 | 갤럭시 + (가능하면) API 26~29 기기/에뮬레이터 | `BIOMETRIC_STRONG\|DEVICE_CREDENTIAL` 동작, 미등록 시 버튼 비활성, API 26~29 폴백 조합의 androidx.biometric 1.1.0 지원 여부 |
| P8 | FGS 생존 | 화면 꺼짐 2시간 + `adb shell dumpsys deviceidle force-idle` | 연결 유지 또는 30초 내 복구; 삼성 절전 예외 미설정/설정 비교(3일 시나리오는 Phase 1 말) |
| P9 | 알림 체감 | 잠금 화면에서 승인 요청 10회 | HIGH 헤드업 표시, 탭 → 상세 → 생체 → PC 반영까지 **평균 15초 이내**; 본문에 명령 전문 없음 |
| P10 | 보안 수용 기준 | `security.md` §12 | 항목 전부(현재 13항목) |
| P11 | Keystore | 갤럭시 | AES-GCM 래핑 라운드트립(잠금 상태 포함), EC P-256 공개키 SPKI 추출, StrongBox 가용성·폴백 |
| P12 | DPAPI(선택, Phase 3 준비) | windows-latest `cargo test` | `windows` 0.62.2 `Win32_Security_Cryptography`에 `CryptProtectData`/`CryptUnprotectData` 존재 확인, 다른 사용자 계정에서 복호 실패 |
| P13 | 콩이 성능 | 갤럭시 프레임 측정 | 60 fps 유지, 애니메이션 off 시 정지 프레임 + 설명문, 백그라운드 중단 |
| P14 | rcgen/rustls API 경로 | 컴파일 | `CertificateParams.not_before/not_after`, `rustls::crypto::ring::default_provider().install_default()` 경로 확인 |
| ★P15 | **Windows 방화벽·네트워크 프로필** (`security.md` §3.1) | **클린 Windows 11**(표준 사용자, 공장 상태 방화벽, NSIS `currentUser` 설치)에서 앱 첫 실행 → 리스너 바인드 → 폰 접속 시도. 시나리오: ① Defender '액세스 허용' 프롬프트에서 허용/취소 ② 네트워크 프로필 Private/Public ③ 앱의 UAC 규칙 생성(`netsh advfirewall`, Private+LocalSubnet+설치 exe) ④ 연결 진단 뷰 판정 ⑤ 언인스톨 시 규칙 제거 | (a) 규칙 없음 → 폰 접속 실패·진단 뷰가 원인(프로필/규칙/차단)을 정확히 표시, (b) 규칙 생성 후 같은 Wi-Fi 폰이 QR 페어링 성공, (c) Public 프로필에서는 차단되고 안내가 나옴, (d) 언인스톨 후 규칙이 남지 않거나(또는 `program=` 범위로 무해), (e) `netsh` 구문·exe 이름 확정 → `security.md` §3.1 갱신 |
| P16 | **PC 주소 변경(DHCP) 복구** (`security.md` §3.2, `protocol.md` §4.5) | (a) PC에 IP를 **추가**(두 번째 NIC) → `hosts_update`로 폰이 새 주소를 저장·사용 (b) 단일 NIC에서 IP를 **교체**(DHCP 재발급/어댑터 재활성) → 데몬 재바인드+인증서 재발급(같은 키) → 폰이 `PcUnreachable` → 'IP 직접 입력' 또는 QR 재스캔(주소만 갱신)로 복구 | (a) 자동 전환 확인, (b) **재페어링 없이** 수동 복구가 30초 안에 가능, 핀 불변, 기존 토큰 유효; 한계(단일 IP 교체는 자동 불가)를 문서와 UI 문구가 일치 — **대안**: 불가하면 DHCP 예약 안내를 온보딩 필수 항목으로 격상 |
| P17 | **Coucou 소스·라이선스 검토** (PRD §5/§7) | 저장소 확보 → `LICENSE`(MIT 주장 확인)·서드파티 고지·의존성 라이선스 열람 → 재사용 후보(훅 설치기·트레이·Tauri 구조 등)와 코드 품질·보안 이슈 목록화 → 산출물 `docs/coucou-review.md`(Phase 0에서 작성) | 라이선스 문구·귀속 의무가 기록됨, 재사용/비재사용 결정과 근거가 모듈별로 표에 있음, **복사한 코드는 출처·라이선스 헤더 유지**, 이미지·캐릭터 같은 에셋은 코드와 별도로 라이선스 범위를 확인(불명확하면 재사용 금지) — **대안**: 라이선스가 불명확하면 재사용 0(독립 구현) — 설계에 영향 없음 |
| P18 | **기존 GitHub 작업 흐름 분석** (PRD §7) | 사용자의 기존 저장소·`.github/workflows`·브랜치/PR 규칙·Codex 리뷰 호출 방식을 열람해 정리 → 산출물 `docs/github-workflow-analysis.md` | 사용 중인 트리거·필수 체크·리뷰 호출 경로·토큰 권한이 기록됨, Phase 2 GitHub 연동 지점(Checks API vs `workflow_run`)과 필요한 최소 권한이 결정됨 — **대안**: 정보 부족 시 사용자 인터뷰 항목으로 남기고 Phase 2 착수 전 재확인 |

---

## 4. Phase 0 통과 조건과 Phase 1 착수 게이트

### 4.1 PRD §7 Phase 0 통과 조건 ("실제 이벤트 식별")

**A1 + A12 + (C1·C2 또는 C6) + P2 + P3 + P4** 통과로 충족된다.

### 4.2 Phase 1 착수 게이트 (★ 전체)

**★A1–★A4 + ★A12 + [(★C1 + ★C2) 또는 ★C6] + ★P1–★P4 + ★P15.** 4.1에 없는 ★A2·★A3·★A4(승인 보류 UX·TTL 상한·훅 소음)·★P1(Windows 번들)·★P15(방화벽)는 이벤트 식별이 아니라 **Phase 1 설계값을 확정**하는 항목이라 착수 전에 필요하다. 비★ 항목(A5–A11, A13, A14, C3–C5, C7–C10, P5–P14, P16–P18)은 Phase 1 중 병행하되 해당 기능을 켜기 전에 통과해야 한다(예: C10은 hooks 정규화기 특화 매핑, P16은 MVP 릴리스 전).

### 4.3 PRD §7 Phase 0 항목 ↔ 이 체크리스트

| PRD §7 Phase 0 항목 | 담당 항목 | 담당 |
| --- | --- | --- |
| Coucou 소스코드 및 라이선스 검토 | **P17**(`docs/coucou-review.md`) | Claude Code 조사 → 사용자 재사용 결정 |
| Windows 앱 실행 확인 | P1 + **P15** | Claude Code(CI) + 사용자(클린 PC 실기) |
| Android 빌드 확인 | P3 | CI |
| Claude Code 이벤트 수집 | A1, A12 | 사용자 실기 + Claude Code |
| Codex 이벤트 수집 | C1·C2 또는 C6, C10 | 사용자 실기 + Claude Code |
| 기존 GitHub 작업 흐름 분석 | **P18**(`docs/github-workflow-analysis.md`) | Claude Code 조사 → 사용자 확인 |

## 5. Phase 1 수용 기준 ↔ PRD §9

| PRD §9 조건 | 충족 수단 | 검증 |
| --- | --- | --- |
| Windows PC에서 실행 가능 | NSIS 설치본, 트레이 상주, 자동 시작(`--minimized`), **방화벽 규칙·연결 진단**(`security.md` §3.1) | P1, **P15** + 설치 후 `GET /v1/health` |
| 갤럭시 스마트폰에서 실행 가능 | `android.yml` APK 사이드로드(minSdk 26), FGS `connectedDevice` | P3, P8 |
| QR 코드로 안전하게 연결 가능 | `security.md` §4(HMAC 소지 증명 + SAS(폰 로컬 계산) + PC 확인, 120초 1회용), SPKI 핀 TLS, 토큰 Keystore 래핑, 방화벽·네트워크 프로필 안내, PC 주소 변경 복구 경로(`hosts`/수동 IP) | P4, P5, **P15, P16** + 토큰 재사용 거부 테스트 |
| Claude Code 상태를 실시간 확인 | HTTP 훅 → 정규화 → `session_state`(< 1초) | A1 + 터미널에서 Edit/Bash/테스트 → 폰 chip·콩이 2초 내 변경 |
| Codex 상태를 실시간 확인 | hooks(B) 또는 데몬 소켓(A) → `session_state`. **Codex 리뷰 결과(P0/P1 개수·문제 목록, PRD §2 "Codex 세션 및 리뷰 상태"·§3.B)는 Phase 1에서 best-effort·선택 기능**: 모드 A(C1·C2) 또는 C7 픽스처로 입증된 경로가 있을 때만 제공하고, 기본 hooks 모드에서는 `meta.review.state=unavailable` + "리뷰 정보 없음 (hooks 모드)"를 표시한다(`integrations/codex.md` §8). 도구 이름 매핑이 C10 전이면 세분 상태(`writing_code`/`reviewing`)는 `working`으로 축약될 수 있다 | C6 또는 C1/C2 + C10 + `codex` TUI 명령 → 폰 반영. 리뷰 푸시는 C1·C2·C7 중 해당 경로 통과 시에만 검증 |
| 지원되는 승인 요청에 응답 가능 | `PermissionRequest` 브리지 / Codex `requestApproval`(A) 또는 hooks `PermissionRequest`(C6 후) | A12, C2/C6 + 터미널 "Allowed by PermissionRequest hook" |
| 승인과 거절의 실제 처리 결과 확인 가능 | `decision_result{APPLIED}` + `approval_resolved{delivery, observed_result, message_ko}` + 데스크톱 승인 기록 + `approval_audit` | A7, Codex `item/completed` 상관 |
| 연결 장애가 발생해도 위험한 명령이 자동 승인되지 않음 | `security.md` I5·§7 fail-closed, 오프라인 버튼 비활성·결정 큐잉 없음, 허용 응답 불투명 타입 + `ApplyProof::mint` 호출 1곳 grep 테스트 | 승인 브로커 매트릭스 + 폰 비행기 모드 중 요청 → 로컬 다이얼로그, 재연결 후 `handed_off_local` |
| 캐릭터가 AI 작업 상태에 맞춰 변화 | 전이표 + mood 우선순위/히스테리시스 + 링크 오버레이 | `state_transitions.json`·`mood_priority.json` + P13 |
| 최소한의 오류 복구 및 재연결 기능 작동 | `hello.last_seq` 재동기화, 백오프, 어댑터 재접속, 데몬 재시작 시 pending→expired | ws 테스트 + 비행기 모드 on/off → 10초 내 재연결, 놓친 이벤트 복구 |
