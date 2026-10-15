# Phase 0 검증 체크리스트 · Phase 1 수용 기준

- 상태: 확정(리드 종합본) — 2026-10-15
- 목적(PRD §7 Phase 0): "Claude Code와 Codex가 발생시킨 실제 이벤트를 PC에서 식별할 수 있어야 한다." 각 항목은 결과를 **실제 페이로드 캡처**(`protocol/fixtures/`, 민감값 마스킹)로 남기고 이 문서에 통과/실패와 날짜를 기록한다.
- ★ = 통과 전 Phase 1 착수 금지. 실패 시 대안이 명시된 항목은 대안을 채택하고 해당 설계 문서를 갱신한다.
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

---

## 2. Codex (C-시리즈) — `integrations/codex.md`

| # | 항목 | 방법 | 통과 기준 | 실패 시 대안 |
| --- | --- | --- | --- | --- |
| ★C1 | 공유 데몬 소켓 존재(Windows AF_UNIX) | 사용자가 `codex`(TUI)만 실행 → `%USERPROFILE%\.codex\app-server-control\` 확인 → AgentNest `initialize` | 소켓 파일 존재 + `userAgent` 캡처 | 모드 A 폐기, hooks(B)만 |
| ★C2 | 제3 연결 구독·승인 수신 | 소형 Rust 클라이언트 `thread/list` → `thread/resume{excludeTurns:true}` | TUI 스레드의 `item/*`·`thread/status/changed`·**`requestApproval`** 수신, 폰(콘솔) `accept` 시 TUI 진행 | 모드 A 폐기 |
| C3 | 첫 응답 승리 + `serverRequest/resolved` | TUI와 AgentNest 동시 대기, 한쪽 응답 | 다른 쪽에 `serverRequest/resolved`, 중복 실행 없음, 레이스(폰 accept 직후 TUI decline) 결과 기록 | 카드 취소 로직 조정 |
| C4 | 소켓 인증/권한 | 비상승·상승 프로세스 각각 접속 | 토큰 요구 여부, `ensure_non_elevated_peer` 결과 | 필요 설정 문서화 |
| C5 | 스키마 스냅샷 | `codex app-server generate-json-schema` | `protocol/fixtures/codex/app-server/schema/` 커밋, 드리프트 테스트 통과 | — |
| ★C6 | hooks 설정 파일 형식·trust·폴백 | `~/.codex/hooks.json` 작성 후 `/hooks` | 최상위 구조(`hooks` 키 유무)·matcher 필드·`commandWindows` 선택 규칙 확정; trust 절차 캡처; `agentnest-hook codex` 호출 확인; `PermissionRequest` 빈 stdout 시 **로컬 프롬프트 폴백** 확인; `max_permission_request_timeout` 키·값 | 폴백 미확인이면 hooks `PermissionRequest`는 **관찰만** 유지(Codex 원격 승인은 모드 A 또는 Phase 2) |
| C7 | 리뷰 출력 | `codex exec review --json --output-schema` + TUI `/review` | 실제 출력 캡처; `exitedReviewMode.review` 텍스트 형식 → `[P0]` 파서 픽스처 | 텍스트 파서만 |
| C8 | `thread/list` 소스·정책 노출 | `sourceKinds` 생략/명시 비교; `thread/resume` 응답·`config/read` | TUI 세션 포함 여부; `approvalPolicy`/`sandbox` 노출 여부(위험 배지) | `sourceKinds` 명시 / 배지 생략 |
| C9 | A+B 동시 사용 시 이중 카드 | hooks + 데몬 소켓 동시 활성 | hooks allow가 app-server 승인 요청을 생략하는지 | 한 채널만 활성 |

---

## 3. 플랫폼·보안 (P-시리즈)

| # | 항목 | 방법 | 통과 기준 |
| --- | --- | --- | --- |
| ★P1 | windows-latest(VS2026) `tauri build` | `desktop-windows.yml` 1회 | NSIS `-setup.exe` 산출, 설치본에서 토스트에 앱 이름/아이콘, 트레이 4단계 교체 |
| ★P2 | 빌드박스 로컬 | `cargo test`(default-members), `cargo check --target x86_64-pc-windows-msvc`, `pnpm typecheck && pnpm test`, `./gradlew :core:test` | 전부 녹색(리서치 실측과 동일) |
| ★P3 | Android CI | `android.yml` | `:core:test` + `:app:assembleDebug` 녹색; `./gradlew :app:dependencies`로 `play-services-code-scanner` 최신 버전 확인·확정; AGP built-in Kotlin이 KGP 2.4.21을 쓰는지 로그 확인 |
| ★P4 | WSS + SPKI 핀 실기 | Windows 데몬(rcgen+ring) ↔ 갤럭시 OkHttp | (a) 핀 일치 → 연결, (b) 다른 키 → 실패, (c) 같은 키 재발급(SAN 변경) → 재페어링 없이 연결, (d) IP 변경 후 재연결 |
| P5 | 페어링 UX | QR → SAS → PC 승인 | 폰·PC SAS 일치, 거절 시 미등록, 촬영 QR로 먼저 보낸 `pair`가 PC 모달 거절로 차단됨, 120초 만료·3회 실패 소각 |
| P6 | axum 보류 핸들러 drop | 클라이언트가 연결을 끊음 | `DropGuard`가 호출되어 `superseded` 기록(hyper 취소 동작 [추정] 확인) |
| P7 | 생체 게이트 | 갤럭시 + (가능하면) API 26~29 기기/에뮬레이터 | `BIOMETRIC_STRONG\|DEVICE_CREDENTIAL` 동작, 미등록 시 버튼 비활성, API 26~29 폴백 조합의 androidx.biometric 1.1.0 지원 여부 |
| P8 | FGS 생존 | 화면 꺼짐 2시간 + `adb shell dumpsys deviceidle force-idle` | 연결 유지 또는 30초 내 복구; 삼성 절전 예외 미설정/설정 비교(3일 시나리오는 Phase 1 말) |
| P9 | 알림 체감 | 잠금 화면에서 승인 요청 10회 | HIGH 헤드업 표시, 탭 → 상세 → 생체 → PC 반영까지 **평균 15초 이내**; 본문에 명령 전문 없음 |
| P10 | 보안 수용 기준 | `security.md` §12 | 8항목 전부 |
| P11 | Keystore | 갤럭시 | AES-GCM 래핑 라운드트립(잠금 상태 포함), EC P-256 공개키 SPKI 추출, StrongBox 가용성·폴백 |
| P12 | DPAPI(선택, Phase 3 준비) | windows-latest `cargo test` | `windows` 0.62.2 `Win32_Security_Cryptography`에 `CryptProtectData`/`CryptUnprotectData` 존재 확인, 다른 사용자 계정에서 복호 실패 |
| P13 | 콩이 성능 | 갤럭시 프레임 측정 | 60 fps 유지, 애니메이션 off 시 정지 프레임 + 설명문, 백그라운드 중단 |
| P14 | rcgen/rustls API 경로 | 컴파일 | `CertificateParams.not_before/not_after`, `rustls::crypto::ring::default_provider().install_default()` 경로 확인 |

---

## 4. Phase 0 통과 조건

PRD §7 Phase 0 "실제 이벤트 식별"은 **A1 + A12 + (C1·C2 또는 C6) + P2 + P3 + P4** 통과로 충족된다. Coucou 소스/라이선스 검토와 기존 GitHub 작업 흐름 분석은 이 체크리스트 범위 밖(별도 항목).

---

## 5. Phase 1 수용 기준 ↔ PRD §9

| PRD §9 조건 | 충족 수단 | 검증 |
| --- | --- | --- |
| Windows PC에서 실행 가능 | NSIS 설치본, 트레이 상주, 자동 시작(`--minimized`) | P1 + 설치 후 `GET /v1/health` |
| 갤럭시 스마트폰에서 실행 가능 | `android.yml` APK 사이드로드(minSdk 26), FGS `connectedDevice` | P3, P8 |
| QR 코드로 안전하게 연결 가능 | `security.md` §4(HMAC 소지 증명 + SAS + PC 확인, 120초 1회용), SPKI 핀 TLS, 토큰 Keystore 래핑 | P4, P5 + 토큰 재사용 거부 테스트 |
| Claude Code 상태를 실시간 확인 | HTTP 훅 → 정규화 → `session_state`(< 1초) | A1 + 터미널에서 Edit/Bash/테스트 → 폰 chip·콩이 2초 내 변경 |
| Codex 상태를 실시간 확인 | hooks(B) 또는 데몬 소켓(A) → `session_state` | C6 또는 C1/C2 + `codex` TUI 명령 → 폰 반영 |
| 지원되는 승인 요청에 응답 가능 | `PermissionRequest` 브리지 / Codex `requestApproval`(A) 또는 hooks `PermissionRequest`(C6 후) | A12, C2/C6 + 터미널 "Allowed by PermissionRequest hook" |
| 승인과 거절의 실제 처리 결과 확인 가능 | `decision_result{APPLIED}` + `approval_resolved{delivery, observed_result, message_ko}` + 데스크톱 승인 기록 + `approval_audit` | A7, Codex `item/completed` 상관 |
| 연결 장애가 발생해도 위험한 명령이 자동 승인되지 않음 | `security.md` I5·§7 fail-closed, 오프라인 버튼 비활성·결정 큐잉 없음, Allow 생성 경로 유일성 grep 테스트 | 승인 브로커 매트릭스 + 폰 비행기 모드 중 요청 → 로컬 다이얼로그, 재연결 후 `handed_off_local` |
| 캐릭터가 AI 작업 상태에 맞춰 변화 | 전이표 + mood 우선순위/히스테리시스 + 링크 오버레이 | `state_transitions.json`·`mood_priority.json` + P13 |
| 최소한의 오류 복구 및 재연결 기능 작동 | `hello.last_seq` 재동기화, 백오프, 어댑터 재접속, 데몬 재시작 시 pending→expired | ws 테스트 + 비행기 모드 on/off → 10초 내 재연결, 놓친 이벤트 복구 |
