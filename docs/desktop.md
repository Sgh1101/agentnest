# 데스크톱 앱(Tauri 2) 설계

- 상태: 확정(리드 종합본) — 2026-10-15
- 버전 근거: 리서치 `tauri2-desktop.md`(crates.io/npm 조회, tauri-docs v2 원문, 빌드박스 실측). 별도 표기 없는 항목은 [검증].
- 역할: 데스크톱은 **데몬 + 설정/페어링/로컬 폴백 UI**다. 모니터링의 주무대는 폰이며, 캐릭터는 데스크톱에 없다.

---

## 1. 버전·플러그인

| 항목 | 버전 | 비고 |
| --- | --- | --- |
| tauri / tauri-build / @tauri-apps/cli / @tauri-apps/api | 2.12.4(`features=["tray-icon"]`) / 2.7.3 / 2.12.3 / 2.12.4 | MSRV 1.90. **3.0.0-alpha 금지**(`@next`, `--pre` 사용 안 함) |
| tauri-plugin-single-instance | 2.5.4 | **첫 번째로 등록**, 데스크톱 cfg 전용. 콜백: 메인 창 `show()+set_focus()` |
| tauri-plugin-notification | 2.7.0 | Windows 토스트는 **설치본에서만** AppUserModelID 적용(`tauri dev`에서 다르게 보임) |
| tauri-plugin-autostart | 2.7.0 | `init(MacosLauncher::LaunchAgent, Some(vec!["--minimized"]))` |
| tauri-plugin-opener | 2.7.2 | `opener:allow-open-url`(github.com, code.claude.com 스코프), `reveal_item_in_dir` |
| tauri-plugin-store | 2.5.0 | UI 설정만. 토큰·비밀은 core(SQLite/ACL 파일) |
| tauri-plugin-log | 2.10.1 | 선택: webview console → tracing |
| tauri-plugin-shell | **미사용** | 프로세스 실행은 Rust 코어(`tokio::process`) |
| vite / typescript / vitest / eslint / prettier | 8.3.4 / ~5.9.3 / 5.0.4 / 10.12.0 / 3.9.10 | TS 7 네이티브 포트는 생태계 리스크 → 5.9. vite 8 문제 시 ^7.3.7 |

---

## 2. 프로세스 구조

Tauri 셸은 **얇은 글루**다. 판단·매핑·검증 로직은 전부 `agentnest-shell-api`(Tauri 타입 없음, Linux/Windows 단위 테스트)에 있고, `src-tauri`는 그것을 `#[tauri::command]`·창·트레이·토스트·플러그인에 연결만 한다(`architecture.md` §3).

```rust
// src-tauri/src/lib.rs (요약)
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| show_main(app)))   // 첫 번째: 둘째 프로세스는 여기서 종료
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec!["--minimized"])))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_log::Builder::new().skip_logger().build())                  // 전역 로거는 셸이 직접 설치(파일 롤링)
        .invoke_handler(tauri::generate_handler![/* §3 의 27개 */])
        .setup(startup::setup)
        .on_window_event(|w, e| if let WindowEvent::CloseRequested { api, .. } = e { api.prevent_close(); let _ = w.hide(); })
        .build(tauri::generate_context!())?
        .run(|app, ev| match ev { RunEvent::ExitRequested { api, code: None, .. } => api.prevent_exit(), RunEvent::Exit => startup::shutdown(app), _ => {} });
}
// startup::setup: Paths → AppConfig::load(&paths.config)  ← 데몬 시작 전에(저장된 설정이 무시되지 않게) → 파일 로거 → Daemon::start_with(config, options)
//                 → ShellApi::new(daemon, ui-settings, 방화벽 구현, 시계, 옵션) → manage(Shell) → 트레이 → 이벤트 펌프(데몬 런타임) → 필요하면 창 표시
```

- **데몬은 `main`이 아니라 `setup`에서 시작한다.** 플러그인은 `Builder::build()`에서 초기화되고 `setup`은 그 뒤 이벤트 루프에서 돈다. 그래서 단일 인스턴스 플러그인이 둘째 프로세스를 먼저 종료시킨다. `main`에서 먼저 시작하면 둘째 프로세스가 포트 47833으로 둘째 데몬을 띄우고 **`daemon.json`(포트·훅 토큰)을 덮어쓴 뒤** 종료해 첫 데몬의 훅이 깨진다.
- 런타임: `Daemon::start`가 **자기 tokio 런타임을 소유**한다. Tauri는 자기 런타임을 그대로 쓰고(`tauri::async_runtime::set` 불필요) 둘은 채널(`DaemonHandle.cmds`/`events`)로만 만난다. 이벤트 펌프는 데몬 런타임에서, 커맨드는 Tauri 런타임에서 돈다.
- `--minimized`로 시작하면 창을 숨긴 채 트레이만 — **단, 첫 실행 체크리스트(`onboarding.completed`)가 끝나지 않았으면 창을 연다**(`first_run::show_window_at_start`).
- 종료: 트레이 "종료" → `app.exit(0)` → `RunEvent::Exit` → `DaemonHandle::shutdown_blocking()`(별도 스레드, 최대 6초 대기. WSS에 `bye{shutdown}` + 1012, 보류 승인은 빈 2xx/무응답으로 종결(`handed_off_local`), HTTP graceful 2초, SQLite 체크포인트). 창이 모두 숨겨져도 `ExitRequested{code: None}`은 막는다(트레이 상주).
- 데몬 패닉 시 Tauri 프로세스는 살아 있고 트레이가 빨간색 + "데몬 오류 — 재시작" 메뉴(재시작 = `app.restart()`).

### 2.1 모듈

```text
desktop/crates/agentnest-shell-api/src/        # Tauri 없음. `cargo test -p agentnest-shell-api`
├── commands.rs      COMMAND_NAMES / COMMAND_ARGS / EVENT_KINDS (프런트 계약의 Rust 쪽)
├── contract_tests.rs backend.ts·tauri.ts·guards.ts·errors.ts·types.ts 와 글루 commands.rs/lib.rs 를 텍스트로 읽어 어긋남 검출
├── error.rs         IpcError{code, message?}, CommandError/거부된 결정 → 코드
├── dto.rs           daemon_status·device·hooks·pairing_start·history·승인 카드(nonce 제거)·이벤트(detail 제거)
├── events.rs        EventMapper: DaemonEvent → daemon-event{kind,payload}, 토스트, 창 표시
├── pump.rs          run_event_pump(배칭 100 ms, 순서 보존) + UiSink 트레이트
├── settings.rs      settings_get/set 화이트리스트(금지 필드는 존재하지 않음), ui-settings.json
├── history.rs       approvals_history, last_event_at (읽기 전용 SQL)
├── logs.rs          파일 로거(일 단위 롤링 7개, 모든 줄 기록 전 `redact::mask` 통과), logs_tail(레댁션·상한)
├── codex.rs         codex_probe(경로 존재 확인만; RPC 핸드셰이크는 UNVERIFIED C1)
├── net.rs           NetworkOps 트레이트 + WindowsNetwork<ProcessRunner>(PowerShell/netsh) + UnsupportedNetwork, 출력 파서
├── diagnostics.rs   diagnostics_run 보고서·한국어 힌트
├── tray.rs          TrayModel(아이콘 4종·메뉴·툴팁), 메뉴 id 파서, inline_decision_allowed
├── first_run.rs     첫 실행 체크리스트 상태, show_window_at_start
├── api.rs           ShellApi: 커맨드 27개 + process(이벤트) + tray_input/tray_decide
└── api_tests.rs     실제 데몬(임시 디렉터리·루프백)에 대한 통합 테스트

desktop/apps/desktop/src-tauri/                # 글루: Linux 에서는 msvc 타깃 check/clippy 만 (testing-and-ci.md 2.1)
├── Cargo.toml       tauri 2.12.4(tray-icon, image-png) + 플러그인 + 위 크레이트 path 의존
├── build.rs / tauri.conf.json / capabilities/default.json / icons/ (tools/gen_icons.py 로 생성한 자리표시 아이콘)
└── src/ lib.rs(빌더·플러그인·핸들러 등록) · commands.rs(커맨드당 한 줄) · startup.rs(setup/shutdown) · tray.rs(네이티브 메뉴·아이콘·깜빡임) · sink.rs(UiSink 구현) · state.rs

desktop/apps/desktop/                          # 프런트엔드(TypeScript strict, any 금지, 프레임워크 없음)
├── src/api/{backend,types,guards,errors,tauri,mock}.ts  # 계약(§3.1)의 TS 쪽, src/views/*, src/ui/*, src/logic/*
├── dist/index.html  더미(커밋; Linux msvc check 전제), index.html, vite.config.ts, tsconfig.json, package.json
```

---

## 3. Tauri 커맨드·이벤트

| 커맨드 | 인자 → 반환 | 용도 |
| --- | --- | --- |
| `daemon_status` | → `{running, hook_port, wss_addr, hosts[], link_enabled, cert_expires_at, spki_pin, hooks_installed, effective_ttl_s, hook_timeout_s, codex_mode, sessions, devices_online}` | 상태 페이지(비밀 없음) |
| `diagnostics_run` | → `{listener{bound, addr, port}, network_profile(private\|public\|domain\|unknown), firewall{rule_present, scoped_ok, block_rule_present}, last_preauth_attempt{at, ip_masked}?, self_connect_ok, hosts[], hints_ko[]}` | **연결 진단**(`security.md` §3.1). 비밀 없음 |
| `firewall_rule_create` / `firewall_rule_remove` | → `{ok, elevated, error?}` | 사용자 동의 후 **UAC 상승**으로 `netsh advfirewall`(Private + LocalSubnet + 설치 exe) 생성/제거. 앱 자체는 비관리자 유지. `audit_log` 기록 |
| `link_set_enabled` | `(enabled: bool)` → `()` | **'휴대폰 연결 끊기'**(`security.md` §3.3). false: 리스너 닫기·보류 승인 `handed_off_local`·`bye{shutdown, reconnect:false}`·감사. 트레이 토글과 동일 |
| `risk_accept` | `(risk_id: "R1")` → `()` | 수용된 위험 확인(`security.md` §1.3) → `audit_log(risk_accepted)`. 확인 전 `pairing_start`는 `RISK_NOT_ACCEPTED`로 거부 |
| `pairing_start` / `pairing_cancel` | → `{pairing_id, qr_svg, expires_at}` / `(pairing_id)` | QR 표시(SVG만; 토큰 값은 UI에 노출하지 않음). 동시에 1개(`PAIRING_BUSY`) |
| `pairing_confirm` | `(pairing_id, approve: bool)` → `()` | **SAS 모달의 승인/거절**. Rust 측에서 `pair_pending` 상태 확인. 승인 버튼은 모달 표시 2초 후 활성 |
| `devices_list` | → `[{device_id, name, platform, model, paired_at, last_seen_at, online, revoked_at}]` | 공개키·해시 미반환 |
| `device_revoke` | `(device_id, name_typed: String)` → `()` | **기기 이름을 입력해야** 폐기(오조작 방지), 되돌리기 없음 |
| `sessions_list` | → `[SessionState]` | 폰과 같은 headline |
| `events_recent` | `(session_key?, limit)` → `[AgentEvent]` | |
| `approvals_pending` | → `[ApprovalRequest + delivery{sent_to[], acked, seen}]` | "전송됨 / 휴대폰이 받음 / 열어봄" |
| `approval_handoff_local` | `(request_id)` → `()` | **"로컬로 처리"**: 즉시 빈 2xx, `handed_off_local`(resolved_by=desktop). 위험 등급과 무관하게 항상 허용(결정을 만들지 않으므로 안전) |
| `approval_decide_local` | `(request_id, decision, tool_input_sha256, confirm_ack: bool, reason?)` → `()` | 데스크톱 허용/거부. **폰과 같은 브로커 전이**(actor=desktop, 감사). 두 번째 allow 경로 아님. 검증은 `security.md` §6.2.1: 2·3·5(카드의 `tool_input_sha256` 에코)·6·7 필수, `risk.extra_confirmation != none`이면 `confirm_ack == true` 필수(`high`: 길게 누르기, `critical`: 명령 전체 재표시 + 확인 체크 — UI가 거친 뒤에만 true), 1·4·9 해당 없음. 실패는 폰과 같은 사유 코드 |
| `remote_approval_pause` / `_resume` | → `()` | 트레이 토글과 동일 |
| `hooks_install` / `hooks_uninstall` / `hooks_status` | `{agent: "claude_code"\|"codex", mode: "http"\|"cli"}` → `{installed, path, warnings[]}` | Claude: settings.json 병합. Codex: C6 전까지 안내만 |
| `codex_probe` | → `{socket_path, reachable, user_agent?, threads}` | Phase 0 진단 |
| `settings_get` / `settings_set` | 키 화이트리스트(`security.md` §9) | 금지 필드는 존재하지 않음 |
| `logs_open_dir` | → `()` | opener `reveal_item_in_dir` |

이벤트(`Emitter::emit`): `daemon-event{kind: "event"|"session_state"|"approval"|"device"|"pairing"|"adapter"|"link", payload}`. 고빈도 `event`는 100 ms 창으로 배열 배치(이벤트 시스템은 고처리량용이 아님 [검증]; 필요 시 `tauri::ipc::Channel`).

### 3.1 프런트엔드 계약 보충 (`desktop/apps/desktop/src/api` 가 가정하는 형태 — Rust 셸은 이 형태를 구현한다)

- **인자 이름**: 위 표의 snake_case(`request_id`, `tool_input_sha256`, `confirm_ack`, `name_typed`, `pairing_id` …)가 기준이다. Tauri 기본값(camelCase)과 어긋나지 않도록 커맨드에 `#[tauri::command(rename_all = "snake_case")]`를 쓴다(프런트는 두 철자를 모두 보내므로 어느 쪽이어도 동작하지만 snake_case가 규범). `hooks_*`는 평평한 인자 `agent`, `mode`를 받는다. `events_recent`는 `session_key`를 생략할 수 있다(`Option<String>`).
- **오류**: 커맨드는 `Err`로 `{ "code": "UPPER_SNAKE", "message"?: string }`를 직렬화해 반환한다. UI는 `code`만 한국어로 옮겨 보이고 `message` 자유 문장은 표시하지 않는다. 사용하는 코드: `UNKNOWN_REQUEST` `ALREADY_RESOLVED` `INPUT_HASH_MISMATCH` `EXPIRED` `NOT_ALLOWED` `EXTRA_CONFIRMATION_REQUIRED`(`security.md` §6.2.1과 같은 사유), `RISK_NOT_ACCEPTED` `PAIRING_BUSY` `PAIRING_NOT_FOUND` `PAIRING_NOT_PENDING` `LINK_DISABLED` `NAME_MISMATCH` `DEVICE_NOT_FOUND` `INVALID_SETTING` `UNKNOWN_SETTING` `ELEVATION_DENIED` `DAEMON_NOT_RUNNING` `INTERNAL`.
- **표에 없던 커맨드 2개**: `approvals_history(limit: number)` → `[{request_id, title, tool_name, risk_level, outcome, resolved_by, resolved_device_name|null, resolved_at}]`(승인 화면 "최근 50건 기록"), `logs_tail(limit: number)` → `string[]`(로그 화면 "최근 200줄", 레댁션본).
- **`daemon_status` 추가 필드**: `remote_approval_paused: bool`(트레이 일시정지 상태), `last_event_at: {claude_code: ts|null, codex: ts|null}`(상태 화면 "마지막 이벤트"·첫 이벤트 수신 확인). `approvals_pending`의 `nonce_b64`는 UI가 받지 않으므로 생략해도 된다(보내도 폐기).
- **`settings_get`/`settings_set(key, value)`**: 평평한 점 표기 키 — `approval.ttl_s`(60~180 정수), `approval.deny_requires_auth`, `approval.critical_remote`(`extra_confirmation`\|`local_only`), `approval.daemon_down_deny`, `app.notifications`, `app.log_level`(`error`\|`warn`\|`info`\|`debug`), `onboarding.completed`, `onboarding.codex_steps_done`(`hooks_json`\|`trust`\|`doctor` 배열), `risk.accepted`(읽기 전용, 쓰기는 `risk_accept`). `settings_set`은 갱신된 전체 설정 객체를 반환하고 범위 밖 값은 `INVALID_SETTING`, 그 외 키는 `UNKNOWN_SETTING`. **`app.autostart`는 JS의 `tauri-plugin-autostart`가 직접 다루므로 Rust 설정에 없다.** `link.enabled`는 `link_set_enabled`로만 바꾼다.
- **`daemon-event` payload**(`kind` → payload): `event` → `AgentEvent[]`(배치; 단일 객체도 허용) · `session_state` → `SessionState` · `approval` → `{op:"requested", approval: ApprovalRequest+delivery}` \| `{op:"delivery", request_id, delivery}` \| `{op:"resolved", resolved: approval_resolved payload}` · `device` → `{op:"paired"\|"online"\|"offline"\|"revoked"\|"updated", device}` · `pairing` → `{op:"pending_sas", pairing_id, sas, device:{name,platform,model|null}, confirm_timeout_ms}` \| `{op:"completed", pairing_id, device_id}` \| `{op:"ended", pairing_id, reason:"expired"\|"cancelled"\|"rejected"\|"failed"\|"timeout"\|"link_disabled"}` · `adapter` → `adapter_status` payload · `link` → `{enabled, remote_approval_paused}`. 셸은 `pairing`/`pending_sas`에서 메인 창을 `show()+set_focus()` 한다(SAS 모달은 창이 보여야 의미가 있다).
- **방화벽 차단 규칙**: 진단 화면은 `block_rule_present`일 때 `firewall_rule_remove` 후 `firewall_rule_create`를 안내한다 — `firewall_rule_remove`는 AgentNest 이름의 허용 규칙뿐 아니라 이 앱 exe에 대한 차단 규칙도 지운다고 가정한다.
- **`deny_and_stop`과 게이트**: 데스크톱 UI는 `allow`와, `auth_required_for`에 든 `deny_and_stop`에 길게 누르기(+`critical`은 재확인)를 적용하고 `confirm_ack=true`를 보낸다. 일반 `deny`는 게이트 없이 `confirm_ack=false`(`security.md` §6.2 단계 8과 같은 해석).

### 3.2 셸 구현 노트 (계약을 어떻게 채우는가)

구현은 `agentnest-shell-api`다. 아래는 코어가 직접 주지 않는 값과 근사한 부분을 적은 것이며, 프런트가 보는 형태는 §3·§3.1 그대로다.

- **`daemon_status`**: 코어의 `DaemonStatus`에 `last_event_at`(`sessions` 테이블의 에이전트별 `MAX(last_event_at)`)을 더한다. `wss_addr`는 리스너가 없으면 `""`, `hook_timeout_s`는 훅이 설치되지 않았으면 `0`(가드가 숫자를 요구). 코어는 `codex_mode`를 `daemonobserver`로 쓰므로 `daemon_observer`로 정규화한다. 비밀은 없다(`spki_pin`은 공개키 지문).
- **`approvals_pending` / 승인 이벤트**: 카드에서 `nonce_b64`를 **제거**하고 `delivery{sent_to, acked, seen}`를 붙인다. `AgentEvent`는 `detail`(바운드 객체)을 제거한다(UI가 쓰지 않음). `approval`/`resolved`의 `resolved_at`은 셸 시계, `resolved_device_id`는 `null`(데몬 이벤트가 주지 않음).
- **`approval_decide_local`**: 브로커의 `approval_decide_local` 한 곳만 호출한다. 결정이 **적용되지 않으면 항상 `Err`**: 사유 `UNKNOWN_REQUEST`/`ALREADY_RESOLVED`/`INPUT_HASH_MISMATCH`/`EXPIRED`/`NOT_ALLOWED`/`EXTRA_CONFIRMATION_REQUIRED`는 같은 코드로, 데스크톱 경로에 없는 사유(`AUTH_REQUIRED` 등)나 알 수 없는 값은 `INTERNAL`. 거부 `reason`은 제어 문자 제거 + 200자 상한.
- **`pairing_start`**: 링크가 꺼져 있으면 `LINK_DISABLED`. 결과는 `{pairing_id, qr_svg, expires_at}`뿐이다 — QR 내용(`agentnest://` URI, 페어링 비밀)은 SVG로만 나간다. `pairing`/`pending_sas`의 `device.platform`은 데몬 이벤트가 주지 않아 `""`(UI는 이름·모델을 보임). `pairing`/`completed`는 데몬이 `paired` 종료 직후 내는 `Device::Paired`에서 `device_id`를 받아 만든다.
- **`device` 이벤트**: 데몬은 `device_id`만 주므로 셸이 `devices_list`에서 기기 행을 찾아 `{op, device}`를 만든다(폐기된 기기도 목록에 있다).
- **`settings_get/set`**: 키는 `settings.rs`의 화이트리스트뿐이다. `approval.*`·`app.log_level`은 코어 `AppConfig`(검증·영속은 코어), `app.notifications`·`onboarding.*`는 `<데이터 디렉터리>/ui-settings.json`(셸 소유, 알 수 없는 키 무시). `risk.accepted`는 `daemon_status`의 R1 수락 여부에서 읽고 쓰기는 `INVALID_SETTING`. `link.enabled`·`codex.mode`·`link.bind_addr` 등 **그 밖의 키와 금지 필드는 `UNKNOWN_SETTING`**(어떤 것도 바뀌지 않음). TTL은 60~180 **정수**만. `app.log_level` 변경은 영속되지만 실행 중인 로거에는 **다음 시작부터** 적용된다.
- **`firewall_rule_create/remove`**: `net.rs`. 규칙 = 인바운드·TCP·**실제 WSS 포트**·`profile=private`·`remoteip=localsubnet`·`program=<현재 exe>`(규칙 이름 `AgentNest Link (TCP <포트>)`). 읽기는 비상승 PowerShell NetSecurity cmdlet(로케일 독립 `RULE|...` 줄), 쓰기는 **상승한 PowerShell 자식 1개**(`-Verb RunAs`, UAC 1회)가 `netsh advfirewall firewall`을 실행한다(생성은 같은 이름 규칙 삭제 후 추가). UAC 거절(종료 코드 1223) = **`ELEVATION_DENIED`**(`Err`). 그 밖의 실패는 `{ok:false, elevated, error}`. 성공 후 **상태를 다시 읽어 검증**하고(`scoped_ok`/차단·허용 규칙 제거), `audit_log(firewall_rule_created/removed)`에는 포트·프로필만 남기고 경로는 남기지 않는다. `remove`는 이름으로 지운 뒤 `name=all dir=in program=<exe>`로 이 exe의 허용·**차단** 규칙을 모두 지운다. exe 경로는 절대 경로·따옴표/제어문자 없음이 아니면 프로세스를 시작하지 않는다. **Windows 실기 동작은 `[추정]`**(Phase 0 P15). Windows가 아니면 `not_available`.
- **`diagnostics_run`**: 리스너·프로필·방화벽·마지막 인증 전 시도(코어의 `PreAuthAttempt` 이벤트를 셸이 기억; 시작 후 한 번도 없으면 `null`)·셀프 접속(LAN 주소로 TCP 1.5초)·`hosts`·한국어 `hints_ko`. 프로필은 **바꾸지 않는다**(안내만).
- **`approvals_history`**: `approvals`에서 종결된 행을 `COALESCE(resolved_at, expires_at)` 내림차순 최대 200건(기본 UI 50건). 표시 필드만 선택한다(명령·nonce·해시 없음).
- **`logs_tail`**: 최신 `agentnest.<날짜>.log`들의 마지막 줄들(파일 끝 512 KiB만 읽음). 각 줄은 공용 레댁터 + `Authorization`/`Bearer` 헤더 마스킹 후 600자로 자른다. `logs_open_dir`은 opener 플러그인의 `reveal_item_in_dir`.
- **`codex_probe`**: 문서화된 소켓 경로(`$CODEX_HOME` 또는 `~/.codex` 아래 `app-server-control/app-server-control.sock`)의 **존재 여부만** 확인한다. `initialize` 핸드셰이크(`user_agent`, `threads`)는 `// UNVERIFIED (Phase 0 C1)`이라 하지 않는다(`null`/`0`).
- **트레이 클릭**: "기기 추가…"는 창만 연다(프런트에 화면 이동 이벤트 계약이 없음). 요청별 "허용/거부"는 `ShellApi::tray_decide`가 **현재 카드**를 다시 읽어 허용은 `low`, 거부는 `low`/`medium`이면서 추가 확인이 없을 때만 `confirm_ack=false`로 같은 로컬 결정을 보낸다(그 밖에는 창을 연다). `high`/`critical`은 메뉴에 허용/거부 항목 자체가 없다.

---

## 4. 트레이

- 아이콘 4종(포커스 상태 `protocol.md` §5.5 규칙과 동일): 회색(idle/세션 없음), 파랑(working 계열), 노랑 깜빡임(awaiting_approval/awaiting_input), 빨강(error/데몬 오류). 툴팁 "AgentNest — 승인 대기 1".
- 메뉴: `열기` · `기기 추가…` · `승인 대기 N건 ▸ (요청별: 로컬로 처리 / 승인 창 열기 …)` · `원격 승인 일시정지`(체크) · `휴대폰 연결 끊기`(체크, `link.enabled` — 리스너 중지, `security.md` §3.3) · 상태 줄(비활성: "Claude Code ● 연결됨 / Codex ○ hooks / 폰 1대 온라인") · `자동 시작`(체크) · `로그 폴더` · `종료`.
- **트레이는 승인 게이트의 단축 경로가 아니다.** 요청별 항목은 항상 `로컬로 처리`와 `승인 창 열기`뿐이다. **인라인 `허용`은 `low` 요청에 한해서만** 둔다(트레이 메뉴에는 제목과 위험 등급만 보이고 명령은 보이지 않으므로, 명령 표시 + 생체가 필요한 폰보다 낮은 마찰이 되지 않도록 `medium`은 승인 창에서만 허용한다). 인라인 `거부`는 안전하므로 `low`/`medium`에 둔다. **`high`/`critical` 요청은 트레이에 `허용`을 두지 않는다** — 승인 창을 열어 §6의 길게 누르기(+`critical`은 명령 전체 재표시와 확인 체크)를 거쳐야 하며, 서버도 `confirm_ack` 없이는 거부한다(`security.md` §6.2.1). 한 번의 오클릭이 폰보다 낮은 마찰로 위험 명령을 허용하는 경로는 없다. 트레이 메뉴 항목 라벨에는 `title`과 위험 등급만 쓰고 명령 전문은 쓰지 않는다. 인라인 항목의 조건은 허용: `risk.level == low`, 거부: `risk.level ∈ {low, medium}` **그리고** `risk.extra_confirmation == none` **그리고** 카드의 `allowed_decisions`에 그 결정이 있을 때다(알 수 없는 값은 막힘; `deny_and_stop`은 인라인 없음). 요청은 최대 5건을 개별 나열하고 나머지는 "외 N건 — 승인 창 열기"로 묶는다.
- Windows 토스트(`notification`): 승인 요청이 `handed_off_local`/`no_device`로 떨어졌을 때("PC에서 처리해야 하는 요청"), 승인 요청 도착(본문 `title`만), 페어링 완료, 기기 폐기, 인증서 갱신(코어에 해당 이벤트가 없어 **미구현**), 폰 연결/끊김. 토스트는 설정 `app.notifications`를 따른다.

---

## 5. 설정 파일

`tauri.conf.json`(키 이름은 tauri-utils 2.10.2 `config.rs` [검증]):

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "AgentNest",
  "version": "0.1.0",
  "identifier": "dev.agentnest.desktop",
  "build": { "beforeDevCommand": "pnpm dev", "devUrl": "http://localhost:1420", "beforeBuildCommand": "pnpm build", "frontendDist": "../dist" },
  "app": {
    "windows": [{ "label": "main", "title": "AgentNest", "width": 1000, "height": 700, "visible": false }],
    "security": { "csp": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self' ipc: http://ipc.localhost" }
  },
  "bundle": {
    "active": true,
    "targets": ["nsis", "msi"],
    "icon": ["icons/32x32.png", "icons/128x128.png", "icons/icon.ico"],
    "windows": { "webviewInstallMode": { "type": "downloadBootstrapper" }, "nsis": { "installMode": "currentUser" } }
  }
}
```

- **`agentnest-hook` 사이드카**: Claude Code 는 `SessionStart` 를 `type:"http"` 훅으로 보내지 않으므로(실측, `integrations/claude-code.md`) 설치본에 `agentnest-hook.exe` 가 반드시 있어야 한다. `tauri.conf.json` 의 `bundle.externalBin: ["binaries/agentnest-hook"]` 로 앱 실행 파일 옆에 설치되고, `startup.rs::hook_cli_path` 가 그 경로를 훅 설정에 쓴다. 빌드 전에 `desktop/tools/prepare-hook-sidecar.sh` 가 `binaries/agentnest-hook-<triple>.exe` 를 만든다(`tauri-build` 가 모든 빌드에서 파일 존재를 검사하므로 타입 검사 전용 잡은 `--placeholder` 빈 파일을 쓴다).
- `nsis.installMode: currentUser`(비관리자)라 설치 단계에서 **방화벽 규칙을 만들 수 없다.** 규칙은 앱의 '연결 진단'/첫 실행 체크리스트가 UAC 상승으로 만들고(`security.md` §3.1), 언인스톨러(NSIS 훅)는 UAC로 규칙 제거를 시도한다. 규칙의 `program=` 경로는 설치된 메인 exe의 실제 이름·경로로 채우며 이름은 첫 Windows 빌드(Phase 0 P1/P15)에서 확정한다.
- CSP의 IPC 허용 구문(`ipc: http://ipc.localhost`)은 첫 Windows 빌드에서 검증 [추정].
- `capabilities/default.json`(최소 권한; 식별자는 `tauri-build`가 플러그인 ACL 매니페스트와 대조해 **빌드 때 검증**한다): `core:default`(이벤트 `listen`/`unlisten` 포함), `autostart:allow-enable`/`allow-disable`/`allow-is-enabled`(프런트가 직접 쓰는 유일한 플러그인). 앱 자신의 커맨드는 권한이 필요 없다. **알림·opener·창 제어·트레이는 Rust에서만 쓰므로 JS 권한을 주지 않는다**(`notification:*`, `opener:*`, `core:window:*`, `store:*`, `log:*` 없음). 프런트가 이후 해당 플러그인을 JS에서 쓰게 되면 그때 필요한 식별자만 추가한다. `core:default`가 실제로 listen을 허용하는지는 첫 Windows 실행에서 확인 [추정].
- 트레이를 Rust에서 만들므로 `core:tray`/`core:menu` 권한 불필요.

---

## 6. Phase 1 UI 범위 (vanilla TS)

| 페이지 | 내용 |
| --- | --- |
| 상태 | 데몬 실행·포트·호스트, 연동 상태(Claude Code 훅 설치 여부·마지막 이벤트, Codex 모드·소켓 상태), 온라인 폰, 활성 세션 카드(상태·프로젝트·headline), `link.enabled` 상태 배지 |
| **연결 진단** | `diagnostics_run` 결과를 체크리스트로: 리스너 바인드(주소:포트) · **네트워크 프로필**(Public이면 '개인'으로 바꾸라는 안내) · **방화벽 규칙**(없음 → [규칙 만들기](UAC), 차단 규칙 → 삭제 안내, 있음 → 범위 표시) · 마지막 폰 접속 시도 시각(없으면 "휴대폰이 PC에 닿지 못했어요" + 같은 Wi-Fi·방화벽 확인 문구) · 셀프 접속 테스트 · 현재 `hosts` 목록(IP 변경 시 폰이 'IP 직접 입력'으로 복구할 값) · [방화벽 규칙 제거] · **[휴대폰 연결 끊기]**. 폰이 연결하지 못할 때 사용자가 가장 먼저 보는 화면이다. 비밀 값은 표시하지 않는다 |
| 페어링 | QR(SVG) + 남은 시간 + 안내("같은 Wi-Fi에서 AgentNest 앱 → 설정 → PC 연결 → QR 스캔"); **SAS 확인 모달**("휴대폰에 표시된 숫자 482 915 와 같습니까?" + 기기 이름/모델, [승인](2초 후 활성) [거절]) |
| 기기 | 목록(이름·모델·마지막 접속·온라인), 폐기(이름 입력 확인) |
| 세션 | 세션 카드 목록, 종료 세션 접기 |
| 승인 | 보류 카드: 전달 상태("전송됨/휴대폰이 받음/열어봄"), 남은 시간, **로컬로 처리**, 허용/거부(로컬). 게이트: `low`/`medium`은 바로 가능, **`high`는 1.5초 길게 누르기, `critical`은 길게 누르기 + 명령 전체 재표시 + "내용을 확인했어요" 체크**가 끝나야 [허용]이 활성화되고 그때만 `confirm_ack=true`를 보낸다(트레이와 같은 서버 검증). `purpose`는 "에이전트가 한 말 (검증 안 됨)" 라벨로 명령·위험 등급 아래에 작게 표시한다. Codex hooks 출처 카드는 "거부만 가능"(`deny_and_stop` 없음). 최근 50건 기록(결과·주체·기기) |

**승인 카드 시각 규칙**(브라우저 스크린샷 검토로 확정, `desktop/apps/desktop/src/styles.css`): ① 위험 등급은 색만이 아니라 글자("위험 낮음/보통/높음/매우 높음")와 도형(● ◆ ▲ ■)으로 구분한다. ② 안전한 동작(거부·로컬로 처리)이 왼쪽 묶음, [허용]은 오른쪽의 별도 묶음(구분선·24px 간격, 좁은 창에서는 아래 줄)이며 Tab 순서도 허용이 마지막이다. 거부가 채워진 버튼, 허용은 윤곽선 버튼이다. 카드가 열릴 때 어떤 버튼에도 기본 포커스를 주지 않고, SAS 모달은 [거절]에 포커스를 둔다. ③ 허용이 비활성인 이유("내용을 확인했어요" 미체크)는 버튼 아래에 글자로 보여 준다. ④ 300자를 넘는 명령은 "전체 명령 보기"로, 5개를 넘는 대상 파일은 "외 N개 더 보기"로 전부 볼 수 있다(모두 텍스트 노드). ⑤ 색 토큰은 `:root` 한 곳에만 두고 텍스트/배경 쌍은 WCAG AA(4.5:1), 입력 컨트롤 테두리는 3:1 이상을 지킨다.
| 연동 | Claude Code 설치/제거/점검 + trust 안내 + **유효 TTL 경고**(설정 TTL > 훅 `timeout−30`이면 "훅 재설치" 1클릭); Codex 모드(hooks/off, flag 빌드면 daemon_observer) + 소켓 진단 + hooks.json 수동 설치 안내(C6 전) + **Codex hooks 온보딩 체크리스트**(§6.1) + Codex 리뷰 상태(hooks 모드: "리뷰 결과 수집 불가") |
| 설정 | 승인 TTL(60~180), **`approval.deny_requires_auth`(폰 거부에도 인증 요구 — 소유자는 PC, `welcome.policy`로 전달)**, `link.enabled`, 자동 시작, 알림 토글, 로그 레벨, 로그 폴더, '수용된 위험'(R1) 확인 상태. 금지 필드 없음 |
| 로그 | 최근 200줄(레댁션본), 폴더 열기 |

### 6.1 첫 실행 체크리스트 (온보딩 화면, 완료 상태는 `settings`에 저장)

새 PC에서 "QR로 연결"이 막히지 않도록, 상태 페이지 진입 전에 아래를 순서대로 보여 주고 각 항목의 통과/미통과를 실측으로 표시한다. 항목은 나중에 상태 페이지에서도 다시 열 수 있다.

| # | 항목 | 내용 |
| --- | --- | --- |
| 1 | **수용된 위험 확인(R1)** | "PC의 TLS 키·훅 토큰이 DPAPI가 아닌 사용자 전용 파일에 저장돼요(Phase 3에서 개선)" 설명 + [이해했어요] → `risk_accept("R1")`. 이 확인 전에는 페어링 시작 불가(`security.md` §1.3) |
| 2 | **네트워크·방화벽** | 연결 진단(`diagnostics_run`)을 실행해 프로필이 Private인지, 방화벽 규칙이 있는지 확인. 없으면 [규칙 만들기](UAC 설명 포함). Public이면 변경 안내 |
| 3 | **Claude Code 훅 설치** | 설치(`hooks_install`) → "이 프로젝트에서 이벤트가 오지 않으면 Claude Code의 폴더 신뢰(trust)를 수락하세요" → 첫 이벤트 수신 확인(마지막 수신 시각) |
| 4 | **Codex hooks 온보딩** (Codex 사용 시. 설치기가 C6 전까지 비활성이므로 **수동**) | (a) 안내된 `hooks.json` 초안을 [복사] 버튼으로 복사해 `%USERPROFILE%\.codex\hooks.json`에 저장(최상위 구조는 C6 확정 전 초안임을 표시), (b) Codex TUI에서 `/hooks`를 열어 AgentNest 항목을 **trust**(미신뢰 훅은 실행되지 않음), (c) `agentnest-hook doctor`로 데몬 도달성·토큰 점검, (d) Codex에서 명령 하나를 실행해 **첫 이벤트 수신 확인**, (e) 상태 표시: `Codex 승인: 관찰만`(C6 전) / `리뷰 결과: 수집 불가 (hooks 모드)`. 미완료 항목은 상태 페이지에 "Codex hooks 설정 필요" 배지로 남는다 |
| 5 | **기기 추가** | 1·2가 통과한 뒤 `pairing_start` |

---

## 7. 빌드·검증

- Linux 빌드박스/ubuntu CI: 셸 **로직**은 `cargo test -p agentnest-shell-api`(default-members)로 전부 테스트한다. 글루는 `cargo check`/`cargo clippy -D warnings -p agentnest-desktop --target x86_64-pc-windows-msvc`로 타입 검사한다. `ring`·번들 SQLite의 C 빌드 스크립트 때문에 **`tools/cc-msvc-check.sh` 심 + `apt install llvm clang mingw-w64-x86-64-dev`가 필요**하다(`testing-and-ci.md` 2.1; `llvm-rc`, `icons/icon.ico`, `dist/index.html` 더미도 필요) [검증: 실측 통과]. 이 검사는 링크·번들·실제 동작을 증명하지 않는다.
- windows-latest: `pnpm install --frozen-lockfile && pnpm typecheck && pnpm test` → `tauri-apps/tauri-action@v1`(`projectPath: desktop/apps/desktop`, `uploadWorkflowArtifacts: true`, `args: --target x86_64-pc-windows-msvc`) → NSIS(`-setup.exe`)/MSI. NSIS는 번들러가 자동 다운로드(SHA 검증), WiX 3.14.1은 이미지에 존재. 미서명(SmartScreen 경고 수용).
- VS2026 이미지에서 `tauri build` 1회 실증은 Phase 0 P1.
- 프런트 테스트(vitest): 상태 스토어 리듀서, QR 카운트다운, 승인 카드 렌더, `protocol/examples` 파싱.
