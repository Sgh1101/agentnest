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

```rust
fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();          // [추정: 함수 경로 관례]
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("agentnest-core").build().expect("tokio runtime");
    tauri::async_runtime::set(rt.handle().clone());                             // Builder 이전 1회 [검증]
    let daemon = agentnest_core::Daemon::start(config).expect("daemon");        // DaemonHandle{events: broadcast, cmds: mpsc}
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| { show_main(app) }))  // 첫 번째
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec!["--minimized"])))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .manage(daemon)                                                          // State<'_, DaemonHandle>
        .invoke_handler(tauri::generate_handler![/* §3 */])
        .setup(|app| { tray::build(app)?; bridge::pump(app.handle().clone()); Ok(()) })
        .on_window_event(|w, e| if let tauri::WindowEvent::CloseRequested { api, .. } = e { let _ = w.hide(); api.prevent_close(); })
        .run(tauri::generate_context!())
        .expect("tauri run");
    // rt 는 여기까지 살아 있어야 한다(drop 금지)
}
```

- `--minimized`로 시작하면 창을 숨긴 채 트레이만. 창 닫기 = 숨기기(데몬 유지).
- 종료: 트레이 "종료" → `RunEvent::ExitRequested` → `Daemon::shutdown()`(WSS에 `bye{shutdown}` + 1012, 보류 승인은 빈 2xx/무응답으로 종결(`handed_off_local`), HTTP graceful 2초, SQLite 체크포인트) → `app.exit(0)`.
- 데몬 패닉 시 Tauri 프로세스는 살아 있고 트레이가 빨간색 + "데몬 오류 — 재시작" 메뉴.

### 2.1 모듈

```text
desktop/apps/desktop/
├── src-tauri/
│   ├── Cargo.toml                 # tauri 2.12.4(tray-icon) + 플러그인 + agentnest-core/protocol path 의존
│   ├── build.rs                   # tauri_build::build()
│   ├── tauri.conf.json            # §5
│   ├── capabilities/default.json  # §5
│   ├── icons/icon.ico (+png)      # 필수(msvc check 통과 조건) — 커밋
│   └── src/
│       ├── main.rs                # 위 코드
│       ├── commands.rs            # #[tauri::command] (§3)
│       ├── tray.rs                # TrayIconBuilder, 아이콘 4종 교체, 메뉴
│       ├── bridge.rs              # DaemonHandle.events → Emitter::emit (100 ms 배치)
│       ├── notify.rs              # Windows 토스트
│       └── integrations.rs        # Claude Code settings.json 병합/제거, Codex hooks 안내
├── src/                           # TypeScript strict, any 금지, 프레임워크 없음(작은 상태 스토어 + 템플릿)
│   ├── main.ts, api.ts(invoke 래퍼), store.ts, types.ts(protocol/schema에서 생성 또는 수동 + vitest 예제 파싱 검증)
│   └── views/{status,pairing,devices,sessions,approvals,integrations,settings,logs}.ts
├── dist/index.html                # 더미(커밋; Linux msvc check 전제)
├── index.html, vite.config.ts, tsconfig.json, package.json
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

---

## 4. 트레이

- 아이콘 4종(포커스 상태 `protocol.md` §5.5 규칙과 동일): 회색(idle/세션 없음), 파랑(working 계열), 노랑 깜빡임(awaiting_approval/awaiting_input), 빨강(error/데몬 오류). 툴팁 "AgentNest — 승인 대기 1".
- 메뉴: `열기` · `기기 추가…` · `승인 대기 N건 ▸ (요청별: 로컬로 처리 / 승인 창 열기 …)` · `원격 승인 일시정지`(체크) · `휴대폰 연결 끊기`(체크, `link.enabled` — 리스너 중지, `security.md` §3.3) · 상태 줄(비활성: "Claude Code ● 연결됨 / Codex ○ hooks / 폰 1대 온라인") · `자동 시작`(체크) · `로그 폴더` · `종료`.
- **트레이는 승인 게이트의 단축 경로가 아니다.** 요청별 항목은 항상 `로컬로 처리`와 `승인 창 열기`뿐이다. **`low`/`medium` 요청에 한해** 추가로 인라인 `허용`/`거부`를 둔다(§6의 게이트가 `none`/생체 불필요 수준과 같은 마찰). **`high`/`critical` 요청은 트레이에 `허용`을 두지 않는다** — 승인 창을 열어 §6의 길게 누르기(+`critical`은 명령 전체 재표시와 확인 체크)를 거쳐야 하며, 서버도 `confirm_ack` 없이는 거부한다(`security.md` §6.2.1). 한 번의 오클릭이 폰보다 낮은 마찰로 위험 명령을 허용하는 경로는 없다. 트레이 메뉴 항목 라벨에는 `title`과 위험 등급만 쓰고 명령 전문은 쓰지 않는다.
- Windows 토스트(`notification`): 승인 요청이 `handed_off_local`/`no_device`로 떨어졌을 때("PC에서 처리해야 하는 요청"), 승인 요청 도착(본문 `title`만), 페어링 완료, 기기 폐기, 인증서 갱신, 폰 연결/끊김.

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

- `nsis.installMode: currentUser`(비관리자)라 설치 단계에서 **방화벽 규칙을 만들 수 없다.** 규칙은 앱의 '연결 진단'/첫 실행 체크리스트가 UAC 상승으로 만들고(`security.md` §3.1), 언인스톨러(NSIS 훅)는 UAC로 규칙 제거를 시도한다. 규칙의 `program=` 경로는 설치된 메인 exe의 실제 이름·경로로 채우며 이름은 첫 Windows 빌드(Phase 0 P1/P15)에서 확정한다.
- CSP의 IPC 허용 구문(`ipc: http://ipc.localhost`)은 첫 Windows 빌드에서 검증 [추정].
- `capabilities/default.json`: `core:default`, `core:window:allow-show/hide/minimize/unminimize/set-focus`, `notification:default`, `autostart:allow-enable/disable/is-enabled`, `store:default`, `log:default`, `opener:allow-open-url`(`https://github.com/*`, `https://code.claude.com/*`), `opener:allow-reveal-item-in-dir`. `core:default` 구성은 첫 빌드의 `gen/schemas`로 검증 [추정].
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

- Linux 빌드박스/ubuntu CI: `cargo check -p agentnest-desktop --target x86_64-pc-windows-msvc`(llvm-rc 필요, 링크 없음) — `icons/icon.ico`와 `dist/index.html` 더미가 저장소에 있어야 통과 [검증: 실측].
- windows-latest: `pnpm install --frozen-lockfile && pnpm typecheck && pnpm test` → `tauri-apps/tauri-action@v1`(`projectPath: desktop/apps/desktop`, `uploadWorkflowArtifacts: true`, `args: --target x86_64-pc-windows-msvc`) → NSIS(`-setup.exe`)/MSI. NSIS는 번들러가 자동 다운로드(SHA 검증), WiX 3.14.1은 이미지에 존재. 미서명(SmartScreen 경고 수용).
- VS2026 이미지에서 `tauri build` 1회 실증은 Phase 0 P1.
- 프런트 테스트(vitest): 상태 스토어 리듀서, QR 카운트다운, 승인 카드 렌더, `protocol/examples` 파싱.
