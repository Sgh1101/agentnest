# Claude Code 연동 계약

- 상태: 확정(리드 종합본) — 2026-10-15
- 기준 버전: Claude Code **v2.1.300** [검증: 공식 hooks/settings/statusline 문서 원문 + CHANGELOG + transcript 실측]
- 신뢰도: 별도 표기가 없는 항목은 **[검증]**. "검증 필요 (Phase 0)" 항목은 `phase0-checklist.md` A-시리즈에 대응한다(★ = Phase 1 착수 전 필수 — 의미는 체크리스트 범례가 규범, A-시리즈 목록은 두 문서가 항상 같아야 한다).

---

## 1. 채널 개요

| 채널 | 용도 | 상태 |
| --- | --- | --- |
| `type: "http"` 훅 → `POST http://127.0.0.1:47831/v1/hooks/claude-code` | 실시간 이벤트 + 원격 승인(**1차**) | [검증] v2.1.63+. 요청 본문 = command 훅 stdin JSON, 응답 본문 = 출력 JSON. 셸을 쓰지 않으므로 Git Bash/PowerShell 함정 회피 |
| `agentnest-hook claude-code`(command 훅, exec form) | HTTP 훅이 금지된 환경(`allowedHttpHookUrls` 정책)·디버깅 폴백. 같은 엔드포인트로 POST | [검증] 구조 |
| statusLine 커맨드 `agentnest-hook statusline` → `POST /v1/statusline/claude-code` | AI 생성 세션 제목(`session_name`)·비용·컨텍스트 사용률·PR 번호 — **훅에는 없는 유일한 공식 소스** | [검증] statusline 문서. 선택 설치(기존 `statusLine`이 없을 때만) |
| transcript JSONL 백필 | 세션 복구·AI 제목 추출. 형식 비공개 | [실측 v2.1.300만] Phase 1 **off**, Phase 2 검토 |

검증된 핵심 사실(설계 근거):

- `PermissionRequest` 훅 존재(v2.0.45+). 입력: `tool_name`, `tool_input`, `permission_suggestions[]`, (MCP면 `mcp_server`). **`tool_use_id` 없음**. 출력: `hookSpecificOutput.decision{behavior: allow|deny, updatedInput?, updatedPermissions?, message?, interrupt?}`. exit 2는 무시. **결정이 없으면 로컬 권한 다이얼로그**(프롬프트를 띄울 수 없는 세션 — 백그라운드 서브에이전트·`-p` — 에서는 거부).
- HTTP 훅 응답: 2xx+빈 본문 = 성공(출력 없음); 2xx+JSON = 출력 스키마로 파싱; non-2xx/연결 실패 = **비차단 오류, 동작 계속**; 타임아웃 = 출력 폐기(결정 없음). `onFailure: "block"`(v2.1.295+)은 `PermissionRequest`에서 **거부**가 된다.
- `timeout` 단위는 초. 기본 600(command/http). **상한은 문서에 없음** → Phase 0 A3.
- `PreToolUse.permissionDecision: "ask"`는 auto 모드에서도 프롬프트를 강제한다. 훅의 `allow`는 deny/ask 규칙을 뒤집지 못한다("조이기만 가능").
- `headers` 값은 **리터럴**이며 `$VAR`는 `allowedEnvVars`에 나열된 변수만 치환되고 나머지는 빈 문자열이 된다 → 리터럴 토큰 채택(환경변수 방식은 변수 없는 프로세스에서 전 훅 401).
- 대화형 세션은 폴더 **workspace trust 수락 전까지 훅이 실행되지 않는다**.
- Windows: `tool_input.file_path`는 절대경로·백슬래시; Git Bash가 없으면 `Bash` 대신 `PowerShell` 도구 → matcher는 `Bash|PowerShell`(AgentNest는 matcher를 생략하므로 무관하나 정규화기는 두 이름을 모두 처리).
- `Notification.permission_prompt`는 프롬프트가 약 6초 대기한 뒤 발생하며, 샌드박스 명령의 네트워크 요청 프롬프트에는 `PermissionRequest`가 **발생하지 않는다** → `permission_prompt`를 `awaiting_approval` 보완 신호로 사용.
- `SessionEnd` 기본 예산 1.5초 → 즉시 204.

---

## 2. 설치되는 `settings.json` (사용자 레벨 `%USERPROFILE%\.claude\settings.json`, 기존 `hooks`와 병합)

```json
{
  "hooks": {
    "SessionStart":       [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "UserPromptSubmit":   [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "PreToolUse":         [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "PermissionRequest":  [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 150,
                                         "statusMessage": "AgentNest: 휴대폰 승인 대기 중 (트레이에서 '로컬로 처리' 가능)",
                                         "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "PermissionDenied":   [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "PostToolUse":        [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "PostToolUseFailure": [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "Notification":       [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "SubagentStart":      [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "SubagentStop":       [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "Stop":               [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "StopFailure":        [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "TaskCreated":        [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "TaskCompleted":      [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "PostCompact":        [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }],
    "SessionEnd":         [{ "hooks": [{ "type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 1, "headers": { "X-AgentNest-Token": "an_hk_3f9c…" } }] }]
  },
  "statusLine": { "type": "command", "command": "agentnest-hook statusline" }
}
```

설치 규칙(`agentnest-core::adapters::claude_code::install`, 골든 테스트):

| 규칙 | 내용 |
| --- | --- |
| 병합 | 기존 파일을 파싱해 각 `hooks.<Event>` 배열에서 `url`이 `http://127.0.0.1:*/v1/hooks/claude-code`인 항목만 제거 후 새 항목 **append**. 다른 사용자 훅은 절대 건드리지 않음. 제거도 동일 필터 |
| 원자성·백업 | 임시 파일 작성 → `settings.json.agentnest-backup-<ts>` 1회 백업 → 원자적 교체. JSONC/주석이 있으면 설치 중단 + 안내 |
| 토큰 | `an_hk_` + 32바이트 base64url. `%LOCALAPPDATA%\AgentNest\daemon.json`(`{"hook_port","wss_port","hook_token"}`, 사용자 ACL)과 settings.json에 기록, DB에는 해시 |
| `PermissionRequest.timeout` | `approval.ttl_s + 30`(기본 150). 설치 시점에 고정되는 값이다 |
| **유효 TTL 클램프** | TTL은 런타임 설정(60~180)이지만 훅 `timeout`은 설치 때 고정되므로, TTL만 올리고 재설치하지 않으면 Claude Code가 데몬이 응답하기 전에 훅을 취소한다. 그래서 데몬은 시작 시·`approval.ttl_s` 변경 시·60초 주기로 `settings.json`의 AgentNest `PermissionRequest` 항목의 `timeout`을 **읽기 전용으로 파싱**해 `effective_ttl = min(approval.ttl_s, installed_timeout − 30)`을 쓴다(항목이 없거나 읽을 수 없으면 120). `ttl_seconds`/`expires_at`/`welcome.limits.approval_ttl_s`는 유효 TTL이다. 설정 화면은 설정 TTL > 유효 TTL이면 "훅 `timeout`이 {n}초라 TTL이 {m}초로 제한돼요 · 훅 다시 설치"를 경고하고, TTL 저장 시 재설치(1클릭)를 제안한다(`settings.json` 수정은 사용자 동작으로만; 무음 자동 재설치 금지). 재설치되면 다음 점검에서 클램프가 풀린다 |
| `onFailure` | 기본 미지정(= `continue`). `approval.daemon_down_deny=true`일 때만 `"onFailure": "block"` 기록(옵트인) |
| 미등록 이벤트 | `MessageDisplay`(렌더링 보류 부작용), `PostToolBatch`, `PreCompact`, `UserPromptExpansion` |
| `statusLine` | 기존 값이 없을 때만 설치(단일 슬롯). 있으면 "AI 제목/비용 수집 비활성" 안내 |
| `allowedHttpHookUrls` | 사용자가 설정해 둔 경우 `http://127.0.0.1:47831/*` 추가 필요를 안내(자동 수정 금지) |
| trust 안내 | 설치 완료 화면·세션 카드에 "이 프로젝트에서 이벤트가 오지 않으면 Claude Code의 폴더 신뢰(trust) 확인을 수락하세요" |
| 포트 충돌 | 47831 점유 시 47833~47840 순으로 시도하고 **훅 URL을 갱신(재설치)**, 데스크톱 UI에 표시 |
| 데몬 미실행 소음 | 이벤트마다 `hook error` 알림이 뜨는지 Phase 0 A4에서 확인. 심하면 "데몬 종료 시 AgentNest 훅 항목 제거" 옵션(기본 off). `disableAllHooks`는 전체를 끄므로 사용 금지 |

---

## 3. 훅 바이너리 계약 (`agentnest-hook`, Rust CLI: clap 4.6.7 + ureq 3.4.2 `default-features = false`)

```text
agentnest-hook claude-code     # stdin 훅 JSON → POST /v1/hooks/claude-code → stdout 응답 본문 → exit 0
agentnest-hook codex           # stdin 훅 JSON → POST /v1/hooks/codex       → stdout 응답 본문 → exit 0  (Codex 필수 경로)
agentnest-hook statusline      # stdin statusline JSON → POST /v1/statusline/claude-code → stdout 상태 1줄
agentnest-hook doctor          # 데몬 도달성·토큰·포트 점검(사람용)
HTTP 클라이언트: 훅은 `http://127.0.0.1`에만 말하므로 TLS가 필요 없다. ureq 3.4.2의 기본 feature(`rustls`+`gzip`)는 rustls·ring·webpki-roots를 끌어와 훅 바이너리를 부풀리므로 `default-features = false, features = ["json"]`로 쓴다(기본 feature 구성은 crates.io API로 2026-10-15 확인). 평문 HTTP 클라이언트로 충분하며 더 줄이려면 `TcpStream` HTTP/1.1 직접 구현도 허용한다.
옵션: --daemon-config <path> (기본 %LOCALAPPDATA%\AgentNest\daemon.json), --timeout-ms <n>, --quiet
환경: AGENTNEST_HOOK_DEBUG=1 → stderr 진단 (stdout 은 절대 오염하지 않음)
```

1. stdout에는 **데몬 응답 본문만**(JSON 객체 1개) 또는 **아무것도** 쓰지 않는다(stdout 전체가 하나의 JSON 객체여야 파싱됨).
2. 종료 코드는 **항상 0**. 데몬 미실행·연결 실패·타임아웃·401 → stdout 비움 + exit 0(= 결정 없음). exit 2는 어떤 경우에도 쓰지 않는다(`PermissionRequest`에서는 무시, `PreToolUse` 등에서는 차단이 되어 의도치 않은 fail-closed).
3. HTTP 타임아웃: `PermissionRequest` = `ttl + 28`s(데몬 TTL보다 길게), `SessionEnd` 0.8s, 그 외 4s. CLI는 결정을 만들지 않는다(패스스루만).
4. 32 KiB를 넘는 문자열 필드(`tool_input.content`, `tool_response.stdout` 등)는 **절단**하고 `_agentnest_truncated: ["tool_input.content"]`를 추가(데몬도 동일 상한).
5. Windows 등록은 exec form: `{"type":"command","command":"C:\\Program Files\\AgentNest\\agentnest-hook.exe","args":["claude-code"],"timeout":150}` — 셸 미사용(프로필 출력 오염 방지; `.exe`만 spawn 가능).
6. Codex 입력(`turn_id`, `model`, `permission_mode` 포함)은 변환하지 않는다. 데몬이 경로 + `hook_event_name`으로 구분한다. **Codex `PreToolUse`에 대해 CLI는 절대 Claude 스타일 `ask` 응답을 전달하지 않는다**(데몬이 `/v1/hooks/codex`에서는 결정을 생성하지 않으므로 자연히 보장되지만, CLI도 `/codex` 경로 응답에서 `permissionDecision` 키를 발견하면 버리고 빈 stdout으로 끝낸다 — 이중 방어).

---

## 4. HTTP 수집 API (`agentnest-core::http`, axum 0.8.9, `127.0.0.1` 전용)

| 메서드/경로 | 인증 | 요청 | 응답 |
| --- | --- | --- | --- |
| `POST /v1/hooks/claude-code` | `X-AgentNest-Token` | 훅 입력 JSON 그대로 | 관찰 이벤트: `204`. `PermissionRequest`: 결정 있으면 `200 application/json`, 없으면 `204`. `PreToolUse`: critical + `force_ask_on_critical`이면 `200 {ask}`, 아니면 `204` |
| `POST /v1/hooks/codex` | 동일 | Codex 훅 입력 | `codex.md` §5 |
| `POST /v1/statusline/claude-code` | 동일 | statusLine stdin JSON | `204` |
| `GET /v1/health` | 없음 | — | `{"ok":true,"version":"0.1.0"}` (비밀 없음) |
| `GET /v1/daemon` | 토큰 | — | `{"hook_port":47831,"wss_port":47832,"uptime_s":…}` |

가드(`security.md` I8): `127.0.0.1` + `[::1]` 바인드 고정, `Origin`/`Sec-Fetch-Site` 존재 시 403, 토큰 `subtle` 상수시간 비교 실패 401(본문 폐기, 토큰 값 미기록), 본문 1 MiB 초과 413, 관찰 이벤트 200건/초 초과 429(`PermissionRequest` 제외). 관찰 이벤트 처리 목표 **< 10 ms**(큐에 넣고 즉시 204). 요청 본문은 절대 전체 로깅하지 않는다.

중복 제거(**관찰 이벤트용**): `dedupe_key = sha256(session_id | hook_event_name | tool_use_id ?? sha256(body))`, 2초 창 내 동일 키 무시. `PermissionRequest`는 이 규칙으로 버리지 않고 §6 [6]의 **승인 카드 병합 규칙**(`agent_id` 포함, 2초 창)을 따른다(같은 훅이 사용자+프로젝트 settings에 중복 정의될 수 있음; 문서상 "동일 핸들러는 한 번만 실행"이지만 URL이 다르게 보일 수 있어 방어 — Phase 0 A10).

### 4.1 이벤트별 응답

| 이벤트 | 응답 |
| --- | --- |
| `PermissionRequest` | 폰/데스크톱 결정 → `200 {"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}` 또는 `{"behavior":"deny","message":"AgentNest: 사용자가 휴대폰에서 거부했습니다. 사유(사용자 입력): …","interrupt":false|true}`(`message`의 사유는 `protocol.md` §4.10의 정제 규칙을 통과한 값만: 제어·양방향 문자 제거, 200자, JSON 직렬화기로만 인코딩). 그 외 전부 **204 빈 본문** |
| `PreToolUse` | 기본 204. `risk == critical && force_ask_on_critical` → `200 {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"AgentNest: 위험 명령은 확인이 필요합니다"}}` (**allow는 절대 반환하지 않음**) |
| `SessionEnd` | 즉시 204(처리는 비동기) |
| 나머지 | 204 |

`allow` 응답에 `updatedInput`/`updatedPermissions`는 **절대** 포함하지 않는다(`security.md` I11).

---

## 5. 정규화 (`adapters::claude_code::normalize`, 순수 함수, 골든 `protocol/fixtures/claude-code/hooks/*.json`)

| 훅 입력 | `AgentEvent.kind` | 핵심 detail | `state_hint` |
| --- | --- | --- | --- |
| `SessionStart{source, model?, permission_mode?, session_title?}` | `session_started` | `source_reason`, `model`, `permission_mode`, `title` | `idle`(startup/clear) |
| `UserPromptSubmit{prompt}` | `prompt_submitted` | `prompt_preview`(200자, 마스킹), `prompt_len`, `auto_turn_suspect`(프롬프트가 `<`/`[`로 시작하거나 `scheduled`/`background` 접두 — 휴리스틱, 검증 필요 (Phase 0) A11) | `working` |
| `PreToolUse{Bash\|PowerShell}` | `command_started` (+ `test_run` if class=test) | `command`, `description`, `command_class`, `run_in_background` | `testing`/`working` |
| `PreToolUse{Edit\|Write\|MultiEdit\|NotebookEdit}` | `tool_started` + 리듀서 `writing_code` | `file_path`(축약), `op` | `writing_code` |
| `PreToolUse{Read\|Grep\|Glob}` | `file_read` | `file_path`/`pattern` | `reviewing`(연속 2회) |
| `PreToolUse{Agent\|WebFetch\|WebSearch\|mcp__*\|기타}` | `tool_started` | `tool_name`, `tool_input_summary`, `mcp_server` | `working` |
| `PermissionRequest` | `approval_requested` + **ApprovalOpened**(§6) | `request_id`, `risk`, `channel` | `awaiting_approval` |
| `PermissionDenied{reason}` | `permission_denied_auto` | `tool_name`, `reason` | — |
| `PostToolUse{Write\|Edit}` | `file_modified` | `file_path`, `op`(`tool_response.type`), `bashEditDiff.changedFiles` | — |
| `PostToolUse{Bash}` | `command_completed` (+ `test_passed`) | `exit_code?`, `stdout_tail`(1 KiB), `stderr_tail`, `duration_ms` | — |
| `PostToolUse{기타}` | `tool_completed` | `duration_ms`, `result_summary` | — |
| `PostToolUseFailure{error}` | `command_failed`/`tool_failed` (+ `test_failed`) | `error`(첫 줄 `Exit code N`), `is_interrupt` | `error`(transient) |
| `Notification{notification_type}` | `notification`; `idle_prompt` → `idle`; `permission_prompt` → `notification{notification_type:"permission_prompt"}`(`state_hint: awaiting_approval`; **리듀서가** 보류 승인이 없을 때만 `awaiting_approval`로 올린다 — `approval_requested` 이벤트로 만들지 않는다: 닫아 줄 `approval_resolved`가 없다); `agent_needs_input` → `notification{notification_type:"agent_needs_input"}`(`state_hint: awaiting_input`) | `notification_type`, `message` | 타입별 |
| `SubagentStart`/`SubagentStop` | `subagent_started`/`subagent_stopped` | `agent_id`, `agent_type`, `final_message_preview` | — |
| `Stop{last_assistant_message, background_tasks, session_crons}` | `turn_completed` | `final_message_preview`(300자), `background_tasks`(수), `session_crons`(수) | `completed`/`working` |
| `StopFailure{error}` | `turn_failed` | `error_code`(rate_limit/overloaded/…), `error_message` | `error`(sticky) |
| `TaskCreated`/`TaskCompleted` | `task_created`/`task_completed` | `task_id`, `task_subject` | — |
| `PostCompact{compact_summary}` | `context_compacted` | `summary_preview`(300자) | — |
| `SessionEnd{reason}` | `session_ended` | `reason` | ended |
| 알 수 없는 `hook_event_name` | `notification{notification_type:"unknown_hook:<name>"}` | — | — |

공통: `cwd` → 프로젝트 해석(git 루트 탐색, `project_key` 소문자·`/`), `agent_id`/`agent_type` → `actor`, `tool_use_id`/`prompt_id`/`session_id` → `source.native_ids`, `permission_mode` → 세션 `remote_approval`(`bypassPermissions`/`dontAsk`/`auto` → `unavailable`).

statusLine(`POST /v1/statusline/claude-code`): `session_name`(AI 생성 제목), `cost.total_cost_usd`, `context_window.used_percentage`, `pr.{number,url,review_state}`, `model.display_name` → `session_meta_updated`(10초 스로틀).

---

## 6. 원격 승인 시퀀스

```text
Claude Code            agentnest-core (PC)                                    폰                 사용자
   │ POST PermissionRequest {tool_name, tool_input, session_id, cwd, permission_mode}            │
   │──────────────────────▶│                                                   │                 │
   │ (연결 열림, ≤150s)    │ [1] 토큰·크기·Origin 가드, dedupe                   │                 │
   │                       │ [2] tool_input_sha256 = SHA-256(canonical JSON)    │                 │
   │                       │ [3] risk::classify → level/reasons/extra_confirmation               │
   │                       │ [4] summarize::ko → title/purpose/details(마스킹·상한)              │
   │                       │ [5] request_id(ar_UUIDv7), nonce(16B), expires_at = now + 유효 TTL(기본 120s, §2 클램프) │
   │                       │ [6] 병합 판단(단일 writer): 같은 (session_key, agent_id, tool_name, hash)의 pending이 2초 이내면 그 요청에 새 HTTP 핸들을 추가 구독, 아니면 INSERT approvals(pending)
   │                       │ [7] (critical && critical_remote=local_only) → 204, handed_off_local ───▶ (로컬 다이얼로그)
   │                       │ [8] 온라인 인증 기기 0 → 즉시 204, handed_off_local ────────────────▶ (로컬 다이얼로그)
   │                       │ [9] approval_request{seq} ───────────────────────▶│ HIGH 알림 + 카드 │
   │                       │ [10] ack 대기 5s×3; 데스크톱 "휴대폰이 받음"; 트레이 '!'; '로컬로 처리' 버튼 노출
   │                       │                                                   │ 열기·읽기·이해   │
   │                       │                                                   │ high: 길게 누르기 / critical: + 재확인 시트
   │                       │                                                   │ 생체/기기잠금 ──▶│ 인증
   │                       │ ◀── decision{request_id, session_key, nonce, hash, allow, auth, extra} ──│
   │                       │ [11] Validator 9단계 (security.md §6.2) — 상태 변경 전                 │
   │                       │ [12] UPDATE … WHERE status='pending' AND expires_at>now → decisions/audit INSERT
   │◀── 200 {decision:allow}│ [13] responder.respond(ApprovalReply::allow(proof)) → decision_result{APPLIED} ─▶│ "PC에 전달했어요"
   │ "Allowed by PermissionRequest hook"                                                          │
   │ (PreToolUse/PostToolUse 동일 tool_name+hash 관찰, 60s 창)                                     │
   │                       │ [14] approval_resolved{delivery:delivered, observed_result:unknown→executed} ▶│ 카드 종료·알림 취소
```

분기(`security.md` §7 fail-closed 표가 규범):

- **만료**(유효 TTL, 기본 120s): 204 → 로컬 다이얼로그. 훅 `timeout` 150은 TTL보다 30초 길어 **데몬이 항상 먼저** 응답한다(Claude Code가 훅을 취소하는 경로를 만들지 않음). 이 불변식은 §2의 **유효 TTL 클램프**가 TTL 설정 변경 뒤에도 유지한다.
- **중복 병합 vs 중복 실행**: 병합은 같은 훅 호출이 user+project settings 양쪽에서 거의 동시에 도착한 경우에만 허용한다(**같은 `agent_id`, 2초 창**). 병렬 서브에이전트가 같은 명령을 낼 때는 `agent_id`가 다르므로 **카드가 둘**이고 각각의 승인이 각자의 훅 호출 하나에만 적용된다(한 번의 승인으로 두 번 실행되지 않음 — PRD Phase 3 "중복 실행 없음"과 정합). `PermissionRequest` 입력에 `agent_id`가 실제로 실리는지는 A14로 확인하며, **실리지 않으면 병합 창을 0으로**(병합하지 않음) 두어 보수적으로 카드를 나눈다.
- **로컬로 처리**(데스크톱 트레이/창 버튼): 즉시 204, `handed_off_local`(resolved_by=desktop). 로컬 다이얼로그가 훅 대기 중 동시에 표시되는지는 **검증 필요 (Phase 0) A2** — 이 버튼과 "폰 없음 → 즉시 204" 규칙으로 두 경우 모두 동작한다.
- **데스크톱 허용/거부**: 폰 결정과 **같은 브로커 전이**(actor=desktop, 감사). 두 번째 allow 경로를 만들지 않는다.
- **폰 연결 끊김**(보류 중): 10초 유예 후 204 `handed_off_local`.
- **Claude가 먼저 종료**(로컬 결정·Ctrl-C): HTTP 연결 끊김 → 핸들러 future drop → `DropGuard` → `superseded`(resolved_by=agent) [추정: hyper가 연결 종료 시 서비스 future를 취소 — P6].
- **거부**: `{"behavior":"deny","message":"AgentNest: 사용자가 휴대폰에서 거부했습니다. 사유: <reason|없음>","interrupt":false}`; `deny_and_stop` → `interrupt:true`.
- **관찰 결과**: 훅 응답만으로는 실행 여부를 알 수 없다(`tool_use_id` 없음). 60초 창 내 같은 세션의 `PreToolUse`(동일 `tool_name` + `sha256(tool_input)`) → `PostToolUse`/`PostToolUseFailure`를 상관시켜 `observed_result`를 `executed`/`declined`로 갱신하고 `approval_resolved`를 재전송. 매칭률은 Phase 0 A7.
- **`permission_suggestions`**: 개수만 전달. `updatedPermissions`로 되돌려 보내지 않는다.

타임아웃 요약: 훅 `timeout` = 설치 시 TTL+30 (150) / 유효 TTL = min(설정 120(60~180), timeout−30) / 재연결 유예 10s / 생체 인증 유효 60s(폰 로컬, 동일 request_id 1회) / 결과 상관 창 60s / ack 5s×3.

---

## 7. 위험 분류 규칙 (`agentnest-core::risk`, **코드 상수**, 픽스처 `protocol/fixtures/risk_cases.json` 규칙당 양성·음성 ≥2)

입력: `tool_name`, `tool_input`(원본), `cwd`, `permission_mode`. 출력: `level`, `reasons[]`(코드 + 한국어), `extra_confirmation`. 규칙은 순서 있는 목록, **최고 등급이 이김**, 명령은 `&&`/`;`/`|`로 분리한 각 세그먼트에도 적용. 비교 전 정규화(소문자, 연속 공백 축약, `\`→`/`, 따옴표 제거)하되 **해시는 원본**으로.

| 등급 | 원격 승인 | 폰 UX | 규칙(발췌; Bash·PowerShell 공통) | reason |
| --- | --- | --- | --- | --- |
| `critical` | 가능 + `hold_and_reconfirm`(설정으로 `local_only` 강화 가능) | 빨간 카드, 길게 누르기 → 재확인 시트(명령 전체 재표시 + "내용을 확인했어요") → 생체 프롬프트(`BIOMETRIC_STRONG\|DEVICE_CREDENTIAL`; `confirmationRequired`는 수동 생체에만 닿는 힌트라 게이트로 세지 않음) | `rm -rf /`·`~`·`$HOME`·`C:\`·`%USERPROFILE%`, `del /s /q C:\`; `format`, `diskpart`, `mkfs`, `dd if=`; `(curl\|wget\|iwr\|irm) … \| (sh\|bash\|zsh\|powershell\|pwsh\|iex)`, `Invoke-Expression`; `git push --force*` to `main\|master\|release*`; `reg (add\|delete) HKLM`, `netsh`, `schtasks /create`, `sc (create\|delete)`, `bcdedit`, `shutdown`, `Stop-Computer`, `Restart-Computer`; `Write/Edit`의 `file_path`가 `C:\Windows\`, `/etc/`, `/usr/`, `Program Files`; 키/인증서 경로 **쓰기**(`.ssh/`, `.gnupg/`, `id_rsa`, `*.pem`, `*.pfx`, `*.key`); `tool_input` 직렬화 > 64 KiB(검토 불가, `details.truncated=true`); 분류기 패닉/정규식 오류 | `delete_root`, `disk_format`, `remote_code_exec`, `git_force_push_main`, `system_modify`, `system_path_write`, `secret_path_write`, `input_too_large`, `classifier_error` |
| `high` | 가능 + `hold`(1.5초) | 주황 카드 | `rm -rf`/`rm -r`/`rmdir /s`/`Remove-Item -Recurse`(cwd 안), `git push --force*`(기타 브랜치), `git reset --hard`, `git clean -f*d`, `git checkout -- .`, `git branch -D`; `npm publish`, `cargo publish`, `gh release create`, `twine upload`, `docker push`; `sudo`, `runas`, `Start-Process -Verb RunAs`; `chmod -R 777`, `icacls … /grant Everyone`; `docker system prune`, `docker rm -f`, `kubectl delete`, `terraform apply\|destroy`; 비밀 경로 **읽기**(`.env*`, `credentials`, `secrets`, `.npmrc`, `.pypirc`); `Write/Edit`의 `file_path`가 세션 `cwd`(및 addDirectories) 밖; `>` 리다이렉션으로 cwd 밖 쓰기 | `recursive_delete`, `git_force_push`, `git_destructive`, `publish`, `elevation`, `permissions_wide_open`, `infra_destructive`, `secret_path_read`, `write_outside_project` |
| `medium` | 가능(생체만) | 파랑 카드 | `git push`(force 아님), `git commit --amend`, `git rebase`; `npm (i\|install\|ci)`, `pnpm (add\|install)`, `pip install`, `cargo install`, `winget\|choco install`; `curl`/`wget`/`ssh`/`scp`(파이프 없음); `Edit/Write`의 `.github/workflows/*`, `*.gradle.kts`, `Cargo.toml`, `package.json`, `.claude/settings*.json`; `Read/Grep/Glob`의 `~/.ssh`, `~/.aws`, `%APPDATA%`; 알 수 없는 MCP 서버; Codex `reason`/`networkApprovalContext` 네트워크 접근; **그 외 모든 Bash/PowerShell**(기본값) | `git_history`, `installs_deps`, `network_tool`, `build_or_policy_file`, `read_sensitive`, `mcp_unknown`, `network_access`, `shell_generic` |
| `low` | 가능(생체만) | 기본 카드 | `command_class ∈ {test, build}`; `Edit/Write` 프로젝트 내부; `Read/Grep/Glob` 프로젝트 내부; `WebFetch`/`WebSearch`; `Agent`; `TodoWrite`; `AskUserQuestion` | `test_or_build`, `edit_in_project`, `read_in_project`, `network_read`, `subagent` |

- Codex: `commandExecution.command`에 Bash 규칙, `fileChange.changes[].path`에 Edit 규칙; 스레드가 `approvalPolicy=never`/`sandbox=danger-full-access`면 +1 등급(노출 여부 검증 필요 (Phase 0) C8).
- `permission_mode == "plan"`이면 쓰기 계열 +1 등급(계획 모드의 쓰기는 비정상).
- 규칙 테이블은 `risk/rules.rs` 상수. 외부 파일(`rules.toml`, `risk-rules.json`) 로드 코드는 **존재하지 않는다**(`security.md` I10). 새 규칙 추가 시 픽스처 케이스 필수(CLAUDE.md).

---

## 8. Fail-closed 규칙(요약; 규범은 `security.md` §7)

1. `behavior:"allow"`는 검증된 폰/데스크톱 결정이 있을 때만, `apply_decision` 성공 분기에서만.
2. 폰 없음·미응답·만료·검증 실패·내부 오류·재시작·패닉 → **204 빈 본문**(= 로컬 프롬프트 위임; 프롬프트 없는 세션은 거부).
3. `onFailure`는 `continue` 유지. `block`은 옵트인 설정으로만.
4. `permission_mode ∈ {bypassPermissions, dontAsk, auto}` 세션은 `remote_approval: unavailable` 배지, 대체 승인 시도 없음.
5. 결정은 `request_id + session_key + nonce + tool_input_sha256`에 바인딩, `expires_at` 이후 적용 불가, 조건부 UPDATE로 한 번만 적용.

---

## 9. Phase 0 검증 항목 (A-시리즈; 통과 기준·캡처 위치는 `phase0-checklist.md`)

| # | 검증 | 설계 의존 |
| --- | --- | --- |
| ★A1 | 사용자 settings.json HTTP 훅으로 16개 이벤트 수신, 원본 50건 → 픽스처 | §2, §5 |
| ★A2 | `PermissionRequest` 보류 중 **터미널 로컬 다이얼로그 표시 여부**와 로컬 결정 시 HTTP 연결 종료(`superseded`) | `local_prompt`, 로컬 처리 버튼, DropGuard |
| ★A3 | `timeout: 150/600/3600` 허용 여부·상한 | TTL 범위 |
| ★A4 | 데몬 미실행 시 `hook error` 소음 수준 | 훅 설치 수명 동기화 옵션 |
| A5 | 비정상 종료 시 `SessionEnd` 발생 여부 | dead 타이머 값 |
| A6 | Git Bash 없는 Windows: `PowerShell` 도구명, 백슬래시 경로 | 정규화기 픽스처 |
| A7 | `allow` 후 PreToolUse/PostToolUse 상관 성공률 ≥ 90%(60s 창) | `observed_result` |
| A8 | auto/acceptEdits에서 PreToolUse `ask`가 `PermissionRequest`를 유발하는가 | `force_ask_on_critical` 기본값 |
| A9 | statusLine으로 `session_name`·`cost`·`pr` 수신 | `session_meta_updated` |
| A10 | 사용자+프로젝트 settings 중복 정의 시 호출 횟수 | dedupe |
| A11 | `UserPromptSubmit` 자동 턴 휴리스틱 오탐률 | `auto_turn_suspect` |
| ★A12 | 원격 `allow`/`deny` 응답이 실제 적용됨("Allowed by PermissionRequest hook", deny 사유 전달) | §6 |
| A13 | `permission_mode`별(default/acceptEdits/plan/auto/dontAsk/bypass) `PermissionRequest` 발생 여부 | `remote_approval` 배지 규칙(§5 공통) |
| A14 | 병렬 서브에이전트가 같은 명령으로 `PermissionRequest`를 낼 때 **입력에 `agent_id`가 실리는지**, 사용자+프로젝트 settings 중복 호출 간격 | §6 병합 규칙(`agent_id` 키·2초 창) |
