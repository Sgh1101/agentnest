# Codex 연동 계약

- 상태: 확정(리드 종합본) — 2026-10-15
- 기준: `openai/codex` HEAD `bb64b894fd67158be0f874872e6d7bfe717e7368`(2026-10-15), 최신 태그 `rust-v0.162.1` [검증: 소스 clone 직접 열람 + 생성 JSON Schema]. 공식 문서 사이트(`developers.openai.com`)는 조사 환경에서 차단되어 **검색 스니펫만** 참고했고 2026-10-15 재시도에서도 접근하지 못했다 → 공식 hooks 설정 형식은 교차 검증하지 못했다(**신뢰도 낮음**). 그 출처의 항목은 [추정] 또는 검증 필요 (Phase 0). **정규화기·응답 직렬화 코드는 C5의 생성 JSON Schema 스냅샷에서 이 문서의 메서드·알림 목록을 다시 도출한 뒤에 쓴다**(이 표를 그대로 코드의 근거로 삼지 않는다).
- 원칙: **검증되지 않은 외부 API 형태는 코드에서 `// UNVERIFIED (Phase 0)` 주석 + feature flag(기본 off)** 뒤에 둔다. Phase 0 C-시리즈 통과 전까지 기본 경로에 들어오지 않는다.

---

## 1. 검증된 것 vs 가정

| 항목 | 상태 | 근거 | 코드 처리 |
| --- | --- | --- | --- |
| `codex app-server --listen stdio://\|unix://PATH\|ws://IP:PORT`; 줄 단위 JSON-RPC 2.0, **`"jsonrpc"` 필드 없음**; `initialize`→`initialized` 핸드셰이크 | [검증] | `app-server/src/main.rs`, `transport/stdio.rs`, `rpc.rs`, `v1.rs` | 기본 경로(RPC 코덱) |
| 제어 소켓 경로 `$CODEX_HOME/app-server-control/app-server-control.sock`; 비상승 피어 검사 `ensure_non_elevated_peer` | [검증] 경로·피어 검사 | `app-server-transport/src/transport/mod.rs` | — |
| **Windows 제어 소켓의 구현 방식**(AF_UNIX 여부, 어떤 crate) | **[추정] 미확인** — 리서치는 Windows 구현을 *미확인*으로 기록하고 `codex_uds`(named pipe/UDS 등가물)를 언급했다. 이전 판의 "AF_UNIX via `uds_windows`"는 근거가 없어 철회 | 리서치 `codex-app-server.md` §4.1 | `// UNVERIFIED (Phase 0)`, flag `codex-daemon-observer` 뒤. C1에서 실제 소켓 종류 확인 |
| TUI가 기본적으로 공유 데몬에 붙음(`daemon_auto_start` Stable, default on; `--no-daemon`) | [검증] 구조 / [추정] 실동작 | `features/src/lib.rs`, `tui/src/lib.rs` | — |
| **제3자 연결이 `thread/resume`으로 TUI 스레드의 알림·`requestApproval`을 받고, 첫 응답이 승리하며 `serverRequest/resolved`가 온다** | **[추정]** (`outgoing_message.rs` 구조 추론) | 실동작 미확인 | `codex-daemon-observer` flag, 기본 off, `// UNVERIFIED (Phase 0)` → C1~C4 |
| 소켓 접속 인증/토큰 요구 여부, 동시 연결 한도 | 미확인 | `ConnectionAuth` 존재만 | C4 |
| `thread/resume{threadId}`로 실행 중 스레드를 구독(알림·승인 요청 수신) | [검증] 구조 / [추정] 실동작 | 리서치 §4.1(소스 구조) | `// UNVERIFIED (Phase 0)` → C2 |
| `thread/resume`의 **`excludeTurns` 파라미터**와 "원자적 구독" 세부 | **[추정]** — 리서치 파일에 `excludeTurns` 문자열이 없다. C5 스냅샷(`ThreadResumeParams`)으로 확인 전까지 가정 | — | 파라미터가 없으면 `thread/resume{threadId}`만 보내고 응답의 과거 turns는 **정규화에서 무시**(백필 금지, 이벤트 폭주 방어) |
| `thread/list{limit, sortKey, sourceKinds?, useStateDbOnly?}` — `sourceKinds` 생략 시 interactive 소스만 | [검증] 파라미터 / [추정] TUI 세션 포함 여부 | `common.rs` | C8 |
| 알림: `thread/started`, `thread/status/changed{notLoaded\|idle\|systemError\|active{activeFlags:[waitingOnApproval\|waitingOnUserInput]}}`, `turn/started`, `turn/completed{status: completed\|interrupted\|failed\|inProgress, error?}`, `item/started\|completed{item}`, `item/commandExecution/outputDelta{delta}`, `turn/diff/updated{diff}`, `thread/tokenUsage/updated`, `serverRequest/resolved{threadId, requestId}`, `error{message, codexErrorInfo?, willRetry}` | [검증] | 생성 스키마 `schema/json/v2/*.json` | 기본 경로(정규화기) |
| 알림 `turn/plan/updated`, `thread/closed`, `thread/archived`, `thread/compacted`, `thread/name/updated` | **[추정]** — 리서치에 이름이 한 번씩만 나오고 페이로드 상세가 없다 | — | C5 스냅샷으로 필드 확인 전까지 정규화는 `unknown` 취급(필드 미사용, 이벤트만 `notification`으로 보존) |
| `ThreadItem.type`: `userMessage`, `agentMessage`, `commandExecution{command, cwd, status, commandActions[], exitCode?, aggregatedOutput?, durationMs?}`, `fileChange{changes[{path, kind}], status}`, `mcpToolCall`, `webSearch`, `subAgentActivity`, `enteredReviewMode{review}`, `exitedReviewMode{review}`, `contextCompaction`, … | [검증] | `v2/item.rs` | — |
| 승인 요청(서버→클라이언트 **요청**, `id` 있음): `item/commandExecution/requestApproval{kind, threadId, turnId, itemId, startedAtMs, approvalId?, reason?, command?, cwd?, commandActions?, proposedExecpolicyAmendment?, availableDecisions?(experimental)}`, `item/fileChange/requestApproval{threadId, turnId, itemId, startedAtMs, reason?, grantRoot?}` | [검증] | `v2/item.rs`, `common.rs` | 기본 경로(타입) |
| 결정 직렬화: 단위 변형은 문자열 `"accept"`/`"acceptForSession"`/`"decline"`/`"cancel"`; 데이터 변형은 외부 태그 객체 | [검증] 문자열 / [추정] 객체형 | 테스트 코드 / serde 속성 | 문자열 3종만 생성. 객체형 생성 코드 **없음** |
| 응답 봉투 `{"id": <요청 id>, "result": {"decision": …}}` | [검증] | `rpc.rs` | — |
| app-server 측 승인 타임아웃 **없음**(`ReviewDecision::TimedOut`는 TUI·Guardian·core 매칭에만) | [검증] grep / [추정] 의미 | — | 만료 시 **응답을 보내지 않는다** |
| `UserInput` 텍스트 항목 `{"type":"text","text":"…"}` | [검증] | `TurnStartParams.json` | Phase 2 |
| hooks 이벤트: `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, `Stop`, `Interrupt`; 공통 입력 `session_id, turn_id, agent_id?, agent_type?, transcript_path(null 가능), cwd, hook_event_name, model, permission_mode` | [검증] | `hooks/schema/generated/*.schema.json` | 기본 경로(hooks 정규화기) |
| hooks 입력의 **`tool_name` 값**(shell·apply_patch·MCP·웹 검색)과 이벤트별 **`tool_use_id` 제공 여부** | **UNVERIFIED** — 리서치는 `PreToolUse`/`PostToolUse`만 `tool_use_id`를 가진다고 적었고(`PermissionRequest`에는 **없음**) Codex 도구 이름 값은 어디에도 없다(`apply_patch` grep 0건) | `hooks/schema/generated` 필드명만 | §5.3 Codex 전용 표(`// UNVERIFIED (Phase 0)`) + C10 |
| hooks 핸들러 타입: `command`(+ `commandWindows`, `timeout`, `statusMessage`, `async`), `mcp_tool`; `prompt`/`agent`는 파싱만 되고 "not supported yet"; **`http` 타입 없음** | [검증] | `config/src/hook_config.rs`, `hooks/src/engine/discovery.rs` | `agentnest-hook codex` CLI **필수** |
| hooks `PermissionRequest` 출력: `decision.behavior ∈ allow\|deny`, `message?`; `updatedInput`/`updatedPermissions`/`interrupt:true`가 있으면 **결정 전체 폐기(fail-closed)** | [검증] | `hooks/src/engine/output_parser.rs` | 생성기가 세 필드를 넣지 않음 |
| hooks `PreToolUse` 출력 파서: `permissionDecision:"ask"`는 **항상 거부**, `"allow"`는 `updatedInput` 필수, `"deny"`는 비어 있지 않은 `reason` 필수 | [검증] | `output_parser.rs` | Codex `PreToolUse`는 **관찰 전용**(빈 stdout) |
| hooks `timeout`(초) 기본 600, `SessionEnd`/`Interrupt`는 1..3초 clamp; `PermissionRequest` 핸들러 동시 실행·총 타임아웃 `max_permission_request_timeout` | [검증] | `discovery.rs` | — |
| hooks matcher: `""`/`"*"` 전체, 영숫자·`_`·`\|`만이면 정확 일치 목록, 그 외 정규식 | [검증] | `hooks/src/engine/matcher.rs` | matcher 생략 |
| hooks 설정 파일 **위치/최상위 구조**(`~/.codex/hooks.json`, `config.toml [hooks]`), 레이어 병합, 비관리 훅은 `/hooks`에서 trust(`hooks.state."file:…".trusted_hash`) | [검증] 구조 일부 / **최상위 키(`hooks` 유무)·TOML 문법은 검증 필요 (Phase 0)** | `discovery.rs load_hooks_json` 반환만 확인 | 설치기는 C6 결과 후 확정; 그 전엔 **수동 설치 안내 문서** |
| hooks `PermissionRequest`에서 **결정 없음(빈 stdout) → 로컬 프롬프트 폴백 여부**, 훅 allow가 app-server 승인 요청을 생략하는지 | 미확인 | — | C6 통과 전 hooks `PermissionRequest`는 **관찰만**(빈 stdout) |
| `review/start{threadId, target{type: uncommittedChanges\|baseBranch\|commit\|custom}, delivery}` → `{turn, reviewThreadId}`; 결과는 `exitedReviewMode.review` **문자열** | [검증] | `v2/review.rs` | Phase 2 |
| 리뷰 JSON 스키마(`findings[].priority 0-3`, `[P0]`~`[P3]` 접두, `overall_correctness`), 텍스트 렌더링 `- <title> — <path>:<start>-<end>` | [검증] | `rubric.md`, `review_format.rs` | 텍스트 파서(Phase 1) |
| `codex exec review --json --output-schema` 실제 출력 | 미확인 | — | C7, Phase 2 |
| rollout JSONL 경로 `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-*.jsonl`(+`.jsonl.zst`) | [검증] 경로 / **줄 포맷 [낮음]** | `rollout/src/list.rs` | `codex-rollout` flag off, Phase 2 백필 전용 |
| `notify = [...]`(legacy, `agent-turn-complete`만) | [검증] | `legacy_notify.rs` | 미채택(deprecated 경로) |
| Thread 객체에 `approvalPolicy`/`sandbox` 노출 여부 | 미확인 | — | C8(위험 배지용) |
| `codex remote-control` | 존재는 [검증]하나 **설계 근거로 사용하지 않는다**(`features/src/lib.rs`에 제거된 호환 플래그로 기록된 흔적 — 정확한 상태 [낮음]) | — | — |
| 클라우드 PR 리뷰: 기본 P0/P1만 코멘트, 작성자 계정명 | [추정] 스니펫 / 미확인 | — | Phase 2 |

---

## 2. 어댑터 설계 (`agentnest-adapter-api` + `agentnest-core::adapters::codex`)

### 2.1 플러그인 API (`agentnest-adapter-api`, 모든 어댑터 공통)

```rust
use futures_util::future::BoxFuture;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind { ClaudeCode, Codex, GeminiCli, OpenCode, Other }

#[derive(Clone, Debug, Default, Serialize)]
pub struct AdapterCapabilities {
    pub observe_sessions: bool,          // 사용자가 직접 띄운 세션 관찰
    pub remote_approval: bool,           // 승인 요청에 응답 가능
    pub approval_decisions: Vec<Decision>, // {allow, deny, deny_and_stop} 의 부분집합 — 범위 확장 값은 타입에 없음
    pub start_turn: bool,                // Phase 2
    pub review: bool,
    pub token_usage: bool,
    pub hook_ingest: bool,               // /v1/hooks/<kind> 라우트 필요
}

pub enum RawObservation {
    Event(AgentEvent),
    ApprovalOpened { draft: ApprovalDraft, responder: Box<dyn ApprovalResponder> },
    ApprovalClosedByAgent { binding: NativeBinding, reason: AgentCloseReason },
    ApprovalOutcomeObserved { binding: NativeBinding, observed: ObservedResult, evidence_event_id: String /* UUIDv7 문자열 — adapter-api 는 uuid 크레이트에 의존하지 않는다 */ },
    SessionMeta { session_key: SessionKey, patch: SessionMetaPatch },
    Health(AdapterHealth),
}

pub struct NativeBinding {
    pub agent_kind: AgentKind,
    pub native_session_id: String,
    /// claude_code: {"tool_name","tool_input_sha256","prompt_id"?}; codex: {"rpc_id","thread_id","turn_id","item_id","approval_id"?,"kind"}
    pub ids: BTreeMap<String, String>,
}

pub trait AgentAdapter: Send + Sync + 'static {
    fn kind(&self) -> AgentKind;
    fn label(&self) -> &'static str;
    fn capabilities(&self) -> AdapterCapabilities;
    fn start(&self, ctx: AdapterContext) -> BoxFuture<'static, Result<AdapterHandle, AdapterError>>;
    fn ingest_hook(&self, body: serde_json::Value, meta: HookMeta) -> BoxFuture<'static, HookReply> { Box::pin(async { HookReply::Empty }) }
    fn health(&self) -> BoxFuture<'static, AdapterHealth>;
}

/// 브로커만 허용 응답을 만들 수 있다. 어댑터는 번역만 한다.
/// 불투명 타입: 내부 enum 이 비공개이고 허용 값의 생성자는 ApplyProof 를 요구한다.
/// NoDecision 은 respond 가 아니라 abandon 으로 표현한다.
pub struct ApprovalReply(Inner);
enum Inner { Allow, Deny { message: String, interrupt: bool } }          // 모듈 밖에서 이름도 쓸 수 없음

/// 응답자가 matching 하는 읽기 전용 뷰. 이 값으로는 ApprovalReply 를 만들 수 없다.
pub enum ReplyKind<'a> { Allow, Deny { message: &'a str, interrupt: bool } }

/// 허용을 허가하는 증명 토큰. 필드가 비공개라 리터럴로 만들 수 없다.
pub struct ApplyProof(());
impl ApplyProof {
    /// `apply_decision` 성공 분기(agentnest-core::approvals::broker)에서만 호출한다.
    /// CI 가 이 호출의 위치를 1곳으로 강제한다(security.md §12 #6). 테스트용은 cfg(test)/`test-util` feature 뒤의 별도 생성자.
    #[doc(hidden)] pub fn mint() -> ApplyProof { ApplyProof(()) }
}

impl ApprovalReply {
    pub fn allow(_proof: ApplyProof) -> Self { ApprovalReply(Inner::Allow) }       // 증명 없이 허용 불가
    pub fn deny(message: String, interrupt: bool) -> Self { ApprovalReply(Inner::Deny { message, interrupt }) } // 거부는 언제든 안전
    pub fn as_wire(&self) -> ReplyKind<'_> { /* Inner → ReplyKind */ }
}

pub trait ApprovalResponder: Send + Sync {
    fn respond(self: Box<Self>, reply: ApprovalReply) -> BoxFuture<'static, Result<(), ResponderError>>;
    /// 만료·폐기·끊김: 에이전트에 아무것도 보내지 않는다(Claude 는 빈 2xx, Codex 는 no-op).
    fn abandon(self: Box<Self>, reason: AbandonReason) -> BoxFuture<'static, ()>;
}
```

- **허용 생성 경로 유일성(I5)의 강제 방식**: 어댑터 크레이트(claude_code/codex)의 응답자는 `match reply.as_wire() { ReplyKind::Allow => …, ReplyKind::Deny{…} => … }`로 **번역만** 하므로 코드에 `ApprovalReply::Allow` 같은 문자열이 존재하지 않는다(그런 variant가 없다). 검사는 (1) `compile_fail` doctest — 외부에서 `ApprovalReply(Inner::Allow)`·`ApprovalReply::allow()`(증명 없이)·`ApplyProof(())` 리터럴이 컴파일되지 않음, (2) CI grep — `ApplyProof::mint`의 비테스트 호출이 `approvals/broker.rs`의 `apply_decision` 성공 분기 1곳뿐(`testing-and-ci.md` §2), (3) `desktop/clippy.toml`의 `disallowed-methods`가 `ApplyProof::mint`를 금지하므로(구현·검증됨) 유일한 호출 한 줄에만 `#[allow(clippy::disallowed_methods)]`가 붙는다. 이 grep 이 빗나가지 않도록 adapter-api 의 `src/` 주석에는 해당 리터럴을 쓰지 않고, compile_fail 예제는 `tests/compile_fail.md` 에 둔다. 서로 다른 크레이트라 `pub(crate)`로는 막을 수 없어 `mint`는 `#[doc(hidden)] pub`이며, 2·3번이 이를 보완한다.
- 레지스트리(`agentnest-core::adapters::Registry`)는 설정 순서대로 `start`. Cargo feature: `adapter-claude-code`(기본 on), `adapter-codex-hooks`(기본 on), `codex-daemon-observer`(**기본 off**), `codex-rollout`(off), `adapter-mock`(dev; 픽스처 JSONL 재생으로 폰/데스크톱 E2E).
- 어댑터는 `AgentEvent.summary`를 직접 쓰지 않고 `summarize::ko`를 호출한다.

### 2.2 Codex 어댑터 구성

```text
adapters/codex/
├── hooks.rs            # (기본) POST /v1/hooks/codex 수신 정규화, PermissionRequest 홀드(C6 통과 후)
├── rpc/
│   ├── framing.rs      # 줄 단위 JSON 읽기/쓰기(최대 줄 16 MiB)
│   ├── client.rs       # 요청 id(u64 증가), pending oneshot 맵, 서버 요청 디스패치, 알림 스트림
│   ├── transport.rs    # Uds(unix: tokio UnixStream / windows: 구현 방식 미확인 [추정] — C1 결과(AF_UNIX 또는 named pipe)로 확정, `// UNVERIFIED (Phase 0)`) | Stdio(child)
│   └── types.rs        # 필요한 메서드/알림/서버요청만 serde(camelCase), 미사용 필드는 #[serde(flatten)] extra
├── daemon_observer.rs  # (flag codex-daemon-observer) initialize → thread/list(30s 폴링) → thread/resume{threadId[, excludeTurns:true — [추정] C5]} // UNVERIFIED (Phase 0)
├── normalize.rs        # 알림 → AgentEvent (protocol.md §5.2). 작성 전 선행: C5 스키마 스냅샷에서 알림·아이템 목록 재도출
├── approvals.rs        # requestApproval → ApprovalDraft + CodexResponder(JSON-RPC 응답)
├── review.rs           # enteredReviewMode/exitedReviewMode → review_* 이벤트, [P0]-[P3] 텍스트 파서
└── rollout.rs          # (flag codex-rollout) 관대한 백필 파서, Phase 2
```

---

## 3. 관찰 모드와 선택 규칙

| 모드 | 조건 | 수집 | 승인 | Phase 1 상태 |
| --- | --- | --- | --- | --- |
| **B. hooks(기본)** | `~/.codex/hooks.json`에 AgentNest 항목(사용자가 `/hooks`에서 trust — 설치기는 C6 전까지 **비활성**이라 사용자가 수동으로 파일을 쓴다. 절차는 데스크톱 첫 실행 체크리스트 `desktop.md` §6.1) | `SessionStart`/`UserPromptSubmit`/`PreToolUse`/`PostToolUse`/`Stop`/`Interrupt`/`SessionEnd` → `/v1/hooks/codex` | `PermissionRequest` allow/deny — **C6 통과 후** 활성; 그 전엔 관찰만(빈 stdout) | 기본 on(`adapter-codex-hooks`). **리뷰 결과는 이 모드로는 수집되지 않는다**(§8) |
| **A. 공유 데몬 소켓 구독** | 소켓 존재 + `initialize` 성공 + C1~C4 통과 | 전체 알림 | JSON-RPC 서버 요청 응답 | flag `codex-daemon-observer` **기본 off**, `// UNVERIFIED (Phase 0)` |
| C. 자체 `codex app-server --listen stdio://` spawn | AgentNest가 턴/리뷰를 시작할 때 | 전체 | 가능 [검증] | Phase 2(`review/start`, 작업 지시). Phase 1에서는 **연결성 프로브·스키마 스냅샷에만** 사용(관찰 대상이 없음) |
| D. rollout 테일링 | `$CODEX_HOME/sessions/**` | 사후 백필 | 불가 | flag off, Phase 2 |
| E. `codex exec --json` | AgentNest가 exec를 직접 실행 | 전체 | 불가 | Phase 2(리뷰) |

- A와 B가 동시에 켜지면 B 이벤트는 `dedupe_key`(`session_id`/`turn_id`/`tool_use_id` ↔ `thread_id`/`turn_id`/`item_id`)로 중복 제거하고 **승인은 한 채널에서만** 응답한다(A가 검증되면 A 우선, B의 `PermissionRequest`는 빈 stdout). 이중 카드 금지.
- `codex.mode = off`면 Codex 어댑터는 `not_configured`.

---

## 4. 모드 A — app-server 데몬 소켓 (flag `codex-daemon-observer`, 기본 off)

```jsonl
→ {"id":1,"method":"initialize","params":{"clientInfo":{"name":"agentnest","title":"AgentNest","version":"0.1.0"},"capabilities":{"experimentalApi":true,"optOutNotificationMethods":["item/reasoning/textDelta","item/reasoning/summaryTextDelta","item/agentMessage/delta"]}}}
← {"id":1,"result":{"userAgent":"codex_cli_rs/0.162.1 …","codexHome":"C:\\Users\\me\\.codex","platformFamily":"windows","platformOs":"windows"}}
→ {"method":"initialized"}
→ {"id":2,"method":"thread/list","params":{"limit":50,"sortKey":"updated_at","useStateDbOnly":true}}
← {"id":2,"result":{"data":[{"id":"0199d7b3-…","cwd":"C:\\dev\\proj","status":{"type":"active","activeFlags":[]},"preview":"테스트 고쳐줘"}],"nextCursor":null}}
→ {"id":3,"method":"thread/resume","params":{"threadId":"0199d7b3-…","excludeTurns":true}}   // excludeTurns 는 [추정] — C5 스냅샷으로 확인, 없으면 생략
← {"id":3,"result":{"thread":{…}}}
← {"method":"thread/status/changed","params":{"threadId":"0199d7b3-…","status":{"type":"active","activeFlags":["waitingOnApproval"]}}}
← {"id":17,"method":"item/commandExecution/requestApproval","params":{"kind":"command","threadId":"0199d7b3-…","turnId":"0199d7b4-…","itemId":"call_7","startedAtMs":1760500010123,"command":"rm -rf build && cargo build --release","cwd":"C:\\dev\\proj","commandActions":[{"type":"unknown","command":"rm -rf build && cargo build --release"}],"availableDecisions":["accept","acceptForSession","decline","cancel"]}}
→ {"id":17,"result":{"decision":"accept"}}
← {"method":"serverRequest/resolved","params":{"threadId":"0199d7b3-…","requestId":17}}
```

규칙:

- `thread/resume`에는 **어떤 정책 override도 넘기지 않는다**(`approvalPolicy`, `sandbox`, `approvalsReviewer`, `model` 생략). 사용자의 TUI 설정을 바꾸면 안 된다.
- `optOutNotificationMethods`로 델타 스트림을 끈다. `item/commandExecution/outputDelta`는 유지하되 마지막 1 KiB만 링버퍼 → `command_completed.stdout_tail`.
- 구독 대상: `status.type ∈ {active, idle}` + `updatedAt` 24시간 이내 + `thread/started`로 새로 뜨는 스레드. `thread/closed`/`archived` 시 해제. `thread/list`의 `sourceKinds` 기본값이 TUI 세션을 포함하는지는 C8.
- 재연결: EOF → 지수 백오프(1s→30s) → `thread/list` 재조회로 구독 복원. 연결 중 보류 승인은 `ApprovalClosedByAgent{connection_lost}` → 카드 `superseded`.
- 버전 드리프트: `protocol/fixtures/codex/app-server/schema/`의 생성 스키마 스냅샷에 어댑터 타입이 적합한지 `cargo test`(jsonschema). Phase 0에서 `codex app-server generate-json-schema` 결과로 교체(C5).
- Windows 소켓 구현(AF_UNIX인지 named pipe인지, 어떤 crate인지)은 **[추정]** — C1. 코드는 `// UNVERIFIED (Phase 0)` 주석과 flag 뒤에 둔다.

---

## 5. 모드 B — hooks (기본)

### 5.1 설정 파일 (형식은 검증 필요 (Phase 0) C6 — 아래는 Claude Code 호환 스키마 기반 **초안**)

```json
// ~/.codex/hooks.json — 최상위 키 "hooks" 유무, matcher 필드명은 C6 에서 확정. 그 전까지 설치기는 이 파일을 쓰지 않고 안내만 한다.
{
  "hooks": {
    "SessionStart":      [{ "matcher": "", "hooks": [{ "type": "command", "command": "agentnest-hook codex", "commandWindows": "agentnest-hook.exe codex", "timeout": 5 }] }],
    "UserPromptSubmit":  [{ "matcher": "", "hooks": [{ "type": "command", "command": "agentnest-hook codex", "commandWindows": "agentnest-hook.exe codex", "timeout": 5 }] }],
    "PreToolUse":        [{ "matcher": "", "hooks": [{ "type": "command", "command": "agentnest-hook codex", "commandWindows": "agentnest-hook.exe codex", "timeout": 5 }] }],
    "PermissionRequest": [{ "matcher": "", "hooks": [{ "type": "command", "command": "agentnest-hook codex", "commandWindows": "agentnest-hook.exe codex", "timeout": 150 }] }],
    "PostToolUse":       [{ "matcher": "", "hooks": [{ "type": "command", "command": "agentnest-hook codex", "commandWindows": "agentnest-hook.exe codex", "timeout": 5 }] }],
    "Stop":              [{ "matcher": "", "hooks": [{ "type": "command", "command": "agentnest-hook codex", "commandWindows": "agentnest-hook.exe codex", "timeout": 5 }] }],
    "Interrupt":         [{ "matcher": "", "hooks": [{ "type": "command", "command": "agentnest-hook codex", "commandWindows": "agentnest-hook.exe codex", "timeout": 2 }] }],
    "SessionEnd":        [{ "matcher": "", "hooks": [{ "type": "command", "command": "agentnest-hook codex", "commandWindows": "agentnest-hook.exe codex", "timeout": 3 }] }]
  }
}
```

- `commandWindows`(alias `command_windows`) 필드는 설정 스키마에 존재 [검증]; 실제 선택 규칙은 C6.
- 위 `agentnest-hook` 은 문서용 표기다. 설치본의 사이드카는 앱 exe 옆에만 있고 `PATH` 에 없으므로, 데스크톱이 보여 주는 초안은 데몬이 **절대경로(공백이 있으면 큰따옴표)** 와 현재 TTL(`PermissionRequest` timeout = TTL+30)로 채워 돌려준다(`desktop.md` §3 `hooks_status`). 경로를 쓰는 `command` 문자열을 Codex 가 어떤 셸로 해석하는지는 C6 에서 확인한다 [추정].
- 설치 후 사용자가 Codex TUI `/hooks`에서 **trust**해야 실행된다 [검증: `HookTrustStatus::Untrusted` 기본]. 온보딩에 절차 안내.
- `PermissionRequest` 핸들러는 동시 실행, 총 타임아웃 `max_permission_request_timeout` [검증] — 값과 설정 키는 C6.

### 5.2 `/v1/hooks/codex` 응답 규칙

| 이벤트 | 응답 |
| --- | --- |
| `PreToolUse` | **항상 204**(관찰 전용). `permissionDecision`을 절대 출력하지 않는다(`ask` 무효, `allow`는 `updatedInput` 필수 [검증]) |
| `PermissionRequest` | C6 통과 전: 204. 통과 후: 폰 결정 → `200 {"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}` 또는 `{"behavior":"deny","message":"AgentNest: 휴대폰에서 거부했어요"}`. **`interrupt`/`updatedInput`/`updatedPermissions` 금지**(있으면 결정 폐기 [검증]). **`deny_and_stop`은 이 경로의 `allowed_decisions`에서 제외**한다(`origin=codex.hook.cli`; 카드에 "거부만 가능 (Codex hooks는 작업을 멈출 수 없어요)" 표시 — 사후 강등으로 사용자가 더 약한 동작을 모르고 고르는 일이 없게 한다). 결정 없음 → 204(= CLI 빈 stdout). 승인 capability는 `codex_approve_hooks`(C6 통과 후, `protocol.md` §4.5) |
| 나머지 | 204 |

### 5.3 hooks 정규화 (Codex 전용 표 — UNVERIFIED, C10)

Codex hooks 입력의 **공통 필드**(`session_id`, `turn_id`, `agent_id?`, `cwd`, `hook_event_name`, `model`, `permission_mode`)는 Claude와 같은 모양이라 [검증] 공통 후처리(프로젝트 해석·마스킹·상한)는 재사용한다. 그러나 **도구 이름 값과 이벤트별 `tool_use_id`는 검증되지 않았으므로 Claude 정규화기를 그대로 재사용하지 않는다**(Claude의 `Edit|Write|MultiEdit|NotebookEdit`, `Bash|PowerShell`, `Read|Grep|Glob` 키가 Codex에서 맞는지 모른다). Codex 전용 매핑 표를 별도로 두고 `agent_kind=codex`, `session_key=codex:<session_id>`, `turn_id`를 `native_ids`에 보존한다. 골든 `protocol/fixtures/codex/hooks/*.json`은 **C10 실캡처로 만든다**(그 전의 픽스처는 합성이며 `synthetic: true` 표시).

| Codex hooks `tool_name`(후보 — **UNVERIFIED C10**) | `AgentEvent` | 상태(`protocol.md` §5.4) |
| --- | --- | --- |
| 셸 실행 도구(후보: `Bash`, `shell`, `local_shell`, `exec_command`) | `command_started`/`command_completed`/`command_failed` (+ `command_class`) | `testing`/`working` |
| 패치 적용 도구(후보: `apply_patch`; 별칭 가능) | `tool_started` + `file_modified`(PostToolUse, 경로는 `tool_input`의 패치 헤더에서 파싱 — 형식 미검증) | `writing_code`(PreToolUse 시점) |
| `mcp__<server>__<tool>` 형태 | `tool_started` | `working` |
| 웹 검색(후보: `web_search`) | `tool_started` | `working` |
| **그 밖·미지의 값** | `tool_started{tool_name}` | `working` |

- **미지 이름은 잘못 특화하지 않고 `working`으로 둔다.** C10 전에는 hooks 모드에서 `writing_code`·`reviewing`·`observed_result` 상관이 **발동하지 않을 수 있고**, 그때 Codex 상태 표시는 `working`/`awaiting_approval`/`completed`/`error`로 축약된다(PRD의 Codex P0 요구 "세션 상태 확인"은 충족, 세분화는 Phase 0 결과에 의존).
- **상관 키**: 리서치상 `PermissionRequest` 입력에는 `tool_use_id`가 **없다**(`PreToolUse`·`PostToolUse`만 있음 — 이것도 C10에서 확인). 따라서 Codex `PermissionRequest`도 Claude와 같이 **열린 훅 호출 핸들 + `sha256(tool_input)`(+`tool_name`) 60초 창**으로 `observed_result`를 상관시키며, `dedupe_key`는 `tool_use_id`가 있을 때만 `tool_use_id`를 쓰고 없으면 `sha256(tool_input)`로 대체한다(`tool_use_id`를 전제한 일반 규칙 금지).

---

## 6. 승인 브로커 매핑

| 폰/데스크톱 결정 | app-server `commandExecution` 응답 | app-server `fileChange` 응답 | hooks 출력 |
| --- | --- | --- | --- |
| `allow` | `"accept"` | `"accept"` | `behavior:"allow"` |
| `deny` | `"decline"` | `"decline"` | `behavior:"deny"` + `message` |
| `deny_and_stop` | `"cancel"` | `"cancel"` | **제공하지 않음**(`allowed_decisions`에서 제외; `interrupt` 금지) |
| 만료·끊김·폐기·재시작 | **응답 없음** | 응답 없음 | 빈 stdout |
| (금지) | `acceptForSession`, `acceptWithExecpolicyAmendment`, `applyNetworkPolicyAmendment` | 동일 | — |

- `NativeBinding.ids = {rpc_id, thread_id, turn_id, item_id, approval_id?, kind}`; `created_at = startedAtMs`; `expires_at = created_at + TTL(120s)`. 앱서버에는 자체 타임아웃이 없으므로 만료 시 **응답을 보내지 않는다**(TUI 프롬프트가 처리).
- `serverRequest/resolved{requestId}` 수신 → `superseded`(resolved_by=agent). 그 뒤 도착한 폰 결정은 `ALREADY_RESOLVED` + `audit: late_decision`, 응답 미전송.
- `availableDecisions`(experimentalApi)가 오면 그 목록과 `{accept, decline, cancel}`의 교집합만 `allowed_decisions`에 노출. `decline`이 없으면 `deny`를 빼고 카드에 "거부 = 중단" 표기.
- `fileChange` 요청에는 변경 내용이 없다 [검증] → 같은 `itemId`의 `item/started{fileChange.changes[{path, kind}]}`와 최근 `turn/diff/updated.diff`를 결합해 `details.file_paths` + `diff_preview`(≤4 KiB). 아직 못 모았으면 `details.truncated=true` + "변경 내용을 아직 받지 못했어요", 위험도 최소 `medium`.
- 관찰 결과: 같은 `itemId`의 `item/completed{commandExecution.status ∈ completed|failed|declined}` → `observed_result = executed|executed|declined`.
- 위험 배지: 스레드 `approvalPolicy=never` / `sandbox=danger-full-access` / `approvalsReviewer=auto_review`(Guardian)면 `remote_approval: unavailable` + 경고 — 노출 경로는 C8.

---

## 7. 알림 → `AgentEvent` 정규화 매핑 (상태 전이는 `protocol.md` §5.4가 유일한 출처)

이 절은 **정규화 매핑만** 둔다. 어떤 `AgentState`가 되는지는 `protocol.md` §5.4의 `(Codex)` 행과 `state_transitions.json`이 정하며, 여기에 다시 적지 않는다(Rust·Kotlin 리듀서가 한 표에서 구현되게 하기 위함).

| 소스 | `AgentEvent.kind` | 비고 |
| --- | --- | --- |
| `thread/status/changed{idle}` | `idle` | 직전 턴이 completed면 §5.4의 `completed → idle(60초)`가 선행 |
| `thread/status/changed{active, activeFlags}` | (kind 없음 — 리듀서 입력으로 직접 전달) | `waitingOnApproval`/`waitingOnUserInput`/`[]` |
| `item/started{commandExecution}` | `command_started` | `command_class`는 `risk` 토크나이저와 공유 |
| `item/started{fileChange}` | `tool_started{detail.item_type:"fileChange"}` | `item/completed`에서 `file_modified` |
| `item/started{webSearch\|mcpToolCall\|dynamicToolCall}` | `tool_started` | |
| `enteredReviewMode` / `exitedReviewMode` | `review_started` / `review_completed` | [추정] 실동작 미확인(§8) |
| `turn/completed{failed}` / `thread/status/changed{systemError}` / `error` 알림 | `turn_failed` / `agent_error` / `agent_error` | |
| `turn/completed{interrupted}` / hooks `Interrupt` | `turn_interrupted` | |
| 소켓 EOF | `adapter_status{disconnected, daemon_observer}` | 세션 `disconnected`는 §5.4 |

토큰 사용량(`thread/tokenUsage/updated`)은 `token_usage_updated`로 10초 스로틀.

---

## 8. 리뷰 결과 수집 — Phase 1에서는 **best-effort·선택 기능**

PRD P0 "Codex 세션 및 리뷰 상태"와 §3.B(P0/P1 문제, 검토 대상 PR, 권고)에 대해 Phase 1 기본 빌드가 약속하는 것은 **세션 상태(hooks)** 이다. **리뷰 결과(P0/P1)는 아래 게이트를 통과한 경로에서만 제공되는 선택 기능**이며 기본 빌드(hooks 모드)에서는 없다.

| 경로 | 게이트 | 상태 |
| --- | --- | --- |
| 모드 A에서 TUI `/review` 관찰: `item/started{enteredReviewMode}` → `review_started`, `item/completed{exitedReviewMode}` → `review_completed` + 파서로 `review_finding` | flag `codex-daemon-observer` + **C1·C2** 통과 | [추정], 기본 off |
| `codex exec review --json --output-schema …`(스키마 = `ReviewOutputEvent`) | **C7** 통과 + 픽스처 | Phase 2(사용자가 AgentNest에서 리뷰를 시작하는 경우) |
| hooks `Stop.last_assistant_message` 텍스트 파서 | **C7**의 실캡처 픽스처가 형식을 입증한 뒤에만 활성(리뷰 텍스트가 `Stop`에 실리는지 자체가 [추정]) | 픽스처 전까지 off |

- 파서 정규식(`^\s*[-*]?\s*\[P([0-3])\]\s*(.+?)\s*(?:—|-)\s*(\S+?):(\d+)(?:-(\d+))?`)은 렌더링 형식 [검증 `review_format.rs`]에 기반하며, 파싱 실패 줄은 `review_completed.detail.unparsed_lines`.
- **게이트 밖(기본 hooks 모드)에서의 폰 표시**: `session_state.meta.review.state = "unavailable"` 이고 `adapter_status{agent_kind:codex, mode:hooks_cli}.detail`에 "hooks 모드 · 리뷰 결과 수집 불가"(영문 의미: *review: not available (hooks mode)*)를 싣는다. 폰은 P0/P1 숫자 대신 이 문구를 보여주며, `alerts` 채널의 "Codex P0/P1" 푸시는 **리뷰 소스가 활성일 때만** 발생한다(`android.md` §5). 즉 PRD 완료 기준 §9는 "Codex 상태를 실시간 확인"까지이며 리뷰 알림은 포함하지 않는다.
- 폰 푸시(소스 활성 시): `priority ∈ {0, 1}`만 `alerts` 채널("Codex가 중요한 문제를 찾았어요 (P0 1건)"), 2/3은 타임라인.
- 클라우드 PR 리뷰: Phase 2 GitHub API. 작성자 계정명 미확인.

---

## 9. Phase 0 검증 항목 (C-시리즈; 통과 기준은 `phase0-checklist.md`)

| # | 검증 | 실패 시 |
| --- | --- | --- |
| C1 | 사용자가 `codex`(TUI)만 실행했을 때 `%USERPROFILE%\.codex\app-server-control\app-server-control.sock` 생성(Windows AF_UNIX) + AgentNest `initialize` 성공, `userAgent` 캡처 | 모드 A 폐기, B만 |
| C2 | 제3 연결 `thread/resume{threadId}`(+`excludeTurns` 지원 여부 확인)가 TUI 스레드의 `item/*`·`thread/status/changed`·**`requestApproval`**을 받는가; 폰 accept 시 TUI 진행 | 모드 A 폐기 |
| C3 | 두 클라이언트 중 한쪽이 먼저 응답했을 때 다른 쪽에 `serverRequest/resolved`, 중복 실행 없음 | 카드 취소 로직 조정 |
| C4 | 소켓 접속 인증/토큰 요구, 비상승 피어 검사 통과 | 필요 설정 문서화 |
| C5 | `codex app-server generate-json-schema` 스냅샷 → 픽스처 테스트 통과 | — |
| C6 | `hooks.json` 최상위 구조·`commandWindows` 선택 규칙·`/hooks` trust 절차·`PermissionRequest` 결정 없음 시 폴백·`max_permission_request_timeout` | hooks `PermissionRequest`는 관찰만 유지 |
| C7 | `codex exec review --json --output-schema` 실제 출력 / `exitedReviewMode.review` 텍스트 형식 | 텍스트 파서만 |
| C8 | `thread/list` 기본 `sourceKinds`가 TUI 세션을 포함하는지; Thread 객체/`config/read`에 `approvalPolicy`/`sandbox` 노출 여부 | `sourceKinds` 명시 / 배지 생략 |
| C9 | hooks `PermissionRequest` allow가 app-server 승인 요청을 생략하는지(A+B 동시 사용 시 이중 카드) | 한 채널만 활성 |
| C10 | **실제 hooks 페이로드 캡처**: `PreToolUse`·`PermissionRequest`·`PostToolUse`를 셸 명령·패치 적용(`apply_patch` 류)·MCP 도구·웹 검색 각각으로 유발해 `tool_name` 값과 이벤트별 `tool_use_id` 유무를 기록(민감값 마스킹 → `protocol/fixtures/codex/hooks/`) | §5.3 Codex 전용 표를 실값으로 교체; 미지 이름은 계속 `working`; `PermissionRequest` 상관은 `sha256(tool_input)` 유지 |
