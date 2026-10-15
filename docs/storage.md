# 저장소 설계 (SQLite)

- 상태: 확정(리드 종합본) — 2026-10-15
- 엔진: `rusqlite 0.40.2`(`bundled`, SQLite 3.53.2) + `rusqlite_migration 2.6.0`(`user_version`, `M::up`, `Migrations::to_latest`, 테스트에서 `MIGRATIONS.validate()`) [검증]
- 파일: `%LOCALAPPDATA%\AgentNest\agentnest.db`. `PRAGMA journal_mode=WAL; synchronous=NORMAL; foreign_keys=ON; busy_timeout=5000;`
- **내구성**: 기본은 `synchronous=NORMAL`(WAL에서 전원 차단 시 마지막 커밋 일부를 잃을 수 있음)이지만, **승인·결정·감사 트랜잭션(§2의 '승인 적용', 만료 전이, `decisions`/`approval_audit`/`audit_log` INSERT)은 `synchronous=FULL`** 로 커밋한다. 단일 writer 태스크가 해당 트랜잭션 직전에 `PRAGMA synchronous=FULL`을 설정하고 커밋 뒤 `NORMAL`로 되돌린다(트랜잭션 밖에서 설정해야 적용됨). 어댑터 응답은 이 커밋 뒤에만 나가므로 '응답은 나갔는데 결정 기록이 없는' 상태가 생기지 않는다.
- **FK 원칙**: 보존 기간이 서로 다른 테이블 사이에는 `ON DELETE CASCADE`를 **두지 않는다**(§3). `session_key`·`request_id` 참조는 평문 TEXT 컬럼이며, 어떤 보존 규칙도 다른 테이블의 삭제를 연쇄시키지 않는다.
- 접근: **단일 writer** 태스크(`mpsc` → `spawn_blocking`, `Mutex<Connection>`), 읽기 연결 2개. 모든 시각은 RFC3339 UTC TEXT, JSON 컬럼은 TEXT(serde_json).
- 원칙(`security.md` I9): **원시 훅 본문은 저장하지 않는다.** 저장되는 본문성 데이터는 바운드·마스킹된 `detail_json`/`details_json`뿐이며 후자는 7일 후 NULL. 비밀은 해시만(디바이스 토큰·훅 토큰·페어링 비밀).

---

## 1. DDL

```sql
-- ===== M001: 신원·기기·페어링 =====
CREATE TABLE pc_identity (
  id               INTEGER PRIMARY KEY CHECK (id = 1),
  pc_id            TEXT NOT NULL,                    -- SPKI SHA-256 앞 8바이트 hex
  pc_name          TEXT NOT NULL,
  cert_pem         TEXT NOT NULL,                    -- 공개 인증서(개인키는 ACL 파일, DB 밖)
  spki_sha256_b64  TEXT NOT NULL,
  hook_token_hash  BLOB NOT NULL,                    -- SHA-256(hook_token)
  created_at       TEXT NOT NULL,
  cert_rotated_at  TEXT
);

CREATE TABLE devices (
  device_id        TEXT PRIMARY KEY,                 -- 'dev_' + 16바이트 hex
  name             TEXT NOT NULL,
  platform         TEXT NOT NULL,                    -- android
  model            TEXT,
  os_version       TEXT,
  app_version      TEXT,
  token_hash       BLOB NOT NULL UNIQUE,             -- SHA-256(device_token) — 토큰 자체는 저장하지 않음
  pubkey_spki_der  BLOB UNIQUE,                      -- 폰 EC P-256 공개키 (Phase 3 서명용, 공개 정보)
  paired_at        TEXT NOT NULL,
  last_seen_at     TEXT,
  last_ip_masked   TEXT,                             -- 마지막 옥텟 마스킹
  last_acked_seq   INTEGER NOT NULL DEFAULT 0,
  revoked_at       TEXT,                             -- NULL = 활성. 되돌리기 없음
  revoked_reason   TEXT                              -- user_desktop | user_phone | key_invalidated | inactive_90d
);
CREATE INDEX devices_active ON devices(revoked_at, last_seen_at);

CREATE TABLE pairings (
  pairing_id       TEXT PRIMARY KEY,                 -- 'p_' + 8바이트 hex
  secret_sha256    BLOB NOT NULL,                    -- 비밀 자체는 메모리에만
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  used_at          TEXT,
  outcome          TEXT,                             -- paired | expired | rejected | failed | cancelled
  device_id        TEXT REFERENCES devices(device_id),
  fail_count       INTEGER NOT NULL DEFAULT 0
);

-- ===== M002: 프로젝트·세션 =====
CREATE TABLE projects (
  project_key      TEXT PRIMARY KEY,                 -- 정규화 경로(소문자, '/')
  name             TEXT NOT NULL,
  path             TEXT NOT NULL,                    -- 전체 경로(폰에는 path_hint 만 전송)
  repo             TEXT,                             -- owner/name (git remote 파싱)
  branch           TEXT,
  first_seen_at    TEXT NOT NULL,
  last_seen_at     TEXT NOT NULL
);

CREATE TABLE sessions (
  session_key        TEXT PRIMARY KEY,               -- '<agent_kind>:<native_session_id>'
  agent_kind         TEXT NOT NULL,
  native_session_id  TEXT NOT NULL,
  project_key        TEXT REFERENCES projects(project_key),
  title              TEXT,
  model              TEXT,
  permission_mode    TEXT,
  remote_approval    TEXT NOT NULL DEFAULT 'available' CHECK (remote_approval IN ('available','unavailable','paused','unknown')),  -- protocol.md §5.3 과 동일 4값. 'unknown' = 정책 미확인(예: Codex approvalPolicy 노출 미검증, C8) → 폰은 unavailable 로 렌더
  source_channel     TEXT NOT NULL,
  transcript_path    TEXT,                           -- PC 전용(폰 미전송)
  started_at         TEXT NOT NULL,
  ended_at           TEXT,
  end_reason         TEXT,
  state              TEXT NOT NULL,
  state_since        TEXT NOT NULL,
  headline           TEXT,
  detail             TEXT,
  turn_active        INTEGER NOT NULL DEFAULT 0,
  turn_started_at    TEXT,
  turn_completed_at  TEXT,                           -- turn_completed/failed/interrupted 시각(작업 완료 시각)
  prompt_preview     TEXT,                           -- ≤200자, 마스킹
  counters_json      TEXT NOT NULL DEFAULT '{}',
  meta_json          TEXT NOT NULL DEFAULT '{}',     -- cost_usd, pr, context_used_pct, token usage, review{p0,p1,state}
  recent_json        TEXT NOT NULL DEFAULT '{}',     -- {recent_files[≤5], recent_commands[≤3], last_test} (바운드·마스킹, protocol.md §5.3)
  last_event_at      TEXT NOT NULL,
  last_event_seq     INTEGER,
  stale              INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX sessions_active_idx ON sessions(ended_at, last_event_at);

-- ===== M003: 이벤트·스트림 =====
CREATE TABLE events (
  event_id     TEXT PRIMARY KEY,                     -- UUIDv7
  seq          INTEGER NOT NULL UNIQUE,              -- stream.seq 와 같은 번호
  ts           TEXT NOT NULL,
  session_key  TEXT NOT NULL,                        -- FK 없음(보존 기간이 sessions 와 독립; §3). 세션 행이 삭제돼도 events 는 자체 규칙으로만 삭제
  agent_kind   TEXT NOT NULL,
  actor_json   TEXT,
  kind         TEXT NOT NULL,                        -- approval_requested / approval_resolved / adapter_status 는 '타임라인 전용' 사본(폰 상태 입력 아님, protocol.md §5.1). source_json.native_ids.request_id 로 dedupe
  category     TEXT NOT NULL,
  severity     TEXT NOT NULL,
  headline     TEXT NOT NULL,
  detail_text  TEXT,
  state_hint   TEXT,
  detail_json  TEXT,                                 -- 바운드(≤ 8 KiB)·마스킹된 detail. 원시 본문 없음
  source_json  TEXT NOT NULL,                        -- channel, native_event, native_ids
  redacted     INTEGER NOT NULL DEFAULT 0,
  dedupe_key   TEXT,
  created_at   TEXT NOT NULL
);
CREATE INDEX events_session_ts_idx ON events(session_key, ts);
CREATE INDEX events_kind_ts_idx ON events(kind, ts);
CREATE INDEX events_session_seq_idx ON events(session_key, seq);   -- events_request(session_key?, before_seq) 페이지 조회
CREATE UNIQUE INDEX events_dedupe_idx ON events(dedupe_key) WHERE dedupe_key IS NOT NULL;

-- 폰 재동기화용 재생 로그(서버→폰 재생 가능 메시지). PC 전역 단일 seq.
CREATE TABLE stream (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           TEXT NOT NULL,
  msg_type     TEXT NOT NULL,                        -- event | session_state | approval_request | approval_resolved | adapter_status. `snapshot`·`events_page`·`hosts_update`·`welcome` 등 비재생 메시지는 저장하지 않으며 seq 를 소비하지 않는다(protocol.md §4.6)
  session_key  TEXT,
  ref_id       TEXT,                                 -- event_id / request_id
  payload_json TEXT NOT NULL,                        -- 와이어 payload 그대로(이미 바운드·마스킹됨)
  expires_at   TEXT                                  -- approval_request 만 (재생 시 만료 판단)
);
CREATE INDEX stream_ts_idx ON stream(ts);

-- ===== M004: 승인 =====
CREATE TABLE approvals (
  request_id                  TEXT PRIMARY KEY,      -- 'ar_' + UUIDv7
  nonce                       BLOB NOT NULL,         -- 16바이트
  session_key                 TEXT NOT NULL,         -- FK 없음(sessions 보다 오래 보존: approvals 90일 > sessions 30일)
  agent_kind                  TEXT NOT NULL,
  agent_id                    TEXT NOT NULL DEFAULT '', -- 훅 입력 agent_id(서브에이전트). 메인 에이전트/미제공 = ''. 중복 병합 키에 포함
  origin                      TEXT NOT NULL,         -- claude_code.hook.http | claude_code.hook.cli | codex.app_server | codex.hook.cli
  native_binding_json         TEXT NOT NULL,         -- NativeBinding.ids (rpc_id, thread_id, …)
  tool_name                   TEXT NOT NULL,
  tool_kind                   TEXT NOT NULL,         -- command | file_write | file_edit | file_read | mcp_tool | web | agent | file_change | permissions | other
  tool_input_sha256           BLOB NOT NULL,         -- 32바이트
  created_at                  TEXT NOT NULL,
  expires_at                  TEXT NOT NULL,
  title                       TEXT NOT NULL,
  purpose                     TEXT,
  details_json                TEXT,                  -- 표시용(명령 2,000자·diff 4 KiB·경로 50개), 7일 후 NULL
  risk_level                  TEXT NOT NULL CHECK (risk_level IN ('low','medium','high','critical')),
  risk_reasons_json           TEXT NOT NULL,
  extra_confirmation          TEXT NOT NULL CHECK (extra_confirmation IN ('none','hold','hold_and_reconfirm')),
  allowed_decisions_json      TEXT NOT NULL,
  permission_mode             TEXT,
  status                      TEXT NOT NULL CHECK (status IN ('pending','resolved','expired','handed_off_local','superseded','failed')),
  outcome                     TEXT CHECK (outcome IN ('allowed','denied','denied_and_stopped','expired','handed_off_local','superseded','failed')),
  resolved_by                 TEXT CHECK (resolved_by IN ('phone','desktop','timeout','agent','system')),
  resolved_at                 TEXT,
  resolved_device_id          TEXT REFERENCES devices(device_id),
  decision_msg_id             TEXT,                  -- 멱등 처리용 decision.id
  decision_auth_json          TEXT,                  -- {method, authenticated_at, extra_confirmation}
  delivery                    TEXT CHECK (delivery IN ('delivered','not_delivered')),
  observed_result             TEXT NOT NULL DEFAULT 'unknown' CHECK (observed_result IN ('executed','declined','unknown')),
  observed_event_id           TEXT,
  delivered_to_json           TEXT NOT NULL DEFAULT '{}'  -- {device_id: {sent_at, acked_at, seen_at}}
);
CREATE INDEX approvals_pending_idx ON approvals(status, expires_at);
CREATE INDEX approvals_session_idx ON approvals(session_key, created_at);
-- 같은 훅이 여러 settings 레벨에서 중복 도착한 경우만 카드 1장으로 병합한다. 조회용 비유니크 인덱스이며, 병합 판단(같은 key + created_at 이 now−2s 이내)은 단일 writer 태스크가 직렬로 수행한다.
-- (유니크 인덱스는 시간 창·agent_id 조건을 표현할 수 없고, 병렬 서브에이전트의 동일 명령을 한 승인으로 합쳐 버린다 → claude-code.md §6)
CREATE INDEX approvals_dedupe_idx ON approvals(session_key, agent_id, tool_name, tool_input_sha256, status, created_at);

-- 수신된 모든 결정 시도(거부된 시도 포함) = 감사 증거
CREATE TABLE decisions (
  id                  TEXT PRIMARY KEY,              -- decision 봉투 id
  request_id          TEXT NOT NULL,                 -- FK 없음: approvals(90일)가 먼저 삭제돼도 decisions(365일)는 남아야 한다
  actor               TEXT NOT NULL,                 -- device:<id> | desktop
  decision            TEXT NOT NULL,                 -- allow | deny | deny_and_stop
  decided_at          TEXT NOT NULL,
  received_at         TEXT NOT NULL,
  auth_method         TEXT,
  extra_confirmation  TEXT,
  verify_result       TEXT NOT NULL,                 -- APPLIED | EXPIRED | ALREADY_RESOLVED | BINDING_MISMATCH | …
  signature           BLOB                           -- Phase 3 (공개키로 검증되는 값, 비밀 아님)
);
CREATE INDEX decisions_request_idx ON decisions(request_id, received_at);

CREATE TABLE approval_audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id  TEXT NOT NULL,                         -- FK 없음(위와 같은 이유)
  ts          TEXT NOT NULL,
  actor       TEXT NOT NULL,                         -- daemon | phone:<device_id> | desktop | agent
  action      TEXT NOT NULL,                         -- opened | sent_to_phone | acked | seen | decision_received | decision_rejected | delivered | expired | handed_off | superseded | observed | late_decision
  detail_json TEXT                                   -- Redactor '감사' 정책 통과본(명령·diff 없음). `opened` 행은 approvals 가 삭제된 뒤에도 감사가 자립하도록 {session_key 앞 12자, agent_kind, tool_name, tool_kind, risk_level, risk_reasons, tool_input_sha256(hex), origin, expires_at} 스냅샷을 담는다
);
CREATE INDEX approval_audit_request_idx ON approval_audit(request_id, ts);

-- ===== M005: 리뷰·어댑터·설정·감사 =====
CREATE TABLE review_findings (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  session_key   TEXT NOT NULL,                       -- FK 없음(review_findings 180일 > sessions 30일)
  review_id     TEXT NOT NULL,                       -- exitedReviewMode item id 또는 exec run id
  ts            TEXT NOT NULL,
  priority      INTEGER,                             -- 0..3, NULL=미분류
  title         TEXT NOT NULL,
  body          TEXT,                                -- ≤ 2 KiB
  file_path     TEXT,
  line_start    INTEGER,
  line_end      INTEGER,
  confidence    REAL,
  source        TEXT NOT NULL                        -- app_server_text | exec_schema | github_pr
);
CREATE INDEX review_findings_prio_idx ON review_findings(priority, ts);

CREATE TABLE adapter_state (
  agent_kind  TEXT PRIMARY KEY,
  status      TEXT NOT NULL,                         -- connected | degraded | disconnected | not_configured
  mode        TEXT,
  detail      TEXT,
  updated_at  TEXT NOT NULL
);

CREATE TABLE audit_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           TEXT NOT NULL,
  actor        TEXT NOT NULL,                        -- system | desktop_user | device:<id> | adapter:<kind>
  action       TEXT NOT NULL,                        -- pairing_started | pairing_confirmed | pairing_rejected | device_paired | device_revoked | hooks_installed | hooks_removed | identity_regenerated | cert_rotated | remote_approval_paused | link_disabled | link_enabled | firewall_rule_created | firewall_rule_removed | risk_accepted | retention_pruned
  target       TEXT,
  details_json TEXT
);
CREATE INDEX audit_ts ON audit_log(ts);

CREATE TABLE settings (                              -- 비밀 없음. 금지 키(security.md §9)는 쓰기 거부
  key         TEXT PRIMARY KEY,
  value_json  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
```

---

## 2. 핵심 쿼리 규약

| 동작 | SQL(개념) |
| --- | --- |
| 승인 적용(단일 전이) | `UPDATE approvals SET status='resolved', outcome=?, resolved_by=?, resolved_at=?, resolved_device_id=?, decision_msg_id=?, decision_auth_json=? WHERE request_id=? AND status='pending' AND expires_at > ?` — 영향 행 0 → `ALREADY_RESOLVED`. 같은 트랜잭션에서 `decisions`·`approval_audit` INSERT 후 커밋, **그 다음** 어댑터 응답 |
| 만료 타이머 | `UPDATE approvals SET status='expired', outcome='expired', resolved_by='timeout', resolved_at=? WHERE status='pending' AND expires_at <= ?` → 영향 행마다 `approval_resolved{expired}` 스트림 |
| 데몬 시작 | `UPDATE approvals SET status='expired', outcome='expired', resolved_by='system', resolved_at=? WHERE status='pending'` |
| 중복 훅 병합 | 단일 writer 안에서 `SELECT request_id FROM approvals WHERE session_key=? AND agent_id=? AND tool_name=? AND tool_input_sha256=? AND status='pending' AND created_at >= (now − 2s)` → 있으면 새 HTTP 핸들을 같은 요청에 추가 구독, 없으면 새 카드 INSERT. **`agent_id`가 다르거나 2초 창 밖이면 병합하지 않는다**(병렬 서브에이전트의 동일 명령이 한 번의 승인으로 두 번 실행되는 것을 막음) |
| 재생 | `SELECT seq, msg_type, payload_json, expires_at FROM stream WHERE seq > ? ORDER BY seq` — `approval_request`는 `expires_at <= now` 또는 해당 `approvals.status != 'pending'`이면 `approval_resolved`로 치환 |
| 멱등 결정 | `SELECT 1 FROM decisions WHERE request_id=? AND actor=? AND verify_result='APPLIED' AND (id=? OR id LIKE '?#%')` → **같은 요청·같은 행위자의 이미 적용된 결정**이면 재적용 없이 `decision_result{APPLIED}` 재응답. `decisions.id`는 폰이 고른 봉투 id라 유일하지 않을 수 있으므로, 이미 쓰인 id의 새 시도는 `<id>#<n>`으로 저장한다(거부된 시도가 같은 id의 다음 유효한 결정을 막지 못함) |
| 이벤트 페이지(`events_request`) | `SELECT … FROM events WHERE seq < :before_seq [AND session_key = :k] [AND kind IN (…≤16)] ORDER BY seq DESC LIMIT :limit(≤100)` — `stream`이 아니라 `events`(§3 보존 기간)에서 읽는다. 응답 바이트 예산 초과 시 `detail_json`을 빼고, 그래도 넘으면 행 수를 줄이고 `has_more=true` |
| `hello` | `SELECT token_hash, revoked_at FROM devices WHERE device_id = ?` → 상수시간 비교 |

---

## 3. 보존 정책 (`store::retention`, 시작 시 + 매시간)

| 데이터 | 규칙 |
| --- | --- |
| `events` | 14일 초과 또는 100,000행 초과분 삭제(오래된 순). `kind IN ('turn_failed','agent_error','test_failed','approval_*','review_*','turn_completed')`는 30일. 세션당 최근 200건은 기간과 무관하게 유지 |
| `stream` | **`max(48시간, 최신 10,000행)`** 을 유지한다 — 즉 '48시간보다 오래됐고 **동시에** 최신 10,000행 밖'인 행만 삭제. 관찰 이벤트(PreToolUse/PostToolUse)가 폭주해도 10,000행이 수 분에 불과해지지 않도록 하한은 48시간이다. 단 **크기 상한**(기본 64 MiB, `payload_json` 합계)을 넘으면 오래된 행부터 추가 삭제하며 이때는 창이 48시간보다 짧아질 수 있다. **재동기화 결과**: `hello.last_seq`가 남은 최소 seq보다 작으면 `welcome.resync.mode=snapshot`(상태는 스냅샷으로 복구, 놓친 타임라인은 `events_request`로 `events` 테이블에서 조회). 창 부족은 데이터 손실이 아니라 '리플레이 대신 스냅샷'으로 귀결된다 |
| `approvals.details_json` | **7일 후 NULL**. 행은 90일(pending 제외) |
| `decisions`, `approval_audit`, `audit_log` | 365일. `approvals` 행이 먼저 삭제돼도 남는다(FK·CASCADE 없음). `approval_audit.opened` 스냅샷이 도구명·위험 등급·입력 해시를 보존 |
| `sessions` | `ended_at` 30일 경과 시 삭제 — **다른 테이블로 연쇄 삭제하지 않는다**(`events`/`approvals`/`review_findings`는 각자의 규칙으로만 삭제) |
| `review_findings` | 180일 |
| `pairings` | 만료 24시간 후 삭제 |
| `devices` | 폐기 후 365일(감사 참조용), `revoked_reason=inactive_90d`는 90일 미접속 자동 폐기(설정) |
| 로그 파일 | 일 단위 롤링, 최근 7개 파일(`tracing-appender`, `agentnest-core::logging`) |
| **시계 점프 방어** | 모든 연령 규칙은 "지금"을 **저장된 가장 최신 타임스탬프 + 2일**로 제한한다(`RetentionConfig::max_clock_advance_days`). 시스템 시계가 10년 앞으로 튀어도 평소 일정이 지우지 않을 행은 지워지지 않는다. 데이터가 오래 안 들어오면 정리가 기다릴 뿐이고 새 행이 들어오면 따라잡는다. 한계: 틀린 시계가 찍은 새 행은 "가장 최신"을 끌어올린다(처음부터 틀린 시계는 알아채지 못함) |
| 유지보수 | 주 1회 `PRAGMA wal_checkpoint(TRUNCATE)`, 월 1회 유휴 시 `VACUUM`. DB 500 MiB 초과 시 가장 오래된 `events`부터 추가 삭제 + 경고 |

**삭제 독립성 불변식**: 어떤 보존 규칙도 다른 테이블의 행을 암묵적으로 지우지 않는다. 이는 PRD §9 '승인과 거절의 실제 처리 결과 확인'의 근거인 `decisions`/`approval_audit`이 세션 정리(30일)나 승인 행 정리(90일)와 함께 사라지는 것을 막기 위함이다(`PRAGMA foreign_keys=ON`이어도 위 컬럼에는 FK 자체가 없다).

DB 파일(`agentnest.db`, `-wal`, `-shm`)은 Unix에서 `0600`으로 생성·보정한다(데이터 디렉터리 `0700`). 백업/이전: DB에는 폐기 가능한 공개 정보·해시만 있어 사용자가 복사해도 자격 증명 재사용은 불가(A5). 개인키는 DB 밖 ACL 파일(→ Phase 3 DPAPI).

---

## 4. 테스트

- `MIGRATIONS.validate()`; 임시 DB(`tempfile 3.27.0`)로 전 마이그레이션 적용. **스키마 린트 테스트**: DDL에 `ON DELETE CASCADE`가 한 줄도 없고(`approvals`/`decisions`/`approval_audit`/`review_findings`/`events`에 `REFERENCES sessions|approvals` 없음) `sessions.remote_approval` CHECK 값이 `protocol.md` §5.3 enum과 같다.
- **보존 회귀 테스트(blocker 대응)**: 가상 시계로 세션 종료 → 승인 1건(resolved)·결정·감사·`review_findings`·`events` 생성 → **31일 경과** + `retention::run` → `sessions` 행은 삭제되지만 `approvals`·`decisions`·`approval_audit`(opened 스냅샷 포함)·`review_findings`는 **모두 남아 있음** → 91일: `approvals` 삭제, `decisions`/`approval_audit` 잔존 → 181일: `review_findings` 삭제 → 366일: `decisions`/`approval_audit` 삭제.
- 내구성 테스트: 승인 적용 트랜잭션 직전 `PRAGMA synchronous`가 `FULL`이고 커밋 뒤 `NORMAL`로 복귀(`PRAGMA synchronous` 조회).
- 스트림 보존: 48시간 안의 행은 10,000행을 넘어도 삭제되지 않고(`max` 규칙), 크기 상한 초과 시에만 앞당겨 삭제되며 그 뒤 `last_seq`가 창 밖이면 `resync=snapshot`.
- 이벤트 페이지: `events_request` 쿼리가 `before_seq` 경계(배타)·`kinds` 필터·`limit ≤ 100`·바이트 예산(detail 제거 → 행 축소)을 지킨다.
- 중복 병합: 같은 key 2건이 2초 안이면 카드 1장, `agent_id`가 다르면 2장, 같은 key라도 2초 밖이면 2장.
- 조건부 UPDATE 원자성(동시 결정 2건 → 1건만 통과), 데몬 시작 시 pending→expired, 재생 치환 규칙, 보존 정책 경계(7일 NULL, 48h stream), `details_json`에 `tool_input.content` 전체가 들어가지 않음(길이 상한 테스트), 트랜잭션 중 패닉 시 롤백.
