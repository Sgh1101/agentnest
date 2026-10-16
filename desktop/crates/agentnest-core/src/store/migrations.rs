//! rusqlite_migration migrations (storage.md DDL).
//!
//! The SQL of each migration is copied **verbatim** from the DDL block of `docs/storage.md` section 1 (one migration
//! per `-- ===== M00x` marker). A test compares these constants with the document, so editing one without the other
//! fails the build.
//!
//! There is deliberately no `ON DELETE CASCADE` anywhere: tables with different retention periods must never delete
//! each other's rows (storage.md "FK 원칙"; the lint tests in this module enforce it).

use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

/// M001: see docs/storage.md section 1.
pub const M001: &str = r##"-- ===== M001: 신원·기기·페어링 =====
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
"##;

/// M002: see docs/storage.md section 1.
pub const M002: &str = r##"-- ===== M002: 프로젝트·세션 =====
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
"##;

/// M003: see docs/storage.md section 1.
pub const M003: &str = r##"-- ===== M003: 이벤트·스트림 =====
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
"##;

/// M004: see docs/storage.md section 1.
pub const M004: &str = r##"-- ===== M004: 승인 =====
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
"##;

/// M005: see docs/storage.md section 1.
pub const M005: &str = r##"-- ===== M005: 리뷰·어댑터·설정·감사 =====
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
"##;

/// All migrations in order.
pub const ALL: [&str; 5] = [M001, M002, M003, M004, M005];

/// The migration set. `Migrations::to_latest` stores the applied count in `PRAGMA user_version`.
pub fn migrations() -> Migrations<'static> {
    Migrations::new(ALL.iter().map(|sql| M::up(sql)).collect())
}

/// Applies all pending migrations.
pub fn migrate(conn: &mut Connection) -> Result<(), rusqlite_migration::Error> {
    migrations().to_latest(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage_doc_ddl() -> Vec<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../docs/storage.md");
        // Normalise CRLF so the check also holds on a Windows checkout with autocrlf.
        let doc = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
        let start = doc.find("```sql\n").unwrap() + "```sql\n".len();
        let end = start + doc[start..].find("\n```").unwrap();
        let sql = &doc[start..end];
        let mut parts: Vec<String> = Vec::new();
        for line in sql.lines() {
            if line.starts_with("-- ===== M0") {
                parts.push(String::new());
            }
            if let Some(last) = parts.last_mut() {
                last.push_str(line);
                last.push('\n');
            }
        }
        parts
    }

    #[test]
    fn migrations_are_valid() {
        migrations().validate().unwrap();
    }

    #[test]
    fn migrations_equal_the_documented_ddl_verbatim() {
        let doc = storage_doc_ddl();
        assert_eq!(doc.len(), ALL.len());
        for (i, (d, code)) in doc.iter().zip(ALL).enumerate() {
            assert_eq!(
                d.trim_end(),
                code.trim_end(),
                "M00{} differs from docs/storage.md",
                i + 1
            );
        }
    }

    #[test]
    fn no_cascade_and_no_cross_retention_foreign_keys() {
        let all = ALL.join("\n").to_uppercase();
        assert!(
            !all.contains("ON DELETE"),
            "no ON DELETE action may exist (not even SET NULL)"
        );
        assert!(!all.contains("CASCADE"));
        // events / approvals / decisions / approval_audit / review_findings never reference sessions or approvals
        for line in ALL.join("\n").lines() {
            let l = line.to_lowercase();
            if let Some(code) = l.split("--").next() {
                assert!(
                    !(code.contains("references sessions")
                        || code.contains("references approvals")),
                    "forbidden foreign key: {line}"
                );
            }
        }
    }

    #[test]
    fn sessions_remote_approval_check_matches_the_protocol_enum() {
        let sql = M002;
        let start = sql.find("remote_approval").unwrap();
        let line_end = sql[start..]
            .find('\n')
            .map(|i| start + i)
            .unwrap_or(sql.len());
        let chunk = sql[start..line_end].split("--").next().unwrap_or("");
        for v in agentnest_protocol::RemoteApproval::KNOWN {
            assert!(chunk.contains(&format!("'{v}'")), "CHECK lacks {v}");
        }
        assert_eq!(
            chunk.matches('\'').count() / 2,
            agentnest_protocol::RemoteApproval::KNOWN.len() + 1 /* default 'available' */
        );
    }

    #[test]
    fn applies_to_a_fresh_database_and_is_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 5);
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for t in [
            "adapter_state",
            "approval_audit",
            "approvals",
            "audit_log",
            "decisions",
            "devices",
            "events",
            "pairings",
            "pc_identity",
            "projects",
            "review_findings",
            "sessions",
            "settings",
            "stream",
        ] {
            assert!(
                tables.iter().any(|x| x == t),
                "missing table {t}: {tables:?}"
            );
        }
    }
}
