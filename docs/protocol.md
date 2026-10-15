# AgentNest 와이어 프로토콜 v1 (PC ↔ 폰)

- 상태: 확정(리드 종합본) — 2026-10-15
- 단일 진실 공급원은 `protocol/schema/**` JSON Schema(draft 2020-12)이며, 이 문서는 그 사람이 읽는 판이다. **코드와 문서가 어긋나면 `protocol/schema` → 이 문서 → Rust → Kotlin → 예제/테스트 순으로 함께 고친다.**
- 보안 의미(바인딩·만료·fail-closed)는 `security.md`가 규범이다. 이 문서는 형식을 정의한다.

---

## 1. 전송·프레이밍

| 항목 | 값 |
| --- | --- |
| 전송 | **WSS 1개**: `wss://<host>:47832/v1/link`. 평문 `ws://`, HTTP 폴링, mDNS 응답 등 인증 없는 수신 경로는 없다 |
| TLS | 자가서명 ECDSA P-256(rcgen 0.14.10, ring). 폰은 QR의 **SPKI SHA-256 핀과 정확히 일치하는 리프 인증서만** 신뢰(`security.md` §3) |
| 서브프로토콜 | `Sec-WebSocket-Protocol: agentnest.v1` (서버는 불일치 시 핸드셰이크 거부) |
| 프레임 | UTF-8 **텍스트 프레임 1개 = JSON 객체 1개**. 바이너리 프레임은 1003으로 닫음 |
| 크기 상한 | 서버→폰 256 KiB, 폰→서버 32 KiB. 초과 시 1009 |
| 연결 상태(인증 전) | 연결은 상태기계다. **`PreAuth`**: 서버는 `challenge` **한 프레임만** 보내고, 폰은 유효한 `pair` 또는 `hello` **한 프레임만** 보낼 수 있다(`ping` 포함 다른 타입은 즉시 4001). **5초 타이머는 '유효한 `pair`/`hello` 수신'까지**만 덮는다(인증 완료까지가 아님). 유효한 `hello` → 인증 완료. 유효한 `pair` → **`PairPending`**: 서버가 보낼 수 있는 것은 `pair_pending`/`pair_result`/`error`뿐, 폰이 보낼 수 있는 것은 중단용 `unpair{pairing_id}`와 close뿐이며 **그 밖의 폰 프레임은 4001**. `PairPending`의 상한은 `confirm_timeout_ms`(60초) — 초과 시 `E_PAIR_REJECTED` → 4002. 이 두 상태 밖의 어떤 정보(PC 이름·세션·이벤트)도 나가지 않는다 |
| 시각 | RFC 3339, 밀리초, UTC. **보안 판단은 서버 시계만** 사용. 폰은 `welcome.server_time`으로 skew를 보정해 표시에만 쓴다 |

---

## 2. 봉투(envelope)

```json
{
  "v": 1,
  "type": "event",
  "id": "01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f",
  "ts": "2026-10-15T09:12:33.120Z",
  "seq": 1842,
  "payload": { }
}
```

| 필드 | 타입 | 필수 | 설명 |
| --- | --- | --- | --- |
| `v` | int | 예 | 프로토콜 메이저 버전. 현재 `1`. 불일치 시 `error{E_PROTO_VERSION}` 후 4010 |
| `type` | string | 예 | 메시지 타입(§3). **알 수 없는 타입은 조용히 무시**(오류 없음, 전방 호환) |
| `id` | UUIDv7 | 예 | 송신 측 발급. 중복 수신 제거·`in_reply_to` 참조용. 보안 의미 없음 |
| `ts` | RFC3339 | 예 | 송신 시각 |
| `seq` | int64 | 재생 가능 메시지에만 | **PC 전역 단조 증가**(기기 무관). `snapshot`, `event`, `session_state`, `approval_request`, `approval_resolved`, `adapter_status`에 존재. 재동기화 키(§8) |
| `payload` | object | 예 | 타입별 본문. 알 수 없는 필드는 무시(Rust `#[serde(default)]`, `deny_unknown_fields` 미사용; Kotlin `ignoreUnknownKeys = true`) |

버전 정책: 필드·enum 값 **추가**는 `v`를 올리지 않는다(`welcome.protocol.minor` 증가). 의미 변경·삭제·필수 필드 추가는 `v: 2`. 알 수 없는 enum 값의 처리 규칙은 §10.

---

## 3. 메시지 목록

### 3.1 폰 → PC

| type | 인증 전 허용 | 용도 |
| --- | --- | --- |
| `pair` | 예(1회) | QR 비밀 소지 증명 + 기기 공개키 등록 |
| `hello` | 예(1회) | 등록 기기 인증(디바이스 토큰 + 챌린지 에코) + 재동기화 커서 |
| `ack` | 아니오 | 수신 확인(`through_seq`, 승인 카드 id) |
| `ping` | 아니오 | 앱 레벨 하트비트 |
| `snapshot_request` | 아니오 | 전체 스냅샷 재요청 |
| `events_request` | 아니오 | 과거 이벤트 페이지 조회(세션 상세·활동 타임라인, §4.15) |
| `decision` | 아니오 | 승인 결정 |
| `approval_seen` | 아니오 | 승인 카드가 화면에 표시됨(배달 확인, UI용) |
| `unpair` | 부분(`PairPending`에서 `pairing_id`로만) | 폰 측 자진 등록 해제 / 페어링 중단 |

### 3.2 PC → 폰

| type | `seq` | 용도 |
| --- | --- | --- |
| `challenge` | 없음 | 연결 직후 서버가 보내는 유일한 `PreAuth` 메시지 |
| `pair_pending` | 없음 | 소지 증명 통과, PC 화면 확인 대기(SAS). **`PairPending` 상태 진입 메시지** |
| `pair_result` | 없음 | 페어링 결과(성공 시 `device_id`, `device_token`) |
| `welcome` | 없음 | 인증 완료. PC 정보·능력·재동기화 방식·정책 |
| `snapshot` | 있음 | 전체 상태(그 시점까지의 스트림을 대체) |
| `event` | 있음 | 정규화 `AgentEvent` 1건 |
| `session_state` | 있음 | 세션별 파생 상태(캐릭터·카드 입력) |
| `approval_request` | 있음 | 승인 카드 |
| `approval_resolved` | 있음 | 승인 종결(누가·어떻게·전달·관찰 결과) |
| `decision_result` | 없음 | 내 `decision`의 처리 결과(적용/거부 사유) |
| `events_page` | 없음 | `events_request`의 응답 페이지(§4.15) |
| `hosts_update` | 없음 | PC 주소 목록 갱신 통지(§4.5) |
| `adapter_status` | 있음 | 어댑터(Claude Code/Codex) 건강 상태 |
| `pong` | 없음 | `ping` 응답 |
| `error` | 없음 | 프로토콜/요청 오류 |
| `bye` | 없음 | 서버 측 종료 통지(폐기·종료·재시작) 후 close |

---

## 4. 메시지별 정의

### 4.1 `challenge` (PC→폰, `PreAuth` 단계의 유일한 서버 프레임)

```json
{ "v": 1, "type": "challenge", "id": "…", "ts": "…", "payload": {
  "challenge_b64": "cXk4Z1l0d2VyN3U4aW9wMQ==",
  "pc_id": "pc_5c1d9a2b7e3f4a60",
  "server_time": "2026-10-15T09:12:33.100Z",
  "expires_in_ms": 5000
} }
```

| 필드 | 설명 |
| --- | --- |
| `challenge_b64` | 16바이트 CSPRNG. 연결마다 새로 발급. `pair`/`hello`가 에코해야 함 |
| `pc_id` | QR에 이미 있는 값(노출 아님). PC 이름·버전은 **없다** |
| `expires_in_ms` | 이 시간 안에 유효한 `pair`/`hello`를 **받지 못하면** 4001(이후 `PairPending` 60초 등 다음 상태의 시간 제한은 별도, §1) |

### 4.2 `pair` (폰→PC)

```json
{ "v": 1, "type": "pair", "id": "…", "ts": "…", "payload": {
  "pairing_id": "p_3f9c2b1ea8d04c77",
  "challenge_b64": "cXk4Z1l0d2VyN3U4aW9wMQ==",
  "device": { "name": "Galaxy S25", "platform": "android", "model": "SM-S938N", "os_version": "16", "app_version": "0.1.0" },
  "device_pubkey_spki_b64": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…",
  "proof_b64": "HMAC-SHA256(pairing_secret, canonical_pair_bytes) 32바이트",
  "protocol": 1
} }
```

| 필드 | 설명 |
| --- | --- |
| `pairing_id` | QR의 값 |
| `challenge_b64` | 서버 `challenge` 에코 |
| `device_pubkey_spki_b64` | 폰 Keystore EC P-256 공개키(X.509 SPKI DER). Phase 1에서는 **저장만**(Phase 3 결정 서명용). 선택 필드 |
| `proof_b64` | `HMAC-SHA256(key = pairing_secret, msg = canonical_pair_bytes)`. `pairing_secret`은 QR에만 존재하고 **와이어에 실리지 않는다** |

`canonical_pair_bytes`(모든 가변 필드는 **u16 BE 길이 프리픽스**):

```text
"agentnest-pair-v1" ‖ L(pc_id) pc_id ‖ L(pairing_id) pairing_id ‖ L(challenge) challenge(16B raw)
 ‖ L(device_name) device_name(UTF-8 NFC, ≤64B) ‖ L(spki) spki(DER raw, 없으면 L=0)
```

인코더는 `agentnest-protocol::canonical`(Rust)와 `dev.agentnest.core.crypto.Canonical`(Kotlin)에 있고 `protocol/vectors/pair.json`으로 바이트 단위 일치를 검증한다. `pairing_secret` 은 QR 의 base64url 을 디코드한 **원시 32바이트**가 HMAC 키다. `device_name` 의 NFC 정규화와 64바이트 상한 검사는 **폰이 `pair` 를 보내기 전에** 하고(`device.name` 과 HMAC 입력에 같은 문자열을 쓴다), PC 는 받은 문자열의 UTF-8 바이트를 그대로 쓴다(재정규화하지 않음; 64바이트 초과는 `E_BAD_MESSAGE`). SAS 의 `challenge`·`spki` 도 원시 바이트이며 길이 프리픽스는 붙이지 않는다.

### 4.3 `pair_pending` / `pair_result` (PC→폰)

```json
{ "type": "pair_pending", "payload": { "pairing_id": "p_…", "sas": "482915", "confirm_timeout_ms": 60000 } }
{ "type": "pair_result", "payload": { "ok": true, "device_id": "dev_8a1f3c…", "device_token": "Zr9…(base64url 32B, 1회만 전송)",
                                      "pc": { "pc_id": "pc_5c…", "name": "DESKTOP-HOME", "app_version": "0.1.0" } } }
{ "type": "pair_result", "payload": { "ok": false, "error_code": "E_PAIR_REJECTED" } }
```

- `sas` = `HMAC-SHA256(pairing_secret, "sas" ‖ challenge ‖ spki)` 앞 4바이트 BE `% 1_000_000`을 6자리 0-패딩. **폰은 PC가 보낸 `pair_pending.sas`를 그대로 표시하지 않는다.** 폰은 `pairing_secret`·자신이 받은 `challenge`·자신의 SPKI로 SAS를 **로컬에서 계산**해 **그 값을 화면에 표시**하고, `pair_pending.sas`와 상수시간 비교한다. **불일치하면** 폰이 `unpair{pairing_id}`(중단)를 보내고 연결을 닫은 뒤 로컬 페어링 상태를 폐기하며 "PC에서 받은 확인 숫자가 달라요. 페어링을 중단했어요"를 표시한다(PC는 `outcome=failed`로 소각하고 모달을 닫는다). PC가 보낸 값을 그대로 보여주면 불일치를 감지할 수 없는 동어반복이 되므로 금지한다. 사용자는 PC 모달의 숫자와 **폰이 계산한** 숫자를 눈으로 비교하고 **PC에서 [승인]** 해야 `pair_result{ok:true}`가 온다.
- 성공 시 서버는 이 연결을 인증된 것으로 승격하고 곧바로 `welcome`을 보낸다(별도 `hello` 불필요).
- 실패 코드: `E_PAIR_FAILED`(미지 pairing_id·증명 불일치·만료 — 구분 없이 동일), `E_PAIR_REJECTED`(PC 사용자가 거절 또는 60초 무응답), `E_PAIR_BUSY`(다른 페어링 확인 대기 중). 실패 후 1초 지연 후 4002. `PairPending` 중 허용되지 않는 폰 프레임은 4001.

### 4.4 `hello` (폰→PC)

```json
{ "v": 1, "type": "hello", "id": "…", "ts": "…", "payload": {
  "device_id": "dev_8a1f3c…",
  "device_token": "Zr9…",
  "challenge_b64": "cXk4Z1l0d2VyN3U4aW9wMQ==",
  "protocol": 1,
  "app_version": "0.1.0",
  "last_seq": 1830,
  "wants_snapshot": false
} }
```

- 서버 검사 순서: 기기 존재·미폐기 → 토큰 해시 상수시간 비교 → `challenge_b64`가 이 연결에서 발급한 값 → 통과 시 `welcome`. 실패는 모두 `error{E_AUTH_FAILED}`(원인 구분 없음) → 1초 지연 → 4002. 폐기된 기기만 `E_DEVICE_REVOKED` → 4003(폰이 토큰을 지우도록).
- Phase 3: `signature_b64`(Keystore ECDSA over `"agentnest-hello-v1" ‖ device_id ‖ pc_id ‖ challenge`) 추가 예정. v1 스키마에 선택 필드로 두되 Phase 1 서버는 무시한다.

### 4.5 `welcome` (PC→폰)

```json
{ "v": 1, "type": "welcome", "id": "…", "ts": "…", "payload": {
  "pc": { "pc_id": "pc_5c…", "name": "DESKTOP-HOME", "app_version": "0.1.0", "os": "windows" },
  "protocol": { "version": 1, "minor": 0, "min_client_version": "0.1.0" },
  "hosts": { "addresses": ["192.168.0.10", "10.8.0.2"], "port": 47832 },
  "capabilities": ["events", "approvals", "snapshot", "resync", "events_history", "claude_code", "codex_observe"],
  "server_time": "2026-10-15T09:12:33.400Z",
  "heartbeat": { "client_ping_interval_s": 30, "server_idle_close_s": 90 },
  "resync": { "mode": "replay", "from_seq": 1831, "to_seq": 1842 },
  "limits": { "approval_ttl_s": 120, "max_frame_bytes": 262144, "snapshot_max_bytes": 196608, "events_page_max_bytes": 196608 },
  "policy": { "remote_approval": { "critical": "extra_confirmation", "high": "hold" }, "deny_requires_auth": false }
} }
```

- `resync.mode`: `replay`(이어서 `from_seq..to_seq` 재전송) | `snapshot`(창 밖 → 곧바로 `snapshot`) | `none`(최신).
- `capabilities`에 없는 기능의 UI는 폰이 숨긴다. `events_history` = `events_request`/`events_page` 지원. **Codex 승인 capability는 경로별로 둘이다**: `codex_approve`(app-server 경로 — flag `codex-daemon-observer` 활성 + C1~C4 통과 시에만), `codex_approve_hooks`(hooks `PermissionRequest` 경로 — C6 통과 후에만; **`deny_and_stop`이 제공되지 않는다**, §6.1). 둘 다 없으면 Codex 카드는 관찰 전용이다.
- `approval_ttl_s`는 **유효 TTL**이다(설정값과 설치된 훅 `timeout − 30` 중 작은 값, `integrations/claude-code.md` §2).
- **`hosts`(PC 주소 갱신 경로)**: 인증된 `welcome`마다 PC의 현재 비루프백 LAN 주소 목록과 포트를 싣는다. 폰은 이를 **저장하고 QR의 `hosts[]`보다 먼저 시도**한다(성공 호스트를 선두로). 폰은 사설 대역(10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)의 주소만, 최대 8개 저장하며 그 밖의 값은 무시한다(핀 고정 TLS + `hello` 인증을 통과한 PC가 준 값이라도 범위를 제한). 연결 중 PC의 주소가 바뀌면 PC는 연결된 기기에 `hosts_update{addresses, port}`(seq 없음, 비재생)를 보내고 같은 규칙으로 저장한다.
- **한계(문서화된 사실)**: 단일 NIC의 DHCP 재할당처럼 **기존 주소가 사라지는** 변경은 연결이 먼저 끊겨 `hosts_update`가 닿지 않는다. 이 경우 폰은 저장된 옛 주소를 순회하다 `PcUnreachable`이 되며, 복구는 (1) 폰의 **'IP 직접 입력'**(핀 검증 + `hello` 인증은 그대로 — 재페어링 불필요), (2) PC에서 '기기 추가' QR을 폰이 다시 스캔하되 `pc_id`·`spki_pin`이 저장값과 같으면 **주소만 갱신**(`pair` 미전송), (3) 예방으로 공유기 DHCP 예약/고정 IP 권장이다. mDNS/`agentnest.local`은 쓰지 않는다(Android가 `.local`을 일반 DNS로 풀지 못하고 PC에 응답기가 없음 — §1). 시나리오 검증은 Phase 0 P16.

### 4.6 `snapshot` (PC→폰)

```json
{ "v": 1, "type": "snapshot", "id": "…", "ts": "…", "seq": 1842, "payload": {
  "sessions": [ { "...": "session_state.payload 와 동일 구조 (§5.3)" } ],
  "pending_approvals": [ { "...": "approval_request.payload 와 동일 구조 (§6.1), 만료 전인 것만" } ],
  "recent_errors": [ { "...": "AgentEvent severity>=warning 최대 5건" } ],
  "recent_events": [ { "...": "AgentEvent 최대 50건, seq 오름차순 (바이트 예산 초과 시 detail 제거)" } ],
  "adapters": [ { "agent_kind": "claude_code", "status": "connected", "mode": "hooks_http", "detail": "hooks installed (user settings)", "updated_at": "…" },
                { "agent_kind": "codex", "status": "degraded", "mode": "hooks_cli", "detail": "daemon observer disabled", "updated_at": "…" } ],
  "focus": { "session_key": "claude_code:7f1e…", "state": "testing" },
  "pending_approval_ids_complete": ["ar_01929f1a-…", "ar_01929f1b-…"],
  "pending_followup": 0,
  "truncated": { "sessions": false, "pending_approvals": false, "recent_events": true, "recent_events_detail": true, "approval_previews": false }
} }
```

- **크기 상한은 바이트 기준**이다: `limits.snapshot_max_bytes`(기본 **192 KiB** = 196,608; 프레임 상한 256 KiB 아래). 항목 수 상한(세션 20개, 보류 승인 20개, 최근 이벤트 50개)은 그대로 두되 **최대 크기 승인 20건(명령 2,000자 + `diff_preview` 4 KiB + 경로 50개 ≈ 13~19 KiB/건)만으로도 192 KiB를 넘을 수 있으므로** 아래 **절단 순서**를 정한다. 보류 승인은 **절대 목록에서 조용히 잘라내지 않는다.**
  1. `recent_events[].detail` 제거(`truncated.recent_events_detail=true`).
  2. `pending_approvals[].details.diff_preview`·`content_preview`를 `null`로(`details.truncated=true`, `truncated.approval_previews=true`). `command`·`file_paths`·`risk`·바인딩 필드는 유지.
  3. `recent_events` 개수를 50→20→0으로 축소(`truncated.recent_events=true`).
  4. 세션 요약 축소: `recent_files`/`recent_commands` 비우기 → 보류 승인·`awaiting_*`가 없는 세션 중 `last_event_at`이 오래된 순으로 제외(`truncated.sessions=true`).
  5. 그래도 넘으면 **본문이 맞지 않는 승인 카드를 `pending_approvals[]`에서 빼되, 스냅샷 직후 개별 `approval_request` 프레임(원래 `seq`·전체 바인딩 포함)으로 이어 보낸다**(`pending_followup`=그 개수). 한 승인 카드는 단독으로 항상 프레임 상한 안이다.
- **`pending_approval_ids_complete[]`**: 스냅샷 시점의 **모든** 보류 승인 `request_id`(잘림 여부와 무관, 건당 ≈ 40바이트). 폰은 `pending_approvals`를 교체하되 **이 목록에 없는 카드만** "PC에서 처리됨/시간 초과"로 정리한다. 목록에는 있지만 본문이 아직 없는 카드는 **"불러오는 중" 상태(버튼 비활성)** 로 두고 후속 `approval_request`를 기다린다(후속 프레임은 `request_id`로 중복 제거). 그래서 잘림 때문에 아직 유효한 카드가 '처리됨'으로 오표시되지 않는다.
- **`snapshot.seq` = 전송 시점의 PC 전역 최대 `seq`이며 `seq`를 소비하지 않는다**(스냅샷은 `stream`에 저장되지 않고 새 번호를 발급받지 않는다). 폰은 이를 `last_seq`로 삼고 이후 `seq > snapshot.seq`인 메시지만 적용한다. `recent_events`의 모든 `seq`는 `snapshot.seq` 이하다.
- 폰은 `sessions`·`pending_approvals`를 **교체**하고(병합 아님, 단 위 `ids_complete` 규칙으로), `recent_events`는 `seq`로 중복 제거 후 병합한다.
- 테스트(`agentnest-core::link`): **최대 크기 승인 20건**으로 스냅샷을 만들어 (a) 프레임이 `max_frame_bytes` 이하, (b) `pending_approval_ids_complete`가 20건 전부, (c) 어떤 승인도 목록에서 사라지지 않고 후속 프레임으로 전달됨, (d) 절단 순서(1→5)를 검증한다.
- 폰은 마지막 `snapshot`+이후 상태를 DataStore에 캐시해 콜드 스타트 시 "마지막 확인 N분 전"과 함께 즉시 렌더한다(스피너 금지).

### 4.7 `event` (PC→폰) — payload = `AgentEvent`(§5.1)

```json
{ "v": 1, "type": "event", "id": "…", "ts": "…", "seq": 1843, "payload": { "...": "AgentEvent" } }
```

### 4.8 `session_state` (PC→폰) — payload = `SessionState`(§5.3)

### 4.9 `approval_request` (PC→폰) — payload = `ApprovalRequest`(§6.1). 폰은 **즉시 `ack`** 해야 한다(§8.3).

### 4.10 `decision` (폰→PC)

```json
{ "v": 1, "type": "decision", "id": "c3d2…", "ts": "2026-10-15T09:12:40.510Z", "payload": {
  "request_id": "ar_01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f",
  "session_key": "claude_code:7f1e2d3c-…",
  "nonce_b64": "Kq2…(approval_request.nonce_b64 에코)",
  "tool_input_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "decision": "allow",
  "reason": null,
  "decided_at": "2026-10-15T09:12:40.500Z",
  "auth": { "method": "biometric", "authenticated_at": "2026-10-15T09:12:39.900Z" },
  "extra_confirmation": { "method": "hold", "completed": true }
} }
```

| 필드 | 설명 |
| --- | --- |
| `request_id`, `session_key`, `nonce_b64`, `tool_input_sha256` | 4중 바인딩. 전부 `approval_request`에서 받은 값을 에코. 폰은 해시를 계산하지 않는다 |
| `decision` | `allow` \| `deny` \| `deny_and_stop`. **`allow_for_session` 등 범위 확장 값은 v1에 존재하지 않는다**(스키마 enum 밖 → `E_BAD_MESSAGE`) |
| `reason` | 거부 사유(≤200자, 선택). Claude에게 `message`로 전달되므로 **PC가 정제한다**: NFC 정규화 → 제어 문자(U+0000–001F, U+007F–009F)·줄바꿈·U+2028/2029·양방향 제어(U+202A–202E, U+2066–2069) 제거(줄바꿈은 공백으로) → 200자 절단 → 고정 접두(`AgentNest: 사용자가 휴대폰에서 거부했습니다. 사유(사용자 입력): `)와 합친 뒤 JSON 직렬화기로만 인코딩(문자열 이어붙이기 금지). 정제 결과가 비면 `사유 없음` |
| `decided_at` | 폰 시계 + skew 보정. 서버는 `created_at − 60s .. now + 60s` 창 밖이면 거부 |
| `auth.method` | `biometric` \| `device_credential` \| `none`. `allow`·`deny_and_stop`에 `none`은 거부. **Phase 1에서는 핀 고정 TLS 채널 위의 폰 측 주장**이다(`security.md` §6.4 한계 명시) |
| `extra_confirmation` | `method` ∈ `hold` \| `hold_and_reconfirm`, `completed`. 요청의 `risk.extra_confirmation`과 같거나 강해야 함 |
| (Phase 3) `signature_b64` | ECDSA over `canonical_decision_bytes`. v1 선택 필드, Phase 1 서버는 무시 |

### 4.11 `decision_result` (PC→폰)

```json
{ "type": "decision_result", "payload": { "request_id": "ar_…", "in_reply_to": "c3d2…", "accepted": false, "reason": "EXPIRED",
                                          "message_ko": "요청 시간이 지나 PC에서 직접 처리하도록 넘겼어요." } }
```

`reason`: `APPLIED` | `UNKNOWN_REQUEST` | `ALREADY_RESOLVED` | `EXPIRED` | `BINDING_MISMATCH` | `INPUT_HASH_MISMATCH` | `NOT_ALLOWED` | `AUTH_REQUIRED` | `EXTRA_CONFIRMATION_REQUIRED` | `CLOCK_SKEW` | `PAUSED` | `DEVICE_REVOKED`. 한국어 문구 매핑은 §9.2.

### 4.12 `approval_resolved` (PC→폰)

```json
{ "v": 1, "type": "approval_resolved", "id": "…", "ts": "…", "seq": 1850, "payload": {
  "request_id": "ar_…",
  "session_key": "claude_code:7f1e…",
  "outcome": "allowed",
  "resolved_by": "phone",
  "resolved_device_id": "dev_8a1f3c…",
  "resolved_at": "2026-10-15T09:12:40.620Z",
  "delivery": "delivered",
  "observed_result": "unknown",
  "message_ko": "허용했어요. Claude가 명령을 실행해요."
} }
```

| 필드 | 값 |
| --- | --- |
| `outcome` | `allowed` \| `denied` \| `denied_and_stopped` \| `expired`(TTL 만료 → 로컬 위임) \| `handed_off_local`(폰 없음·끊김·데스크톱 버튼 → 로컬 위임) \| `superseded`(에이전트 쪽/다른 클라이언트가 먼저 처리·취소) \| `failed`(전달 실패) |
| `resolved_by` | `phone` \| `desktop` \| `timeout` \| `agent` \| `system` |
| `delivery` | `delivered`(훅 응답/JSON-RPC 응답 전송 완료) \| `not_delivered` |
| `observed_result` | `executed` \| `declined` \| `unknown`. 이후 관찰(PreToolUse/PostToolUse, Codex `item/completed`)로 갱신되면 **같은 `request_id`로 재전송**(멱등). PRD §9 "실제 처리 결과 확인"의 근거 |
| `message_ko` | 사람이 읽는 결과 한 줄(§9.2) |

### 4.13 `adapter_status` (PC→폰)

```json
{ "type": "adapter_status", "seq": 1851, "payload": { "agent_kind": "codex", "status": "connected", "mode": "hooks_cli", "detail": "codex hooks trusted", "updated_at": "…" } }
```

`status`: `connected` | `degraded` | `disconnected` | `not_configured`. `mode`: `hooks_http` | `hooks_cli` | `daemon_observer` | `rollout_tail` | `none`.

### 4.14 `ack` / `approval_seen` / `ping` / `pong` / `snapshot_request` / `unpair` / `error` / `bye`

```json
{ "type": "ack", "payload": { "through_seq": 1843, "approval_ids": ["ar_…"] } }
{ "type": "approval_seen", "payload": { "request_id": "ar_…", "seen_at": "…" } }
{ "type": "ping", "payload": { "sent_at": "…" } }
{ "type": "pong", "payload": { "in_reply_to": "…", "server_time": "…" } }
{ "type": "snapshot_request", "payload": { "reason": "pull_to_refresh" } }
{ "type": "unpair", "payload": { "device_id": "dev_…" } }
{ "type": "unpair", "payload": { "pairing_id": "p_…" } }
{ "type": "hosts_update", "payload": { "addresses": ["192.168.0.23"], "port": 47832 } }
{ "type": "error", "payload": { "code": "E_RATE_LIMITED", "message": "too many decisions", "message_ko": "잠시 후 다시 시도해 주세요.", "in_reply_to": "…", "fatal": false } }
{ "type": "bye", "payload": { "reason": "device_revoked", "reconnect": false, "message_ko": "PC에서 이 기기의 연결을 해제했어요." } }
```

`bye.reason`: `device_revoked` | `shutdown` | `restart` | `superseded_connection` | `unpaired`. `shutdown`에 `reconnect:false`가 오면(PC에서 '휴대폰 연결 끊기'를 켠 경우, `security.md` §3.3) 폰은 재연결 간격을 5분으로 늦추고 배너에 `message_ko`를 표시한다.

### 4.15 `events_request` / `events_page` — 과거 이벤트 조회

폰 화면(세션 상세 타임라인, 활동 전체 타임라인·날짜 구분선·필터)은 `snapshot.recent_events`(전역 50건)와 `stream`(48시간 창)을 넘는 이력을 필요로 하므로 **조회 메시지를 둔다**. 데스크톱의 Tauri `events_recent`와 같은 데이터이며 폰에 직접 노출되는 저장소는 `events` 테이블(`storage.md` §3: 14일/중요 종류 30일/세션당 최근 200건)이다.

```json
{ "v": 1, "type": "events_request", "id": "…", "ts": "…", "payload": {
  "session_key": "claude_code:7f1e…",
  "before_seq": 1830,
  "limit": 50,
  "kinds": ["turn_failed", "test_failed", "file_modified"]
} }
{ "v": 1, "type": "events_page", "id": "…", "ts": "…", "payload": {
  "in_reply_to": "…",
  "events": [ { "...": "AgentEvent, seq 오름차순" } ],
  "has_more": true,
  "next_before_seq": 1781,
  "detail_omitted": false
} }
```

| 필드 | 규칙 |
| --- | --- |
| `session_key` | 선택. 없으면 전역 |
| `before_seq` | 필수. **배타적** 상한(`seq < before_seq`). 처음 페이지는 `snapshot.seq + 1` |
| `limit` | 1~100(초과는 100으로 절단) |
| `kinds` | 선택, ≤16개. 알 수 없는 값은 무시 |
| 응답 크기 | `limits.events_page_max_bytes`(기본 192 KiB). 초과 시 먼저 각 이벤트의 `detail`을 제거(`detail_omitted=true`), 그래도 넘으면 이벤트 수를 줄이고 `has_more=true`. 결과가 없으면 `events:[]`, `has_more:false` |
| 속도 제한 | 기기당 **12건/분**(별도 버킷, `snapshot_request`와 같은 방식 — 초과 시 `E_RATE_LIMITED`, 3회 누적 시 4005). 인증 후에만 허용 |
| 성격 | `events_page`는 `seq`가 없는 비재생 메시지이며 `stream`에 저장되지 않는다. 폰은 페이지를 로컬 캐시(최근 N=200건)와 `seq`로 병합·중복 제거한다. `events_history` capability가 없으면 폰은 캐시된 최근 이벤트만 보여준다(`android.md` §2.3) |

---

## 5. 정규화 모델

### 5.1 `AgentEvent`

```json
{
  "event_id": "01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f",
  "seq": 1843,
  "ts": "2026-10-15T09:12:33.120Z",
  "agent_kind": "claude_code",
  "session_key": "claude_code:7f1e2d3c-…",
  "actor": { "agent_id": "def456", "agent_type": "Explore", "is_subagent": true },
  "project": { "project_key": "c:/dev/agentnest", "name": "agentnest", "path_hint": "…\\dev\\agentnest", "repo": "owner/agentnest", "branch": "feat/pairing" },
  "kind": "command_started",
  "category": "command",
  "severity": "info",
  "summary": { "headline": "테스트를 돌리고 있어요 (cargo test -p core)", "detail": "Run core tests." },
  "state_hint": "testing",
  "detail": { "tool_name": "Bash", "command": "cargo test -p agentnest-core", "description": "Run core tests", "command_class": "test", "cwd_hint": "…\\agentnest", "run_in_background": false },
  "source": { "channel": "claude_code.hook.http", "native_event": "PreToolUse",
              "native_ids": { "tool_use_id": "toolu_01ABC…", "prompt_id": "550e8400-…", "session_id": "7f1e2d3c-…" } },
  "redacted": false
}
```

| 필드 | 규칙 |
| --- | --- |
| `event_id` | UUIDv7 |
| `agent_kind` | `claude_code` \| `codex` \| `gemini_cli` \| `opencode` \| `other` |
| `session_key` | `<agent_kind>:<native_session_id>` (Claude `session_id`, Codex `thread.id`) |
| `actor` | 서브에이전트/팀원 컨텍스트(훅 `agent_id`/`agent_type` [검증], Codex `subAgentActivity`/`parentThreadId` [검증]) |
| `project.path_hint` | 마지막 2 세그먼트만(전체 경로는 PC DB에만). `project_key`는 소문자·`/` 정규화 |
| `category` | `lifecycle` \| `turn` \| `tool` \| `file` \| `command` \| `approval` \| `error` \| `review` \| `notification` \| `usage` \| `adapter` |
| `severity` | `debug` \| `info` \| `notice` \| `warning` \| `error` |
| `summary` | PC가 만든 한국어(`headline ≤ 40자`, `detail ≤ 200자`). 폰은 가공하지 않는다 |
| `state_hint` | 정규화기가 제안하는 상태(리듀서 입력). 없을 수 있음 |
| `detail` | kind별 바운드 객체(총 8 KiB, 문자열 필드 2 KiB). **파일 본문·stdout 전체·프롬프트 전문은 절대 없음** |
| `source.channel` | `claude_code.hook.http` \| `claude_code.hook.cli` \| `claude_code.statusline` \| `codex.hook.cli` \| `codex.app_server` \| `codex.rollout` \| `codex.exec_json` |
| `source.native_ids` | 원본 식별자 맵(문자열). 승인 결과 상관·중복 제거에 사용 |
| `redacted` | 마스킹이 일어났으면 `true` |
| **타임라인 전용 kind** | `approval_requested`, `approval_resolved`, `adapter_status` 3종은 같은 사실이 와이어 메시지 `approval_request`/`approval_resolved`/`adapter_status`로도 온다. **`AgentEvent` 형태는 타임라인 표시 전용이며 폰의 상태 입력(`NestReducer`)이 아니다** — 승인 카드·어댑터 배지는 전용 메시지로만 갱신한다. 두 형태가 겹쳐 보이지 않도록 이 3종의 `source.native_ids`에 `request_id`(adapter_status는 `adapter_kind`+`updated_at`)를 반드시 넣고, 타임라인은 `(kind, native_ids.request_id)`로 중복을 제거한다. 이 3종도 `events`/`stream`에서 각자 `seq`를 받는다(재생 가능, 단 상태에는 영향 없음) |

### 5.2 `kind` 목록과 `detail` 필수 필드

| kind | category | detail 필수 필드 | Claude Code 소스 [검증] | Codex 소스 (검증 상태는 `integrations/codex.md` §1이 규범; 아래 [추정]은 그 표와 같은 판정) |
| --- | --- | --- | --- | --- |
| `session_started` | lifecycle | `source_reason`(startup/resume/clear/compact/fork), `model?`, `permission_mode?`, `title?` | `SessionStart` | `thread/started`, `thread/resume` 결과 [추정: excludeTurns 형태 C5], hooks `SessionStart` |
| `session_ended` | lifecycle | `reason` | `SessionEnd` | `thread/closed`/`archived` [추정: 이름만 확인, C5], hooks `SessionEnd` |
| `prompt_submitted` | turn | `prompt_preview`(≤200자, 마스킹), `prompt_len`, `auto_turn_suspect` | `UserPromptSubmit` | `item/started{userMessage}`, hooks `UserPromptSubmit` |
| `turn_started` | turn | `turn_id?` | (prompt_submitted와 합성) | `turn/started` |
| `turn_completed` | turn | `final_message_preview?`(≤300자), `background_tasks`(수), `session_crons`(수), `duration_ms?` | `Stop` | `turn/completed{completed}`, hooks `Stop` |
| `turn_failed` | error | `error_code`, `error_message?`, `will_retry?` | `StopFailure` | `turn/completed{failed}`, `error` 알림 |
| `turn_interrupted` | turn | — | (없음: Stop 미발생) | `turn/completed{interrupted}`, hooks `Interrupt` |
| `tool_started` | tool | `tool_name`, `tool_input_summary`, `mcp_server?` | `PreToolUse`(Bash/Edit/Write/Read 계열 제외) | `item/started{mcpToolCall,webSearch,dynamicToolCall,…}`, hooks `PreToolUse` |
| `tool_completed` | tool | `tool_name`, `duration_ms?`, `result_summary?` | `PostToolUse` | `item/completed{…}`, hooks `PostToolUse` |
| `tool_failed` | error | `tool_name`, `error`(첫 줄, ≤2 KiB), `is_interrupt` | `PostToolUseFailure` | `item/completed{status:failed}` |
| `file_read` | file | `file_path`(표시용 축약), `pattern?` | `PreToolUse{Read\|Grep\|Glob}` | `commandActions[type=read\|search\|listFiles]` |
| `file_modified` | file | `file_path`, `op`(create/update/delete/edit), `lines_added?`, `lines_removed?` | `PostToolUse{Write→tool_response.type, Edit}`, `bashEditDiff.changedFiles` | `item/completed{fileChange.changes[]}` |
| `command_started` | command | `command`(≤2 KiB, 마스킹), `description?`, `command_class`, `cwd_hint`, `run_in_background` | `PreToolUse{Bash\|PowerShell}` | `item/started{commandExecution}` |
| `command_completed` | command | `command`, `exit_code?`, `duration_ms?`, `stdout_tail?`(≤1 KiB), `stderr_tail?`(≤1 KiB), `command_class` | `PostToolUse{Bash}` | `item/completed{commandExecution}` |
| `command_failed` | error | `command`, `exit_code?`, `error` | `PostToolUseFailure{Bash}` | `item/completed{commandExecution.status:failed}` |
| `test_run` / `test_passed` / `test_failed` | command | `command_completed`와 동일 + `runner` | `command_class == test`인 명령의 시작/완료/실패 | 동일 |
| `subagent_started` / `subagent_stopped` | lifecycle | `agent_id`, `agent_type`, `final_message_preview?` | `SubagentStart`/`SubagentStop` | `item/{started,completed}{subAgentActivity}` |
| `task_created` / `task_completed` | turn | `task_id`, `task_subject` | `TaskCreated`/`TaskCompleted` | `turn/plan/updated` 항목 완료 전이 [추정: 이름만 확인, C5] |
| `approval_requested` | approval | `request_id`, `risk`, `tool_name`, `title`, `channel`(remote/local_only/no_device) | `PermissionRequest` | `item/*/requestApproval`, hooks `PermissionRequest` |
| `approval_resolved` | approval | `request_id`, `outcome`, `resolved_by` | 브로커 | 브로커 / `serverRequest/resolved` |
| `permission_denied_auto` | approval | `tool_name`, `reason` | `PermissionDenied`(auto 모드 전용) | — |
| `notification` | notification | `notification_type`, `message`(≤300자), `title?` | `Notification` | — |
| `idle` | lifecycle | `idle_seconds` | `Notification{idle_prompt}` / 데몬 타이머 | `thread/status/changed{idle}` + 타이머 |
| `context_compacted` | lifecycle | `trigger`, `summary_preview?`(≤300자) | `PostCompact` | `item/completed{contextCompaction}`, `thread/compacted` [추정: 이름만 확인, C5] |
| `review_started` / `review_completed` | review | `review_target?`, `review_text_preview?`, `p0_count?`, `p1_count?` | — | `item/started{enteredReviewMode}` / `item/completed{exitedReviewMode}` [추정: 실동작 미확인, 모드 A 또는 C7 필요] |
| `review_finding` | review | `priority`(0-3), `title`, `file_path?`, `line_start?`, `line_end?`, `body_preview` | — | `exitedReviewMode.review` 텍스트 파싱 [추정: C7 픽스처 전까지 best-effort] |
| `token_usage_updated` | usage | `total_tokens`, `input_tokens`, `cached_input_tokens`, `output_tokens`, `reasoning_output_tokens`, `context_window?` | statusline `context_window.*` | `thread/tokenUsage/updated`(10초 스로틀) |
| `session_meta_updated` | lifecycle | `title?`, `cost_usd?`, `pr_number?`, `pr_url?`, `model?` | statusline(`session_name`, `cost`, `pr`) | `thread/name/updated` [추정: 이름만 확인, C5] |
| `agent_error` | error | `message`, `code?` | — | `thread/status/changed{systemError}` |
| `adapter_status` | adapter | `status`, `mode`, `detail` | 데몬 | 데몬 |

Codex **hooks 경로**의 `tool_name` 값과 이벤트별 `tool_use_id` 제공 여부는 UNVERIFIED(Phase 0 C10)다. 매핑은 `integrations/codex.md` §5.3의 Codex 전용 표를 따른다.

알 수 없는 훅 이벤트/Codex 아이템 타입은 **버리지 않고** `notification{notification_type: "unknown_hook:<name>"}` / `tool_started{tool_name: <item.type>}`으로 보존한다.

`command_class`(`risk` 토크나이저와 공유): `test`(`cargo test`, `pytest`, `python -m pytest`, `npm test`, `pnpm test`, `vitest`, `jest`, `gradlew .*test`, `go test`, `mvn test`, `dotnet test`, `ctest`), `build`(`cargo build|check|clippy|fmt`, `npm run build`, `pnpm build|typecheck|lint`, `gradlew assemble|build|lint`, `tsc`, `vite build`, `make`), `vcs`(`git `, `gh `), `package`(`npm i|install|ci`, `pnpm add|install`, `pip install`, `cargo add|install`), `fs`(`ls`, `cat`, `find`, `rg`, `grep`, `dir`, `Get-ChildItem`, `type`), `network`(`curl`, `wget`, `Invoke-WebRequest`, `irm`, `iwr`, `ssh`, `scp`), `shell`(그 외).

### 5.3 `SessionState`

```json
{
  "session_key": "claude_code:7f1e…",
  "agent_kind": "claude_code",
  "agent_label": "Claude Code",
  "project": { "project_key": "c:/dev/agentnest", "name": "agentnest", "path_hint": "…\\dev\\agentnest", "branch": "feat/pairing" },
  "state": "testing",
  "state_since": "2026-10-15T12:34:50.000Z",
  "headline": "테스트를 돌리고 있어요 (cargo test -p core)",
  "detail": "Run core tests.",
  "started_at": "2026-10-15T11:02:10.000Z",
  "turn": { "active": true, "started_at": "2026-10-15T12:30:01.000Z", "completed_at": null, "prompt_preview": "페어링 토큰 만료 테스트 추가해줘" },
  "permission_mode": "default",
  "remote_approval": "available",
  "pending_approval_ids": [],
  "counters": { "tools": 42, "files_modified": 3, "commands": 7, "tests": 2, "errors": 1 },
  "recent_files": [ { "path_hint": "…\\src\\pairing.rs", "op": "update", "at": "2026-10-15T12:34:40.000Z" } ],
  "recent_commands": [ { "command_preview": "cargo test -p agentnest-core", "command_class": "test", "exit_code": null, "at": "2026-10-15T12:34:50.000Z" } ],
  "last_test": { "status": "running", "command_class": "test", "at": "2026-10-15T12:34:50.000Z" },
  "meta": { "title": "훅 수집기 구현", "model": "claude-opus-5", "cost_usd": 1.23, "context_used_pct": 41,
            "review": { "p0": 0, "p1": 2, "state": "completed" } },
  "last_event_seq": 1842,
  "last_event_at": "2026-10-15T12:34:55.000Z",
  "ended": false,
  "stale": false
}
```

`remote_approval`: `available` | `unavailable`(`permission_mode ∈ {bypassPermissions, dontAsk, auto}`, 훅 미설치, Codex `approvalPolicy=never`/`danger-full-access`[검증 필요 (Phase 0)]) | `paused`(PC에서 원격 승인 일시정지) | `unknown`(정책을 판단할 수 없음 — 예: Codex `approvalPolicy` 노출 미검증(C8). **폰은 `unavailable`과 같게 렌더**하고 승인 버튼을 만들지 않는다. `storage.md`의 CHECK와 같은 4값).

**화면용 파생 필드(모두 PC가 계산·마스킹·바운드; 폰은 가공하지 않음)**

| 필드 | 규칙 | 화면 근거 |
| --- | --- | --- |
| `started_at` | 세션 첫 이벤트 시각(`session_started` 또는 첫 관찰) | AI 화면 "시작 시각", PRD §3.B "작업 시작 및 완료 시각" |
| `turn.completed_at` | `turn_completed`/`turn_failed`/`turn_interrupted` 시각. 새 `prompt_submitted`에서 `null`로 초기화 | PRD §3.B "작업 완료 시각" |
| `recent_files[≤5]` | 최신순, 같은 경로 중복 제거. `{path_hint(마지막 2 세그먼트), op(create\|update\|delete\|edit\|read), at}`. `file_modified`·`file_read` 이벤트로 갱신 | AI 화면 "최근 파일 5" |
| `recent_commands[≤3]` | 최신순. `{command_preview(≤80자, 마스킹), command_class, exit_code?(완료 시 채움), at}` | AI 화면 "명령 3" |
| `last_test` | `{status: running\|passed\|failed, command_class, runner?, at}`. `command_class==test` 명령의 시작/완료/실패로 갱신. 아직 없으면 필드 생략 | 홈 "최근 오류 및 테스트 결과", PRD §3.A "최근 테스트 결과" |
| `meta.review` | `{p0, p1, state: none\|running\|completed\|unavailable}`. `review_started`→`running`, `review_completed`→`completed`(+`p0_count`/`p1_count`). **리뷰 소스가 없는 Codex 모드(hooks 기본)에서는 `unavailable`** — 폰은 숫자 대신 "리뷰 정보 없음 (hooks 모드)"를 표시한다(`adapter_status.detail`과 같은 문구). 알 수 없는 값은 `unavailable` | AI 화면 Codex "P0/P1 개수", PRD §3.B |

세션 요약 하나의 추가 크기는 약 1 KiB 이하다(§4.6 절단 순서 4단계에서 `recent_files`/`recent_commands`부터 비운다).

### 5.4 `AgentState` 파생 규칙 (PC `state::SessionReducer`, 순수 함수 `reduce(prev, event, now)`; `protocol/fixtures/state_transitions.json`을 Rust·Kotlin이 공유)

상태: `idle` · `working` · `writing_code` · `reviewing` · `testing` · `awaiting_approval` · `awaiting_input` · `error` · `completed` · `disconnected`

| 입력 | 조건 | 다음 상태 | 비고 |
| --- | --- | --- | --- |
| `session_started` | `startup`/`clear` | `idle` | 리듀서 초기화 |
| `session_started` | `resume`/`fork`/`compact` | 직전 상태 유지(없으면 `idle`) | |
| `prompt_submitted` | — | `working` | `turn_active=true`, error latch 해제 |
| `command_started` | `command_class ∈ {test, build}` | `testing` | PRD "공구" = 빌드/테스트 |
| `command_started` | 그 외 | `working` | |
| `file_modified` 또는 `PreToolUse{Edit\|Write\|MultiEdit\|NotebookEdit}` | — | `writing_code` | PreToolUse 시점에 즉시 전이 |
| **(Codex)** `item/started{fileChange}`(= `tool_started`/`file_modified`, `detail.item_type==fileChange`) 또는 hooks `PreToolUse{apply_patch}` [tool_name UNVERIFIED C10] | — | `writing_code` | Claude의 Edit/Write 행과 같은 의미. hooks에서 tool_name이 알 수 없는 값이면 이 행은 **매칭되지 않고** `working`으로 남는다 |
| **(Codex)** `review_started`(`enteredReviewMode`) | — | `reviewing` | `file_read` 연속 규칙과 무관. `pre_review_state` 저장 |
| **(Codex)** `review_completed`(`exitedReviewMode`) | 보류 승인 0건 | `working` | 이어지는 `turn_completed`가 `completed`로 바꾼다. `meta.review` 갱신 |
| **(Codex)** `thread/status/changed{active, activeFlags:[waitingOnApproval]}` | 보류 승인 없음(TUI 로컬 프롬프트) | `awaiting_approval` | 플래그 해제 시 직전 상태로. 승인 카드는 만들지 않음(`channel:local_only`) |
| **(Codex)** `thread/status/changed{active, []}` | 최근 아이템 없음 | `working` | |
| **(Codex)** `item/started{webSearch\|mcpToolCall\|dynamicToolCall}` | — | `working` | Claude `tool_started{WebFetch\|…}` 행과 동일 |
| **(Codex)** `adapter_status{disconnected, mode:daemon_observer}`(소켓 EOF) | — | 해당 어댑터(`source.channel==codex.app_server`) 소속 세션 전부 `disconnected` | 재접속 후 `thread/list` 복원 시 최신 이벤트로 재파생. 이 입력은 보류 승인을 `superseded`로 만든 뒤 적용 |
| `file_read`(Read/Grep/Glob) | **연속 2회 이상**이거나 `actor.agent_type ∈ {Explore}` | `reviewing` | 1회는 `working` 유지(깜빡임 방지) |
| `tool_started{WebFetch\|WebSearch\|mcp__*\|Agent}` | — | `working` | |
| `approval_requested` | — | `awaiting_approval` | `pre_approval_state` 저장. **`pending_approval_ids`가 비기 전엔 어떤 입력도 벗어나게 하지 못함** |
| `approval_resolved` | 보류 승인 0건 | `pre_approval_state` 또는 `working` | `denied_and_stopped`면 `idle` |
| Codex `activeFlags:[waitingOnUserInput]`, `item/tool/requestUserInput`, Claude `Notification{agent_needs_input}` | — | `awaiting_input` | 캐릭터는 승인 요청과 같은 "손 들기"(배지 `?`) |
| `Notification{permission_prompt}` | 상태 ≠ `awaiting_approval` | `awaiting_approval` | `PermissionRequest`가 오지 않는 샌드박스 네트워크 프롬프트 보완 [검증] |
| `tool_failed` / `command_failed` | — | `error`(transient, 5초) | 다음 `*_started`/`prompt_submitted`에서 해제 |
| `test_failed` | — | `error`(30초 sticky) | 같은 세션 `test_passed`/`turn_completed`/`prompt_submitted`면 즉시 해제 |
| `turn_failed` / `agent_error`(Codex `systemError`, `error` 알림 포함) | — | `error`(sticky) | `prompt_submitted` 또는 `session_started{resume}`에서만 해제 |
| `turn_completed` | `background_tasks == 0` | `completed` | 60초 뒤 타이머로 `idle` |
| `turn_completed` | `background_tasks > 0` | `working` | headline "백그라운드 작업 N개를 기다리고 있어요" |
| `turn_interrupted` | — | `idle` | |
| `idle` | — | `idle` | |
| 타이머 `stale_after` | `turn_active && 15분 무이벤트` | 상태 유지 + `stale=true` | 장시간 명령 고려 |
| 타이머 `dead_after` | `turn_active && 45분 무이벤트` 또는 `!turn_active && 30분 무이벤트` | `disconnected` | 비정상 종료 시 `SessionEnd` 미발생 가능 — 검증 필요 (Phase 0) |
| `session_ended` | — | `ended=true`(10분 후 활성 목록 제거) | 캐릭터 입력에서 제외 |

**픽스처 입력 규약**: `thread/status/changed` 는 전용 `AgentEvent.kind` 가 없어 정규화기가 `kind: "notification"` + `detail{notification_type:"codex_thread_status", status, active_flags, has_recent_items?}` 로 내보낸다. 오류 래치(5초/30초/sticky)는 기저 상태 위에 덮어쓰는 방식이라 해제되면 기저 상태가 드러난다 — 세부 규약은 `state_transitions.json` 의 `_format.conventions` 가 규범이다.

**단일 출처 규칙**: 두 에이전트의 모든 상태 전이는 이 표 한 곳에만 있다. `integrations/codex.md` §7은 Codex 알림 → `AgentEvent.kind` **정규화 매핑**만 두고 상태 결과를 다시 적지 않는다. `protocol/fixtures/state_transitions.json`에는 위 `(Codex)` 행마다 케이스(`codex_file_change`, `codex_review_window`, `codex_waiting_on_approval_flag`, `codex_active_idle`, `codex_web_mcp`, `codex_socket_eof`, `codex_system_error`, `codex_hooks_unknown_tool`)가 있고 Rust·Kotlin 리듀서가 같은 파일을 읽는다.

**에러 지속시간의 단일 출처**: `error` 상태가 얼마나 지속되는지는 이 표(PC 리듀서)만이 정한다 — `tool_failed`/`command_failed` 5초 일시, `test_failed` 30초(또는 해제 입력), `turn_failed`/`agent_error` 다음 프롬프트까지. 폰의 `MoodResolver`는 별도의 `flustered` 타이머를 두지 않고 `AgentState.error`를 그대로 따른다(`character.md` §2.2).

우선순위 규칙: 보류 승인이 있으면 `awaiting_approval`이 모든 것을 이긴다. `error(sticky)`는 `awaiting_approval`보다 낮다(승인 요청이 오면 손 들기 우선).

### 5.5 캐릭터 매핑 (PRD §4) — 상세·히스테리시스는 `character.md`

| `AgentState` | 콩이 mood | PRD 행 |
| --- | --- | --- |
| `idle` | `blink_slow` | 대기 |
| `working` | `typing`(약한 변형: 손만) | (PRD 미정의 → 코드 작성 변형) |
| `writing_code` | `typing` | 코드 작성 |
| `reviewing` | `magnifier` | 코드 리뷰 |
| `testing` | `tools` | 테스트 실행 |
| `awaiting_approval` / `awaiting_input` | `raise_hand`(배지 `!` / `?`) | 승인 요청 |
| `error` | `flustered` | 오류 발생 |
| `completed` | `celebrate`(4초 후 `blink_slow`) | 작업 완료 |
| `disconnected`(세션) / 링크 끊김(폰) | `worried` / `sleepy` | 연결 끊김 |

다중 세션 포커스(`focus`): `awaiting_approval 0 > awaiting_input 1 > error 2 > testing 3 > writing_code 4 > reviewing 5 > working 6 > completed 7 > idle 8 > disconnected 9`, 동점은 `last_event_at` 최신. 링크 끊김은 세션 상태와 무관하게 모든 것을 덮는다. 같은 규칙을 Rust(`state::focus`)와 Kotlin(`MoodResolver`)에 구현하고 `protocol/fixtures/mood_priority.json`으로 양쪽 테스트.

---

## 6. 승인

### 6.1 `ApprovalRequest` (`approval_request.payload`, `snapshot.pending_approvals[]`)

```json
{
  "request_id": "ar_01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f",
  "nonce_b64": "Kq2hYm9zZ3FwdHZ4eXoxMg==",
  "session_key": "claude_code:7f1e2d3c-…",
  "agent_kind": "claude_code",
  "agent_label": "Claude Code",
  "project": { "project_key": "c:/dev/agentnest", "name": "agentnest", "path_hint": "…\\dev\\agentnest", "branch": "feat/pairing" },
  "origin": "claude_code.hook.http",
  "created_at": "2026-10-15T12:35:00.000Z",
  "expires_at": "2026-10-15T12:37:00.000Z",
  "ttl_seconds": 120,
  "tool_name": "Bash",
  "title": "명령을 실행하려고 해요",
  "purpose": "node_modules 폴더를 지우고 다시 설치합니다.",
  "details": {
    "kind": "command",
    "command": "rm -rf node_modules && pnpm install",
    "cwd_hint": "…\\apps\\desktop",
    "file_paths": ["desktop/apps/desktop/node_modules"],
    "diff_preview": null,
    "content_preview": null,
    "mcp_server": null,
    "reason": null,
    "truncated": false,
    "permission_suggestions_count": 1
  },
  "tool_input_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "risk": { "level": "high", "reasons": ["recursive_delete"], "reasons_ko": ["폴더를 통째로 지우는 명령이에요"], "extra_confirmation": "hold" },
  "allowed_decisions": ["allow", "deny", "deny_and_stop"],
  "auth_required_for": ["allow", "deny_and_stop"],
  "permission_mode": "default",
  "local_prompt": "unknown"
}
```

| 필드 | 설명 |
| --- | --- |
| `request_id` | `ar_` + UUIDv7(PC 발급). Claude `PermissionRequest`에는 `tool_use_id`가 없으므로 [검증] 열린 HTTP 요청이 상관 키 |
| `nonce_b64` | 16바이트 CSPRNG, 요청별 |
| `tool_input_sha256` | `SHA-256(canonical JSON(tool_input))` 소문자 hex — **PC만 계산**. 폰은 에코만. 표시 축약(`details`)이 바인딩을 약화시키지 않게 함. **canonical JSON = RFC 8785(JCS)**: 객체 키를 UTF-16 코드 유닛 순으로 정렬, 공백 없음, 문자열은 `"` `\` 와 U+0020 미만 제어 문자만 이스케이프(`\b \t \n \f \r`, 나머지는 `\u00xx` 소문자 hex; 그 외 문자는 UTF-8 원문), 모든 숫자는 IEEE-754 double 의 ECMAScript `Number::toString`(`-0`→`0`, `1.0`→`1`, `1e21`→`1e+21`, 2^53 초과 정수는 double 로 반올림), 중복 키는 마지막 값. 바이트 단위 벡터: `protocol/vectors/tool_input_sha256.json` |
| `details.kind` | `command` \| `file_write` \| `file_edit` \| `file_read` \| `mcp_tool` \| `web` \| `agent` \| `file_change`(Codex) \| `permissions`(Codex) \| `other` |
| `details.*` | 표시용 상한: `command` 2,000자, `diff_preview` 4 KiB, `content_preview`(Write 신규 첫 20줄, 마스킹), `file_paths` 50개. 전체 파일 본문은 없음 |
| `title` / `purpose` | `title`은 도구별 고정 한국어(§7). **`purpose`는 에이전트가 쓴 `description`이라 에이전트(또는 공격자) 통제 문자열이며 검증되지 않는다**(없으면 null). PC가 제어 문자·양방향 제어를 제거하고 200자로 절단한다. 폰·데스크톱은 이를 **"에이전트가 한 말 (검증 안 됨)"** 으로 라벨링해 실제 명령·위험 등급보다 시각적으로 낮은 위치·작은 글씨로 표시한다(`android.md` §2.2, `desktop.md` §6) |
| `risk.level` | `low` \| `medium` \| `high` \| `critical`. `extra_confirmation`: `none` \| `hold`(1.5초 길게 누르기) \| `hold_and_reconfirm`(길게 누르기 + 재확인 시트(명령 전체 재표시 + 체크박스)). 생체 프롬프트의 `setConfirmationRequired`는 얼굴·홍채 같은 수동 생체에만 영향을 주는 시스템 힌트라 **보안 게이트로 세지 않는다**(`android.md` §4.2) — 실제 게이트는 길게 누르기와 재확인 시트이며 서버는 `extra_confirmation.completed`로 검사한다 |
| `allowed_decisions` | Codex `availableDecisions`와 교집합. `decline`이 없으면 `deny`를 제외하고 카드에 "거부 = 중단" 표기. **`origin == codex.hook.cli`이면 `deny_and_stop`을 항상 제외**한다(hooks 출력의 `interrupt`는 결정 전체를 무효화하므로 구현할 수 없다). 카드는 "거부만 가능 (Codex hooks는 작업을 멈출 수 없어요)"를 표시한다 — 사후에 조용히 `deny`로 강등하지 않는다 |
| `auth_required_for` | 기본 `["allow","deny_and_stop"]`; `policy.deny_requires_auth`면 `deny`도 포함 |
| `local_prompt` | `unknown` \| `visible` \| `hidden` — Phase 0 A2 결과로 확정 |

### 6.2 결정 검증 순서 (`security.md` §6.2가 규범, 여기서는 요약)

1 인증된 연결 → 2 `request_id` 존재 → 3 `status == pending` → 4 `session_key`·`nonce` 일치 → 5 `tool_input_sha256` 일치 → 6 `now < expires_at` 및 `decided_at` 창 → 7 `decision ∈ allowed_decisions` → 8 `auth`(**`authenticated_at` 신선도 포함**)/`extra_confirmation` 충족 → 9 원격 승인 일시정지 아님. 데스크톱(`actor=desktop`) 경로는 2·3·5(카드 해시 에코)·6(만료만)·7과 8의 데스크톱 판(`confirm_ack`)이 필수이고 1·4·9는 해당 없음이다(`security.md` §6.2.1). 전부 통과 시 **단일 조건부 UPDATE**(`WHERE status='pending' AND expires_at > now`) 후에만 어댑터에 전달. 같은 `decision.id` 재수신은 `decision_result{APPLIED}` 멱등 응답.

---

## 7. 한국어 요약 템플릿 (`summarize::ko`, 골든 `protocol/fixtures/summaries_ko.json`)

어조: 해요체, 진행형 "~하고 있어요", 결과 "~했어요". `headline ≤ 40자`, `detail ≤ 200자`. 경로는 basename(+상위 1단계), 명령은 `{cmd60}`(선행 `cd X &&`/`env VAR=` 제거 → 토큰 패턴 `***` 마스킹 → 60자 초과 시 59자 + `…`). **모든 `headline`/`detail`은 템플릿을 채운 뒤 마지막에 한도로 절단한다(초과 시 앞 39자 + `…`; `detail` 은 199자 + `…`).** 그래서 `{cmd60}` 이 길면 헤드라인에서 한 번 더 잘린다(예: `테스트를 돌리고 있어요 (cargo test -p agentnest-c…`). 정확한 규칙과 골든 케이스는 `protocol/fixtures/summaries_ko.json`(`_format.rules`)이 규범이다.

| 입력 | `title`(승인 카드) | `headline` | `detail` |
| --- | --- | --- | --- |
| Bash/PowerShell, `command_class=test` | "테스트를 실행하려고 해요" | "테스트를 돌리고 있어요 ({cmd60})" | "{description}." 또는 "{cwd_short} 에서 {cmd}" |
| Bash/PowerShell, `build` | "빌드를 실행하려고 해요" | "빌드하고 있어요 ({cmd60})" | "{description}" |
| Bash/PowerShell 일반 | "명령을 실행하려고 해요" | "명령을 실행하고 있어요: {cmd60}" | "{description}" |
| Edit | "파일을 고치려고 해요" | "{basename} 파일을 고치고 있어요" | "{rel_path} 의 일부를 바꿉니다. {description?}" |
| Write(신규) | "새 파일을 만들려고 해요" | "{basename} 파일을 새로 만들고 있어요" | "{rel_path} ({n}줄)" |
| Write(덮어쓰기) | "파일을 다시 쓰려고 해요" | "{basename} 파일을 다시 쓰고 있어요" | |
| Read / Grep / Glob | "파일을 읽으려고 해요" | "{basename} 파일을 읽고 있어요" / "'{pattern}'을(를) 찾고 있어요" | |
| WebFetch / WebSearch | "웹에 접속하려고 해요" | "{host} 에서 자료를 가져오고 있어요" | URL은 host만 |
| Agent | "보조 에이전트를 실행하려고 해요" | "보조 에이전트에게 맡겼어요: {description60}" | |
| `mcp__srv__tool` | "{srv} 도구를 쓰려고 해요" | "{srv}의 {tool}을(를) 쓰고 있어요" | |
| Stop(background 0) | — | "이번 작업을 마쳤어요" | `last_assistant_message` 첫 문장 ≤120자 |
| Stop(background N) | — | "백그라운드 작업 {n}개를 기다리고 있어요" | |
| PostToolUseFailure(Bash) | — | "명령이 실패했어요 (exit {code})" | error 첫 줄 ≤160자 |
| StopFailure | — | 오류 타입별 12종(예: `rate_limit` → "사용량 한도에 걸려 멈췄어요") | |
| PermissionRequest | 도구별 title | "허락을 기다리고 있어요: {headline}" | |
| Codex commandExecution | 명령 규칙 동일 | | |
| Codex fileChange | "파일 {n}개를 바꾸려고 해요" | "{basename} 외 {n-1}개 파일을 고치고 있어요" | 변경 종류별 개수 |
| Codex enteredReviewMode / exitedReviewMode | — | "코드 리뷰를 시작했어요" / "리뷰를 마쳤어요 · P0 {a} · P1 {b}" | overall 문장 |
| 알 수 없는 도구 | "{tool_name} 도구를 쓰려고 해요" | "{tool_name} 도구를 쓰고 있어요" | |

---

## 8. 하트비트·ack·재동기화 규칙

### 8.1 하트비트

| 계층 | 메커니즘 | 실패 시 |
| --- | --- | --- |
| WebSocket | 폰 OkHttp `pingInterval(25s)` [검증]; 서버 axum ws 자동 pong | OkHttp `onFailure` → 재연결 상태기계 |
| 앱 | 폰 `ping` 30초(직전 30초 프레임이 없을 때만), 서버 `pong` | 폰: 70초 수신 없음 → 끊고 재연결. 서버: 90초 프레임 없음 → 4008 |
| 승인 | `expires_at`(서버 시계) | `approval_resolved{expired}` + 훅 빈 2xx |

### 8.2 `seq`/`ack`

- 서버는 재생 가능 메시지를 `stream` 테이블에 기록한다. 보존은 **`max(48시간, 최신 10,000행)`** + 크기 상한(`storage.md` §3) — 크기 상한에 걸리면 창이 48시간보다 짧아질 수 있고 그 결과는 `resync=snapshot`이다. 기기별 `last_acked_seq`를 저장.
- 폰은 1초 배치로 `ack{through_seq}`를 보낸다(승인 ack에 편승 가능).
- 같은 기기의 새 연결이 오면 이전 연결은 `bye{superseded_connection}` 후 4009(기기당 연결 1개).

### 8.3 승인 요청의 배달 확인

- `approval_request`는 폰이 **즉시** `ack{approval_ids:[…]}` 한다. 서버는 5초 안에 ack가 없으면 같은 `request_id`로 최대 3회 재전송한다(폰은 `request_id`로 중복 제거). ack를 받으면 데스크톱에 "휴대폰이 받음"을 표시하고, 3회 실패 시 `event{approval_delivery_failed}`를 데스크톱에 올린다(결정은 TTL까지 기다린다 — 결정 없음 = 로컬 폴백).
- `approval_seen`은 UI용(데스크톱 "휴대폰에서 열어봄").

### 8.4 재동기화

```text
연결 1 (최초)                              연결 2 (재연결, last_seq=1830)
S→C challenge                               S→C challenge
C→S hello{last_seq:0}                       C→S hello{last_seq:1830}
S→C welcome{resync:snapshot}                S→C welcome{resync:{replay,1831,1842}}
S→C snapshot{seq:1842}                      S→C event{1831} … approval_resolved{1842}
C→S ack{through_seq:1842}                   C→S ack{through_seq:1842}
```

- `last_seq`가 창 밖이면 `resync.mode=snapshot`. `snapshot_request`는 언제든 전체 스냅샷. 스냅샷은 새 `seq`를 소비하지 않고 현재 최대 `seq`를 싣는다(§4.6). 놓친 타임라인 이력은 `events_request`로 가져온다(§4.15).
- **승인 요청 재생 규칙**: 재생 중 `approval_request`는 `expires_at`이 지났거나 이미 종결됐으면 보내지 않고 `approval_resolved{expired|…}`로 대체한다. 살아 있는 요청은 `snapshot.pending_approvals`에도 포함된다. → 만료된 카드가 되살아나지 않는다(PRD Phase 3 "중복 실행 없음" 선행 충족).
- 폰은 오프라인 동안 **결정을 큐에 넣지 않는다**(버튼 비활성). 재연결 후 `snapshot.pending_approvals`가 카드 목록을 교체한다.

---

## 9. 오류 코드·종료 코드·한국어 문구

### 9.1 `error.code`

| 코드 | fatal | 발생 조건 | 폰 동작 |
| --- | --- | --- | --- |
| `E_PROTO_VERSION` | 예 | `v` 불일치 | "앱을 업데이트해 주세요" |
| `E_AUTH_REQUIRED` | 예 | 인증 전 금지 메시지 | 재연결 |
| `E_AUTH_FAILED` | 예 | 토큰/챌린지/기기 불일치(원인 비구분) | 3회 연속이면 `LinkState.NeedsRepair` + '다시 페어링' 버튼(`android.md` §3.2) |
| `E_DEVICE_REVOKED` | 예 | PC에서 폐기됨 | 로컬 토큰·핀 삭제, "PC에서 연결을 해제했어요" |
| `E_PAIR_FAILED` / `E_PAIR_REJECTED` / `E_PAIR_BUSY` | 예 | §4.3 | QR 재생성 안내 / "PC에서 거절했어요" / "PC에서 다른 요청을 먼저 처리하세요" |
| `E_RATE_LIMITED` | 아니오 | 기기당 decision 10건/분, `snapshot_request` 6건/분, `events_request` 12건/분, ping 과다 | 잠시 후 재시도 |
| `E_BAD_MESSAGE` | 아니오 | 스키마 위반(3회 누적 시 4004) | 개발 로그 |
| `E_RESUME_TOO_OLD` | 아니오 | 재생 창 밖 | 곧 `snapshot` 수신 |
| `E_INTERNAL` | 상황별 | 서버 오류 | 토스트 |

### 9.2 `decision_result.reason` → 한국어

| reason | `message_ko` |
| --- | --- |
| `APPLIED` | "{허용했어요\|거부했어요}. {에이전트}에 전달했어요." |
| `EXPIRED` | "요청 시간이 지나 PC에서 직접 처리하도록 넘겼어요." |
| `ALREADY_RESOLVED` | "이미 처리된 요청이에요." |
| `UNKNOWN_REQUEST` | "PC에 없는 요청이에요. 카드를 닫을게요." |
| `BINDING_MISMATCH` / `INPUT_HASH_MISMATCH` | "요청 내용이 바뀌어 적용하지 않았어요(보안)." |
| `NOT_ALLOWED` | "이 요청에는 쓸 수 없는 결정이에요." |
| `AUTH_REQUIRED` | "허용하려면 생체 인증이나 기기 잠금 인증이 필요해요." |
| `EXTRA_CONFIRMATION_REQUIRED` | "위험한 작업이라 추가 확인이 필요해요." |
| `CLOCK_SKEW` | "휴대폰 시계가 PC와 많이 달라요. 시간 설정을 확인해 주세요." |
| `PAUSED` | "PC에서 원격 승인을 잠시 멈춰 두었어요." |
| `DEVICE_REVOKED` | "PC에서 이 기기의 연결을 해제했어요." |

### 9.3 WebSocket 종료 코드(서버 발신)

| 코드 | 의미 |
| --- | --- |
| 4001 | 인증 전 타임아웃(유효한 `pair`/`hello` 미수신) / 인증 전·`PairPending` 중 비허용 메시지 |
| 4002 | 인증·페어링 실패(1초 지연 후) |
| 4003 | 기기 폐기됨 |
| 4004 | 프로토콜 위반(봉투 파싱 실패 누적) |
| 4005 | 레이트리밋 |
| 4008 | 하트비트 타임아웃 |
| 4009 | 같은 기기의 새 연결로 대체됨 |
| 4010 | 프로토콜 버전 비호환 |
| 1003 / 1009 / 1012 | 바이너리 프레임 / 프레임 과대 / 서버 재시작 |
| 1013 | 전체 동시 연결 한도(16) 초과 — 인증 전에 즉시 거절(`security.md` §11). 폰은 백오프 후 재시도 |

---

## 10. 전방 호환(fail-safe) 규칙

| 알 수 없는 값 | 처리 |
| --- | --- |
| 메시지 `type` | 무시(오류 없음) |
| payload 필드 | 무시 |
| `AgentState` | `working`으로 렌더(캐릭터 `typing` 약한 변형) |
| `risk.level` | `high`로 취급(길게 누르기 + 생체). **절대 `low`로 내리지 않음** |
| `decision` 값(폰이 모름) | 카드에서 버튼 미표시(승인 불가) |
| `outcome`/`resolved_by` | "처리됨"으로 표시 |
| `remote_approval` / `meta.review.state` | `unavailable`로 렌더(승인 버튼·리뷰 숫자 없음) |
| `AgentEvent.kind` | 타임라인에 "기타"로 표시, 상태 전이 없음 |

Kotlin: `Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false; classDiscriminator = "type"; coerceInputValues = true }` + 각 enum에 `UNKNOWN` 기본값. Rust: `#[serde(other)] Unknown` 변형.

---

## 11. 스키마 배치와 라운드트립

- `protocol/schema/envelope.schema.json`이 `type`별 payload 스키마(`c2s/<type>`, `s2c/<type>` = **payload 만** 기술)를 `if/then` 분기로 참조한다(`oneOf` 는 알 수 없는 `type` 을 무시해야 하는 전방 호환 규칙과 충돌하므로 쓰지 않는다; 재생 가능 타입은 `seq` 필수). 공용 정의(ID·타임스탬프·공용 enum)는 `model/common.schema.json`. 예제 `protocol/examples/<type>.<n>.json`(유효, 전체 봉투) + `protocol/examples/model/*`·`qr/*`(봉투 없는 모델/QR 페이로드) + `protocol/examples/invalid/<type>.<n>.json`(반드시 거부: `decision`에 `allow_for_session`, `v: 2`, 음수 `seq`, `nonce_b64` 누락 등; `invalid/_index.json` 이 파일별 사유·오류 위치·Rust 타입도 거부해야 하는지를 기록). `protocol/examples/forward_compat/` 은 **스키마엔 위반하지만 읽기 쪽이 관대하게 받아야 하는** 파일(알 수 없는 enum·필드; §10) 이라 스키마 검증 대상이 아니다. 스키마의 enum 은 v1 값으로 닫혀 있고(`decision` 은 3값), 전방 호환은 읽기 구현(Rust `Unknown(String)`, Kotlin `UNKNOWN`)의 책임이다. `$id` 는 가상의 `https://agentnest.example/protocol/schema/…` 이며 네트워크로 가져오지 않는다.
- Rust(`jsonschema 0.58.6`, default-features=false)와 Kotlin(kotlinx.serialization 디코드 → 재인코딩 비교)이 **같은 파일**을 읽는다. 한쪽만 통과하면 CI 실패.
- `protocol/vectors/`: `pair` canonical 바이트열·HMAC·SAS, `tool_input_sha256` canonical JSON 케이스. Phase 3 ECDSA 벡터는 그때 추가.
