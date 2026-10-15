# AgentNest 보안 설계 (협상 불가 규칙)

- 상태: 확정(리드 종합본) — 2026-10-15
- 이 문서의 규칙은 PRD §6 과 CLAUDE.md 보안 불변식의 구체화다. **`docs/security.md`와 어긋나는 코드는 Codex 리뷰 P0(머지 차단)** 이다(`AGENTS.md`).
- 형식 정의는 `protocol.md`, 연동별 세부는 `integrations/*.md`.

---

## 1. 위협 모델

### 1.1 공격자

| ID | 공격자 | 능력 | 목표 | 주 방어 |
| --- | --- | --- | --- | --- |
| A1 | **같은 Wi-Fi의 낯선 사람** | LAN 스니핑, 포트 스캔, 임의 TCP/TLS/WS 연결, ARP 스푸핑/MITM, QR 미보유 | 상태 엿보기, 승인 위조, 데몬 DoS | I1(인증 전 무출력), I2(SPKI 핀), §7 레이트리밋 |
| A2 | **분실/도난 휴대폰** | 잠금 전: 앱 데이터 복사 시도(비루팅 가정) / 잠금 후: 앱 실행 | 위험 명령 승인 | I6(즉시 폐기), 토큰 Keystore 래핑, 승인 생체 게이트, `allowBackup=false` |
| A3 | **PC 위의 악의적 로컬 프로세스**(에이전트가 실행한 스크립트 등) | `127.0.0.1` 훅 포트에 POST, 같은 사용자 파일 읽기 | 가짜 승인 카드, 실제 요청과 혼동, 데몬 교란 | I8(훅 HTTP 가드), 단일 승인 경로(I5), 감사 |
| A4 | **QR을 어깨너머로 촬영한 사람** | QR 전체 페이로드 보유, 같은 LAN | 사용자보다 먼저 페어링 | I7(소지 증명 + **PC 화면 확인 + SAS**) |
| A5 | **PC 디스크/백업을 복사한 사람** | SQLite·설정 파일 오프라인 읽기 | 기기 자격 증명 재사용 | 디바이스 토큰은 **해시만** 저장, 비밀 파일은 사용자 ACL(→ Phase 3 DPAPI) |

Phase 1 범위 밖(명시적 비목표): 루팅된 폰, PC 관리자 권한 탈취, 외부망 노출(Phase 3), 사용자가 PC SAS 모달을 보지 않고 승인하는 경우(§4.3 완화만).

### 1.2 A3 한계 명시

같은 사용자 권한의 프로세스는 `settings.json`의 훅 토큰을 읽을 수 있다. 토큰이 막는 것은 **우발적 POST**(브라우저, curl 예시)이다. 토큰을 훔친 A3는 가짜 `PermissionRequest`를 데몬에 넣어 폰에 가짜 카드를 띄울 수 있지만, 데몬의 응답은 **그 가짜 HTTP 요청으로만** 돌아가므로 실제 Claude Code 프로세스에는 아무 영향이 없다. A3가 얻는 것은 사용자 혼란이지 명령 실행이 아니다. 완화: 승인 카드에 `origin`과 프로젝트·세션을 표시하고, 같은 `(session_key, agent_id, tool_name, tool_input_sha256)`이 **2초 안에** 다시 도착한 중복 훅만 카드 1장으로 합친다(`agent_id`가 다르거나 2초가 지나면 별도 카드 — 병렬 서브에이전트의 같은 명령이 한 번의 승인으로 두 번 실행되지 않게 함, `integrations/claude-code.md` §6).

### 1.3 수용된 위험 (사용자 확인이 필요한 PRD 편차)

| ID | 위험 | 내용 · 영향 | 완화 | 종료 조건 |
| --- | --- | --- | --- | --- |
| R1 | **PC 측 비밀이 DPAPI가 아닌 ACL 파일** (PRD §6 "인증 정보는 가능한 한 PC의 안전한 저장소에 보관"에 대한 Phase 1 편차) | 서버 TLS 개인키(`identity\server-key.pem`)와 훅 토큰(`daemon.json`)은 사용자 전용 ACL 파일(설치 시 `icacls`로 상속 제거)에 **평문**으로 있다. 같은 사용자 권한의 프로세스(A3)나 디스크·백업을 복사한 사람(A5)이 읽을 수 있다. 영향: TLS 키가 새면 같은 LAN의 공격자가 이 PC로 가장해(핀이 일치) 폰이 `hello`로 보내는 **디바이스 토큰을 받을 수 있다**(Phase 3 결정 서명 전까지 토큰은 베어러). 훅 토큰이 새면 §1.2의 가짜 카드 | 사용자 전용 ACL, 디바이스 토큰은 PC에 해시만, "PC 신원 재생성"(§10)·기기 폐기로 즉시 무효화, 로그·DB에 키 미기록 | Phase 3 DPAPI 키 래핑(Phase 0 P12) + `hello` 서명 |

R1은 **문서화만으로 수용되지 않는다.** 데스크톱 첫 실행 체크리스트(`desktop.md` §6.1)에서 사용자가 이 편차를 읽고 명시적으로 확인해야 하며, 확인은 `audit_log(action=risk_accepted, target=R1)`로 기록된다. 확인 전에는 '기기 추가'(페어링)를 시작할 수 없다. `ADR-0001` 결과에도 같은 내용을 기록한다. `decision.auth`가 폰의 주장이라는 한계(§6.4)는 별도의 문서화된 Phase 1 한계다.

---

## 2. 보안 불변식 (코드 리뷰·테스트 기준)

| ID | 불변식 | 강제 지점 | 테스트 | Codex P0 |
| --- | --- | --- | --- | --- |
| I1 | 인증 전 연결은 상태기계(`protocol.md` §1)다. **`PreAuth`**: 서버는 `challenge` 한 프레임만 보내고 폰은 유효한 `pair`/`hello` 한 프레임만 보낼 수 있으며, 5초 안에 못 받으면 4001. 유효한 `pair` 뒤 **`PairPending`**: 서버는 `pair_pending`/`pair_result`/`error`만, 폰은 중단용 `unpair{pairing_id}`·close만 허용(그 밖의 폰 프레임은 4001), 60초 상한. 이 상태들에서 PC 이름·세션·이벤트는 **한 바이트도** 나가지 않는다(`pair_result{ok:true}`의 `pc`는 사용자가 PC에서 승인한 뒤). `ping`도 인증 후에만 | `link::Session` 상태기계 | `ws::preauth_*`, `ws::pair_pending_*` | 4 |
| I2 | 모든 LAN 트래픽은 TLS. 폰은 QR의 **SPKI SHA-256 핀과 정확히 일치하는 리프 인증서만** 신뢰. 평문 `ws://` 경로 없음 | Android `SpkiPinTrustManager`; PC는 WSS 리스너만 | 핀닝 4케이스 | 4 |
| I3 | 디바이스 토큰은 PC에 **해시만**, 폰에는 Keystore AES-GCM 래핑으로만 존재. 페어링 비밀은 와이어에 실리지 않는다(HMAC 소지 증명). 폰 EC 공개키는 페어링 때 등록(Phase 3 서명용) | `auth::devices`, `TokenVault` | store, 실기 | 5 |
| I4 | 모든 `decision`은 `request_id + session_key + nonce + tool_input_sha256`에 바인딩되고, 서버는 §6.2의 **9단계를 고정 순서**로, **상태 변경 전에** 검사한다. 하나라도 실패하면 아무 일도 일어나지 않는다 | `approvals::Validator`, `Broker::apply_decision` | 단계별 단독 실패 9개 + 전부 통과 1개 | 1, 2, 3 |
| I5 | 만료·끊김·폰 미응답·데몬 오류·재시작·검증 실패·알 수 없는 상태의 결과는 항상 **"결정 없음"**(Claude: 빈 2xx / Codex: 무응답). 허용 응답은 **불투명 타입**으로만 만들 수 있다 — `ApprovalReply`는 내부 enum이 비공개인 구조체이고 허용 값은 `ApprovalReply::allow(ApplyProof)`로만 생성되며, `ApplyProof::mint()`는 `apply_decision` 성공 분기 **한 곳**에서만 호출된다(데스크톱 로컬 결정도 같은 분기를 지난다). 응답자는 `ReplyKind` 읽기 전용 뷰(`as_wire()`)만 본다 | `approvals::Broker`, `agentnest-adapter-api` | `compile_fail` doctest(공개 허용 생성자·내부 enum 리터럴 불가) + **`ApplyProof::mint` 호출 위치 1곳 grep** + fail-closed 매트릭스 | 1 |
| I6 | 기기 폐기는 즉시 효력: 활성 연결에 `bye{device_revoked}` 후 4003, 그 기기의 진행 중 결정 무효, 이후 `hello` 거부. **되돌리기 없음** | `devices.revoked_at`, `link::Registry::kick` | 폐기 3종 | 8 |
| I7 | 페어링은 (1) QR 비밀 소지 증명(HMAC) **그리고** (2) **PC 화면에서 사용자의 명시적 승인(SAS 표시)** 두 가지가 모두 있어야 완료. QR은 120초·1회용·3회 실패 시 소각 | `auth::pairing` | HMAC/SAS/거절/만료 | 3 |
| I8 | 훅 수집 HTTP는 `127.0.0.1`(+`[::1]`)에만 바인드(설정으로도 변경 불가), `Origin`/`Sec-Fetch-Site` 헤더가 있으면 403, 토큰 상수시간 비교 실패 401, 본문 1 MiB 초과 413 | `http::guard` | hooks_http 5종 | 4 |
| I9 | 로그·감사·DB·폰 전송 어디에도 토큰/키/nonce/서명/파일 본문/stdout 전체/프롬프트 원문을 남기지 않는다. 원시 훅 본문은 **디스크에 쓰지 않는다** | `redact` 뉴타입 + 3-싱크 정책 | 로그 grep 테스트, `payload ≤ 8 KiB` | 5 |
| I10 | 위험 규칙은 코드 상수이며 설정으로 **완화할 수 없고 강화만** 가능. 설정 스키마에 §9의 금지 필드가 존재하지 않는다. 분류 실패 → `critical` | `risk`, `config.rs` | 규칙 테이블, 금지 필드 컴파일 테스트 | 6 |
| I11 | 범위 확장 결정(`allow_for_session`, Claude `updatedPermissions`/`updatedInput`, Codex `acceptForSession`/`acceptWithExecpolicyAmendment`/`applyNetworkPolicyAmendment`)은 v1 스키마·어댑터 응답·설정 어디에도 **존재하지 않는다**("예약·거부"도 금지) | `protocol` enum, 어댑터 응답 생성기 | 스키마 invalid 예제, 응답 JSON 골든 | 1, 7 |
| I12 | Claude `PermissionRequest` 훅의 `onFailure`는 기본 `continue`. `block`은 "데몬 다운 시 거부" **옵트인 설정**으로만 존재 | `hooks_install` | 설치 JSON 골든 | 7 |

---

## 3. 전송 보안: TLS와 핀

| 항목 | 결정 |
| --- | --- |
| 서버 키쌍 | rcgen 0.14.10 `KeyPair::generate()`(기본 P-256 [검증]) 1회 생성 후 **재사용**. 저장: `%LOCALAPPDATA%\AgentNest\identity\server-key.pem` — Phase 1 파일 ACL 사용자 전용(설치 시 `icacls`로 상속 제거), Phase 3 DPAPI(`windows` 0.62.2 `Win32_Security_Cryptography` — `CryptProtectData` 소속 모듈 검증 필요 (Phase 0) P0-21) |
| 인증서 | `CertificateParams::new(sans)?.self_signed(&key)`; SAN = 현재 비루프백 IP 전부(폰은 호스트명을 검증하지 않고 SPKI 핀만 본다. PC에 mDNS 응답기가 없고 Android가 `.local`을 일반 DNS로 풀지 못하므로 `agentnest.local`은 넣지 않는다); `not_before = now − 1h`(시계 오차), `not_after = now + 2y`(`time::OffsetDateTime` [검증]). IP 변경·만료 30일 전 자동 재발급(**같은 키쌍** → 핀 불변; 재페어링은 필요 없으나 **폰이 새 주소를 아는 경로는 §3.2**) |
| 핀 | QR의 `spki_pin` = `base64(SHA-256(DER(SubjectPublicKeyInfo)))` — OkHttp `sha256/` 핀 형식과 동일 [검증]. 인증서 전체 지문이 아니라 **키 지문**이므로 재발급에 영향 없음 |
| 폰 검증 | `SpkiPinTrustManager`: 리프 SPKI 해시 == 핀 (상수시간 비교) + `checkValidity()`; 체인/CA/호스트명 무시; `HostnameVerifier`도 핀 재확인; `CertificatePinner` 2중 방어; 평문 폴백 없음 [검증: Android는 `sslSocketFactory(factory, trustManager)` 필수] |
| TLS 버전 | 1.3 우선, 1.2 허용. 클라이언트 인증서 없음(인증은 앱 계층) |
| 바인드 | WSS `0.0.0.0:47832`는 **아니라** 설정에서 선택한 LAN 인터페이스 주소(기본: QR 생성 시점의 주 인터페이스; DHCP 변경 시 재바인드 + 인증서 SAN 재발급). Phase 3 전까지 사설 대역 소스 IP만 수락(기본 on). **Windows 방화벽·네트워크 프로필은 §3.1** |
| MITM(A1) | 공격자는 핀과 일치하는 키를 갖지 못하므로 핸드셰이크 실패. 트래픽 분석으로 얻는 것은 프레임 길이뿐(키 파일 유출 시는 §1.3 R1) |

### 3.1 Windows 방화벽·네트워크 프로필

WSS 리스너는 LAN 인터페이스 주소의 TCP 47832에 바인드한다(훅 HTTP 47831은 루프백이라 규칙이 필요 없다). 서명되지 않은 새 앱은 Windows Defender 방화벽 프롬프트를 띄우거나, **'공용(Public)' 네트워크 프로필**에서는 조용히 차단되고, 비관리자 NSIS(`installMode: currentUser`) 설치는 방화벽 규칙을 만들 수 없다. 따라서 "QR로 연결"은 깨끗한 PC에서 다음 절차가 있어야 성립한다.

| 항목 | 규칙 |
| --- | --- |
| 담당 | 앱은 **관리자 권한으로 상시 실행되지 않는다.** 인바운드 규칙은 데스크톱 앱이 **사용자 동의 + UAC 상승 프롬프트**로 한 번만 만든다(상승한 `netsh` 실행). 자동·무음 생성 금지 |
| 규칙 범위 | 이름 `AgentNest Link (TCP 47832)`, 인바운드, TCP, `localport=47832`, **`profile=private`**, **`remoteip=localsubnet`**, `program=<설치된 메인 exe 전체 경로>`. 예: `netsh advfirewall firewall add rule name="AgentNest Link (TCP 47832)" dir=in action=allow protocol=TCP localport=47832 profile=private remoteip=localsubnet program="<exe>" enable=yes` [추정: 구문은 일반 `netsh advfirewall` 형식, 클린 Windows 11에서 P15로 확정]. Public/Domain 프로필·다른 프로그램·임의 원격 주소에는 열리지 않는다 |
| 첫 실행 점검 | 데몬 시작 시 (1) 리스너 바인드 성공 여부, (2) 바인드된 인터페이스의 **네트워크 프로필**(Private/Public/Domain), (3) 위 규칙의 존재·활성·범위를 확인한다. 프로필이 Public이면 앱은 프로필을 **바꾸지 않고** "이 네트워크가 '공용'이라 휴대폰이 연결하지 못해요. Windows 설정 → 네트워크 → 속성에서 '개인'으로 바꾸거나, 공용 Wi-Fi라면 연결을 끄세요(§3.3)"를 안내한다 |
| 연결 진단 뷰 | 데스크톱 '연결 진단'(`desktop.md` §6): 리스너 바인드 주소·포트, 네트워크 프로필, 방화벽 규칙(존재/범위/차단 규칙 유무), 마지막 인증 전 접속 시도(시각·IP 마스킹 — 시도가 한 번도 없으면 '휴대폰이 PC에 닿지 못했어요(방화벽·네트워크 프로필·같은 Wi-Fi 확인)'), 자기 LAN 주소 셀프 접속 테스트(방화벽은 못 거름), 현재 `hosts` 목록. 각 실패에 한국어 조치문. 비밀 값은 표시하지 않는다 |
| 프롬프트 대응 | 첫 접속 시 Windows가 띄우는 '액세스 허용' 대화상자에서 [취소]하면 **차단 규칙**이 생긴다. 진단 뷰가 차단 규칙을 감지하면 삭제 안내(UAC 상승 `netsh ... delete rule`)를 제공한다 |
| 제거 | 앱 내 '방화벽 규칙 제거' 버튼(UAC)과, 언인스톨러(NSIS 훅)가 UAC로 `netsh advfirewall firewall delete rule name="AgentNest Link (TCP 47832)"`를 시도한다. 사용자가 거부해 규칙이 남아도 `program=` 범위라 다른 바이너리에는 열리지 않는다. 생성·제거는 `audit_log(firewall_rule_created/removed)` |
| 검증 | Phase 0 **P15**: 클린 Windows 11(표준 사용자, NSIS currentUser 설치)에서 프롬프트 동작, Public 프로필 차단, UAC 규칙 생성, 폰 접속, 언인스톨 시 규칙 제거를 실측 |

### 3.2 PC 주소 변경과 폰의 주소 갱신

- 데몬은 LAN 주소를 주기적으로(10초 폴링 [추정], 또는 OS 주소 변경 통지) 확인한다. 변경 시: 리스너 재바인드 → 인증서 **같은 키로** 재발급(SAN 갱신) → 연결된 기기에 `hosts_update` → 이후 모든 `welcome.hosts`에 반영(`protocol.md` §4.5).
- **재페어링은 필요 없다**(핀은 키 지문). 그러나 **단일 NIC에서 기존 주소가 사라지는 DHCP 변경**은 연결이 먼저 끊겨 `hosts_update`가 닿지 않는다. 이때 폰은 옛 주소를 돌다 `PcUnreachable`이 되며, 복구는 폰의 'IP 직접 입력' 또는 QR 재스캔(주소만 갱신), 예방은 DHCP 예약/고정 IP다. 이 한계를 숨기지 않는다(ADR-0001, Phase 0 P16).
- mDNS 응답기·`NsdManager` 발견은 Phase 1에서 채택하지 않는다(인증 없는 수신 경로 금지 원칙). 도입한다면 발견 결과도 `hello` 인증 + SPKI 핀을 통과해야 하는 옵트인이어야 한다(Phase 2+ 검토).

### 3.3 링크 비활성화 (`link.enabled`) — 원격 연결 끊기

PRD §6 "사용자가 원격 연결을 해제할 수 있게 한다"는 기기 폐기·원격 승인 일시정지만으로는 부족하다(공용 Wi-Fi 등에서 **리스너 자체**를 닫을 수 없음). 트레이 **'휴대폰 연결 끊기'**(설정 `link.enabled=false`)는:

1. WSS 리스너를 닫는다(새 연결 불가). 보류 승인은 전부 `handed_off_local`(`resolved_by=desktop`)로 종결하고 훅에는 빈 2xx를 반환한다 — 어떤 결정도 적용되지 않는다.
2. 연결된 기기에 `bye{reason:"shutdown", reconnect:false, message_ko:"PC에서 휴대폰 연결을 껐어요"}` 후 닫는다.
3. `audit_log(link_disabled)`를 기록하고 설정을 영속한다(재시작 후에도 꺼진 상태). 페어링 모드도 꺼진다.
4. 훅 HTTP(`127.0.0.1`)와 로컬 수집·저장은 계속된다(휴대폰으로만 안 나감). 이 동안 새 `PermissionRequest`는 '온라인 기기 0' 규칙으로 즉시 빈 2xx다.
5. 다시 켜는 것(`link.enabled=true`, `audit_log(link_enabled)`)은 사용자의 명시 동작뿐이다. 네트워크 프로필이 Public으로 바뀌면 앱이 끄기를 **제안**한다(자동으로 끄지는 않음).


---

## 4. 페어링

### 4.1 QR 페이로드 (`protocol/schema/qr/pairing_payload.schema.json`)

`agentnest://pair?d=<base64url(JSON)>` (≈300~400자, QR 버전 ≤15, `qrcode 0.14.1` svg)

```json
{
  "v": 1,
  "pc_id": "pc_5c1d9a2b7e3f4a60",
  "pc_name": "DESKTOP-HOME",
  "hosts": ["192.168.0.10", "10.8.0.2"],
  "port": 47832,
  "spki_pin": "sha256/r6j1…(base64 44자)",
  "pairing_id": "p_3f9c2b1ea8d04c77",
  "pairing_secret": "k7Qx…(base64url 32B)",
  "expires_at": "2026-10-15T09:14:33Z"
}
```

- `pc_id` = SPKI SHA-256 앞 8바이트 hex(QR과 `challenge.pc_id` 일관성 검사).
- `pairing_secret`: `ring::rand::SystemRandom` 32바이트. PC 메모리 + `pairings.secret_sha256`(해시만). **120초**, 1회 사용, 실패 3회 시 소각. 페어링 모드는 데스크톱에서 명시적으로 켜고, 성공/만료/취소/거절 시 자동 종료. 동시에 1개만.
- 폰은 `pairing_secret`을 ViewModel 메모리에만 두고 페어링 종료 시 `fill(0)`.

### 4.2 흐름

```text
PC(데스크톱)                                                   폰
1. "기기 추가" → pairing_id/secret 생성, QR 표시(SVG, 화면에만)
                                                               2. QR 스캔 → 파싱·검증(v==1, 핀 형식, hosts 1~8, port, expires_at 미래, pc_id ↔ spki_pin)
                                                               3. Keystore EC P-256 키쌍 생성(없으면) → wss://host:47832/v1/link (핀 검증)
                                                               4. ◀ challenge{challenge_b64, pc_id}
                                                               5. proof = HMAC-SHA256(pairing_secret, canonical_pair_bytes)
                                                                  ▶ pair{pairing_id, challenge, device, spki, proof}
6. pairing_id 조회(미만료·미사용·fail_count<3) → proof 상수시간 비교(ring::hmac::verify)
   실패 → fail_count++ → 1초 지연 → error{E_PAIR_FAILED} → 4002
   성공 → SAS = HMAC-SHA256(secret, "sas"‖challenge‖spki)[0..4] BE % 1_000_000 (6자리)
   ▶ pair_pending{sas, confirm_timeout_ms:60000}
   PC 모달: "휴대폰에 표시된 숫자 482 915 와 같습니까?  [승인] [거절]"
                                                               7. 폰이 SAS를 **로컬 계산**(secret·challenge·자기 SPKI)해 그 값을 표시 + `pair_pending.sas`와 비교
                                                                  (불일치 → `unpair{pairing_id}` 중단, 로컬 폐기) + "PC에서 승인을 눌러 주세요"
8. [승인](60초 내) → 트랜잭션: devices INSERT(token_hash, pubkey_spki_der, name, …), pairings.used_at
   ▶ pair_result{ok:true, device_id, device_token(1회만)} ▶ welcome{resync:snapshot} ▶ snapshot
   [거절]/60초 경과 → error{E_PAIR_REJECTED} → 4002, pairing 소각
                                                               9. device_token → TokenVault(Keystore AES-GCM) 봉인 → DataStore; POST_NOTIFICATIONS 요청; LinkService 시작
```

### 4.3 A4(QR 촬영) 분석

촬영자가 먼저 `pair`를 보내면 PC 모달이 뜬다. 사용자는 (a) 자기 폰이 아직 SAS를 표시하지 않았거나 (b) 숫자가 다르면 [거절]한다. 사용자 폰은 `E_PAIR_BUSY`를 받고 "PC에서 낯선 요청을 거절한 뒤 다시 스캔"을 안내한다. 남는 위험은 사용자가 모달을 보지 않고 승인하는 경우뿐이며, 모달에는 기기 이름·모델과 SAS를 크게 표시하고 승인 버튼은 2초 후 활성화한다. `retype_sas`(폰에서 SAS 입력) 모드는 설정으로 **강화**만 가능.

---

## 5. 토큰·키 수명주기

| 대상 | 생성 | 저장(PC) | 저장(폰) | 갱신 | 폐기 |
| --- | --- | --- | --- | --- | --- |
| 서버 TLS 키쌍 | 첫 실행 | ACL 파일(→ Phase 3 DPAPI) | 핀만 | 없음("PC 신원 재생성" → 전 기기 재페어링 경고) | 파일 삭제 |
| 서버 인증서 | 첫 실행/IP 변경/만료 30일 전 | `pc_identity.cert_pem` | — | 자동(같은 키) | — |
| `hook_token`(`an_hk_` + 32B) | 훅 설치 | `daemon.json`(사용자 ACL) + DB 해시 | — | "훅 토큰 재발급"(settings.json 재병합) | 연동 제거 |
| `pairing_secret` | 페어링 시작 | 메모리 + 해시 | 메모리(종료 시 0 채움) | 없음 | 120초 / 1회 / 3회 실패 / 취소 |
| `device_token`(32B) | `pair` 성공 | `devices.token_hash`(SHA-256) | Keystore AES-256-GCM 래핑(인증 **비바인딩**, `setUnlockedDeviceRequired` 금지 — FGS 잠금 중 재연결) → DataStore | 없음 | 데스크톱 폐기 / 폰 `unpair` / 90일 미접속 자동 폐기(설정) |
| 폰 EC P-256 키쌍 | 첫 페어링 전 | `devices.pubkey_spki_der`(공개키만) | Keystore 비추출 | 없음 | `unpair` 시 `deleteEntry`; `KeyPermanentlyInvalidatedException` → 재페어링 |
| `nonce`(16B) | 승인 요청마다 | `approvals.nonce` | 카드 메모리 | — | 요청 종결 |

- `hello` 검증: `devices` 조회 → `revoked_at IS NULL` → `subtle::ConstantTimeEq`로 해시 비교 → 챌린지 일치 → `last_seen_at` 갱신. 실패 **5회/분**(IP당) → 해당 IP 60초 차단(§11과 같은 값 — 레이트리밋 테스트의 기준). 실패는 원인을 구분하지 않고 `E_AUTH_FAILED`(폐기만 `E_DEVICE_REVOKED`).
- 폰: `KeyPermanentlyInvalidatedException`/`AEADBadTagException` → 토큰 폐기 + 재페어링 유도. 로그에 토큰·핀 값 출력 금지.

---

## 6. 승인 바인딩·만료·재생 방지

### 6.1 바인딩 필드

| 필드 | 생성 | 목적 |
| --- | --- | --- |
| `request_id` | PC(`ar_` + UUIDv7), 열린 HTTP 요청 핸들 / Codex `(thread_id, rpc_id)`에 바인딩 | 응답 대상 특정. Claude `PermissionRequest`에는 `tool_use_id`가 없다 [검증] |
| `session_key` | 어댑터 | 교차 세션 적용 방지 |
| `nonce` | PC 16B CSPRNG | 요청별 재생 방지 |
| `tool_input_sha256` | **PC만** `SHA-256(canonical JSON(tool_input))` | PreToolUse↔PermissionRequest 사이 입력 교체 방어, 표시 축약과 바인딩 분리 |
| `expires_at` | `created_at + TTL`(기본 120초, 60~180) | PRD "만료 후 실행 금지" |
| `decided_at` | 폰(skew 보정) | `created_at − 60s .. now + 60s` 창 |

### 6.2 `apply_decision` 9단계 (순서 고정, 모두 **상태 변경 전**; 실패 사유는 `decision_result.reason`)

1. 인증된 기기 연결에서 왔고 기기가 미폐기인가 (`DEVICE_REVOKED` / 연결 종료)
2. `request_id`가 `approvals`에 존재 (`UNKNOWN_REQUEST`)
3. `status == pending` (`ALREADY_RESOLVED`)
4. `session_key`와 `nonce`가 일치 (`BINDING_MISMATCH`, 보안 로그 warn)
5. `tool_input_sha256`이 일치 (`INPUT_HASH_MISMATCH`)
6. 서버 시계로 `now < expires_at`(`EXPIRED`, 동시에 `expired` 전이) **그리고** `decided_at` 창 (`CLOCK_SKEW`)
7. `decision ∈ allowed_decisions` (`NOT_ALLOWED`)
8. `decision ∈ auth_required_for`이면 `auth.method ∈ {biometric, device_credential}`(`AUTH_REQUIRED`) **그리고 인증 신선도**: `authenticated_at ≥ created_at − 5s`(요청 이전의 인증 재사용 금지)·`authenticated_at ≤ decided_at + 5s`(미래 시각 금지) 위반은 `CLOCK_SKEW`, `decided_at − authenticated_at ≤ 60s` 위반은 `AUTH_REQUIRED`(재인증 필요). 시각은 `decided_at`과 같은 skew 보정값. `risk.extra_confirmation != none`이면 `extra_confirmation.completed && method ≥ 요구`(`EXTRA_CONFIRMATION_REQUIRED`). **이 신선도 검사도 폰의 주장에 대한 것이며 Phase 3 서명 전까지 암호학적 증명이 아니다**(§6.4)
9. 원격 승인 일시정지 아님 (`PAUSED`)

10. 적용: **단일 트랜잭션**에서 `UPDATE approvals SET status=…, resolved_by=…, … WHERE request_id=? AND status='pending' AND expires_at > ?`(영향 행 0이면 `ALREADY_RESOLVED`) → `decisions` INSERT → `approval_audit` INSERT → 커밋 → 그 **다음에야** `responder.respond(…)`. 허용이면 이 성공 분기에서 `ApplyProof::mint()`로 만든 증명으로 `ApprovalReply::allow(proof)`를, 거부면 `ApprovalReply::deny(message, interrupt)`를 만든다(다른 어느 곳도 `ApplyProof::mint`를 호출하지 않는다). `decision_result{APPLIED}` + `approval_resolved{seq}`.

#### 6.2.1 데스크톱(`actor=desktop`) 경로의 검증

데스크톱 허용/거부(`approval_decide_local`)는 폰과 **같은 브로커 전이**(10단계의 조건부 UPDATE + 감사)를 지난다. 원격 채널 개념인 단계만 빠지고 나머지는 **생략할 수 없다**.

| 단계 | 데스크톱 | 사유 코드 / 비고 |
| --- | --- | --- |
| 1 인증된 기기 연결 | 해당 없음(IPC는 메인 창 webview만 호출 가능 — capabilities) | |
| 2 `request_id` 존재 | **필수** | `UNKNOWN_REQUEST` |
| 3 `status == pending` | **필수** | `ALREADY_RESOLVED` |
| 4 `session_key`·`nonce` | 해당 없음(원격 재생 방지용, 서버가 `request_id`로 직접 조회) | |
| 5 `tool_input_sha256` | **에코 확인**: 커맨드 인자 `tool_input_sha256`(카드가 가진 값)이 저장값과 같아야 함 — 사용자가 본 카드와 결정 대상이 같음을 보장 | `INPUT_HASH_MISMATCH` |
| 6 만료 | **필수**(서버 시계 `now < expires_at`만; `decided_at` 창은 해당 없음) | `EXPIRED` |
| 7 `decision ∈ allowed_decisions` | **필수** | `NOT_ALLOWED` |
| 8 `auth`/`extra_confirmation` | 생체는 해당 없음(OS 로그인 사용자의 물리 접근). **`risk.extra_confirmation != none`이면 `confirm_ack == true` 필수** — `high`: 1.5초 길게 누르기, `critical`: 명령 전체 재표시 + 체크박스를 UI가 거친 뒤에만 `true` | `EXTRA_CONFIRMATION_REQUIRED` |
| 9 원격 승인 일시정지 | 해당 없음(일시정지는 원격 경로만 막는다) | |
| 10 조건부 UPDATE + `decisions`(`actor='desktop'`)·`approval_audit` | **필수**, `resolved_by=desktop` | `ALREADY_RESOLVED` |

트레이 메뉴는 이 게이트를 우회하는 단축 경로가 되어서는 안 된다: 트레이는 `low`/`medium`에서만 인라인 허용/거부를 제공하고 `high`/`critical`은 승인 창을 열어 위 8단계 게이트를 거치게 한다(`desktop.md` §4). 브로커 테스트: 위 필수 단계마다 단독 실패 테스트, `confirm_ack` 누락 테스트, 일시정지 중에도 데스크톱 결정이 적용되는 테스트(9 해당 없음)를 둔다.

(Phase 3) 6과 7 사이에 ECDSA 서명 검증 단계를 삽입한다. 폰이 보내는 바이트열 조립 규칙은 그때 `protocol/vectors/decision_signed.json`으로 고정.

### 6.3 재생 분석

| 공격 | 멈추는 단계 |
| --- | --- |
| 같은 `decision` 재전송 | 3 (또는 같은 `decision.id` → 멱등 `APPLIED` 응답, 재적용 없음) |
| 다른 요청에 붙이기 | 4·5(nonce·해시가 요청별) |
| 만료 후 전송 | 6 |
| 데몬 재시작 후 과거 결정 | 2 또는 3(상태는 SQLite에 영속). **재시작 시 `pending` 전부 `expired`로 전이**(HTTP 핸들이 사라졌으므로 적용할 곳이 없음) |
| 두 기기가 동시에 결정 | 10의 조건부 UPDATE가 첫 번째만 통과, 두 번째 `ALREADY_RESOLVED` |
| 오프라인 중 큐잉 후 자동 전송 | 폰은 **결정을 큐에 넣지 않는다**(버튼 비활성). 서버도 6에서 차단 |

### 6.4 Phase 1 한계: `auth`는 폰의 주장이다

`decision.auth`는 핀 고정 TLS + 디바이스 토큰 채널 위에서 폰 앱이 보고하는 값이며, **암호학적 증명이 아니다**. 디바이스 토큰을 가진 공격자(= 잠금 해제된 폰을 쥔 A2, 또는 앱 프로세스 침해)는 생체 인증 없이 `auth.method:"biometric"`을 주장할 수 있다. 수용 근거: Phase 1 위협 모델(같은 Wi-Fi·개인용·즉시 폐기 가능)에서 이 공격자는 이미 앱 UI로 생체 프롬프트를 통과할 수 있는 수준이거나, 폐기로 차단된다. Phase 3에서 Keystore EC 키(페어링 때 이미 등록)로 `decision`을 서명하고 `setUserAuthenticationParameters`(작업별)로 생체를 키에 바인딩해 해소한다. Codex 리뷰는 이 필드를 "보장"으로 취급하지 않는다.

### 6.5 범위 확장 금지(I11)

- Claude `PermissionRequest` allow 응답에 `updatedInput`/`updatedPermissions`를 **절대** 넣지 않는다. `permission_suggestions`는 개수만 표시용으로 전달.
- Codex 응답은 문자열 `"accept"`/`"decline"`/`"cancel"`만. 객체형 결정 변형은 생성 코드가 없다.
- Codex hooks `PermissionRequest` 출력에는 `interrupt`/`updatedInput`/`updatedPermissions`를 넣지 않는다(파서가 결정 전체를 폐기 [검증]). `deny_and_stop`은 **hooks 경로(`origin=codex.hook.cli`)의 `allowed_decisions`에서 제외**되고(카드에 "거부만 가능 (Codex hooks는 작업을 멈출 수 없어요)" 표시), 사후에 조용히 `deny`로 강등하지 않는다. app-server 경로에서는 `cancel`로 매핑된다.
- Codex `PreToolUse` 훅에는 `permissionDecision`을 **절대** 출력하지 않는다(`ask`는 항상 무효, `allow`는 `updatedInput` 필수 [검증]) — 관찰 전용 빈 stdout.

---

## 7. Fail-closed 표 (모든 실패 → "결정 없음" 또는 deny; **어떤 경로도 allow 없음**)

| 상황 | 데몬 동작 | Claude Code 결과 | Codex 결과 | 폰 카드 |
| --- | --- | --- | --- | --- |
| 온라인 인증 기기 0 | 즉시 빈 2xx, `approvals.status=handed_off_local`(resolved_by=system) | 로컬 다이얼로그(프롬프트 없는 세션은 거부) | 무응답(TUI 프롬프트) | — (재연결 시 snapshot에 없음) |
| TTL 만료 | 빈 2xx, `expired`, `approval_resolved{expired}` | 로컬 다이얼로그 | 무응답 | "시간이 지나 PC에서 직접 처리하도록 넘겼어요", 버튼 제거 |
| 폰 연결 끊김(요청 보류 중) | 재연결 유예 **10초**(남은 TTL이 더 짧으면 그만큼) 후 빈 2xx `handed_off_local` | 로컬 다이얼로그 | 무응답 | 재연결 후 카드 정리 |
| 결정 검증 실패(§6.2) | `decision_result{accepted:false}`, 요청은 `pending` 유지(TTL까지 재시도 가능) | 대기 지속 | 대기 지속 | 사유 표시 |
| 데몬 내부 오류/패닉 복구 | 가능하면 빈 2xx, 아니면 연결 종료 | 로컬 다이얼로그 / 비차단 오류 [검증] | 무응답 | `superseded` |
| 데몬 재시작 | 시작 시 `pending` 전부 `expired` | 열린 연결 끊김 = 비차단 오류 → 로컬 다이얼로그 | 무응답 | snapshot으로 정리 |
| 데몬 미실행 | — | 연결 실패 = 비차단 오류 [검증] (+ `hook error` 알림, Phase 0 A4) | hooks: CLI가 빈 stdout exit 0 | — |
| 훅 타임아웃 도달(데몬이 먼저 응답하지 못한 비정상) | — | 출력 폐기 = 결정 없음 [검증] | — | `superseded` |
| Claude가 먼저 종료(로컬 결정·Ctrl-C) | 열린 HTTP 연결 끊김 → `DropGuard` → `superseded`(resolved_by=agent) — hyper가 핸들러 future를 drop한다는 가정 [추정] → P6 | — | — | "PC에서 이미 처리됨" |
| Codex `serverRequest/resolved` 선수신 | `superseded`, 늦은 결정은 `audit: late_decision`, 응답 미전송 | — | TUI/다른 클라이언트가 처리 | 카드 닫힘 |
| `permission_mode ∈ {bypassPermissions, dontAsk, auto}` | `remote_approval: unavailable` 배지, `PermissionDenied`는 이벤트로만 | `PermissionRequest` 미발생 가능 [검증] | — | 세션 카드 배지 |
| 기기 폐기(보류 중) | 그 기기의 결정 무효; 다른 온라인 기기 없으면 `handed_off_local` | 로컬 다이얼로그 | 무응답 | `bye` 후 토큰 삭제 |
| 원격 승인 일시정지 | 새 요청은 즉시 빈 2xx; 보류 결정은 `PAUSED` | 로컬 다이얼로그 | 무응답 | 배지 |
| 위험 분류기 패닉/정규식 오류 | `critical`로 분류 후 정상 흐름 | — | — | 빨간 카드 + 재확인 시트 |
| 알 수 없는 `decision` 값 | `E_BAD_MESSAGE`(스키마 거부) | 대기 지속 | 대기 지속 | — |
| 데스크톱 "로컬로 처리" | 즉시 빈 2xx, `handed_off_local`(resolved_by=desktop) | 로컬 다이얼로그 | 무응답 | "PC에서 처리하기로 했어요" |
| 데스크톱 허용/거부 | **동일 브로커 전이**(§6.2.1: 2·3·5(카드 해시 에코)·6·7 필수, 8은 `confirm_ack`, 1·4·9 해당 없음; `actor=desktop`, 감사 기록). 트레이는 `high`/`critical`에 허용을 제공하지 않는다 | allow/deny | accept/decline | `approval_resolved{resolved_by:desktop}` |
| 링크 비활성(`link.enabled=false`) | 보류 승인 전부 `handed_off_local`(resolved_by=desktop), 리스너 닫힘, 감사(§3.3) | 로컬 다이얼로그 | 무응답 | `bye` 후 "PC에서 연결을 껐어요" |
| 거부 결정 | `deny` + `message`(사유) | 도구 거부, Claude에 사유 전달 | `decline` | "거부했어요" |
| 거부+중단 | `deny` + `interrupt:true` | Claude 중단 | `cancel` | "거부하고 멈췄어요" |

문서 전체에서 "결정 없음 = 로컬 프롬프트"는 **프롬프트를 띄울 수 있는 세션에 한한다**. 백그라운드 서브에이전트·`-p` 세션에서는 결정 없음 = 거부다 [검증]. 어느 경우도 allow가 아니므로 수용한다.

---

## 8. 로그·레댁션 (I9)

### 8.1 비밀 타입

`PairingSecret`, `DeviceToken`, `HookToken`, `Nonce`, `TlsKeyPem`(Rust `redact.rs`)은 `Debug`/`Display`가 `"<redacted>"`를 출력하고 `zeroize 1.9.1`로 drop 시 소거한다. `tracing` 필드에는 이 뉴타입만 전달할 수 있다(원시 `String` 토큰 금지 — clippy lint `disallowed_types`로 보조). 단위 테스트 `tests/redaction.rs`: 모든 비밀 타입 × 모든 이벤트 종류에 대해 포맷된 로그 출력에 테스트 비밀 바이트가 0회 등장.

### 8.2 3-싱크 정책

| 싱크 | 포함 | 제외/마스킹 |
| --- | --- | --- |
| `tracing` 로그(파일 롤링 일 단위, 7일, 10 MiB×5, 기본 `info`) | 이벤트 kind, `session_key` 앞 12자, `request_id`, 도구명, 위험 등급, 길이·해시 요약, 오류 코드 | 토큰·키·nonce·서명(값 전부), 명령(`len=42 sha256=9f86…` 형태만), 경로(마지막 2 세그먼트), 프롬프트/stdout/파일 본문(없음), IP 마지막 옥텟 마스킹, 요청 본문 전체(디버그 레벨에서도 금지) |
| `approval_audit`/`audit_log` | 누가(device_id/desktop)·언제·무엇(request_id, decision, risk)·결과·사유 | 명령·diff 원문 없음(`approvals` 참조) |
| `approvals.details_json`, `events.detail_json`(DB·폰 전송) | 명령 2,000자, diff 4 KiB, 경로 50개, stdout 꼬리 1 KiB, 프롬프트 200자 — 모두 패턴 마스킹 후 | `tool_input.content` 전체, `old_string/new_string` 전체, stdout 전체, 원시 훅 본문(**처음부터 저장하지 않음**). `approvals.details_json`은 7일 후 NULL |
| 폰 로컬 로그 | 릴리스 빌드에서 페이로드 no-op(메시지 타입·길이만) | — |
| 알림 본문 | `title` + 위험 등급 + 남은 시간만 | 명령 전문(잠금 화면 노출 금지) |

### 8.3 패턴 마스킹(`redact::mask`, 픽스처 `protocol/fixtures/redact_cases.json`)

`(?i)(api[_-]?key|token|secret|password|passwd|authorization|bearer)\s*[:=]\s*\S+` → `<redacted>`; `AKIA[0-9A-Z]{16}`; `gh[pousr]_[A-Za-z0-9]{36,}`; `sk-[A-Za-z0-9]{20,}`; `-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END`; JWT `eyJ[A-Za-z0-9_-]+\.eyJ…`; 40자 이상 hex/base64 토큰. 마스킹된 이벤트는 `redacted: true`.

---

## 9. 설정 스키마에서 금지되는 것 (I10, Codex P0 항목 6)

`AppConfig`에 다음 필드는 **존재하지 않는다**: `auto_allow_*`, `allow_for_session`, `trust_all_certs`, `bind_hooks_all_interfaces`, `hook_bind_addr`, `disable_biometric`, `skip_auth_for_*`, `approval_ttl_s > 180`, `risk_overrides`, `risk_rules_path`. 존재하는 보안 설정(모두 **강화 방향만**):

| 키 | 기본 | 허용 범위 |
| --- | --- | --- |
| `approval.ttl_s` | 120 | 60~180. **유효 TTL은 설치된 Claude 훅 `timeout − 30`을 넘지 않는다**(`integrations/claude-code.md` §2) |
| `approval.critical_remote` | `extra_confirmation` | `extra_confirmation` \| `local_only` |
| `approval.deny_requires_auth` | false | true로만. **소유자는 PC 설정**이며 `welcome.policy.deny_requires_auth`로 폰에 전달된다(폰 로컬 토글 없음, 폰 설정 화면은 읽기 전용 표시) |
| `approval.daemon_down_deny`(`onFailure:"block"`) | false | true로만(옵트인) |
| `approval.reconnect_grace_s` | 10 | 0~10 |
| `pairing.confirm_mode` | `sas_display` | `sas_display` \| `retype_sas` |
| `risk.force_ask_on_critical` | true | true \| false(PreToolUse `ask` 강제 여부 — 끄면 로컬 프롬프트 강제만 사라짐, 분류는 그대로) |
| `link.bind_addr` | 주 인터페이스 | LAN 인터페이스 주소 중 선택(`0.0.0.0` 거부) |
| `link.private_sources_only` | true | Phase 3 전까지 false 불가 |
| `link.enabled` | true | true \| false(false = 리스너 닫기 — 노출을 줄이는 방향, §3.3) |
| `codex.mode` | `hooks` | `hooks` \| `daemon_observer`(flag 빌드에서만) \| `off` |

설정 파일에 미지 키가 있으면 데몬은 **거부하고 시작하지 않는다**(`deny_unknown_fields`).

---

## 10. 폐기·운영 절차

- **기기 폐기(데스크톱)**: 기기 목록 → "폐기" → **기기 이름을 직접 입력**해야 확정(오조작 방지) → 트랜잭션 `devices.revoked_at` → 메모리 레지스트리 제거 → 활성 연결에 `bye{device_revoked}` + 4003 → 그 기기의 보류 결정 무효 → `audit_log(device_revoked)`. 되돌리기 없음(재페어링만).
- **휴대폰 연결 끊기(리스너 중지)**: 트레이 → '휴대폰 연결 끊기'(§3.3). 기기 폐기와 달리 등록은 유지되고 리스너만 닫힌다.
- **방화벽 규칙 제거**: 앱 내 버튼 또는 언인스톨러(§3.1).
- **폰 연결 해제**: `unpair` 전송(응답 무관) → 로컬 토큰·핀·pc_id 삭제 + Keystore `deleteEntry`.
- **잃어버린 폰**: 트레이 → 기기 → 폐기. 폐기 뒤 그 폰은 TLS는 성공(공개 핀)하지만 `hello`가 4003. 폰에 남은 비밀은 래핑된 토큰뿐이며 PC에서 무효.
- **PC 신원 재생성**(키 유출 의심): 새 키쌍 → 새 SPKI → 모든 기기 재페어링(경고 모달 2단계).
- **훅 토큰 재발급**: `daemon.json` + settings.json 재병합.
- **보존**: `decisions`/`audit_log` 365일, `approvals` 90일(details 7일 후 NULL) — `storage.md`.

---

## 11. 인증 전 방어·레이트리밋

- 연결당 `PreAuth` 5초(유효한 `pair`/`hello` 수신까지)·`PairPending` 60초, IP당 동시 인증 전 연결(`PreAuth`+`PairPending`) 4개, **IP당 인증 실패 5회/분** 초과 시 60초 차단(§5와 같은 값 — 레이트리밋 테스트의 기준), 전체 동시 연결 16(초과 즉시 1013 close, 어떤 프레임도 보내지 않음 — `protocol.md` §9.3).
- 인증 실패는 1초 지연 후 닫는다. 어떤 실패도 "기기 없음"과 "토큰 오류"를 구분하지 않는다.
- 인증 후: 기기당 `decision` 10건/분, `ping` 6건/분, `snapshot_request` 6건/분, `events_request` 12건/분 초과 시 `E_RATE_LIMITED`(3회 누적 시 4005).
- 훅 HTTP: 관찰 이벤트 초당 200건 초과 시 429(`PermissionRequest`는 제외).

---

## 12. Phase 1 수용 기준(보안)

1. 미인증 소켓으로 `wscat` 접속 시 `challenge` 외 아무것도 받지 못하고 5초 내 4001. 유효한 `pair` 뒤 `PairPending`에서 `unpair`·close 외 프레임을 보내면 4001, 60초 무확인이면 4002.
2. 폐기 후 폰의 `hello` → 4003, 활성 연결 즉시 끊김.
3. 로그 파일·DB `grep`에 테스트용 비밀 문자열 0건, 원시 훅 본문 0건.
4. 같은 `decision` 재전송이 재적용되지 않음; 만료 후 결정이 `EXPIRED`.
5. 폰 비행기 모드 중 권한 프롬프트 → 로컬 다이얼로그(또는 프롬프트 없는 세션은 거부); 재연결 후 카드가 `handed_off_local`로 정리됨.
6. `grep -rn 'ApplyProof::mint' desktop/crates/ | grep -v '/tests/\|cfg(test)\|test-util'` 결과가 `approvals/broker.rs`의 `apply_decision` 성공 분기 **1줄**뿐이고, `ApprovalReply::allow(`를 호출하는 곳도 그 한 곳뿐(+ `compile_fail` doctest가 외부 허용 생성 불가를 증명).
7. `aws-lc-rs`가 의존 그래프에 없음(단일 암호 백엔드): CI는 `! cargo tree --workspace --target all -i aws-lc-rs 2>/dev/null`(패키지가 없으면 `cargo tree`가 오류로 종료하므로 종료 코드를 **반전**해 검사; 별도로 `cargo tree --workspace`가 성공함을 먼저 확인).
8. 설치된 `settings.json` 골든에 `onFailure`가 없거나 `continue`.
9. 클린 Windows 11에서 방화벽 규칙(UAC)·네트워크 프로필 안내·연결 진단·언인스톨 시 규칙 제거가 동작(§3.1, P15).
10. `link.enabled=false` → 리스너가 닫히고 보류 승인이 전부 `handed_off_local`로 종결되며 `audit_log(link_disabled)`가 남고 재시작 후에도 유지(§3.3).
11. 세션 종료 31일 뒤에도 `approvals`·`decisions`·`approval_audit`·`review_findings`가 남아 있음(`storage.md` §3 보존 회귀 테스트).
12. 데스크톱 결정 경로가 §6.2.1의 필수 단계를 각각 단독으로 거부하고, 트레이에서 `high`/`critical`을 허용할 수 없음.
13. R1(ACL 파일 편차) 사용자 확인 전에는 페어링을 시작할 수 없고, 확인은 `audit_log(risk_accepted)`로 남음(§1.3).
