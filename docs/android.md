# Android 앱 설계

- 상태: 확정(리드 종합본) — 2026-10-15
- 버전 근거: 리서치 `android-stack.md`(developer.android.com·Maven Central·kotlinlang·빌드박스 실측). 별도 표기 없는 버전은 [검증].
- 원칙: **로직은 `android/core`(순수 Kotlin JVM, Android 의존성 0)**, `android/app`에는 네트워크 바인딩·암호 저장·UI·알림만. `android/core`는 빌드박스에서 `./gradlew :core:test`로 전부 검증된다.

---

## 1. 모듈·빌드

### 1.1 버전

| 항목 | 버전 | 비고 |
| --- | --- | --- |
| Gradle wrapper / AGP / Kotlin(KGP) | 9.7.1 / 9.3.3 / 2.4.21 | AGP 9 built-in Kotlin: `org.jetbrains.kotlin.android` **미적용**, `kapt` 금지. KGP 2.4.21 공식 지원 AGP 상한 9.3.1 → 9.3.3 보수 선택, CI 녹색 후 9.4.x |
| Compose BOM | 2026.09.00 (ui 1.12.1, material3 1.4.0) | 컴파일러 플러그인 `org.jetbrains.kotlin.plugin.compose` 2.4.21 |
| activity / lifecycle / core / datastore-preferences | 1.13.0 / 2.11.0 / 1.19.1 / 1.2.1 | core-ktx는 1.19부터 core에 합쳐짐 |
| biometric | 1.1.0 | 1.4.0-alpha 라인(Compose API)은 beta 이후 검토 |
| OkHttp / okhttp-tls / mockwebserver3-junit5 | 5.5.0 | JVM 호환 → WS 클라이언트·핀닝은 `core`에 |
| kotlinx-serialization-json / coroutines | 1.11.0 / 1.11.0 | |
| play-services-code-scanner | 16.1.0 | **검증 필요 (Phase 0) P3** — Google Maven 접근 불가. `QrScanner` 인터페이스 뒤 격리 |
| compileSdk / targetSdk / minSdk | 36 / 36 / 26 | Play 2026-08-31 요건. targetSdk 37은 `ACCESS_LOCAL_NETWORK` 런타임 권한 대응 후 |
| JDK | CI 17 / 로컬 21 | `jvmTarget 17`, `jvmToolchain` 미사용(foojay 차단 대비) |
| Navigation | **수동**(sealed class + `BackHandler`) | Navigation 3 1.2.0 API 미검증, navigation-compose는 유지보수 모드 → Phase 1은 `nav` 패키지에 격리된 자체 스택 |
| security-crypto | **사용 금지** | 1.1.0에서 전 API deprecated [검증] → Keystore 직접 사용 |

### 1.2 `android/settings.gradle.kts` (리서치 §7.1 패턴 그대로 [검증: 실측])

- `pluginManagement`/`dependencyResolutionManagement`에 `google()`을 **콘텐츠 필터**(`com.android.*`, `com.google.*`, `androidx.*`)와 함께 선언, `mavenCentral()`, `gradlePluginPortal()`.
- `include(":core")` 항상. `:app`은 `ANDROID_HOME`/`ANDROID_SDK_ROOT`/`local.properties sdk.dir`가 있고 `-Pagentnest.skipAndroid=true`가 아닐 때만 include.
- 루트 `build.gradle.kts`에는 `kotlin.jvm`/`kotlin.plugin.compose`/`kotlin.plugin.serialization`만 `apply false`. **AGP를 루트에 선언하면 SDK 없는 머신에서 해석 실패**(실험 [5]) → 선언 금지.

### 1.3 모듈 구조

```text
android/core/src/main/kotlin/dev/agentnest/core/
├── protocol/   Envelope, Message(sealed, classDiscriminator="type"), AgentEvent, SessionState, ApprovalRequest, Decision, ApprovalResolved, QrPayload, Codec(Json 설정)
├── crypto/     Canonical(pair 바이트열), HmacSha256(javax.crypto.Mac), Sas, Sha256
├── link/       LinkState(sealed), LinkStateMachine, BackoffPolicy, SeqTracker(ack/resync), HostBook(welcome/hosts_update/수동 입력 주소 보관·순회), EventsPager(events_request 페이징), WsTransport(interface), OkHttpWsTransport, ClockSkew
├── tls/        SpkiPinTrustManager, PinnedClientFactory
├── nest/       NestState, NestReducer(순수), MoodResolver(히스테리시스 포함), KongiMood, FocusSelector, ApprovalHistory(최근 50건 승인 기록 리듀서)
├── approval/   DecisionValidator(사전검사: 만료 마진·allowed_decisions·auth/extra 요구), DecisionBuilder
└── text/       RelativeTime("3분 전"), Fallbacks

android/app/src/main/kotlin/dev/agentnest/app/
├── AgentNestApp.kt           Application: 알림 채널 생성, 수동 DI, NestRepository 단일 인스턴스
├── MainActivity.kt           FragmentActivity 상속(BiometricPrompt 요구 [검증]) + setContent
├── nav/AppNav.kt             NavKey(sealed): Home, Agents, SessionDetail(key), Approvals, ApprovalDetail(id), ApprovalHistory, Projects, Activity, Settings, Pairing, ManualHost, Devices, NotificationPrefs, CharacterPrefs; BackHandler
├── ui/home/                  HomeScreen(3층), KongiHeader, ActionCard, SessionCardList
├── ui/agents/                AgentsScreen, SessionDetailScreen(타임라인)
├── ui/approvals/             ApprovalsScreen, ApprovalDetailScreen, ApprovalHistoryScreen, HoldToConfirmButton, ExtraConfirmSheet
├── ui/projects/              ProjectsScreen(Phase 1: 세션에서 유추한 프로젝트 목록만)
├── ui/activity/              ActivityScreen(필터: 오류/완료/승인/파일/명령)
├── ui/settings/              SettingsScreen, PairingScreen, DevicesScreen, NotificationPrefsScreen, CharacterPrefsScreen
├── character/                KongiCanvas, KongiSpec, KongiAnimator, SoundCues   (character.md)
├── service/                  LinkService(FGS connectedDevice), BootReceiver
├── notify/                   Channels, ApprovalNotifier, AlertNotifier, LinkNotifier
├── auth/BiometricGate.kt
├── vault/                    TokenVault(Keystore AES-GCM), DeviceKey(Keystore EC P-256 — Phase 1은 공개키 등록만), PairingStore(DataStore)
├── qr/                       QrScanner(interface), GmsQrScanner (zxing 폴백은 별도 모듈 가능)
└── data/                     NestRepository(StateFlow<NestState>), SnapshotCache(DataStore, 콜드스타트), EventCache(최근 200건), ApprovalHistoryStore(DataStore, 최근 50건)
```

아키텍처: `LinkService`가 소켓을 소유하고 수신 메시지를 `NestRepository`로 보내며, `NestReducer.reduce(state, message)`(순수 함수)가 `StateFlow<NestState>`를 갱신한다. Activity는 바인드 없이 Repository를 구독한다. ViewModel은 화면별 파생만.

---

## 2. 화면

### 2.1 홈 (3초 규칙 → 3층, 시간 예산)

```text
┌────────────────────────────────────────┐
│ ● 연결됨 · DESKTOP-HOME        ⚙ 설정   │  링크 상태 점+문구. 끊기면 배너로 확장: "PC와 연결이 끊겼어요 · 다시 연결 중 (3번째, 8초 후)"
│        [콩이 — mood 애니메이션]          │  0층 (0~1초): NestState.mood + headline — 폰이 이미 가진 값, 왕복 없음
│  Claude가 agentnest에서 테스트를 돌리고   │
│  있어요                                 │
│ ┃ 승인 필요 1건                 1:48 남음│  1층 (1~2초): 행동 카드 — pendingApprovals[0] 펼침 + "+N건", 최근 오류 1건
│ ┃ 명령을 실행하려고 해요 · 위험 높음      │
│ ┃ rm -rf node_modules && pnpm install   │
│ ┃                     [거부]  [보기 →]  │
│ ▸ Claude Code · agentnest · feat/proto │  2층 (2~3초): 세션 카드(상태 chip·경과·headline), 우선순위 정렬
│ ▸ Codex · agentnest · 리뷰 중           │
├────────────────────────────────────────┤
│  홈   AI   프로젝트   활동   설정        │  하단 탭 (PRD §3.A)
└────────────────────────────────────────┘
```

- 콜드 스타트: `SnapshotCache`의 마지막 상태를 즉시 렌더 + "마지막 확인 3분 전". 빈 화면·스피너만 있는 상태 금지.
- `snapshot` ≤ 192 KiB(`welcome.limits.snapshot_max_bytes`; 절단 순서·`pending_approval_ids_complete`·후속 `approval_request`는 `protocol.md` §4.6), `NestReducer` 1건 적용 ≤ 5 ms(메인 스레드; JVM 테스트로 측정). 스냅샷에서 본문 없이 ID만 있는 승인 카드는 "불러오는 중"(버튼 비활성)으로 두고 후속 프레임을 기다린다.
- 모든 문자열은 PC가 한국어로 만든다. 폰은 상대 시간 포맷만 한다.
- ActionCard의 "거부"는 기본 인증 없음(**PC 정책** `welcome.policy.deny_requires_auth`가 true면 요구 — 폰에는 이를 바꾸는 토글이 없다), "보기"는 상세로. 카드 아래 "승인 기록 ›" 링크로 `ApprovalHistory`(§2.3)에 갈 수 있다. 1층의 "최근 오류 및 테스트 결과"는 `session_state.last_test`와 `recent_errors`에서 온다. 종료 세션은 5분간 흐리게 후 숨김. Pull-to-refresh = `snapshot_request`.

### 2.2 승인 상세

```text
┌────────────────────────────────────────┐
│ ← 승인 요청                 ⏱ 1:32 남음 │  카운트다운(서버 시계 skew 보정)
│ Claude Code · agentnest · feat/proto    │
│ ■ 명령을 실행하려고 해요                 │  title
│ ┌ 실행될 명령 ─────────────────── 펼치기┐│  details.command 고정폭, 가로 스크롤, 전체 보기
│ │ rm -rf node_modules && pnpm install  ││
│ └──────────────────────────────────────┘│
│ 위치: …\apps\desktop                     │  cwd_hint
│ 영향: desktop/apps/desktop/node_modules  │  file_paths
│ ⚠ 위험 높음 — 폴더를 통째로 지우는 명령   │  risk.reasons_ko
│ 에이전트가 한 말 (검증 안 됨)            │  purpose — 작은 글씨·흐린 색, 명령/위험 블록 아래
│  “node_modules 폴더를 지우고 다시 설치”   │
│ [ 거부 ]            [ ■ 길게 눌러 허용 ] │
│                  ⋯ 거부하고 멈추기        │  더보기 메뉴(실수 방지)
└────────────────────────────────────────┘
```

| 위험 | 허용 흐름 |
| --- | --- |
| `low`/`medium` | 탭 → `BiometricPrompt` → 전송 |
| `high` | 길게 누르기 1.5초(진행 링) → `BiometricPrompt` → 전송 |
| `critical` | 길게 누르기 → `ExtraConfirmSheet`(명령 전체 재표시 + 체크박스 "내용을 확인했어요") → `BiometricPrompt` → 전송 |
| `deny` | 기본 인증 없음(PC 정책 `deny_requires_auth`가 true일 때만 요구) |
| `deny_and_stop` | **allow와 동일 게이트**(턴을 중단시키므로) |

- **추가 확인의 실제 게이트는 길게 누르기와 재확인 시트다.** `setConfirmationRequired`는 얼굴·홍채 같은 *수동* 생체에서 확인 탭을 요구할지에 대한 **시스템 힌트**일 뿐(시스템이 무시할 수 있고 지문 기기에는 영향이 없음 — 갤럭시 S 시리즈처럼 지문 인증 기기에서는 사실상 무의미) 보안 통제로 취급하지 않는다. [검증: developer.android.com `BiometricPrompt.PromptInfo.Builder#setConfirmationRequired` 2026-10-15 열람] 서버는 `extra_confirmation.completed`(클라이언트가 길게 누르기·시트를 거쳤다는 주장)를 검사하되 이것도 폰의 주장임을 안다(`security.md` §6.4).
- `purpose`는 에이전트가 쓴 텍스트라 **"에이전트가 한 말 (검증 안 됨)"** 으로 라벨링하고 실제 명령·영향 경로·위험 등급보다 시각적으로 아래·작게 둔다(영문 의미: *Agent says (unverified)*). 헤드업 알림 본문·생체 프롬프트·`headline`에도 쓰지 않는다(허용 판단의 근거로 삼지 않게). `allowed_decisions`에 없는 결정의 버튼은 만들지 않는다 — Codex hooks 출처(`origin=codex.hook.cli`) 카드는 "거부 + 멈추기" 메뉴 대신 "거부만 가능 (Codex hooks는 작업을 멈출 수 없어요)"를 표시한다.
- 생체 프롬프트: 제목 "승인 확인", 부제 = `title`, 설명 = `details.command` 80자.
- 전송 후 "PC에 전달 중…" → `decision_result{APPLIED}` → "허용했어요 · Claude에 전달했어요" → `approval_resolved{observed_result}` 갱신 시 "Claude가 실행했어요". 5초 내 `decision_result` 없으면 "확인 중…" 유지(**재전송 안 함**).
- 만료/해결된 카드: 버튼 제거 + "시간이 지나 PC에서 직접 처리하도록 넘겼어요" / 결과 배지. `expires_at − skew − 5s` 이후엔 버튼 비활성.
- 오프라인(`link != Connected`): 버튼 비활성 + "PC와 연결이 끊겨 지금은 응답할 수 없어요". **결정을 큐에 넣지 않는다.**

### 2.3 그 외 화면

| 화면 | 내용 |
| --- | --- |
| AI(Agents) | Claude Code / Codex 섹션. 세션별 프로젝트·headline·`recent_files`(5)·`recent_commands`(3)·`started_at`/`last_event_at`/`turn.completed_at`·`permission_mode`/`remote_approval` 배지(`unknown`은 `unavailable`과 같게). Codex: `meta.review{p0,p1,state}` — `state=unavailable`이면 숫자 대신 "리뷰 정보 없음 (hooks 모드)"(PC가 준 `adapter_status.detail`)를 표시. `last_test` 칩 |
| 세션 상세 | 타임라인(headline + 시각, 펼치면 detail), 상단 고정 "지금" 카드. 스크롤이 로컬 캐시 끝에 닿으면 `events_request{session_key, before_seq, limit:50}`로 더 불러온다(`events_history` capability가 없으면 캐시된 최근 이벤트만) |
| 승인 기록 | `ApprovalHistory`(홈 "승인 기록 ›"·활동 필터 "승인"에서 진입): **최근 50건** `approval_resolved`를 폰 DataStore에 캐시해 목록으로 보여준다(`title`·위험 등급·`outcome`·`resolved_by`·시각·`observed_result`·`message_ko`; 카드가 있을 때 저장한 값이며 **명령 원문은 저장하지 않는다**). PRD §3.D·§9 "승인/거절의 실제 처리 결과 확인"을 화면으로 충족. `observed_result`가 나중에 갱신되면(같은 `request_id` 재전송) 항목도 갱신. 알 수 없는 `outcome`은 "처리됨" |
| 프로젝트 | Phase 1: 세션에서 유추한 카드(이름·경로 힌트·브랜치·연결 에이전트·마지막 활동). PR/테스트는 Phase 2 자리 |
| 활동 | 전체 타임라인, 필터 chip(오류/완료/승인/파일/명령), 날짜 구분선. 로컬 캐시(최근 200건) + `events_request` 페이징(`before_seq` 배타). 오프라인이면 캐시만 보이고 "더 불러오기" 비활성 |
| 설정 | PC 연결(페어링/연결 해제/기기 정보), 알림(채널별 토글·조용한 시간), 콩이(애니메이션/소리/저전력), 보안(**PC 정책 읽기 전용 표시** — 거부 인증 요구 여부; 폰에서 바꿀 수 없음), 배터리 안내(삼성 "절전 예외 앱" + 배터리 최적화 설정 딥링크 — 자동 요청 안 함), 정보 |
| 페어링 | 안내 → QR 스캔 → "192.168.0.10 시도 중…" → **폰이 로컬 계산한 SAS 6자리 표시**(`pair_pending.sas`와 비교, 불일치 시 `unpair{pairing_id}`로 중단) **+ "PC에서 승인을 눌러 주세요"** → `pair_result` → `POST_NOTIFICATIONS` 요청 → 홈 |
| 기기 | 이 기기 정보, 연결 해제(`unpair`), **'IP 직접 입력'**(`ManualHost`: 핀·`hello` 인증은 그대로, 재페어링 없이 주소만 추가), 저장된 PC 주소 목록 |
| 온보딩 | 알림 권한 설명, 삼성 절전 예외 안내, 기기 잠금 미설정 시 경고("원격 승인에는 기기 잠금이 필요해요") |

---

## 3. 링크 서비스·재연결

### 3.1 Foreground Service

- `LinkService`: `android:foregroundServiceType="connectedDevice"` + 매니페스트 `CHANGE_WIFI_STATE`(전제조건, normal) [검증]. `ServiceCompat.startForeground(this, 1001, notif, FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)`(API 29 미만은 0). `onTimeout(startId, fgsType)` 방어 구현(connectedDevice엔 제한 없음).
- `dataSync` **금지**(Android 15+ 6h/24h 제한 [검증]). `specialUse`는 Play 게시 시 전환 옵션.
- 시작 지점(Android 12+ 백그라운드 시작 제한 [검증]): 페어링 완료 Activity, 앱 열기, 알림 "다시 연결" 액션, `BOOT_COMPLETED`(설정 on, connectedDevice는 허용 목록). `ForegroundServiceStartNotAllowedException`은 알림으로 안내.
- 서비스는 **결정을 만들지 않는다**. `decision` 송신은 Activity에서 생체 인증 후 `DecisionBuilder`가 만든 메시지를 Repository → 서비스로 넘길 때만.
- Doze: FGS 실행 중에는 네트워크 제한 없음(전력 관리 표 [검증]). Job/WorkManager로 연결 유지 금지(Android 16 쿼터).

### 3.2 `LinkStateMachine` (`android/core`, JVM 테스트)

```kotlin
sealed interface LinkState {
    object Unpaired : LinkState
    data class Connecting(val host: String, val attempt: Int) : LinkState
    object Challenged : LinkState                                   // challenge 수신, hello 전송
    data class Connected(val pc: PcInfo, val since: Instant, val rttMs: Int?) : LinkState
    data class Reconnecting(val attempt: Int, val nextAt: Instant, val lastError: LinkError) : LinkState
    object Offline : LinkState                                      // ConnectivityManager: 네트워크 없음
    data class PcUnreachable(val since: Instant) : LinkState        // 연속 5회 실패 → 화면에 'IP 직접 입력'·'QR 다시 스캔(주소만 갱신)' 제공
    data class NeedsRepair(val reason: RepairReason) : LinkState    // E_AUTH_FAILED 3회 연속 / Revoked 확인 후 / PC 신원 변경 확인 → '다시 페어링' 필수
    data class Revoked(val code: String) : LinkState                // E_DEVICE_REVOKED / 4003 → 재페어링 필요, 자동 재시도 금지
    data class Suspended(val until: Instant) : LinkState            // 핀 불일치 3회 → 1시간 + security 알림 "PC 신원이 바뀌었어요". 1시간 전에도 사용자가 **'다시 페어링'**으로 빠져나갈 수 있다(아래)
    object Incompatible : LinkState                                 // 4010 → 업데이트 안내
}
```

- 백오프: 1, 2, 4, 8, 16, 32, 60, 60… 초 ±20% 지터. `registerDefaultNetworkCallback.onAvailable`·앱 포그라운드 전환·사용자 "재연결"에서 즉시 리셋.
- 호스트 순회(`HostBook`): 시도 순서 = **`welcome.hosts`/`hosts_update`로 저장한 최신 주소 → 수동 입력 주소 → QR `hosts[]`**(각 3초 connect timeout), 성공 호스트를 선두로 저장. 저장 대상은 사설 대역 주소만(10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7), 최대 8개(`protocol.md` §4.5). 단일 NIC DHCP 변경처럼 기존 주소가 사라진 경우 `hosts_update`가 오지 못하므로 `PcUnreachable` 화면에서 **'IP 직접 입력'**(또는 PC '기기 추가' QR을 다시 스캔하되 `pc_id`·`spki_pin`이 저장값과 같으면 주소만 갱신)로 복구한다.
- **`NeedsRepair`와 '다시 페어링'**: `E_AUTH_FAILED`가 연속 3회면(`protocol.md` §9.1) `NeedsRepair(AuthFailed)`로 전이해 자동 재시도를 멈추고 "다시 페어링" 버튼을 보인다. `Revoked`(4003)·`Suspended`(핀 불일치)에서도 같은 버튼을 보인다. 버튼은 확인 대화상자("PC 화면의 QR을 직접 스캔해야 해요. 모르는 사람이 준 QR은 쓰지 마세요") 뒤에 **로컬 토큰·핀·`pc_id`·Keystore 항목을 삭제하고 `Suspended`/`Revoked` 상태를 해제**한 뒤 `Pairing` 화면으로 보낸다. PC 신원 재생성(`security.md` §10)처럼 합법적으로 핀이 바뀐 경우 1시간을 기다리지 않고 이 경로로 복구한다.
- OkHttp `pingInterval(25s)`; 70초 수신 없음 → 끊고 재연결(pong 미수신 시 `onFailure` 여부는 [미검증] → 앱 레벨 규칙이 보증).
- 연결마다 `hello{last_seq}` → `welcome.resync` 처리. `snapshot`은 로컬 상태 **교체**.
- 시계 보정: `welcome.server_time`/`challenge.server_time`과 폰 시계 차 `skew_ms` 저장. `DecisionValidator`는 `expires_at − skew − 5s`, `decided_at`은 폰 시계 + skew.
- 기기당 연결 1개: 4009 수신 시 "다른 곳에서 연결됨" 표시 후 백오프.

### 3.3 핀닝 클라이언트 (`core/tls`, [검증: OkHttp 소스])

리서치 §2.2의 `SpkiPinTrustManager`(리프 SPKI SHA-256 == 핀, `MessageDigest.isEqual`, `checkValidity()`) + `hostnameVerifier`(핀 재확인) + `CertificatePinner("sha256/<pin>")` 2중 방어 + `sslSocketFactory(factory, trustManager)` 2인자. 평문 폴백 없음, `usesCleartextTraffic` 불필요. 테스트(`mockwebserver3-junit5` + `HeldCertificate`): (a) 핀 일치 → 연결, (b) 다른 키 → `SSLPeerUnverifiedException`, (c) 만료 → 실패, (d) 같은 키 재발급(SAN 변경) → 연결.

---

## 4. 보안 저장·인증

### 4.1 TokenVault (Keystore AES-256-GCM, [검증: keystore 가이드])

- alias `agentnest.device_token.v1`, `PURPOSE_ENCRYPT|DECRYPT`, GCM/NoPadding, 256비트, **`setUserAuthenticationRequired(false)`**, **`setUnlockedDeviceRequired` 금지**(FGS가 잠금 중 재연결), StrongBox 시도 후 `StrongBoxUnavailableException`이면 폴백. 봉인 결과 `[iv(12)|ct+tag]` base64 → DataStore.
- `KeyPermanentlyInvalidatedException`/`AEADBadTagException` → 토큰 폐기 + 재페어링 유도.
- `DeviceKey`: alias `agentnest.device.v1`, EC P-256 `PURPOSE_SIGN`, 비추출, StrongBox 시도. Phase 1은 **공개키(SPKI DER)만** `pair`에 실어 등록. Phase 3에서 `setUserAuthenticationParameters`(작업별) + `CryptoObject` 서명 검토.
- `android:allowBackup="false"` + `dataExtractionRules`로 앱 데이터 전부 제외(Keystore 키는 이전 불가라 복원 후 불일치 방지).

### 4.2 BiometricGate (`androidx.biometric 1.1.0`)

| 상황 | 요구 |
| --- | --- |
| `allow` low/medium | `BiometricPrompt(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)`, negative 버튼 없음 [검증] |
| `allow` high | 길게 누르기(1.5초) → `BiometricPrompt` |
| `allow` critical | 길게 누르기 → `ExtraConfirmSheet` → `BiometricPrompt` |
| `deny_and_stop` | allow와 동일 |
| `deny` | 기본 없음(PC 정책 `deny_requires_auth`가 true면 요구) |
| API 26~29 | `STRONG|DEVICE_CREDENTIAL` 미지원 [검증] → `KeyguardManager.isDeviceSecure()` 확인 후 `BIOMETRIC_WEAK or DEVICE_CREDENTIAL`(라이브러리 지원 [미검증] → Phase 0 P7) |
| 등록 인증 없음 | 허용 버튼 비활성 + "기기 잠금을 먼저 설정해 주세요"(`ACTION_BIOMETRIC_ENROLL` API 30+) |
| 인증 결과 유효 | **60초 내 동일 request_id 1회**만 사용, 토큰화하지 않음 |

`setConfirmationRequired`는 어떤 행에서도 보안 요구로 쓰지 않는다(기본값 그대로, 위 §2.2). 인증 결과의 `authenticated_at`은 PC가 `created_at − 5s ≤ authenticated_at ≤ decided_at + 5s`, `decided_at − authenticated_at ≤ 60s`로 검사한다(`security.md` §6.2 8단계).

`auth.method`는 `authenticationType`으로 `biometric`/`device_credential` 기록. Phase 1에서는 PC가 이 값을 폰의 주장으로 받는다(`security.md` §6.4).

### 4.3 QR

`QrScanner.scan(): Result<QrPayload>` → `GmsQrScanner`(`GmsBarcodeScannerOptions` `FORMAT_QR_CODE`, 카메라 권한 불필요 [추정: 샘플 구조]). 파싱: `agentnest://pair?d=` → base64url → JSON → 검증(`v==1`, `spki_pin` `sha256/`+44자, hosts 1~8, port 1024~65535, `expires_at` 미래, `pc_id` ↔ 핀 일관성). 실패 시 "AgentNest 페어링 QR이 아니에요". `pairing_secret`은 ViewModel 메모리에만, 종료 시 `fill(0)`.

---

## 5. 알림

| 채널 id | 중요도 | 내용 | 소리/진동 | 취소 |
| --- | --- | --- | --- | --- |
| `approvals` | HIGH(헤드업) | 제목 "승인 필요 · Claude Code", 본문 = `title` + 위험 등급 + 남은 시간. **명령 전문 없음**(잠금 화면). **인라인 허용/거부 액션 없음**(탭 → ApprovalDetail). `setTimeoutAfter(expires_at − now)` | on(설정) | `approval_resolved`, 만료, 앱에서 열람 |
| `alerts` | DEFAULT | 오류(`turn_failed`, `agent_error`, `test_failed`), Codex P0/P1 리뷰(**리뷰 소스가 활성일 때만** — hooks 기본 모드에서는 발생하지 않음, `codex.md` §8) | 진동 | 세션당 60초 1건 |
| `completions` | LOW | `turn_completed`(30초 이상 턴만) | 없음 | 조용한 시간 무음 |
| `link` | MIN | FGS 상시: "연결됨 · DESKTOP-HOME" / "다시 연결 중 (3회, 8초 후)" / "오프라인". 액션: 다시 연결, 일시정지 | 없음 | 서비스 종료 |
| `security` | HIGH | 기기 폐기됨, 핀 불일치(MITM 의심), 페어링 실패 반복 | 진동 | — |

- `USE_FULL_SCREEN_INTENT` 미사용(Android 14+ 정책 [검증]). 승인 알림 태그 = `request_id`, 세션별 그룹 요약("승인 대기 3건"). 알림 탭 딥링크 `agentnest://approval/{request_id}`.
- `POST_NOTIFICATIONS`는 페어링 직후(사용자 행동 직후) 요청 [검증]. 거부 시 설정 화면 경고 배너.

---

## 6. 매니페스트 권한

`INTERNET`, `ACCESS_NETWORK_STATE`, `CHANGE_WIFI_STATE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_CONNECTED_DEVICE`, `POST_NOTIFICATIONS`, `RECEIVE_BOOT_COMPLETED`(선택), `USE_BIOMETRIC`, `VIBRATE`. 카메라 권한 없음(GMS 코드 스캐너; zxing 폴백 선택 시에만 `CAMERA`). targetSdk 37 전환 시 `ACCESS_LOCAL_NETWORK`.

```xml
<service android:name=".service.LinkService" android:exported="false" android:foregroundServiceType="connectedDevice"/>
<application android:allowBackup="false" android:dataExtractionRules="@xml/data_extraction_rules" …/>
```

---

## 7. `android/core` 테스트 (JUnit5, kotlinx-coroutines-test, mockwebserver3)

| 대상 | 테스트 |
| --- | --- |
| `protocol` | `protocol/examples/**` 라운드트립(디코드 → 재인코딩 비교), `invalid/` 거부, 알 수 없는 enum → `UNKNOWN`(state→`working`, risk→`high`) |
| `crypto` | `protocol/vectors/pair.json` canonical 바이트열·HMAC·SAS 일치 |
| `nest` | `state_transitions.json`, `mood_priority.json`(히스테리시스 포함, 가상 시계), 리듀서 5 ms 예산, 스냅샷 `pending_approval_ids_complete` 교체 규칙(ID만 있는 카드는 유지·"불러오는 중", 목록에 없는 카드만 정리), 승인 기록 50건 한도·`observed_result` 갱신·명령 원문 비저장, 타임라인 전용 kind(`approval_requested` 등)가 상태를 바꾸지 않음 |
| `link` | 백오프·지터, 4003→`Revoked`, 핀 불일치 3회→`Suspended`, `E_AUTH_FAILED` 3회→`NeedsRepair`, '다시 페어링'이 Suspended/Revoked/NeedsRepair를 해제하고 저장 상태를 지움, 4009, `SeqTracker` 재동기화, 70초 무수신, `HostBook` 순서(welcome > 수동 > QR)·사설 대역 필터·최대 8개, `hosts_update` 반영, 로컬 SAS 계산·불일치 시 중단, `EventsPager`(`before_seq` 배타·`has_more`·`detail_omitted`) |
| `approval` | `DecisionValidator`(만료 마진·skew·allowed_decisions·auth 요구), 오프라인 시 비활성 |
| `tls` | 핀닝 4케이스 |

`android/app`: CI `:app:testDebugUnitTest`(알림 빌더 매핑, 딥링크 파싱), `:app:lintDebug`(FGS 타입·권한). 계측 테스트는 Phase 1 후반.
