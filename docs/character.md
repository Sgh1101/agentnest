# 콩이 캐릭터 시스템

- 상태: 확정(리드 종합본) — 2026-10-15
- PRD §4: "둥글고 작은 생명체, 부드러운 움직임과 단순한 눈·표정". 기존 Mochi 디자인·에셋을 복제하지 않고 독립 제작. 앱 성능을 저하시키지 않도록 가볍게. 설정에서 애니메이션·소리를 끌 수 있어야 한다.
- 원칙: **콩이는 장식이 아니라 정보 인터페이스**다. 한 mood = 한 가지 사실("지금 내 손이 필요한가"). 모션 + 색(상태 chip) + 텍스트(headline) 3중 표현으로 애니메이션을 꺼도 정보 손실이 없다.

---

## 1. mood 열거형 (PRD §4 표 1:1 + 변형)

| `KongiMood` | PRD 표현 | 입력 `AgentState` | 상태 chip 색 토큰 |
| --- | --- | --- | --- |
| `blink_slow` | 느린 눈 깜빡임 | `idle`, `completed`(4초 후), 세션 없음 | `neutral` |
| `typing` | 작은 키보드 타이핑 | `writing_code`(빠른 템포), `working`(약한 변형: 키보드 없이 손만) | `accent` |
| `magnifier` | 돋보기 사용 | `reviewing` | `info` |
| `tools` | 공구를 들고 작업 | `testing` | `info` |
| `raise_hand` | 손을 들어 사용자 호출 | `awaiting_approval`(배지 `!`), `awaiting_input`(배지 `?`) | `warning` |
| `flustered` | 당황한 표정 | `error` | `danger` |
| `celebrate` | 기쁜 표정과 작은 점프 | `completed`(최초 4초) | `success` |
| `sleepy` | 졸림 | 링크 `Offline`(네트워크 없음) | `muted` |
| `worried` | 걱정 | 링크 `Reconnecting`/`PcUnreachable`, 세션 `disconnected`(dead) | `muted` |

알 수 없는 `AgentState`는 `working` → `typing`(약한 변형)으로 렌더(`protocol.md` §10).

---

## 2. 상태 기계 (`android/core` `MoodResolver`, 순수 함수 + 가상 시계; 픽스처 `protocol/fixtures/mood_priority.json`을 Rust `state::focus`와 공유)

### 2.1 우선순위(높음 → 낮음)

```text
 1. link != Connected            → sleepy(Offline) / worried(Reconnecting, PcUnreachable, Suspended)
 2. any session awaiting_approval → raise_hand(!)        — 배지에 개수
 3. any session awaiting_input   → raise_hand(?)
 4. any session error            → flustered             — 지속시간은 `AgentState.error`를 그대로 따른다(PC 리듀서가 결정, `protocol.md` §5.4: tool/command 실패 5초, test_failed 30초, turn_failed/agent_error는 다음 프롬프트까지)
 5. any session testing          → tools
 6. any session writing_code     → typing
 7. any session reviewing        → magnifier
 8. any session working          → typing(약한 변형)
 9. any session completed(4초)   → celebrate
10. 그 외(모두 idle / 세션 없음)  → blink_slow
11. 모든 세션 disconnected(dead) → worried
```

동률: 같은 우선순위 안에서는 `last_event_at`이 가장 최근인 세션이 **대표 세션**(`primarySessionKey`)이 되고, 0층 headline은 그 세션의 headline을 쓴다. 세션이 2개 이상이면 "Claude가 …" / "Codex가 …"처럼 에이전트 이름 접두 + "다른 1개는 대기 중" 꼬리말.

### 2.2 히스테리시스

| 규칙 | 값 |
| --- | --- |
| mood 최소 유지 | **1,500 ms**(도구 이벤트가 초당 여러 번 와도 깜빡이지 않음) |
| 상향 전환 | 더 높은 우선순위(링크·승인·입력·오류)는 **즉시**(유지 시간 무시) |
| `celebrate` | 4,000 ms 후 자동 `blink_slow`. 축하 중 새 작업 시작 → 즉시 전환 |
| `flustered` | **폰 측 별도 타이머 없음.** `AgentState.error`인 동안 표시하고 `error`가 해제되면(PC가 `session_state`로 전달) 해제한다. 지속시간·해제 입력은 `protocol.md` §5.4의 단일 출처(일시 5초 / `test_failed` 30초 + `test_passed`·`turn_completed`·`prompt_submitted` 해제 / `turn_failed`·`agent_error`는 다음 프롬프트까지). 최소 유지 1,500 ms 히스테리시스만 폰에서 적용 |
| `reviewing` 진입 | `file_read` 연속 2회 이상(PC 리듀서가 결정; 폰은 상태만 받음) |
| 링크 복귀 | `Connected` 전환 시 세션 상태 기반 mood로 즉시 복귀(스냅샷 교체 후) |

출력은 `NestState.mood`, `NestState.headline`, `NestState.primarySessionKey`로 저장되어 홈 0층·FGS 알림·(Phase 2) 위젯이 공유한다. 데스크톱 트레이 아이콘도 Rust `state::focus`의 같은 규칙(4단계 축약)을 쓴다.

---

## 3. 렌더링 (Compose Canvas, 외부 애니메이션 라이브러리 없음)

### 3.1 구조

- `KongiCanvas(mood, animationsEnabled, reducedMotion)`: `Canvas` + `rememberInfiniteTransition`/`animateFloat`(Compose animation 1.12.1 표준 API [추정: 세부 시그니처는 구현 시 확인]).
- `KongiSpec(mood)`: 몸 색, 눈 openness(0..1), 눈 오프셋, 입 곡률, 바운스 진폭/주기, 소품(`Prop.Keyboard | Magnifier | Wrench | Hand | Sweat | Zzz | None`), 배지(`!`/`?`/없음).
- 전환: mood 변경 시 파라미터를 300 ms `tween`으로 보간. 점프(`celebrate`)·손 들기(`raise_hand`)는 즉시 트리거되는 1회성 키프레임.
- 비트맵·텍스트 없음: 경로/원/선만. 배지 글자는 `Path`로 그린다.

### 3.2 mood별 모션 스펙

| mood | 모션 | 주기 |
| --- | --- | --- |
| `blink_slow` | 눈 깜빡임 2.8~4.2초 랜덤, 몸 상하 2 dp 호흡 | 호흡 3.0초 |
| `typing`(강) | 키보드 위 두 손 교차 타격, 눈 반쯤 감김 | 0.12초/타 |
| `typing`(약) | 키보드 없이 손만 작은 진폭 | 0.25초/타 |
| `magnifier` | 돋보기 좌우 스캔, 한쪽 눈 확대 | 1.6초 |
| `tools` | 렌치 휘두르기 + 작은 불꽃 점 2개 | 0.5초 |
| `raise_hand` | 손 들고 좌우 흔들기, 머리 위 배지 펄스 | 0.6초 / 펄스 1.0초 |
| `flustered` | 땀방울 낙하(1.2초), 눈 떨림(0.08초 진폭 1 dp) | — |
| `celebrate` | 점프 1회(0.5초, 높이 12 dp) + 웃는 눈 → 4초 후 하강 | 1회 |
| `sleepy` | 눈 감김, "z" 두 개 떠오름(2초 주기) | 2.0초 |
| `worried` | 눈썹 내림, 몸 좌우 미세 흔들림 | 1.4초 |

### 3.3 성능 예산

- 60 fps 기준 프레임당 draw 명령 ≤ 40개, 비트맵 0, 텍스트 0.
- `Lifecycle.State < STARTED`(백그라운드·화면 밖)에서는 애니메이션 중단(`LaunchedEffect` + `repeatOnLifecycle`).
- 저전력 모드(설정) 또는 `PowerManager.isPowerSaveMode`: 애니메이션 프레임 30 fps로 제한, 호흡/깜빡임만.
- mood 계산(`MoodResolver`)은 `NestReducer`의 5 ms 예산에 포함.

### 3.4 접근성·설정 토글

| 설정 | 효과 |
| --- | --- |
| `animations_enabled = false` 또는 시스템 애니메이션 배율 0(`Settings.Global.ANIMATOR_DURATION_SCALE` [추정]) | 정지 프레임(mood별 포즈 1장) + 상태 chip + headline. `contentDescription` = "콩이: 승인을 기다리고 있어요" 등 mood별 문장 |
| `sound_enabled`(기본: 승인 on, 완료 off) | `SoundPool` 짧은 효과음 2종(승인 요청·완료). 조용한 시간에는 무음. 소리는 알림 채널 소리와 중복 재생하지 않음(앱 포그라운드일 때만) |
| `low_power_mode` | §3.3 |
| 햅틱 | `raise_hand` 진입 시 1회 짧은 진동(설정) |

### 3.5 그리기 규칙 (스크린샷 검증 반영)

- 손은 항상 어깨와 팔(굵은 둥근 선)로 몸에 이어진다. 팔은 몸 뒤에 그려서 몸 밖으로 나온 부분만 보인다.
- 소품은 배경 위에도 몸 위에도 놓이므로 테마에 맞는 색(라이트: 짙은 갈색, 다크: 밝은 크림)과 반대 명도의 얇은 테두리를 함께 그린다. 얼굴(눈·입·눈썹)은 몸 위에만 있어서 항상 짙은 색이다.
- 키보드는 배 앞에 놓고 손을 그 위에 그린다(목걸이처럼 보이지 않게). 렌치는 손잡이가 머리를 관통하지 않고 열린 고리 모양 머리를 가진다.
- 전체를 1.1배로 그려 40~160 dp 에서 얼굴이 읽히게 한다. 행복한 mood 에는 볼 홍조를 더한다.
- 프레임당 draw 명령 ≤ 40 과 "프레임당 할당 0"을 지킨다: `Stroke` 는 `StrokeCache` 에 두고, 변환은 `canvas.save()/restore()` 를 쓴다(람다 변환 API 를 프레임마다 만들지 않는다).
- 검증: `KongiShotTest`(11개 얼굴 갤러리 라이트/다크, 개별 큰 그림, 크기별), `KongiAnimShotTest`(mood 별 프레임 strip) — `docs/android.md` §8.

---

## 4. 데스크톱 트레이 축약

4단계: 회색(`blink_slow`/`sleepy`), 파랑(`typing`/`magnifier`/`tools`/`celebrate`), 노랑 깜빡임(`raise_hand`), 빨강(`flustered`/`worried`(데몬 오류)). 폰과 동일한 포커스 규칙(`protocol.md` §5.5)을 Rust에서 계산.

---

## 5. 테스트

- `MoodResolver`: `mood_priority.json` 전수(세션 상태 집합 × 링크 상태 → 기대 mood·대표 세션), 히스테리시스(1.5초 유지, 4초 celebrate, 상향 즉시) — 가상 시계. `flustered`는 `AgentState.error` 입력의 존재 여부만 따르는지(5초 일시 오류는 5초, sticky는 해제될 때까지) 검증.
- `KongiSpec`: mood별 파라미터 스냅샷(JVM, Compose 미사용).
- 실기(Phase 0 P5): 승인 요청 → 손 들기 ≤ 2초, 축하 → 대기 복귀 4초, 애니메이션 off 시 정지 프레임 + 설명문.
