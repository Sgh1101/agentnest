# ADR-0005 콩이 렌더링: Compose Canvas + PC 측 상태 파생 + 폰 측 mood 집계

- 상태: 승인됨 (2026-10-15)
- 관련: `docs/character.md`, `docs/protocol.md` §5.4–5.5, `docs/android.md` §2.1

## 맥락

PRD §4는 8개 상태 표현, 가벼운 애니메이션, 애니메이션/소리 토글, Mochi 에셋 비복제를 요구하고 §3.A는 "3초 안에 파악"을 요구한다. 심사는 제품 UX안의 3층 홈·mood 우선순위·히스테리시스·링크 오버레이·콜드스타트 캐시를 그래프트 대상으로, 연동 충실도안의 `file_read → reviewing` 무히스테리시스(깜빡임)를 결함으로 꼽았다. Navigation 3 API와 Lottie류 외부 라이브러리는 미검증이다.

## 결정

1. **상태 파생은 PC에서 한 번**(`state::SessionReducer`, 전이표 `protocol/fixtures/state_transitions.json`), 폰은 `session_state`를 받아 **mood 집계만** 한다(`MoodResolver`, `protocol/fixtures/mood_priority.json`). 같은 픽스처를 Rust(`state::focus`, 트레이)와 Kotlin이 공유한다.
2. `AgentState` 10종(`idle, working, writing_code, reviewing, testing, awaiting_approval, awaiting_input, error, completed, disconnected`) → mood 9종(`blink_slow, typing(강/약), magnifier, tools, raise_hand(!/?), flustered, celebrate, sleepy, worried`). 알 수 없는 상태는 `working`.
3. **우선순위**: 링크 끊김 > 승인 대기 > 입력 대기 > 오류 > 테스트 > 코드 작성 > 리뷰 > 작업 > 완료(4초) > 대기. 동률은 최근 이벤트 세션이 대표. **히스테리시스**: 최소 유지 1.5초(상향은 즉시), `celebrate` 4초, `reviewing`은 `file_read` 연속 2회부터. `flustered`의 지속시간은 폰이 따로 정하지 않고 PC가 파생한 `AgentState.error`(일시 5초 / `test_failed` 30초 / `turn_failed`는 다음 프롬프트까지, `protocol.md` §5.4)를 그대로 따른다.
4. **렌더링은 Compose `Canvas`**(경로/원/선만, 비트맵·텍스트·Lottie 없음), mood 변경 300 ms `tween`, 프레임당 draw ≤ 40, 백그라운드 중단, 저전력 30 fps. 애니메이션 off/시스템 감속 시 정지 프레임 + 상태 chip + headline + contentDescription(3중 표현). 소리는 `SoundPool` 2종, 기본 승인만 on.
5. 홈은 3층 고정(콩이+headline / 행동 카드 / 세션 카드)이며 모든 문자열은 PC가 한국어로 만들어 보낸다. 콜드 스타트는 DataStore 스냅샷 캐시로 즉시 렌더.
6. 내비게이션은 Phase 1에서 수동 스택(sealed class + BackHandler)으로 `nav` 패키지에 격리(Navigation 3 미검증).

## 결과

- (+) 캐릭터가 "지금 내 손이 필요한가"를 1초 안에 알려주고, 접근성 설정에서도 정보 손실이 없다. 폰은 번역·분류·정규식 처리를 하지 않아 리듀서가 5 ms 예산 안에 든다.
- (+) 외부 애니메이션/내비게이션 의존성이 없어 CI 전용 `:app` 모듈의 빌드 리스크가 줄고, 에셋 저작권 문제가 없다.
- (−) 손그림 벡터 캐릭터의 완성도는 디자이너 없이 제한적이다(Phase 4 커스터마이징 여지). 
- (−) PC가 상태를 결정하므로 폰 단독 추론은 링크 오버레이뿐이다(의도된 제약).
