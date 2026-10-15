# ADR-0003 모노레포 구성과 빌드박스 제약

- 상태: 승인됨 (2026-10-15)
- 관련: `docs/architecture.md` §2–§3, §6–§7; `docs/testing-and-ci.md`

## 맥락

빌드박스는 Linux(Rust 1.97, Node 22/pnpm 10, Java 21, Gradle 8.14.3)이며 **webkit2gtk가 없어 Tauri 셸을 호스트 타깃으로 빌드할 수 없고, Android SDK가 없고 `dl.google.com`이 차단**되어 AGP를 해석할 수 없다. 리서치 실측: `[workspace] default-members`로 셸을 제외하면 루트 `cargo test`가 순수 크레이트만 빌드하고, `cargo check -p <tauri 앱> --target x86_64-pc-windows-msvc`는 llvm-rc 덕에 성공(gnu 타깃은 실패); Gradle은 `:app`을 조건부 include하고 루트에 AGP를 선언하지 않으면 `:core`(JVM)만 로컬 검증 가능. windows-latest에는 NSIS·NASM이 없어 rustls 기본 프로바이더(aws-lc-rs)가 빌드 리스크다. 심사는 6크레이트 구조를 다소 과하다고 보면서도 `adapter-api` 분리와 mock 어댑터는 PRD의 플러그인 원칙상 정당하다고 평가했다.

## 결정

1. **Cargo 워크스페이스 `desktop/`**: `agentnest-protocol`, `agentnest-adapter-api`, `agentnest-core`, `agentnest-hook`(default-members) + `apps/desktop/src-tauri`(members만). Claude Code/Codex 어댑터는 별도 크레이트가 아니라 `agentnest-core::adapters` 모듈 + Cargo feature(`adapter-claude-code`, `adapter-codex-hooks` 기본 on; `codex-daemon-observer`, `codex-rollout` 기본 off; `adapter-mock` dev).
2. **셸은 Linux에서 타입체크만**(`cargo check --target x86_64-pc-windows-msvc`, `icons/icon.ico`와 `dist/index.html` 더미 커밋), 링크·번들은 windows-latest에서만. `cargo-xwin` 크로스 빌드는 채택하지 않는다.
3. **암호 백엔드는 ring 하나**: rustls/tokio-rustls `default-features=false, ring`, axum-server `tls-rustls-no-provider`, jsonschema `default-features=false`, rcgen 기본. HMAC/SHA-256/CSPRNG도 `ring`. CI에서 `aws-lc-rs`가 그래프에 없어야 한다(`cargo tree -i`는 패키지가 없으면 오류로 종료하므로 `! cargo tree --workspace --target all -i aws-lc-rs`로 종료 코드를 반전해 검사). 훅 CLI의 `ureq`는 `default-features = false`(TLS 없음, `http://127.0.0.1`만)이고, 테스트용 `tokio-tungstenite`는 TLS feature 없이 쓰며 핀 검증 테스트는 `tokio-rustls`의 커스텀 `ServerCertVerifier` + `client_async`로 한다.
4. **Android**: `android/core`는 `kotlin("jvm")` 2.4.21 + serialization + OkHttp(JVM 호환)로 프로토콜·리듀서·링크 상태기계·핀닝까지 담고 로컬에서 `./gradlew :core:test`; `android/app`은 AGP 9.3.3 built-in Kotlin(`kotlin-android` 미적용)으로 CI(ubuntu-latest)에서만. `settings.gradle.kts`는 조건부 include + `google()` 콘텐츠 필터, 루트에 AGP 미선언.
5. **버전 핀**: `rust-toolchain.toml` 1.97.0, Gradle wrapper 9.7.1, 모든 라이브러리 버전은 리서치 조회값(`architecture.md` §6). 미검증 의존성(Navigation 3, async-trait, proptest, json-schema-to-typescript)은 쓰지 않는다. `play-services-code-scanner` 버전은 인터페이스 뒤에 두고 CI 첫 빌드에서 확정.
6. **공용 픽스처**는 `protocol/`에 두고 Rust·Kotlin이 같은 파일을 읽는다. 위험 규칙 테이블은 픽스처가 아니라 코드 상수(테스트 케이스만 픽스처).

## 결과

- (+) 빌드박스에서 Rust 로직·Android 로직·프런트 타입체크를 전부 검증할 수 있고, CI 비용이 큰 Windows/Android 빌드는 셸·앱에 한정된다.
- (+) 플러그인 경계(`adapter-api`)가 Phase 1부터 존재하되 크레이트 수는 4개로 억제된다.
- (−) 어댑터가 core 내부 모듈이라 외부 프로세스 어댑터(Phase 4)는 그때 크레이트 분리가 필요할 수 있다.
- (−) windows-latest(VS2026) 이미지에서의 첫 `tauri build`는 실증 전까지 리스크(Phase 0 P1).
- CLAUDE.md의 저장소 구조(크레이트 목록)에 `agentnest-adapter-api`를 반영했다. 세 곳(CLAUDE.md·README·`architecture.md`)이 같은 목록을 유지해야 한다.
