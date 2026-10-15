# AgentNest

Windows PC 에서 실행되는 여러 AI 코딩 에이전트(Claude Code, Codex 등)를 **하나의 Android 앱**에서 통합 관제하는 개인용 플랫폼입니다.
휴대폰으로 AI 작업 현황을 확인하고, 권한 승인 요청에 응답하고, 귀여운 캐릭터 **콩이**가 에이전트 상태를 알려 줍니다.

> 상태: **Phase 0 → Phase 1 구현 중.** 설계는 확정(`docs/`), 구현은 단계적으로 진행됩니다. 로드맵은 [`docs/prd.md`](docs/prd.md) 7장을 보세요.

## 핵심 원칙

- 한 화면에서 모든 AI 의 상태를 3초 안에 파악한다.
- 원격 승인은 **fail-closed**: 만료·연결 끊김·검증 실패·알 수 없는 상태는 절대 자동 승인되지 않는다.
- 같은 Wi-Fi 에서만 연결(Phase 1), QR + 비밀 소지 증명 + PC 화면 SAS 확인으로 기기를 등록한다.
- AI 연결은 어댑터 방식(Claude Code · Codex → 이후 Gemini CLI 등).

## 구조

```text
docs/        설계 문서 (색인: docs/README.md), ADR
protocol/    JSON Schema · 예제 · 테스트 벡터 · 픽스처 (언어 중립 단일 진실 공급원)
desktop/     Cargo 워크스페이스: agentnest-protocol / adapter-api / core / hook + Tauri 2 셸
android/     :core (순수 Kotlin JVM) + :app (Jetpack Compose)
.github/     CI
```

자세한 내용은 [`docs/architecture.md`](docs/architecture.md).

## 개발 환경

| 대상 | 필요한 것 |
| --- | --- |
| Rust | 1.97.0 (`rust-toolchain.toml` 이 자동 선택) |
| 프런트엔드 | Node 22, pnpm 10 |
| Android core | JDK 17 이상 (Gradle wrapper 9.7.1 이 자동 다운로드) |
| Android app | Android SDK (compileSdk 36) — 로컬 Android Studio 또는 CI |
| Tauri 셸 실행/번들 | Windows 10/11 + WebView2 (Linux 에서는 타입 검사만) |

## 검증 명령

```bash
# Rust (순수 크레이트 — Linux/Windows 공통)
cd desktop && cargo fmt --all --check \
  && cargo clippy --workspace --exclude agentnest-desktop --all-targets -- -D warnings \
  && cargo test --workspace --exclude agentnest-desktop

# Tauri 셸 타입 검사 (Linux: apt install llvm clang mingw-w64-x86-64-dev, docs/testing-and-ci.md 2.1)
cd desktop && CC_x86_64_pc_windows_msvc=$PWD/tools/cc-msvc-check.sh AR_x86_64_pc_windows_msvc=llvm-ar \
  cargo check -p agentnest-desktop --target x86_64-pc-windows-msvc

# 프런트엔드
cd desktop/apps/desktop && pnpm install --frozen-lockfile && pnpm typecheck && pnpm test

# Android 순수 모듈 (SDK 불필요)
cd android && ./gradlew :core:test

# Android 앱 (SDK 필요)
cd android && ./gradlew :app:assembleDebug
```

## 역할 분담

Claude Code 가 구현하고, Codex 가 PR 을 리뷰하고(P0/P1 중심, [`AGENTS.md`](AGENTS.md)), GitHub Actions 가 자동 검증하며, 최종 승인과 배포는 사용자가 합니다. 작업 규칙은 [`CLAUDE.md`](CLAUDE.md).

## 보안

[`docs/security.md`](docs/security.md) 의 규칙은 협상 대상이 아닙니다. 취약점은 공개 이슈 대신 저장소 소유자에게 직접 알려 주세요.
