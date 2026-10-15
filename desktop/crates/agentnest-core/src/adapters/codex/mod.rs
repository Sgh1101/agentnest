//! Codex adapter (hooks by default; daemon socket and rollout behind UNVERIFIED feature flags).

#[cfg(feature = "adapter-codex-hooks")]
pub mod hooks;
// UNVERIFIED (Phase 0): Codex shared daemon socket subscription.
#[cfg(feature = "codex-daemon-observer")]
pub mod daemon_observer;
// UNVERIFIED (Phase 0): rollout JSONL backfill.
pub mod review;
#[cfg(feature = "codex-rollout")]
pub mod rollout;
