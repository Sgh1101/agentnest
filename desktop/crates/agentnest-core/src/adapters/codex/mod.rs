//! Codex adapter (hooks by default; daemon socket and rollout behind UNVERIFIED feature flags).

#[cfg(feature = "adapter-codex-hooks")]
pub mod hooks;
// UNVERIFIED (Phase 0): Codex shared daemon socket subscription.
#[cfg(feature = "codex-daemon-observer")]
pub mod daemon_observer;
/// Codex hooks configuration (draft; UNVERIFIED Phase 0 C6) and the manual installation text.
pub mod install;
/// Answers to Codex: app-server decision strings and the hooks reply.
pub mod responder;
pub mod review;
// UNVERIFIED (Phase 0): rollout JSONL backfill.
#[cfg(feature = "codex-rollout")]
pub mod rollout;
