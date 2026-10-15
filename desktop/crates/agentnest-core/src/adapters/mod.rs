//! Adapter registry and feature gating (claude_code, codex/*, mock).

#[cfg(feature = "adapter-claude-code")]
pub mod claude_code;
pub mod codex;
#[cfg(feature = "adapter-mock")]
pub mod mock;
