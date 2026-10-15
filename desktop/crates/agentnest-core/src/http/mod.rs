//! Loopback axum router for hook collection: POST /v1/hooks/{claude-code,codex}, /v1/statusline/claude-code, GET /v1/health, /v1/daemon.

pub mod guard;
pub mod hooks;
