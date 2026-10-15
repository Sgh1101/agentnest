//! `DropGuard`: "the agent's connection went away" (docs/security.md 7 "Claude가 먼저 종료", claude-code.md 6).
//!
//! The hook handler of a held `PermissionRequest` creates a guard bound to its approval handle before it starts to
//! wait. If the handler future is dropped while the guard is armed (hyper cancels the service future when the HTTP
//! connection closes: the user answered the local prompt, pressed Ctrl-C, the process died), the guard's `Drop` tells
//! the broker, which removes the handle and, when no handle of the request is left, ends it as `superseded`
//! (`resolved_by = agent`). A late phone decision then gets `ALREADY_RESOLVED` and an audit row `late_decision`.
//!
//! Normal completion disarms the guard. The guard needs a tokio runtime to run the notification; if there is none (the
//! runtime is shutting down) nothing is sent: a restarted daemon expires every pending request anyway.
//!
//! The "hyper drops the service future on disconnect" behaviour is an assumption of the design (Phase 0 P6); the
//! integration tests exercise it against the real server.

use std::sync::Arc;

use agentnest_adapter_api::{AgentCloseReason, NativeBinding};

use crate::approvals::broker::Broker;

/// Notifies the broker when dropped while armed.
pub struct DropGuard {
    broker: Arc<Broker>,
    binding: NativeBinding,
    armed: bool,
}

impl std::fmt::Debug for DropGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropGuard")
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

impl DropGuard {
    /// An armed guard for the handle identified by `binding`.
    pub fn new(broker: Arc<Broker>, binding: NativeBinding) -> Self {
        Self {
            broker,
            binding,
            armed: true,
        }
    }

    /// The handler finished (the responder was answered or abandoned): nothing to report.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// `true` while armed.
    pub fn is_armed(&self) -> bool {
        self.armed
    }
}

impl Drop for DropGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let broker = Arc::clone(&self.broker);
        let binding = self.binding.clone();
        handle.spawn(async move {
            broker
                .agent_closed(&binding, AgentCloseReason::ConnectionClosed)
                .await;
        });
    }
}
