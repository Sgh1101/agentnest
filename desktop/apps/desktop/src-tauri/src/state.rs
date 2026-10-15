//! The state Tauri manages for the commands.

use std::sync::Arc;

use agentnest_shell_api::logs::LogGuard;
use agentnest_shell_api::ShellApi;

/// Managed state: the shell API (the daemon lives inside it) and the log writer guard.
pub struct Shell {
    /// All command logic.
    pub api: Arc<ShellApi>,
    /// Keeps the background log writer alive for the whole process.
    pub _log: LogGuard,
}
