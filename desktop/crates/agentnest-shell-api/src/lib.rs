//! Everything the AgentNest desktop shell does that does not need Tauri types.
//!
//! The Tauri crate (`apps/desktop/src-tauri`) cannot be built or tested on a Linux box without webkit2gtk, so it is a
//! thin glue layer: `#[tauri::command]` wrappers call [`ShellApi`], a forwarding task runs [`pump::run_event_pump`] and a
//! [`pump::UiSink`] implementation talks to the real window, tray and notification plugins. All decisions live here and
//! are unit tested on any platform:
//!
//! * [`commands`]: the command names and argument names of the front-end contract (docs/desktop.md 3 / 3.1);
//! * [`error`]: the `{code, message?}` error shape and the mapping from daemon errors;
//! * [`dto`]: result payloads exactly as `desktop/apps/desktop/src/api/guards.ts` reads them;
//! * [`events`], [`pump`]: `DaemonEvent` to `daemon-event {kind, payload}`, batching, window / notification actions;
//! * [`settings`]: the whitelisted `settings_get` / `settings_set` keys (security.md 9: forbidden fields cannot exist);
//! * [`history`], [`logs`], [`codex`]: approvals history, the redacted log tail, the Codex socket probe;
//! * [`net`], [`diagnostics`]: Windows firewall rule and network profile behind traits (fakes on Linux), the connection
//!   diagnostics report;
//! * [`tray`], [`first_run`]: the tray menu model (only `low` / `medium` requests may be approved inline) and the
//!   first-run checklist;
//! * [`api`]: [`ShellApi`], the object the glue keeps in Tauri's managed state.
//!
//! Hard rules (docs/security.md, CLAUDE.md): this crate never creates an allow reply itself, every local approval goes
//! through `DaemonHandle::approval_decide_local` (the broker's single transition), nothing here logs a token, a nonce or
//! a command line, and the shell has no way to set a forbidden configuration field.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// No `unwrap()` / `expect()` outside tests (CLAUDE.md). Test code is exempt through `cfg(test)`.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod api;
pub mod codex;
pub mod commands;
pub mod diagnostics;
pub mod dto;
pub mod error;
pub mod events;
pub mod first_run;
pub mod history;
pub mod logs;
pub mod net;
pub mod pump;
pub mod settings;
pub mod tray;

pub use api::{ShellApi, ShellApiOptions};
pub use error::IpcError;
pub use events::{Envelope, ShellAction};
pub use pump::{run_event_pump, UiSink};
