//! Risk classifier with code-constant rules and the command_class tokenizer.
//!
//! * [`classify`](fn@classify) / [`classify_input`]: `tool_name + tool_input + cwd + permission_mode -> Risk`
//!   (level, reason codes, Korean reasons, extra confirmation). Rules are code constants ([`rules`]); there is no
//!   external rule file and no configuration key that can lower a level (security.md I10). A classifier failure or panic
//!   is `critical`.
//! * [`command_class::command_class`]: the coarse command class shared with the normalisers and the state reducer.
//! * [`tokenizer`]: shell/PowerShell segmentation used by both.

pub mod classify;
pub mod command_class;
pub mod rules;
pub mod tokenizer;

pub use classify::{classify, classify_input, RiskInput};
pub use command_class::{command_class, command_class_for};
pub use rules::{Level, Rule};
pub use tokenizer::Shell;
