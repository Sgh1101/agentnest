//! Deterministic Korean templates (title/headline/detail).
//!
//! See [`ko`] for the templates and `protocol/fixtures/summaries_ko.json` for the golden cases.

pub mod ko;

pub use ko::{summarize_tool, ToolObservation, ToolSummary};
