//! `agentnest-hook`: tiny CLI invoked by Claude Code / Codex command hooks.
//!
//! Contract (docs/architecture.md 4, integrations/*.md): read the hook JSON from stdin, POST it to the local daemon
//! (`http://127.0.0.1:47831`), print the daemon's reply on stdout and **always exit 0**. It never makes decisions and
//! never edits its input (only strings above 32 KiB are cut). With the daemon down it prints nothing.
//!
//! This is a skeleton; the implementation is a follow-up task.

fn main() {
    // Skeleton: no daemon call yet. An empty stdout and exit code 0 is the documented fail-safe behaviour.
}
