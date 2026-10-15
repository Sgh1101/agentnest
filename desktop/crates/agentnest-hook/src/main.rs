//! `agentnest-hook`: tiny CLI invoked by Claude Code / Codex command hooks.
//!
//! Contract (docs/architecture.md 4, integrations/*.md 3): read the hook JSON from stdin, POST it to the local daemon
//! (`http://127.0.0.1:<hook_port>`), print the daemon's reply on stdout and **always exit 0**. It never makes decisions and
//! never edits its input (only strings above 32 KiB are cut and reported in `_agentnest_truncated`). With the daemon down,
//! unreachable, slow or answering anything but a JSON object, it prints nothing, which every caller reads as "no decision".

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::{Map, Value};

/// Strings longer than this are cut (also the daemon's limit).
const MAX_STRING_BYTES: usize = 32 * 1024;
/// Hard cap on what is read from stdin.
const MAX_STDIN_BYTES: u64 = 16 * 1024 * 1024;
/// Margin over the daemon TTL for the `PermissionRequest` HTTP timeout.
const PERMISSION_MARGIN_S: u64 = 28;
/// TTL assumed when `daemon.json` carries none: the default install clamps the TTL to 150 - 30 s.
const DEFAULT_TTL_S: u64 = 120;
const DEFAULT_TIMEOUT_MS: u64 = 4_000;
const SESSION_END_TIMEOUT_MS: u64 = 800;

/// Command line of the hook binary.
#[derive(Parser, Debug)]
#[command(
    name = "agentnest-hook",
    version,
    about = "AgentNest hook relay (always exits 0)"
)]
struct Cli {
    /// Path of daemon.json (default: the per-user AgentNest data directory).
    #[arg(long, global = true)]
    daemon_config: Option<PathBuf>,
    /// Overrides the HTTP timeout in milliseconds.
    #[arg(long, global = true)]
    timeout_ms: Option<u64>,
    /// Print nothing on stderr even with `AGENTNEST_HOOK_DEBUG`.
    #[arg(long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// stdin Claude Code hook JSON -> POST /v1/hooks/claude-code -> stdout response body.
    ClaudeCode,
    /// stdin Codex hook JSON -> POST /v1/hooks/codex -> stdout response body.
    Codex,
    /// stdin statusLine JSON -> POST /v1/statusline/claude-code -> one status line.
    Statusline,
    /// Checks the daemon reachability, token and ports (for humans).
    Doctor,
}

/// The fields of `daemon.json` this CLI needs.
#[derive(Deserialize)]
struct DaemonConfig {
    hook_port: u16,
    hook_token: String,
    #[serde(default)]
    approval_ttl_s: Option<u64>,
}

fn main() -> ExitCode {
    // A parse error must not exit with clap's code 2 (2 blocks tools in Claude Code): treat it as "no decision".
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            if debug_enabled(false) {
                eprintln!("agentnest-hook: {e}");
            }
            return ExitCode::SUCCESS;
        }
    };
    let debug = debug_enabled(cli.quiet);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match run(&cli, &mut std::io::stdin().lock(), debug) {
        Output::Text(s) => {
            // A closed stdout is not our problem: still exit 0.
            let _ = out.write_all(s.as_bytes());
            let _ = out.flush();
        }
        Output::Nothing => {}
    }
    ExitCode::SUCCESS
}

fn debug_enabled(quiet: bool) -> bool {
    !quiet && std::env::var_os("AGENTNEST_HOOK_DEBUG").is_some_and(|v| v == "1")
}

/// What goes to stdout.
#[derive(Debug, PartialEq, Eq)]
enum Output {
    Text(String),
    Nothing,
}

fn run(cli: &Cli, stdin: &mut dyn Read, debug: bool) -> Output {
    let path = cli.daemon_config.clone().or_else(default_daemon_config);
    let Some(config) = path.as_deref().and_then(|p| read_config(p, debug)) else {
        return Output::Nothing;
    };
    match cli.command {
        Cmd::Doctor => Output::Text(doctor(&config, path.as_deref(), cli.timeout_ms)),
        Cmd::ClaudeCode => relay(cli, &config, stdin, Route::ClaudeCode, debug),
        Cmd::Codex => relay(cli, &config, stdin, Route::Codex, debug),
        Cmd::Statusline => relay(cli, &config, stdin, Route::Statusline, debug),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Route {
    ClaudeCode,
    Codex,
    Statusline,
}

impl Route {
    fn path(self) -> &'static str {
        match self {
            Route::ClaudeCode => "/v1/hooks/claude-code",
            Route::Codex => "/v1/hooks/codex",
            Route::Statusline => "/v1/statusline/claude-code",
        }
    }
}

fn relay(
    cli: &Cli,
    config: &DaemonConfig,
    stdin: &mut dyn Read,
    route: Route,
    debug: bool,
) -> Output {
    let mut raw = Vec::new();
    if stdin.take(MAX_STDIN_BYTES).read_to_end(&mut raw).is_err() || raw.is_empty() {
        return Output::Nothing;
    }
    let (body, event) = prepare_body(raw);
    let timeout = cli
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or_else(|| default_timeout(event.as_deref(), config));
    let Some((status, text)) = post(config, route.path(), &body, timeout, debug) else {
        return Output::Nothing;
    };
    if status != 200 {
        return Output::Nothing;
    }
    match route {
        Route::Statusline => Output::Text("AgentNest\n".to_owned()),
        Route::ClaudeCode | Route::Codex => filter_response(route, &text),
    }
}

/// The body to send (strings above 32 KiB cut) and the hook event name when it can be read.
fn prepare_body(raw: Vec<u8>) -> (Vec<u8>, Option<String>) {
    let Ok(mut value) = serde_json::from_slice::<Value>(&raw) else {
        // Not JSON: forwarded untouched; the daemon answers 400 and we print nothing.
        return (raw, None);
    };
    let event = value
        .get("hook_event_name")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut cut = Vec::new();
    truncate_strings(&mut value, "", &mut cut);
    if cut.is_empty() {
        return (raw, event);
    }
    if let Value::Object(map) = &mut value {
        map.insert(
            "_agentnest_truncated".to_owned(),
            Value::Array(cut.into_iter().map(Value::String).collect()),
        );
    }
    match serde_json::to_vec(&value) {
        Ok(b) => (b, event),
        Err(_) => (raw, event),
    }
}

/// Cuts every string above [`MAX_STRING_BYTES`] at a char boundary and records its dotted path.
fn truncate_strings(v: &mut Value, path: &str, cut: &mut Vec<String>) {
    match v {
        Value::String(s) if s.len() > MAX_STRING_BYTES => {
            let mut end = MAX_STRING_BYTES;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            s.truncate(end);
            cut.push(if path.is_empty() {
                "$".to_owned()
            } else {
                path.to_owned()
            });
        }
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                truncate_strings(item, &format!("{path}[{i}]"), cut);
            }
        }
        Value::Object(map) => {
            for (k, item) in map.iter_mut() {
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                truncate_strings(item, &child, cut);
            }
        }
        _ => {}
    }
}

fn default_timeout(event: Option<&str>, config: &DaemonConfig) -> Duration {
    match event {
        Some("PermissionRequest") => Duration::from_secs(
            config.approval_ttl_s.unwrap_or(DEFAULT_TTL_S) + PERMISSION_MARGIN_S,
        ),
        Some("SessionEnd") => Duration::from_millis(SESSION_END_TIMEOUT_MS),
        _ => Duration::from_millis(DEFAULT_TIMEOUT_MS),
    }
}

/// Prints the daemon body only when it is one JSON object; on the Codex route a `permissionDecision` is dropped.
fn filter_response(route: Route, body: &str) -> Output {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(body) else {
        return Output::Nothing;
    };
    if route == Route::Codex && contains_key(&Value::Object(map.clone()), "permissionDecision") {
        return Output::Nothing;
    }
    if map.is_empty() {
        return Output::Nothing;
    }
    Output::Text(body.trim().to_owned())
}

fn contains_key(v: &Value, key: &str) -> bool {
    match v {
        Value::Object(m) => m.contains_key(key) || m.values().any(|x| contains_key(x, key)),
        Value::Array(a) => a.iter().any(|x| contains_key(x, key)),
        _ => false,
    }
}

fn agent(timeout: Duration) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        // The daemon is on loopback: never go through a system proxy.
        .proxy(None)
        .max_redirects(0)
        .build();
    ureq::Agent::new_with_config(config)
}

fn post(
    config: &DaemonConfig,
    path: &str,
    body: &[u8],
    timeout: Duration,
    debug: bool,
) -> Option<(u16, String)> {
    let url = format!("http://127.0.0.1:{}{path}", config.hook_port);
    let result = agent(timeout)
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-AgentNest-Token", &config.hook_token)
        .header("X-AgentNest-Via", "cli")
        .send(body);
    match result {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let text = resp.body_mut().read_to_string().unwrap_or_default();
            Some((status, text))
        }
        Err(e) => {
            if debug {
                eprintln!("agentnest-hook: request failed: {e}");
            }
            None
        }
    }
}

fn read_config(path: &Path, debug: bool) -> Option<DaemonConfig> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            if debug {
                eprintln!("agentnest-hook: cannot read {}: {e}", path.display());
            }
            return None;
        }
    };
    match serde_json::from_str::<DaemonConfig>(&text) {
        Ok(c) => Some(c),
        Err(e) => {
            if debug {
                eprintln!("agentnest-hook: invalid daemon config: {e}");
            }
            None
        }
    }
}

/// `%LOCALAPPDATA%\AgentNest\daemon.json` on Windows, the XDG data directory elsewhere.
fn default_daemon_config() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_DATA_HOME").map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
        })?;
    Some(base.join("AgentNest").join("daemon.json"))
}

/// Human readable check. Never prints the token.
fn doctor(config: &DaemonConfig, path: Option<&Path>, timeout_ms: Option<u64>) -> String {
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(2_000));
    let mut lines = vec![format!(
        "config: {} (hook_port {})",
        path.map(|p| p.display().to_string()).unwrap_or_default(),
        config.hook_port
    )];
    let base = format!("http://127.0.0.1:{}", config.hook_port);
    let health = agent(timeout).get(&format!("{base}/v1/health")).call();
    match health {
        Ok(r) if r.status().as_u16() == 200 => lines.push("daemon: reachable".to_owned()),
        Ok(r) => lines.push(format!("daemon: unexpected status {}", r.status().as_u16())),
        Err(_) => {
            lines.push(
                "daemon: NOT reachable (hooks will pass through with no decision)".to_owned(),
            );
            return lines.join("\n") + "\n";
        }
    }
    let info = agent(timeout)
        .get(&format!("{base}/v1/daemon"))
        .header("X-AgentNest-Token", &config.hook_token)
        .call();
    match info {
        Ok(mut r) if r.status().as_u16() == 200 => {
            let text = r.body_mut().read_to_string().unwrap_or_default();
            let wss = serde_json::from_str::<Map<String, Value>>(&text)
                .ok()
                .and_then(|m| m.get("wss_port").and_then(Value::as_u64));
            lines.push("token: accepted".to_owned());
            if let Some(p) = wss {
                lines.push(format!("wss_port: {p}"));
            }
        }
        Ok(r) if r.status().as_u16() == 401 => {
            lines.push("token: REJECTED (reinstall the hooks to refresh daemon.json)".to_owned());
        }
        Ok(r) => lines.push(format!("token: unexpected status {}", r.status().as_u16())),
        Err(_) => lines.push("token: check failed".to_owned()),
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn long_strings_are_cut_and_listed() {
        let big = "a".repeat(MAX_STRING_BYTES + 10);
        let raw = serde_json::to_vec(&json!({
            "hook_event_name": "PostToolUse",
            "tool_input": {"content": big, "short": "x"},
            "list": ["ok", big],
        }))
        .unwrap();
        let (body, event) = prepare_body(raw);
        assert_eq!(event.as_deref(), Some("PostToolUse"));
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["tool_input"]["content"].as_str().unwrap().len(),
            MAX_STRING_BYTES
        );
        assert_eq!(v["tool_input"]["short"], "x");
        assert_eq!(
            v["_agentnest_truncated"],
            json!(["list[1]", "tool_input.content"])
        );
    }

    #[test]
    fn cut_respects_char_boundaries() {
        let s = "가".repeat(MAX_STRING_BYTES); // 3 bytes per char
        let (body, _) = prepare_body(serde_json::to_vec(&json!({ "p": s })).unwrap());
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert!(v["p"].as_str().unwrap().len() <= MAX_STRING_BYTES);
    }

    #[test]
    fn small_bodies_are_forwarded_byte_for_byte() {
        let raw = b"{ \"a\" :   1 }".to_vec();
        assert_eq!(prepare_body(raw.clone()).0, raw);
        let junk = b"not json".to_vec();
        assert_eq!(prepare_body(junk.clone()).0, junk);
    }

    #[test]
    fn codex_permission_decision_is_dropped() {
        let ask =
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask"}}"#;
        assert_eq!(filter_response(Route::Codex, ask), Output::Nothing);
        assert!(matches!(
            filter_response(Route::ClaudeCode, ask),
            Output::Text(_)
        ));
        assert_eq!(filter_response(Route::ClaudeCode, "[1]"), Output::Nothing);
        assert_eq!(filter_response(Route::ClaudeCode, ""), Output::Nothing);
    }

    #[test]
    fn timeouts_follow_the_contract() {
        let c = DaemonConfig {
            hook_port: 1,
            hook_token: String::new(),
            approval_ttl_s: Some(100),
        };
        assert_eq!(
            default_timeout(Some("PermissionRequest"), &c),
            Duration::from_secs(128)
        );
        assert_eq!(
            default_timeout(Some("SessionEnd"), &c),
            Duration::from_millis(800)
        );
        assert_eq!(
            default_timeout(Some("PreToolUse"), &c),
            Duration::from_secs(4)
        );
        assert_eq!(default_timeout(None, &c), Duration::from_secs(4));
    }
}
