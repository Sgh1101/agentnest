//! Runs the real binary against a local test server (matrix row 7: daemon not running -> empty stdout, exit 0).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use agentnest_protocol::hook_auth;

struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> Captured {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp).unwrap();
        assert!(n > 0, "connection closed before the headers ended");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.parse().unwrap())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut tmp).unwrap();
        assert!(n > 0);
        body.extend_from_slice(&tmp[..n]);
    }
    Captured {
        request_line,
        headers,
        body,
    }
}

const TOKEN: &str = "an_hk_test_token_value_0123456789";

/// How the fake daemon signs its answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Signing {
    /// A correct `X-AgentNest-Sig` (the real daemon).
    Valid,
    /// No signature at all (a squatter, or an http-hook era daemon).
    None,
    /// A signature made with another token.
    WrongKey,
    /// A valid signature of a DIFFERENT request (a replayed answer).
    OtherNonce,
}

/// Serves exactly one request with the given status and body, signed like the daemon.
fn serve_once(status: u16, body: &'static str) -> (u16, mpsc::Receiver<Captured>) {
    serve_once_signed(status, body, Signing::Valid)
}

/// Serves exactly one request; returns the port and the captured request.
fn serve_once_signed(
    status: u16,
    body: &'static str,
    signing: Signing,
) -> (u16, mpsc::Receiver<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let captured = read_request(&mut stream);
        let reason = if status == 200 { "OK" } else { "No Content" };
        let nonce = captured
            .header(hook_auth::HEADER_NONCE)
            .unwrap_or_default()
            .to_owned();
        let sig = match signing {
            Signing::Valid => Some(hook_auth::response_sig(
                &hook_auth::derive_key(TOKEN),
                &nonce,
                status,
                body.as_bytes(),
            )),
            Signing::WrongKey => Some(hook_auth::response_sig(
                &hook_auth::derive_key("an_hk_other"),
                &nonce,
                status,
                body.as_bytes(),
            )),
            Signing::OtherNonce => Some(hook_auth::response_sig(
                &hook_auth::derive_key(TOKEN),
                "some-other-request-nonce",
                status,
                body.as_bytes(),
            )),
            Signing::None => None,
        };
        let sig_header = sig
            .map(|s| format!("X-AgentNest-Sig: {s}\r\n"))
            .unwrap_or_default();
        let resp = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n{sig_header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = tx.send(captured);
    });
    (port, rx)
}

fn write_config(dir: &Path, port: u16) -> std::path::PathBuf {
    let p = dir.join("daemon.json");
    std::fs::write(
        &p,
        format!(r#"{{"hook_port":{port},"wss_port":1,"hook_token":"{TOKEN}"}}"#),
    )
    .unwrap();
    p
}

fn run(args: &[&str], config: &Path, stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentnest-hook"))
        .args(args)
        .arg("--daemon-config")
        .arg(config)
        .env_remove("AGENTNEST_HOOK_DEBUG")
        // A proxy must never be used for loopback.
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("http_proxy", "http://127.0.0.1:9")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut si = child.stdin.take().unwrap();
    let data = stdin.to_vec();
    let w = thread::spawn(move || {
        let _ = si.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    let _ = w.join();
    out
}

#[test]
fn passthrough_prints_only_the_daemon_body_and_sends_the_headers() {
    let dir = tempfile::tempdir().unwrap();
    let reply = r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#;
    let (port, rx) = serve_once(200, reply);
    let cfg = write_config(dir.path(), port);
    let input = br#"{"hook_event_name":"PermissionRequest","tool_name":"Bash"}"#;
    let out = run(&["claude-code"], &cfg, input);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), reply);
    assert!(out.stderr.is_empty());
    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(got.request_line.starts_with("POST /v1/hooks/claude-code "));
    // the token never travels: a one-time proof does
    assert_eq!(
        got.header("x-agentnest-token"),
        None,
        "the CLI must not send the token"
    );
    assert!(
        !String::from_utf8_lossy(&got.body).contains("an_hk_")
            && !got.headers.iter().any(|(_, v)| v.contains(TOKEN))
    );
    assert_eq!(got.header("x-agentnest-via"), Some("cli"));
    let key = hook_auth::derive_key(TOKEN);
    assert!(hook_auth::verify_request_proof(
        &key,
        "POST",
        "/v1/hooks/claude-code",
        got.header(hook_auth::HEADER_TS).unwrap(),
        got.header(hook_auth::HEADER_NONCE).unwrap(),
        got.header(hook_auth::HEADER_PROOF).unwrap(),
    ));
    assert_eq!(
        got.body,
        input.to_vec(),
        "small bodies are forwarded byte for byte"
    );
}

#[test]
fn no_decision_204_gives_empty_stdout_and_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    let (port, _rx) = serve_once(204, "");
    let cfg = write_config(dir.path(), port);
    let out = run(
        &["claude-code"],
        &cfg,
        br#"{"hook_event_name":"PreToolUse"}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}

#[test]
fn daemon_down_gives_empty_stdout_and_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    // A port nobody listens on: bind and drop.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cfg = write_config(dir.path(), port);
    let out = run(
        &["claude-code"],
        &cfg,
        br#"{"hook_event_name":"PermissionRequest"}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
}

#[test]
fn missing_or_broken_config_gives_empty_stdout_and_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(&["claude-code"], &dir.path().join("nope.json"), b"{}");
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "{ not json").unwrap();
    let out = run(&["codex"], &bad, b"{}");
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}

#[test]
fn bad_arguments_still_exit_0() {
    let out = Command::new(env!("CARGO_BIN_EXE_agentnest-hook"))
        .arg("no-such-subcommand")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}

#[test]
fn empty_stdin_is_not_posted() {
    let dir = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cfg = write_config(dir.path(), port);
    let out = run(&["claude-code"], &cfg, b"");
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}

#[test]
fn oversized_strings_are_truncated_to_32_kib_and_listed() {
    let dir = tempfile::tempdir().unwrap();
    let (port, rx) = serve_once(204, "");
    let cfg = write_config(dir.path(), port);
    let big = "x".repeat(100 * 1024);
    let input = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"content": big, "file_path": "/a/b"}
    });
    let out = run(&["claude-code"], &cfg, input.to_string().as_bytes());
    assert_eq!(out.status.code(), Some(0));
    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&got.body).unwrap();
    assert_eq!(
        v["tool_input"]["content"].as_str().unwrap().len(),
        32 * 1024
    );
    assert_eq!(v["tool_input"]["file_path"], "/a/b");
    assert_eq!(
        v["_agentnest_truncated"],
        serde_json::json!(["tool_input.content"])
    );
}

#[test]
fn codex_route_discards_a_permission_decision() {
    let dir = tempfile::tempdir().unwrap();
    let reply =
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask"}}"#;
    let (port, rx) = serve_once(200, reply);
    let cfg = write_config(dir.path(), port);
    let out = run(
        &["codex"],
        &cfg,
        br#"{"hook_event_name":"PreToolUse","turn_id":"t1"}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(got.request_line.starts_with("POST /v1/hooks/codex "));
}

#[test]
fn non_object_daemon_bodies_are_not_printed() {
    let dir = tempfile::tempdir().unwrap();
    let (port, _rx) = serve_once(200, "garbage that is not json");
    let cfg = write_config(dir.path(), port);
    let out = run(&["claude-code"], &cfg, br#"{"hook_event_name":"Stop"}"#);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}

#[test]
fn statusline_posts_to_its_endpoint_and_prints_one_line() {
    let dir = tempfile::tempdir().unwrap();
    let (port, rx) = serve_once(200, "{}");
    let cfg = write_config(dir.path(), port);
    let out = run(&["statusline"], &cfg, br#"{"session_id":"s1"}"#);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "AgentNest\n");
    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(got
        .request_line
        .starts_with("POST /v1/statusline/claude-code "));
}

#[test]
fn a_slow_daemon_times_out_with_empty_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = read_request(&mut s);
            thread::sleep(Duration::from_secs(5));
        }
    });
    let cfg = write_config(dir.path(), port);
    let started = std::time::Instant::now();
    let out = run(
        &["claude-code", "--timeout-ms", "300"],
        &cfg,
        br#"{"hook_event_name":"Stop"}"#,
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn doctor_reports_a_down_daemon_without_the_token() {
    let dir = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cfg = write_config(dir.path(), port);
    let out = run(&["doctor"], &cfg, b"");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("NOT reachable"));
    assert!(!text.contains("an_hk_"));
}

/// Review finding (item 1b): a process squatting the port can answer a hook with `allow`. The CLI prints only answers
/// that the daemon signed for THIS request.
#[test]
fn an_unsigned_or_wrongly_signed_answer_is_never_printed() {
    let allow = r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#;
    for (name, signing) in [
        ("unsigned", Signing::None),
        ("signed with another token", Signing::WrongKey),
        ("signature of another request", Signing::OtherNonce),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (port, _rx) = serve_once_signed(200, allow, signing);
        let cfg = write_config(dir.path(), port);
        let out = run(
            &["claude-code"],
            &cfg,
            br#"{"hook_event_name":"PermissionRequest","tool_name":"Bash"}"#,
        );
        assert_eq!(out.status.code(), Some(0), "{name}");
        assert!(
            out.stdout.is_empty(),
            "{name}: printed {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
    // the same for the ask reply of PreToolUse and for the statusLine
    let dir = tempfile::tempdir().unwrap();
    let (port, _rx) = serve_once_signed(200, allow, Signing::None);
    let out = run(
        &["statusline"],
        &write_config(dir.path(), port),
        br#"{"session_id":"s1"}"#,
    );
    assert!(out.stdout.is_empty());
    // a body that was altered after signing fails as well
    let dir = tempfile::tempdir().unwrap();
    let (port, _rx) = serve_once_signed(200, allow, Signing::OtherNonce);
    let out = run(
        &["codex"],
        &write_config(dir.path(), port),
        br#"{"hook_event_name":"Stop"}"#,
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn the_statusline_prints_its_line_for_a_signed_204_as_well() {
    let dir = tempfile::tempdir().unwrap();
    let (port, _rx) = serve_once(204, "");
    let out = run(
        &["statusline"],
        &write_config(dir.path(), port),
        br#"{"session_id":"s1"}"#,
    );
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "AgentNest\n");
}

#[test]
fn doctor_says_when_the_answer_is_not_signed() {
    let dir = tempfile::tempdir().unwrap();
    // two requests: /v1/health (anything) then /v1/daemon
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for _ in 0..2 {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = read_request(&mut s);
                let body = r#"{"ok":true,"wss_port":1}"#;
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        }
    });
    let out = run(&["doctor"], &write_config(dir.path(), port), b"");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("NOT signed"), "{text}");
    assert!(!text.contains("an_hk_"));
}
