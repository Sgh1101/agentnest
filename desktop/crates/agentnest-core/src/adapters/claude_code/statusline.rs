//! statusLine collector input (docs/integrations/claude-code.md 5, `POST /v1/statusline/claude-code`).
//!
//! Claude Code runs the configured `statusLine` command with a JSON document on stdin (`agentnest-hook statusline` posts
//! it here). It is the only official source for the AI generated session title, the cost, the context usage and the pull
//! request of a session. [`parse`] turns it into a [`SessionMetaPatch`]; updates per session are throttled to one per
//! 10 s by the HTTP layer. Nothing but the listed scalar fields is read, and nothing is stored raw.

use agentnest_adapter_api::SessionMetaPatch;
use serde_json::Value;

use crate::normalize::hook::str_field;

/// Minimum time between two applied statusLine updates of one session.
pub const THROTTLE_MS: i64 = 10_000;
/// Longest pull request URL kept (bytes). A longer one is dropped, not cut: a cut URL points somewhere else.
pub const PR_URL_MAX_BYTES: usize = 512;

/// A pull request URL worth keeping: `https://`, at most [`PR_URL_MAX_BYTES`], no whitespace or control character
/// (so it cannot fake a second line in a card or a log), and masked like every free text (a token in the query string
/// never reaches the database or the phone).
fn pr_url(raw: &str) -> Option<String> {
    if !raw.starts_with("https://")
        || raw.len() > PR_URL_MAX_BYTES
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return None;
    }
    Some(crate::redact::mask(raw).text)
}

/// Extracts `(session_key, patch)` from a statusLine document. `None` if it has no `session_id`.
pub fn parse(doc: &Value) -> Option<(String, SessionMetaPatch)> {
    let session_id = str_field(doc, "session_id")?;
    let pr = doc.get("pr");
    let patch = SessionMetaPatch {
        title: str_field(doc, "session_name").map(str::to_owned),
        model: doc
            .get("model")
            .and_then(|m| m.get("display_name"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        cost_usd: doc
            .get("cost")
            .and_then(|c| c.get("total_cost_usd"))
            .and_then(Value::as_f64)
            .filter(|c| c.is_finite() && *c >= 0.0),
        context_used_pct: doc
            .get("context_window")
            .and_then(|c| c.get("used_percentage"))
            .and_then(Value::as_f64)
            .filter(|p| p.is_finite() && *p >= 0.0)
            .map(|p| p.round().min(100.0) as u32),
        pr_number: pr.and_then(|p| p.get("number")).and_then(Value::as_u64),
        pr_url: pr
            .and_then(|p| p.get("url"))
            .and_then(Value::as_str)
            .and_then(pr_url),
        ..SessionMetaPatch::default()
    };
    Some((format!("claude_code:{session_id}"), patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_documented_fields_become_a_patch() {
        let (key, p) = parse(&json!({
            "session_id": "7f1e",
            "session_name": "훅 수집기 구현",
            "model": {"display_name": "Claude Opus"},
            "cost": {"total_cost_usd": 1.23},
            "context_window": {"used_percentage": 40.6},
            "pr": {"number": 42, "url": "https://github.com/o/r/pull/42", "review_state": "open"},
            "workspace": {"current_dir": "C:\\secret\\path"}
        }))
        .unwrap();
        assert_eq!(key, "claude_code:7f1e");
        assert_eq!(p.title.as_deref(), Some("훅 수집기 구현"));
        assert_eq!(p.model.as_deref(), Some("Claude Opus"));
        assert_eq!(p.cost_usd, Some(1.23));
        assert_eq!(p.context_used_pct, Some(41));
        assert_eq!(p.pr_number, Some(42));
        assert_eq!(p.pr_url.as_deref(), Some("https://github.com/o/r/pull/42"));
    }

    #[test]
    fn missing_or_odd_values_are_skipped_not_guessed() {
        assert!(parse(&json!({})).is_none());
        assert!(parse(&json!({"session_name": "x"})).is_none());
        let (_, p) = parse(&json!({
            "session_id": "s",
            "cost": {"total_cost_usd": -3},
            "context_window": {"used_percentage": 250},
            "pr": {"number": "x", "url": "javascript:alert(1)"},
            "model": {"display_name": ""}
        }))
        .unwrap();
        assert_eq!(p.cost_usd, None);
        assert_eq!(p.context_used_pct, Some(100));
        assert_eq!(p.pr_number, None);
        assert_eq!(p.pr_url, None);
        assert_eq!(p.model, None);
    }

    #[test]
    fn the_pr_url_is_bounded_single_line_and_masked() {
        let url = |u: &str| {
            parse(&json!({"session_id": "s", "pr": {"number": 1, "url": u}}))
                .unwrap()
                .1
                .pr_url
        };
        assert_eq!(
            url("https://github.com/o/r/pull/7").as_deref(),
            Some("https://github.com/o/r/pull/7")
        );
        // longer than 512 bytes: dropped (not cut)
        let long = format!("https://github.com/{}", "a/".repeat(PR_URL_MAX_BYTES));
        assert_eq!(url(&long), None);
        let mut at_limit = String::from("https://github.com/");
        while at_limit.len() < PR_URL_MAX_BYTES {
            at_limit.push_str("a.b/");
        }
        at_limit.truncate(PR_URL_MAX_BYTES);
        assert_eq!(at_limit.len(), PR_URL_MAX_BYTES);
        assert_eq!(url(&at_limit).as_deref(), Some(at_limit.as_str()));
        // control / whitespace / bidirectional characters
        for bad in [
            "https://github.com/o/r\npull/7",
            "https://github.com/o/r pull/7",
            "https://github.com/o/r\u{1b}[31m",
            "https://github.com/\u{202e}7/llup",
        ] {
            let got = url(bad);
            assert!(
                got.as_deref()
                    .is_none_or(|g| !g.chars().any(|c| c.is_control() && c != '\u{202e}')),
                "{bad:?} -> {got:?}"
            );
        }
        assert_eq!(url("https://github.com/o/r\npull/7"), None);
        assert_eq!(url("https://github.com/o/r pull/7"), None);
        assert_eq!(url("https://github.com/o/r\u{1b}[31m"), None);
        // a secret in the query string is masked
        let masked = url("https://example.test/pull/7?access_token=abcdef123456&x=1").unwrap();
        assert!(!masked.contains("abcdef123456"), "{masked}");
        assert!(masked.contains("redacted"), "{masked}");
    }
}
