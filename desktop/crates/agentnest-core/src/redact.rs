//! Secret newtypes (Debug prints `<redacted>`, zeroize), 3-sink policy, pattern masking (docs/security.md 8).
//!
//! # What lives here
//!
//! * **Secret newtypes** ([`PairingSecret`], [`DeviceToken`], [`HookToken`], [`Nonce`], [`TlsKeyPem`]): `Debug` and
//!   `Display` print `<redacted>`, the value is zeroized on drop, comparison is constant time and there is **no**
//!   `Serialize` implementation, so a secret cannot reach a log line or a JSON document by accident. Reading the value
//!   requires an explicit `expose()` call, which is greppable. String-shaped secrets reuse
//!   [`agentnest_protocol::Secret`]; byte-shaped ones use [`SecretBytes`].
//! * **Pattern masking** ([`mask`], [`mask_cmd_preview`], [`mask_path`]): the regexes of security.md 8.3, pinned by
//!   `protocol/fixtures/redact_cases.json`. Masking is **fail closed**: if a pattern ever failed to compile the whole
//!   input is replaced.
//! * **Bounds** ([`clip`], [`tail_bytes`], [`head_bytes`], [`bound_detail`]): the display limits of security.md 8.2
//!   (command 2,000 chars, diff 4 KiB, 50 paths, stdout tail 1 KiB, prompt 200 chars, `detail` <= 8 KiB). Always
//!   **mask first, then cut**, so a secret that straddles the cut point cannot survive as a partial token.
//! * **Log helpers** ([`shorten_path_for_log`], [`mask_ip`], [`command_log_summary`], [`session_key_prefix`]): what the
//!   `tracing` sink may contain instead of values (security.md 8.2).

use std::fmt;
use std::net::IpAddr;
use std::sync::OnceLock;

use agentnest_protocol::canonical::{ct_eq, sha256_hex};
use agentnest_protocol::Secret;
use regex::Regex;
use serde_json::Value;
use zeroize::Zeroize;

/// Replacement text of [`mask`].
pub const REDACTED: &str = "<redacted>";
/// Replacement text of [`mask_cmd_preview`] (`{cmd60}` in the summary templates).
pub const CMD_MASK: &str = "***";

/// Maximum command length kept in `detail` / approval details (characters, including the ellipsis).
pub const COMMAND_MAX_CHARS: usize = 2_000;
/// Maximum diff preview (bytes).
pub const DIFF_MAX_BYTES: usize = 4 * 1024;
/// Maximum number of file paths in approval details.
pub const FILE_PATHS_MAX: usize = 50;
/// Maximum stdout/stderr tail (bytes).
pub const STDOUT_TAIL_MAX_BYTES: usize = 1024;
/// Maximum prompt preview (characters).
pub const PROMPT_PREVIEW_MAX_CHARS: usize = 200;
/// Maximum size of one serialised `detail` object (bytes, protocol.md 5.1).
pub const DETAIL_JSON_MAX_BYTES: usize = 8 * 1024;
/// Maximum size of one string inside `detail` (bytes, protocol.md 5.1).
pub const DETAIL_STRING_MAX_BYTES: usize = 2 * 1024;
/// Maximum message / preview length of notifications and final messages (characters).
pub const MESSAGE_PREVIEW_MAX_CHARS: usize = 300;
/// Longest input handed to the masking regexes (characters). Longer input is cut first.
pub const MASK_INPUT_MAX_CHARS: usize = 256 * 1024;

// ---------------------------------------------------------------------------------------------------------------------
// Secret newtypes
// ---------------------------------------------------------------------------------------------------------------------

/// A secret byte string (pairing secret, nonce). `Debug`/`Display` print `<redacted>`, zeroized on drop, constant-time
/// equality, no serde.
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps raw bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The raw bytes. Callers must not log them.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Constant-time comparison.
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        ct_eq(&self.0, other)
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(&other.0)
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

macro_rules! secret_string_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(Secret);

        impl $name {
            /// Wraps the secret text.
            pub fn new(value: impl Into<String>) -> Self {
                Self(Secret::new(value))
            }

            /// The secret text. Callers must not log it.
            pub fn expose(&self) -> &str {
                self.0.expose()
            }

            /// Constant-time comparison with a candidate.
            pub fn ct_eq(&self, candidate: &str) -> bool {
                self.0.ct_eq(candidate)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(REDACTED)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(REDACTED)
            }
        }
    };
}

macro_rules! secret_bytes_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(SecretBytes);

        impl $name {
            /// Wraps raw bytes.
            pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
                Self(SecretBytes::new(bytes))
            }

            /// The raw bytes. Callers must not log them.
            pub fn expose(&self) -> &[u8] {
                self.0.expose()
            }

            /// Constant-time comparison with a candidate.
            pub fn ct_eq(&self, candidate: &[u8]) -> bool {
                self.0.ct_eq(candidate)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(REDACTED)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(REDACTED)
            }
        }
    };
}

secret_bytes_newtype!(
    /// The raw 32-byte pairing secret from the QR code (the HMAC key). Never on the wire (security.md I3).
    PairingSecret
);
secret_bytes_newtype!(
    /// A per-request 16-byte approval nonce (raw bytes; the base64 form lives in `ApprovalRequest.nonce_b64`).
    Nonce
);
secret_string_newtype!(
    /// A device token (base64url text of 32 random bytes). The PC stores only its SHA-256.
    DeviceToken
);
secret_string_newtype!(
    /// The hook authentication token (`an_hk_...`) that Claude Code / `agentnest-hook` send in `X-AgentNest-Token`.
    HookToken
);
secret_string_newtype!(
    /// The PEM text of the TLS private key. Never logged, never stored in the database.
    TlsKeyPem
);

// ---------------------------------------------------------------------------------------------------------------------
// Pattern masking
// ---------------------------------------------------------------------------------------------------------------------

/// Result of masking: the text and whether anything was replaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Masked {
    /// The masked text.
    pub text: String,
    /// `true` if at least one pattern matched (the event gets `redacted: true`).
    pub redacted: bool,
}

/// One named masking pattern (names follow `protocol/fixtures/redact_cases.json`).
///
/// A pattern may name two capture groups, `pre` and `post`: they are **kept** and only the rest of the match is replaced
/// (`Authorization: Bearer <redacted>`, `-p<redacted>`, `https://user:<redacted>@host`). A pattern without them is
/// replaced as a whole.
struct Pattern {
    name: &'static str,
    regex: Regex,
    keeps_context: bool,
}

/// The masking patterns of security.md 8.3, in fixture order (order matters: the generic keyword rule runs second, so
/// the header rule before it can still see `Authorization: Bearer <value>` as a whole).
const PATTERN_SOURCES: [(&str, &str); 17] = [
    (
        "auth_header",
        r#"(?i)(?<pre>\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token|digest|negotiate)\s+)[^\s"']+"#,
    ),
    (
        "keyword_assignment",
        r"(?i)(api[_-]?key|token|secret|password|passwd|authorization|bearer)\s*[:=]\s*\S+",
    ),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("sk_token", r"sk-[A-Za-z0-9]{20,}"),
    (
        "vendor_token",
        r"\b(?:xox[abprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|ya29\.[A-Za-z0-9_-]{20,})",
    ),
    (
        "private_key_block",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    (
        "jwt",
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    ),
    (
        "url_userinfo",
        r#"(?i)(?<pre>\b[a-z][a-z0-9+.-]*://[^\s/@:"']+:)[^\s/@"']+(?<post>@)"#,
    ),
    (
        "credential_flag",
        r#"(?i)(?<pre>\B--?(?:password|passwd|pass|token|secret|api-?key|apikey|access-?token|auth-?token|client-?secret|oauth2-bearer)(?:\s+|=))[^\s"'-][^\s"']*"#,
    ),
    (
        "user_flag",
        r#"(?i)(?<pre>(?:\B--(?:proxy-)?user|\b(?:curl|wget)\b[^\n|;&]*?\s-u)\s+[^\s:@"']+:)[^\s"']*[^\s"'\d][^\s"']*"#,
    ),
    (
        "mysql_password_flag",
        r#"(?i)(?<pre>\b(?:mysql(?:dump|admin|import|check|pump|show|slap)?|mariadb(?:-dump|-admin|-import|-check|-show)?)\b[^\n|;&]*?\s(?-i:-p))[^\s"'-]\S*"#,
    ),
    (
        "npm_auth",
        r#"(?i)(?<pre>_auth(?:token|password)?\s*[=\s]\s*)[^\s"']+"#,
    ),
    (
        "query_secret",
        r#"(?i)(?<pre>[?&](?:key|token|api_?key|apikey|access_token|auth|sig|signature|secret|password|passwd|client_secret)=)[^&\s"'#]+"#,
    ),
    (
        "aws_secret",
        r#"(?i)(?<pre>\baws[_-]?(?:secret[_-]?access[_-]?key|secret[_-]?key|session[_-]?token)["']?\s*(?:=|:|\s)\s*["']?)[^\s"',;&]+"#,
    ),
    (
        "env_secret",
        r#"(?i)\b[a-z0-9_.-]*(?:secret|passw(?:or)?d|token|credentials?|(?:api|private|access|auth|signing|encryption|ssh|master)[_-]?key|_key)[a-z0-9_.-]*["']?\s*[=:]\s*["']?[^\s"',;&]+"#,
    ),
    ("long_token_40", r"[A-Za-z0-9+/_-]{40,}={0,2}"),
];

/// Patterns that are safe to apply to **file paths**: everything except the keyword-ish rules (a path such as
/// `docs/token-rotation.md` is not an assignment) and the 40+ character rule (long POSIX paths are not secrets).
const PATH_SAFE_PATTERNS: [&str; 6] = [
    "aws_access_key",
    "github_token",
    "sk_token",
    "vendor_token",
    "private_key_block",
    "jwt",
];

/// The rules [`mask_keep_long_tokens`] skips.
const LONG_TOKEN_PATTERN: &str = "long_token_40";

fn patterns() -> Option<&'static Vec<Pattern>> {
    static PATTERNS: OnceLock<Option<Vec<Pattern>>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            let mut out = Vec::with_capacity(PATTERN_SOURCES.len());
            for (name, src) in PATTERN_SOURCES {
                match Regex::new(src) {
                    Ok(regex) => {
                        let keeps_context = regex
                            .capture_names()
                            .flatten()
                            .any(|n| n == "pre" || n == "post");
                        out.push(Pattern {
                            name,
                            regex,
                            keeps_context,
                        });
                    }
                    Err(_) => return None,
                }
            }
            Some(out)
        })
        .as_ref()
}

fn apply_patterns(input: &str, replacement: &str, use_pattern: impl Fn(&str) -> bool) -> Masked {
    let Some(pats) = patterns() else {
        // Fail closed: a broken pattern table must never turn masking into a no-op.
        return Masked {
            text: replacement.to_owned(),
            redacted: true,
        };
    };
    let input = clip_input(input);
    let mut text = input.to_owned();
    let mut redacted = false;
    for p in pats {
        if !use_pattern(p.name) {
            continue;
        }
        let replaced = if p.keeps_context {
            p.regex
                .replace_all(&text, |c: &regex::Captures<'_>| {
                    let keep = |g: &str| c.name(g).map_or("", |m| m.as_str());
                    format!("{}{replacement}{}", keep("pre"), keep("post"))
                })
                .into_owned()
        } else {
            // a closure-free string would interpret `$`, so use a NoExpand
            p.regex
                .replace_all(&text, regex::NoExpand(replacement))
                .into_owned()
        };
        if replaced != text {
            redacted = true;
            text = replaced;
        }
    }
    Masked { text, redacted }
}

fn clip_input(input: &str) -> &str {
    if input.len() <= MASK_INPUT_MAX_CHARS {
        return input;
    }
    let mut end = MASK_INPUT_MAX_CHARS;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

/// Masks secrets in free text with `<redacted>` (security.md 8.3).
///
/// Input longer than [`MASK_INPUT_MAX_CHARS`] bytes is cut first (nothing downstream keeps that much anyway).
pub fn mask(input: &str) -> Masked {
    apply_patterns(input, REDACTED, |_| true)
}

/// Masks secrets with `***` for the `{cmd60}` command preview of the summary templates (protocol.md 7).
pub fn mask_cmd_preview(input: &str) -> Masked {
    apply_patterns(input, CMD_MASK, |_| true)
}

/// Masks secrets like [`mask`] but without the 40+ character rule. For text that a template clips afterwards (the final
/// summary is masked again with [`mask`] by the post-processing, see `normalize`): the long-token rule would also turn
/// a long identifier or hash in agent prose into `<redacted>` before the template could show a prefix of it.
pub fn mask_keep_long_tokens(input: &str) -> Masked {
    apply_patterns(input, REDACTED, |name| name != LONG_TOKEN_PATTERN)
}

/// Masks secrets in a **file path** (no keyword and no 40+ character rule; see [`PATH_SAFE_PATTERNS`]).
pub fn mask_path(input: &str) -> Masked {
    apply_patterns(input, REDACTED, |name| PATH_SAFE_PATTERNS.contains(&name))
}

// ---------------------------------------------------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------------------------------------------------

/// `s` if it has at most `n` characters, otherwise its first `n - 1` characters plus `…` (so the result has `n`
/// characters). This is the clip rule of protocol.md 7. `n == 0` yields an empty string.
pub fn clip(s: &str, n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    for (count, (idx, _)) in s.char_indices().enumerate() {
        if count == n {
            // more than n characters: cut to n-1 and add the ellipsis
            let cut = s.char_indices().nth(n - 1).map(|(i, _)| i).unwrap_or(idx);
            let mut out = String::with_capacity(cut + 3);
            out.push_str(&s[..cut]);
            out.push('…');
            return out;
        }
    }
    s.to_owned()
}

/// The first `max` bytes of `s`, cut on a character boundary. Returns the text and whether it was cut.
pub fn head_bytes(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_owned(), false);
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_owned(), true)
}

/// The last `max` bytes of `s`, cut on a character boundary (stdout/stderr tails). Returns the text and whether it
/// was cut.
pub fn tail_bytes(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_owned(), false);
    }
    let mut start = s.len() - max;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    (s[start..].to_owned(), true)
}

/// Masks `input` and then clips it to `max_chars` characters.
pub fn mask_and_clip(input: &str, max_chars: usize) -> Masked {
    let m = mask(input);
    Masked {
        text: clip(&m.text, max_chars),
        redacted: m.redacted,
    }
}

/// Removes control characters, bidirectional controls and line breaks (turned into spaces) from agent supplied text
/// that is shown on the phone (`purpose`, notification messages, descriptions).
pub fn sanitize_display_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_space = false;
    for c in input.chars() {
        let is_break = matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}' | '\t');
        let is_ctrl = c.is_control() || is_bidi_control(c);
        if is_break {
            if !last_space && !out.is_empty() {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        if is_ctrl {
            continue;
        }
        last_space = c == ' ';
        out.push(c);
    }
    out.trim().to_owned()
}

/// `true` for the characters that change what a human reads without being visible themselves: bidirectional controls,
/// zero-width and other invisible format characters, line / paragraph separators, ESC and every other control character
/// (except the layout characters `\n` and `\t`, which [`escape_display_text`] treats separately).
fn is_invisible_or_control(c: char) -> bool {
    c.is_control()
        || is_bidi_control(c)
        || matches!(
            c,
            '\u{00AD}'                 // soft hyphen
            | '\u{180E}'               // Mongolian vowel separator
            | '\u{200B}'..='\u{200D}' // zero-width space / non-joiner / joiner
            | '\u{2028}' | '\u{2029}' // line / paragraph separator
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{FEFF}'               // zero-width no-break space / BOM
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation
            | '\u{E0000}'..='\u{E007F}' // tag characters
        )
}

/// Removes the characters of [`is_invisible_or_control`] except `\n` and `\t`. Used **only to make masking robust**: a
/// zero-width character inside `pass\u{200B}word=hunter2` must not keep the keyword rule from matching.
fn without_invisibles(input: &str) -> std::borrow::Cow<'_, str> {
    if !input.chars().any(|c| is_invisible_or_control(c) && c != '\n' && c != '\t') {
        return std::borrow::Cow::Borrowed(input);
    }
    std::borrow::Cow::Owned(
        input
            .chars()
            .filter(|c| !is_invisible_or_control(*c) || *c == '\n' || *c == '\t')
            .collect(),
    )
}

/// Makes text safe to **show** on a card (security.md 8.2, claude-code.md 5): every character that could make the
/// displayed text differ from what is really there becomes a **visible escape** instead of being dropped or acted upon:
///
/// * ESC and every other control character (`\x1b[2K` cursor tricks), CR (`\r` rewrites the line in a terminal), bidi
///   controls (`U+202E` reverses what follows), zero-width and other format characters, line / paragraph separators:
///   `\r` for CR, `\u{202e}` style for the rest;
/// * `\n` and `\t` stay (a command may be several lines) unless `single_line` is set (then `\n` is a space and `\t` a
///   space, so a name or a path cannot fake a second line).
///
/// The result is plain printable text; escaping is idempotent for text that has nothing to escape.
pub fn escape_display_text(input: &str, single_line: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\n' if single_line => out.push(' '),
            '\t' if single_line => out.push(' '),
            '\n' | '\t' => out.push(c),
            '\r' => out.push_str("\\r"),
            c if is_invisible_or_control(c) => {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
}

/// Masks `input` for display ([`mask`]) and then makes it printable ([`escape_display_text`]). Masking sees the text
/// **without** invisible characters, so a zero-width character cannot hide a secret from it; if something was masked the
/// invisible characters are gone from the result, otherwise they are shown as escapes.
pub fn mask_for_display(input: &str, single_line: bool) -> Masked {
    let stripped = without_invisibles(input);
    let masked = mask(&stripped);
    if masked.redacted {
        Masked {
            text: escape_display_text(&masked.text, single_line),
            redacted: true,
        }
    } else {
        Masked {
            text: escape_display_text(input, single_line),
            redacted: false,
        }
    }
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

/// Bounds a `detail` object in place: masks every string (paths with [`mask_path`]), applies the per-key limits of
/// security.md 8.2, caps `file_paths` at [`FILE_PATHS_MAX`], limits every string to [`DETAIL_STRING_MAX_BYTES`] and
/// the serialised object to [`DETAIL_JSON_MAX_BYTES`].
///
/// Returns `(redacted, truncated)`: whether anything was masked and whether anything was cut.
pub fn bound_detail(detail: &mut Value) -> (bool, bool) {
    let mut redacted = false;
    let mut truncated = false;
    bound_value(None, detail, &mut redacted, &mut truncated, 0);
    // Total size: shrink the longest strings until the object fits. The loop is bounded (every round strictly
    // shrinks the longest string or stops).
    for _ in 0..64 {
        let size = serde_json::to_vec(detail)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if size <= DETAIL_JSON_MAX_BYTES {
            return (redacted, truncated);
        }
        if !shrink_longest_string(detail) {
            break;
        }
        truncated = true;
    }
    // Last resort: drop everything but short scalars so the bound always holds.
    if serde_json::to_vec(detail)
        .map(|v| v.len())
        .unwrap_or(usize::MAX)
        > DETAIL_JSON_MAX_BYTES
    {
        if let Value::Object(map) = detail {
            map.retain(|_, v| {
                matches!(v, Value::Bool(_) | Value::Number(_))
                    || v.as_str().is_some_and(|s| s.len() <= 64)
            });
        }
        truncated = true;
    }
    (redacted, truncated)
}

fn path_key(key: &str) -> bool {
    matches!(
        key,
        "file_path" | "cwd_hint" | "path_hint" | "notebook_path" | "path" | "cwd"
    )
}

fn limit_for_key(key: &str) -> Limit {
    match key {
        "command" => Limit::Chars(COMMAND_MAX_CHARS),
        "prompt_preview" => Limit::Chars(PROMPT_PREVIEW_MAX_CHARS),
        "stdout_tail" | "stderr_tail" => Limit::TailBytes(STDOUT_TAIL_MAX_BYTES),
        "diff_preview" => Limit::HeadBytes(DIFF_MAX_BYTES),
        "message" | "final_message_preview" | "summary_preview" | "body_preview" => {
            Limit::Chars(MESSAGE_PREVIEW_MAX_CHARS)
        }
        "error" | "error_message" => Limit::HeadBytes(DETAIL_STRING_MAX_BYTES),
        _ => Limit::HeadBytes(DETAIL_STRING_MAX_BYTES),
    }
}

enum Limit {
    Chars(usize),
    HeadBytes(usize),
    TailBytes(usize),
}

fn bound_value(
    key: Option<&str>,
    value: &mut Value,
    redacted: &mut bool,
    truncated: &mut bool,
    depth: usize,
) {
    if depth > 8 {
        *value = Value::Null;
        *truncated = true;
        return;
    }
    match value {
        Value::String(s) => {
            let is_path = key.is_some_and(path_key);
            let masked = if is_path { mask_path(s) } else { mask(s) };
            if masked.redacted {
                *redacted = true;
            }
            let limit = key
                .map(limit_for_key)
                .unwrap_or(Limit::HeadBytes(DETAIL_STRING_MAX_BYTES));
            let (text, cut) = match limit {
                Limit::Chars(n) => {
                    let clipped = clip(&masked.text, n);
                    let cut = clipped != masked.text;
                    (clipped, cut)
                }
                Limit::HeadBytes(n) => {
                    let (t, cut) = head_bytes(&masked.text, n);
                    (t, cut)
                }
                Limit::TailBytes(n) => tail_bytes(&masked.text, n),
            };
            if cut {
                *truncated = true;
            }
            // Every string is also held to the generic per-string cap.
            let (text, cut2) = head_bytes(&text, DETAIL_STRING_MAX_BYTES);
            if cut2 {
                *truncated = true;
            }
            *s = text;
        }
        Value::Array(items) => {
            if key == Some("file_paths") && items.len() > FILE_PATHS_MAX {
                items.truncate(FILE_PATHS_MAX);
                *truncated = true;
            } else if items.len() > 100 {
                items.truncate(100);
                *truncated = true;
            }
            let child_key = if key == Some("file_paths") {
                Some("file_path")
            } else {
                key
            };
            for item in items.iter_mut() {
                bound_value(child_key, item, redacted, truncated, depth + 1);
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                bound_value(Some(k.as_str()), v, redacted, truncated, depth + 1);
            }
        }
        _ => {}
    }
}

fn shrink_longest_string(value: &mut Value) -> bool {
    fn longest<'a>(v: &'a mut Value, best: &mut Option<&'a mut String>) {
        match v {
            Value::String(s) => {
                if best.as_ref().is_none_or(|b| s.len() > b.len()) {
                    *best = Some(s);
                }
            }
            Value::Array(items) => {
                for i in items {
                    longest(i, best);
                }
            }
            Value::Object(map) => {
                for (_, i) in map.iter_mut() {
                    longest(i, best);
                }
            }
            _ => {}
        }
    }
    let mut best: Option<&mut String> = None;
    longest(value, &mut best);
    match best {
        Some(s) if s.len() > 64 => {
            let target = s.len() / 2;
            let (cut, _) = head_bytes(s, target);
            *s = cut;
            true
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Log-sink helpers (security.md 8.2)
// ---------------------------------------------------------------------------------------------------------------------

/// A path as it may appear in a log line: the last two segments with a leading `…/` (`…/crates/agentnest-core`).
/// Never panics on odd input.
pub fn shorten_path_for_log(path: &str) -> String {
    let norm = path.replace('\\', "/");
    let segs: Vec<&str> = norm
        .split('/')
        .filter(|s| !s.is_empty() && !(s.len() == 2 && s.ends_with(':')))
        .collect();
    let tail: Vec<&str> = segs.iter().rev().take(2).rev().copied().collect();
    let joined = clip(&tail.join("/"), 80);
    format!("…/{joined}")
}

/// Masks the last IPv4 octet (`192.168.0.10` -> `192.168.0.x`) or the last 80 bits of an IPv6 address
/// (`fe80:1:2::x`). Text that is not an IP address becomes `x`.
pub fn mask_ip(ip: &str) -> String {
    match ip.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.x", o[0], o[1], o[2])
        }
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::x", s[0], s[1], s[2])
        }
        Err(_) => "x".to_owned(),
    }
}

/// `len=42 sha256=9f86d081`: what a log may say about a command instead of the command itself.
pub fn command_log_summary(command: &str) -> String {
    let h = sha256_hex(command.as_bytes());
    format!("len={} sha256={}", command.chars().count(), &h[..8])
}

/// The first 12 characters of a session key (the log form, security.md 8.2).
pub fn session_key_prefix(session_key: &str) -> &str {
    match session_key.char_indices().nth(12) {
        Some((idx, _)) => &session_key[..idx],
        None => session_key,
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    fn fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../protocol/fixtures/redact_cases.json"
        );
        let text = std::fs::read_to_string(path).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn pattern_table_matches_the_fixture_file() {
        let f = fixture();
        let pats = f["patterns"].as_array().unwrap();
        assert_eq!(pats.len(), PATTERN_SOURCES.len());
        for (p, (name, src)) in pats.iter().zip(PATTERN_SOURCES) {
            assert_eq!(p["name"], name);
            assert_eq!(p["regex"], src, "pattern {name} differs from the fixture");
        }
        assert!(patterns().is_some(), "all masking patterns must compile");
    }

    #[test]
    fn redact_cases_golden() {
        let f = fixture();
        let cases = f["cases"].as_array().unwrap();
        assert!(cases.len() >= 20);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let got = mask(c["input"].as_str().unwrap());
            assert_eq!(got.text, c["expect"]["output"].as_str().unwrap(), "{name}");
            assert_eq!(
                got.redacted,
                c["expect"]["redacted"].as_bool().unwrap(),
                "{name}"
            );
        }
    }

    /// Review PoC 3: every one of these used to leave the secret in the card / event text.
    #[test]
    fn the_review_leaks_are_masked_in_every_variant() {
        let cases: [(&str, &str); 14] = [
            ("curl -H 'Authorization: Bearer abc123SECRETvalue' https://api.example.com", "abc123SECRETvalue"),
            ("curl -H \"Authorization: Basic dXNlcjpwYXNzd29yZA==\" https://x", "dXNlcjpwYXNzd29yZA"),
            ("export MY_SECRET_KEY=hunter2hunter2", "hunter2hunter2"),
            ("mysql -u root -phunter2 db", "hunter2"),
            ("mysql --password hunter2 db", "hunter2"),
            ("git clone https://user:hunter2@github.com/o/r.git", "hunter2"),
            ("curl --user admin:hunter2 https://x", "hunter2"),
            ("npm config set //registry.npmjs.org/:_authToken npm_abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123456789"),
            ("echo xoxb-test-fake-value-0000", "fake-value-0000"),
            ("curl 'https://x/?key=AIzaSyA1234567890abcdefghijklmnopq'", "AIzaSyA1234567890"),
            ("ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
            ("gh auth login --with-token <<< github_pat_11ABCDEFG0abcdefghijkl_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstu", "11ABCDEFG0"),
            ("curl -d 'client_secret=abc123' https://x", "abc123"),
            ("aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG", "wJalrXUtnFEMI"),
        ];
        for (input, secret) in cases {
            for (label, got) in [
                ("mask", mask(input)),
                ("cmd_preview", mask_cmd_preview(input)),
                ("keep_long", mask_keep_long_tokens(input)),
            ] {
                assert!(got.redacted, "{label}: {input}");
                assert!(!got.text.contains(secret), "{label} leaked {secret:?}: {}", got.text);
            }
        }
        // the readable part of the command survives where the rule keeps context
        assert_eq!(mask("mysql -u root -phunter2 db").text, "mysql -u root -p<redacted> db");
        assert_eq!(
            mask("git clone https://user:hunter2@github.com/o/r.git").text,
            "git clone https://user:<redacted>@github.com/o/r.git"
        );
        // and ordinary text is not over-masked
        for ok in [
            "docker run -p 8080:80 --user 1000:1000 nginx",
            "mysql -u root -p mydb",
            "cargo test -p agentnest-core --all-targets",
            "git clone https://github.com/org/repo.git",
            "open http://localhost:8080/path?page=2&sort=name",
        ] {
            assert_eq!(mask(ok).text, ok);
            assert!(!mask(ok).redacted);
        }
    }

    #[test]
    fn cmd_preview_cases_golden() {
        let f = fixture();
        let cases = f["cmd_preview_cases"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            let got = mask_cmd_preview(c["input"].as_str().unwrap());
            assert_eq!(
                got.text,
                c["expect"]["output"].as_str().unwrap(),
                "{}",
                c["name"]
            );
        }
    }

    #[test]
    fn mask_path_keeps_long_posix_paths() {
        let p = "/home/someone/projects/agentnest-protocol-experiments/crates/agentnest-core/src";
        assert_eq!(mask_path(p).text, p);
        assert!(
            mask(p).redacted,
            "the generic masker intentionally over-masks long path-like runs"
        );
        assert!(mask_path("/x/ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8/y").redacted);
    }

    #[test]
    fn clip_follows_the_protocol_rule() {
        assert_eq!(clip("abc", 3), "abc");
        assert_eq!(clip("abcd", 3), "ab…");
        assert_eq!(clip("가나다라", 3), "가나…");
        assert_eq!(clip("x", 0), "");
        assert_eq!(clip("", 5), "");
        assert_eq!(clip("abc", 1), "…");
        assert_eq!(clip(&"a".repeat(50), 40).chars().count(), 40);
    }

    #[test]
    fn byte_cuts_respect_char_boundaries() {
        let s = "가나다라마";
        let (h, cut) = head_bytes(s, 7);
        assert!(cut);
        assert_eq!(h, "가나");
        let (t, cut) = tail_bytes(s, 7);
        assert!(cut);
        assert_eq!(t, "라마");
        assert_eq!(head_bytes("ab", 5), ("ab".to_owned(), false));
        assert_eq!(tail_bytes("ab", 5), ("ab".to_owned(), false));
    }

    #[test]
    fn mask_then_cut_does_not_leave_a_partial_secret() {
        // The secret straddles the 200 character prompt limit: it must be masked as a whole before the cut.
        let secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789";
        let prompt = format!("{}{secret}", "x ".repeat(95));
        let out = mask_and_clip(&prompt, PROMPT_PREVIEW_MAX_CHARS);
        assert!(out.redacted);
        assert!(!out.text.contains("sk-"));
        assert!(!out.text.contains("abcdefghij"));
    }

    #[test]
    fn bound_detail_applies_per_key_limits() {
        let long_cmd = "a ".repeat(3000);
        let stdout = format!("{}END", "out ".repeat(1500));
        let mut v = serde_json::json!({
            "command": long_cmd,
            "stdout_tail": stdout,
            "prompt_preview": "p".repeat(1000),
            "file_paths": (0..80).map(|i| format!("src/f{i}.rs")).collect::<Vec<_>>(),
            "message": "m".repeat(1000),
            "note": "token=abc123 and more",
        });
        let (redacted, truncated) = bound_detail(&mut v);
        assert!(redacted && truncated);
        assert!(v["command"].as_str().unwrap().chars().count() <= COMMAND_MAX_CHARS);
        let tail = v["stdout_tail"].as_str().unwrap();
        assert!(tail.len() <= STDOUT_TAIL_MAX_BYTES && tail.ends_with("END"));
        assert!(v["prompt_preview"].as_str().unwrap().chars().count() <= PROMPT_PREVIEW_MAX_CHARS);
        assert_eq!(v["file_paths"].as_array().unwrap().len(), FILE_PATHS_MAX);
        assert!(v["message"].as_str().unwrap().chars().count() <= MESSAGE_PREVIEW_MAX_CHARS);
        assert_eq!(v["note"], "<redacted> and more");
        assert!(serde_json::to_vec(&v).unwrap().len() <= DETAIL_JSON_MAX_BYTES);
    }

    #[test]
    fn bound_detail_enforces_the_total_size() {
        let mut v = serde_json::json!({
            "a": "a ".repeat(1000), "b": "b ".repeat(1000), "c": "c ".repeat(1000),
            "d": "d ".repeat(1000), "e": "e ".repeat(1000), "f": "f ".repeat(1000),
        });
        let (_, truncated) = bound_detail(&mut v);
        assert!(truncated);
        assert!(serde_json::to_vec(&v).unwrap().len() <= DETAIL_JSON_MAX_BYTES);
    }

    #[test]
    fn bound_detail_is_total_on_deep_and_odd_input() {
        let mut deep = serde_json::json!("x");
        for _ in 0..50 {
            deep = serde_json::json!({ "k": [deep] });
        }
        let _ = bound_detail(&mut deep);
        let mut odd = serde_json::json!({"command": "\u{0}\u{202e}weird", "file_path": ""});
        let _ = bound_detail(&mut odd);
    }

    #[test]
    fn escape_display_text_makes_every_deceptive_character_visible() {
        // bidi override, zero width, ESC + cursor control, CR: all printable now
        let tricky = "echo safe \u{202e}fdsa\u{200b}\u{1b}[2K\rrm -rf x";
        let shown = escape_display_text(tricky, false);
        assert_eq!(shown, "echo safe \\u{202e}fdsa\\u{200b}\\u{1b}[2K\\rrm -rf x");
        for c in shown.chars() {
            assert!(!c.is_control() || c == '\n' || c == '\t', "{c:?}");
            assert!(!is_bidi_control(c));
        }
        // layout characters stay in a command, not in a name
        assert_eq!(escape_display_text("a\n\tb", false), "a\n\tb");
        assert_eq!(escape_display_text("a\n\tb", true), "a  b");
        // plain text (incl. Korean, emoji, normal punctuation) is untouched
        for ok in ["cargo test -p agentnest-core", "한글 명령 😀", "C:\\dev\\x y"] {
            assert_eq!(escape_display_text(ok, false), ok);
        }
        // other format characters and the C1 range
        assert_eq!(escape_display_text("\u{feff}x\u{85}y\u{2028}", true), "\\u{feff}x\\u{85}y\\u{2028}");
    }

    #[test]
    fn mask_for_display_masks_through_zero_width_tricks_and_shows_the_rest_escaped() {
        // the keyword rule must still see `password=` although a zero-width character splits it
        let m = mask_for_display("login pass\u{200b}word=hunter2hunter2 now", false);
        assert!(m.redacted);
        assert!(!m.text.contains("hunter2"), "{}", m.text);
        // without a secret the invisible character is made visible
        let m = mask_for_display("echo a\u{200b}b", false);
        assert!(!m.redacted);
        assert_eq!(m.text, "echo a\\u{200b}b");
    }

    #[test]
    fn sanitize_display_text_strips_controls_and_bidi() {
        assert_eq!(sanitize_display_text("a\nb\r\nc\u{202e}d\u{0}e"), "a b cde");
        assert_eq!(sanitize_display_text("  hi  "), "hi");
        assert_eq!(sanitize_display_text("\n\n"), "");
    }

    #[test]
    fn log_helpers() {
        assert_eq!(
            shorten_path_for_log("C:\\dev\\agentnest\\src\\main.rs"),
            "…/src/main.rs"
        );
        assert_eq!(shorten_path_for_log("/a/b/c"), "…/b/c");
        assert_eq!(shorten_path_for_log(""), "…/");
        assert_eq!(mask_ip("192.168.0.10"), "192.168.0.x");
        assert_eq!(mask_ip("fe80::1:2:3:4"), "fe80:0:0::x");
        assert_eq!(mask_ip("not an ip"), "x");
        let s = command_log_summary("cargo test");
        assert!(s.starts_with("len=10 sha256="));
        assert_eq!(
            session_key_prefix("claude_code:7f1e2d3c-4b5a"),
            "claude_code:"
        );
        assert_eq!(session_key_prefix("short"), "short");
    }

    // -- the log grep test (security.md 8.1 / testing-and-ci.md) ----------------------------------------------------

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    const SECRET_TEXT: &str = "S3CR3T-TEST-VALUE-ZZZ";

    #[test]
    fn no_secret_newtype_reaches_formatted_or_traced_output() {
        let cap = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let pairing = PairingSecret::new(SECRET_TEXT.as_bytes());
        let nonce = Nonce::new(SECRET_TEXT.as_bytes());
        let device = DeviceToken::new(SECRET_TEXT);
        let hook = HookToken::new(SECRET_TEXT);
        let pem = TlsKeyPem::new(format!(
            "-----BEGIN PRIVATE KEY-----\n{SECRET_TEXT}\n-----END PRIVATE KEY-----"
        ));
        let plain = Secret::new(SECRET_TEXT);
        let raw = SecretBytes::new(SECRET_TEXT.as_bytes());

        let mut formatted = String::new();
        formatted.push_str(&format!("{pairing:?} {pairing} {pairing:#?}"));
        formatted.push_str(&format!("{nonce:?} {nonce}"));
        formatted.push_str(&format!("{device:?} {device}"));
        formatted.push_str(&format!("{hook:?} {hook}"));
        formatted.push_str(&format!("{pem:?} {pem}"));
        formatted.push_str(&format!("{plain:?} {plain}"));
        formatted.push_str(&format!("{raw:?} {raw}"));
        // Containers must not leak either.
        formatted.push_str(&format!("{:?}", vec![&device, &device]));
        formatted.push_str(&format!("{:?}", Some(&hook)));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(token = ?device, hook = %hook, "paired");
            tracing::warn!(pairing = ?pairing, nonce = %nonce, pem = ?pem, plain = ?plain, "secret fields");
            tracing::error!(raw = ?raw, "raw {:?} {}", device, hook);
        });

        let logged = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(
            logged.contains("<redacted>"),
            "the redaction marker must be visible: {logged}"
        );
        for sink in [formatted.as_str(), logged.as_str()] {
            assert!(!sink.contains(SECRET_TEXT), "secret leaked: {sink}");
            assert!(!sink.contains("S3CR3T"), "secret prefix leaked: {sink}");
        }
    }

    #[test]
    fn secret_newtypes_compare_in_constant_time_by_value() {
        assert_eq!(DeviceToken::new("a"), DeviceToken::new("a"));
        assert_ne!(HookToken::new("a"), HookToken::new("b"));
        assert!(PairingSecret::new(vec![1u8, 2, 3]).ct_eq(&[1, 2, 3]));
        assert!(!Nonce::new(vec![1u8; 16]).ct_eq(&[2u8; 16]));
        assert_eq!(HookToken::new("x").expose(), "x");
        assert!(SecretBytes::new(Vec::new()).is_empty());
    }
}
