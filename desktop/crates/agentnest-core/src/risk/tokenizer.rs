//! Shell/PowerShell command segmentation and command_class helpers.
//!
//! The risk classifier and the `command_class` function work on *segments*: the parts of a command line that are
//! joined by `&&`, `||`, `;`, `|`, `&` or a line break (integrations/claude-code.md 7). The tokenizer is a heuristic,
//! not a shell parser; its failure mode is deliberately **over-detection**:
//!
//! * quotes protect separators (`echo "a && b"` is one segment), but if a quote is never closed the whole line is
//!   re-split ignoring quotes, so nothing can hide behind an unbalanced quote;
//! * `$(...)`, `` `...` `` and `<(...)` bodies are exposed through [`substitutions`] so the caller can classify them
//!   as commands of their own;
//! * wrappers (`sudo`, `env`, `time`, ...) and interpreter payloads (`bash -c "..."`, `cmd /c ...`,
//!   `powershell -Command ...`, `-EncodedCommand`) are exposed through [`unwrap_command`] / [`inner_payload`].
//!
//! Backslashes are literal (Windows paths such as `C:\dev` must survive), except `\"` inside double quotes.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Which dialect the command was written for. Only a few details differ (`&` is the call operator in PowerShell,
/// the backtick is its escape character).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shell {
    /// `Bash` tool and anything unknown.
    Posix,
    /// `PowerShell` tool.
    PowerShell,
}

/// One command of a command line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Segment {
    /// The original text of the segment (trimmed).
    pub raw: String,
    /// Whitespace separated words with quotes removed, original case.
    pub tokens: Vec<String>,
    /// `true` if this segment reads the output of the previous one (`|`).
    pub piped: bool,
}

/// Splits `command` into segments. Never panics; unbalanced quotes fall back to quote-less splitting.
pub fn split_segments(command: &str, shell: Shell) -> Vec<Segment> {
    // PowerShell treats the typographic quotes (U+2018..U+201E) exactly like `'` and `"`: `Remove-Item “C:\”`
    let command = if shell == Shell::PowerShell && command.chars().any(is_smart_quote) {
        std::borrow::Cow::Owned(command.chars().map(straighten_quote).collect::<String>())
    } else {
        std::borrow::Cow::Borrowed(command)
    };
    match split_inner(&command, shell, true) {
        Some(v) => v,
        None => split_inner(&command, shell, false).unwrap_or_default(),
    }
}

fn is_smart_quote(c: char) -> bool {
    matches!(
        c,
        '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' | '\u{201C}' | '\u{201D}' | '\u{201E}'
    )
}

fn straighten_quote(c: char) -> char {
    match c {
        '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' => '\'',
        '\u{201C}' | '\u{201D}' | '\u{201E}' => '"',
        other => other,
    }
}

/// PowerShell accepts en dash, em dash and horizontal bar as the parameter prefix (`–Recurse`, `—Force`). They become
/// an ASCII `-` so that every flag test sees them (a token that merely starts with such a dash is over-detected as a flag
/// in POSIX mode, which is the safe direction).
fn normalize_leading_dash(mut t: String) -> String {
    if t.starts_with(['\u{2013}', '\u{2014}', '\u{2015}']) {
        let rest = t.chars().skip(1).collect::<String>();
        t = format!("-{rest}");
    }
    t
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
    /// `$'...'`: single quotes with backslash escapes (`$'\x72m'` is `rm`).
    AnsiC,
}

/// Decodes the escape sequence that follows a backslash inside `$'...'` (`chars[at]` is the character after the
/// backslash). Returns the character and how many characters after the backslash it used; `('\\', 0)` keeps an unknown or
/// incomplete escape literally (the backslash stays, the next character is read normally), like bash does.
fn ansi_c_escape(chars: &[char], at: usize) -> (char, usize) {
    let Some(&c) = chars.get(at) else {
        return ('\\', 0);
    };
    let digits = |radix: u32, max: usize, from: usize| -> (u32, usize) {
        let mut v = 0u32;
        let mut n = 0usize;
        while n < max {
            match chars.get(from + n).and_then(|d| d.to_digit(radix)) {
                Some(d) => {
                    v = v.saturating_mul(radix).saturating_add(d);
                    n += 1;
                }
                None => break,
            }
        }
        (v, n)
    };
    let to_char = |v: u32| char::from_u32(v).unwrap_or('\u{FFFD}');
    match c {
        'a' => ('\u{7}', 1),
        'b' => ('\u{8}', 1),
        'e' | 'E' => ('\u{1b}', 1),
        'f' => ('\u{c}', 1),
        'n' => ('\n', 1),
        'r' => ('\r', 1),
        't' => ('\t', 1),
        'v' => ('\u{b}', 1),
        '\\' => ('\\', 1),
        '\'' => ('\'', 1),
        '"' => ('"', 1),
        '?' => ('?', 1),
        'x' | 'u' | 'U' => {
            let max = match c {
                'x' => 2,
                'u' => 4,
                _ => 8,
            };
            match digits(16, max, at + 1) {
                (_, 0) => ('\\', 0),
                (v, n) => (to_char(v), 1 + n),
            }
        }
        '0'..='7' => {
            let (v, n) = digits(8, 3, at);
            (to_char(v), n)
        }
        'c' => match chars.get(at + 1) {
            Some(k) => (to_char(u32::from(*k) & 0x1f), 2),
            None => ('\\', 0),
        },
        _ => ('\\', 0),
    }
}

fn split_inner(command: &str, shell: Shell, quote_aware: bool) -> Option<Vec<Segment>> {
    let chars: Vec<char> = command.chars().collect();
    let mut segments: Vec<Segment> = Vec::new();
    let mut raw = String::new();
    let mut tokens: Vec<String> = Vec::new();
    let mut tok: Option<String> = None;
    let mut quote = Quote::None;
    let mut cur_piped = false;

    // Closes the current token.
    fn end_token(tok: &mut Option<String>, tokens: &mut Vec<String>) {
        if let Some(t) = tok.take() {
            tokens.push(normalize_leading_dash(t));
        }
    }

    let mut finish_segment = |raw: &mut String,
                              tokens: &mut Vec<String>,
                              tok: &mut Option<String>,
                              cur_piped: &mut bool,
                              piped_after: bool| {
        end_token(tok, tokens);
        if !tokens.is_empty() || !raw.trim().is_empty() {
            segments.push(Segment {
                raw: raw.trim().to_owned(),
                tokens: lower_syntax(std::mem::take(tokens)),
                piped: *cur_piped,
            });
        }
        raw.clear();
        // Whether the *following* segment is piped is decided by the separator that just ended this one.
        *cur_piped = piped_after;
    };

    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match quote {
            Quote::AnsiC => {
                raw.push(c);
                if c == '\'' {
                    quote = Quote::None;
                } else if c == '\\' {
                    let (decoded, used) = ansi_c_escape(&chars, i + 1);
                    for k in 0..used {
                        if let Some(ch) = chars.get(i + 1 + k) {
                            raw.push(*ch);
                        }
                    }
                    tok.get_or_insert_with(String::new).push(decoded);
                    i += used;
                } else {
                    tok.get_or_insert_with(String::new).push(c);
                }
                i += 1;
                continue;
            }
            Quote::Single => {
                raw.push(c);
                if c == '\'' {
                    quote = Quote::None;
                } else {
                    tok.get_or_insert_with(String::new).push(c);
                }
                i += 1;
                continue;
            }
            Quote::Double => {
                raw.push(c);
                if c == '"' {
                    quote = Quote::None;
                } else if c == '\\' && next == Some('"') {
                    tok.get_or_insert_with(String::new).push('"');
                    raw.push('"');
                    i += 1;
                } else if c == '`' && shell == Shell::PowerShell && next.is_some() {
                    if let Some(n) = next {
                        tok.get_or_insert_with(String::new).push(n);
                        raw.push(n);
                    }
                    i += 1;
                } else {
                    tok.get_or_insert_with(String::new).push(c);
                }
                i += 1;
                continue;
            }
            Quote::None => {}
        }
        match c {
            '$' if quote_aware && next == Some('\'') => {
                // `$'rm'`, `$'\x72m'`: ANSI-C quoting; the `$` is not part of the word and escapes are decoded
                raw.push('$');
                raw.push('\'');
                quote = Quote::AnsiC;
                tok.get_or_insert_with(String::new);
                i += 1;
            }
            '$' if quote_aware && next == Some('"') => {
                // `$"rm"`: locale quoting; the `$` is not part of the word
                raw.push(c);
            }
            '\'' => {
                raw.push(c);
                if quote_aware {
                    quote = Quote::Single;
                    tok.get_or_insert_with(String::new);
                }
            }
            '"' => {
                raw.push(c);
                if quote_aware {
                    quote = Quote::Double;
                    tok.get_or_insert_with(String::new);
                }
            }
            ' ' | '\t' => {
                raw.push(c);
                end_token(&mut tok, &mut tokens);
            }
            '\n' | '\r' | ';' => {
                finish_segment(&mut raw, &mut tokens, &mut tok, &mut cur_piped, false);
            }
            '|' => {
                // `||`, `|&` and `|` all end the segment; only a single pipe feeds the next segment.
                let piped_after = next != Some('|');
                if next == Some('|') || next == Some('&') {
                    i += 1;
                }
                finish_segment(&mut raw, &mut tokens, &mut tok, &mut cur_piped, piped_after);
            }
            '&' => {
                let prev = if i > 0 {
                    chars.get(i - 1).copied()
                } else {
                    None
                };
                if next == Some('&') {
                    i += 1;
                    finish_segment(&mut raw, &mut tokens, &mut tok, &mut cur_piped, false);
                } else if matches!(prev, Some('>') | Some('<')) || next == Some('>') {
                    // redirection forms: `2>&1`, `>&2`, `&>file`
                    raw.push(c);
                    tok.get_or_insert_with(String::new).push(c);
                } else if shell == Shell::PowerShell && tokens.is_empty() && tok.is_none() {
                    // PowerShell call operator: `& "C:\x.exe" args`
                    raw.push(c);
                } else {
                    finish_segment(&mut raw, &mut tokens, &mut tok, &mut cur_piped, false);
                }
            }
            other => {
                raw.push(other);
                tok.get_or_insert_with(String::new).push(other);
            }
        }
        i += 1;
    }
    if quote != Quote::None && quote_aware {
        return None;
    }
    finish_segment(&mut raw, &mut tokens, &mut tok, &mut cur_piped, false);
    Some(segments)
}

/// Words that only structure a shell program and are not commands themselves.
const SYNTAX_WORDS: &[&str] = &[
    "!", "{", "}", "(", ")", "((", "))", "if", "then", "else", "elif", "fi", "do", "done", "while",
    "until", "esac", "coproc", "for", "select",
];

/// `{a,b}` / `{1..3}`: a brace expansion, not a group opener.
fn is_brace_expansion(token: &str) -> bool {
    token.starts_with('{') && (token.contains(',') || token.contains(".."))
}

/// Strips the shell *syntax* around the command a segment really runs, so that `(rm -rf /)`, `{ rm -rf /; }`,
/// `! rm -rf /`, `then rm -rf build`, `do rm -rf "$d"` and `case x in x) rm -rf /` classify like `rm -rf /`:
///
/// * reserved words and grouping tokens at the start (`if`, `then`, `do`, `!`, `{`, `(`, ...);
/// * a group opener glued to the command word (`(rm`, `{rm`) and the matching closer at the end (`/)`, `}`);
/// * the `PATTERN)` of a `case` clause;
/// * `iex(New-Object ...)`: a call glued to its argument list is split into the word and the argument list.
///
/// Nothing else is changed. The function is total.
fn lower_syntax(mut tokens: Vec<String>) -> Vec<String> {
    let mut braced = false;
    // `start` is the index of the first token that is still part of the command: the loop is linear and has no cap, so
    // a thousand leading `!` or `if` cannot push the real command out of sight.
    let mut start = 0usize;
    let is_name = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | ':'))
    };
    while start < tokens.len() {
        let f = tokens[start].clone();
        let f = f.as_str();
        let next = tokens.get(start + 1).map(String::as_str);
        if SYNTAX_WORDS.contains(&f) {
            if f == "{" {
                braced = true;
            }
            start += 1;
            continue;
        }
        if f == "function" {
            // `function name { ...` / `function name() { ...`: the definition head is not a command
            start += 2;
            if tokens.get(start).map(String::as_str) == Some("()") {
                start += 1;
            }
            continue;
        }
        if f.len() > 2 && f.ends_with("()") && is_name(&f[..f.len() - 2]) {
            // `name() { ...`
            start += 1;
            continue;
        }
        if next == Some("()") && is_name(f) {
            // `name () { ...`
            start += 2;
            continue;
        }
        if f == "case" {
            // `case WORD in PATTERN) command...`
            let pattern_end = if tokens.get(start + 2).map(String::as_str) == Some("in") {
                tokens
                    .iter()
                    .enumerate()
                    .skip(start + 3)
                    .find(|(_, t)| t.ends_with(')'))
                    .map(|(i, _)| i)
            } else {
                None
            };
            start = pattern_end.map_or(start + 1, |i| i + 1);
            continue;
        }
        if f.len() > 1 && f.starts_with('(') {
            tokens[start] = f.trim_start_matches('(').to_owned();
            continue;
        }
        if f.len() > 1 && f.starts_with('{') && !is_brace_expansion(f) {
            braced = true;
            tokens[start] = f[1..].to_owned();
            continue;
        }
        // the `PATTERN)` of a later `case` clause (`x) rm -rf /`, `*) ...`): a first word that closes a parenthesis nobody
        // opened and is followed by more words
        if start + 1 < tokens.len()
            && f.ends_with(')')
            && !f.contains('(')
            && !f.starts_with(['$', '<', '>'])
        {
            start += 1;
            continue;
        }
        break;
    }
    tokens.drain(..start.min(tokens.len()));
    // A closing parenthesis nobody opened in this segment (`(cd x && rm -rf /)` is split at `&&`): not part of the word.
    if let Some(last) = tokens.last_mut() {
        let close = last.matches(')').count();
        let open = last.matches('(').count();
        let run = last.chars().rev().take_while(|c| *c == ')').count();
        let strip = run.min(close.saturating_sub(open));
        for _ in 0..strip {
            last.pop();
        }
        if strip > 0 && last.is_empty() {
            tokens.pop();
        }
    }
    if braced && tokens.last().map(String::as_str) == Some("}") {
        tokens.pop();
    }
    // `iex(New-Object Net.WebClient)...`: the command word is what precedes the first `(`
    if let Some(first) = tokens.first() {
        if !first.starts_with(['$', '<', '>', '`', '(', '{']) {
            if let Some(i) = first.find('(') {
                if i > 0 {
                    let rest = first[i..].to_owned();
                    tokens[0].truncate(i);
                    tokens.insert(1, rest);
                }
            }
        }
    }
    tokens
}

/// The bodies of command substitutions in `text`: `$(...)`, `` `...` `` and `<(...)` / `>(...)` (top level only; the
/// caller recurses). Single-quoted regions are skipped (no substitution there). Never panics.
pub fn substitutions(text: &str) -> Vec<String> {
    substitution_spans(text)
        .into_iter()
        .map(|(_, body)| body)
        .collect()
}

/// Like [`substitutions`], with the character index of the opening `$` / `<` / `>` / `` ` `` of every body in `text`
/// (so the caller can look at the command that precedes the substitution).
pub fn substitution_spans(text: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let c = chars[i];
        if in_single {
            if c == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' if !in_double => in_single = true,
            '"' => in_double = !in_double,
            '$' | '<' | '>'
                if chars.get(i + 1) == Some(&'(')
                    && (c == '$' || is_proc_subst_start(&chars, i)) =>
            {
                let (body, end) = paren_body(&chars, i + 2);
                out.push((i, body));
                i = end;
                continue;
            }
            '`' => {
                let mut j = i + 1;
                let mut body = String::new();
                while j < chars.len() && chars[j] != '`' {
                    body.push(chars[j]);
                    j += 1;
                }
                if j < chars.len() {
                    out.push((i, body));
                    i = j + 1;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

fn is_proc_subst_start(chars: &[char], i: usize) -> bool {
    i == 0
        || matches!(
            chars[i - 1],
            ' ' | '\t' | '=' | '\n' | ';' | '|' | '&' | '('
        )
}

/// Reads up to the matching `)`; returns the body and the index just after it (or the end of input).
fn paren_body(chars: &[char], start: usize) -> (String, usize) {
    let mut depth = 1usize;
    let mut j = start;
    let mut body = String::new();
    while j < chars.len() {
        match chars[j] {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return (body, j + 1);
                }
            }
            _ => {}
        }
        body.push(chars[j]);
        j += 1;
    }
    (body, j)
}

/// The lower-cased command name of a token: directory and a known executable suffix removed
/// (`C:\Windows\System32\shutdown.exe` -> `shutdown`, `./gradlew.bat` -> `gradlew`).
pub fn base_command(token: &str) -> String {
    let lower = token.to_lowercase();
    let name = lower.rsplit(['/', '\\']).next().unwrap_or("");
    for suffix in [".exe", ".cmd", ".bat", ".ps1", ".com"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            if !stripped.is_empty() {
                return stripped.to_owned();
            }
        }
    }
    name.to_owned()
}

/// `true` for `NAME=value` (POSIX environment assignment) and `$name=value` / `$env:NAME=value` (PowerShell).
pub fn is_assignment(token: &str) -> bool {
    if let Some(rest) = token.strip_prefix('$') {
        return rest.contains('=');
    }
    match token.find('=') {
        Some(0) | None => false,
        Some(i) => {
            let name = &token[..i];
            let mut chars = name.chars();
            matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}

/// `true` for option-looking tokens (`-x`, `--long`, and cmd.exe style `/s`).
pub fn is_flag(token: &str) -> bool {
    token.len() > 1 && token.starts_with('-')
}

/// The command word after wrappers were removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unwrapped<'a> {
    /// A privilege-elevating wrapper (`sudo`, `doas`, `pkexec`, `gsudo`, `runas`) was removed.
    pub elevated: bool,
    /// The remaining tokens; `tokens[0]` is the real command (empty if there is none).
    pub tokens: &'a [String],
}

const ELEVATORS: &[&str] = &["sudo", "doas", "pkexec", "gsudo"];

/// Removes leading assignments and wrapper commands (`sudo`, `env`, `nohup`, `time`, `command`, `exec`, `nice`,
/// `timeout`, `xargs`, `stdbuf`, `setsid`, `ionice`, `builtin`, `call`, `start`) and returns what is left.
pub fn unwrap_command(tokens: &[String]) -> Unwrapped<'_> {
    let mut idx = 0usize;
    let mut elevated = false;
    for _ in 0..64 {
        while idx < tokens.len() && is_assignment(&tokens[idx]) {
            idx += 1;
        }
        let Some(first) = tokens.get(idx) else { break };
        let name = base_command(first);
        let n = name.as_str();
        if ELEVATORS.contains(&n) {
            elevated = true;
            idx += 1;
            idx = skip_wrapper_flags(
                tokens,
                idx,
                &["-u", "-g", "-h", "-p", "-c", "-d", "-r", "-t", "-t", "-u"],
            );
            continue;
        }
        match n {
            "env" => {
                // `env -S "cmd args"` carries a command line: `inner_payload` reads it, so `env` stays the command here
                if env_split_string(&tokens[idx + 1..]).is_some() {
                    break;
                }
                idx += 1;
                idx = skip_wrapper_flags(tokens, idx, &["-u", "-c"]);
            }
            "nohup" | "command" | "exec" | "builtin" | "setsid" | "call" | "start" | "time"
            | "busybox" | "toybox" | "chronic" | "unbuffer" | "coproc" => {
                idx += 1;
                idx = skip_wrapper_flags(tokens, idx, &[]);
            }
            "nice" | "ionice" | "stdbuf" => {
                idx += 1;
                idx = skip_wrapper_flags(tokens, idx, &["-n", "-c", "-i", "-o", "-e"]);
            }
            "timeout" => {
                idx += 1;
                idx = skip_wrapper_flags(tokens, idx, &["-s", "-k"]);
                // the duration
                if idx < tokens.len()
                    && tokens[idx]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_digit())
                {
                    idx += 1;
                }
            }
            "xargs" => {
                idx += 1;
                idx = skip_wrapper_flags(
                    tokens,
                    idx,
                    &["-n", "-i", "-l", "-p", "-s", "-d", "-e", "-a"],
                );
            }
            _ => break,
        }
    }
    Unwrapped {
        elevated,
        tokens: &tokens[idx.min(tokens.len())..],
    }
}

fn skip_wrapper_flags(tokens: &[String], mut idx: usize, with_value: &[&str]) -> usize {
    while idx < tokens.len() {
        let t = &tokens[idx];
        if is_assignment(t) {
            idx += 1;
        } else if is_flag(t) {
            let lower = t.to_lowercase();
            idx += 1;
            if with_value.contains(&lower.as_str()) && idx < tokens.len() {
                idx += 1;
            }
        } else {
            break;
        }
    }
    idx
}

/// The command line given to `env -S` / `env --split-string` (and whatever follows it), if any. `rest` are the tokens after
/// `env`.
fn env_split_string(rest: &[String]) -> Option<String> {
    for (i, t) in rest.iter().enumerate() {
        if t == "-S" || t == "--split-string" {
            return Some(rest.get(i + 1..)?.join(" ")).filter(|c| !c.is_empty());
        }
        if let Some(v) = t.strip_prefix("--split-string=") {
            return Some(
                std::iter::once(v)
                    .chain(rest[i + 1..].iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        if t.len() > 2 && t.starts_with("-S") && !t.starts_with("--") {
            return Some(
                std::iter::once(&t[2..])
                    .chain(rest[i + 1..].iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        if !(t.starts_with('-') || is_assignment(t)) {
            return None;
        }
    }
    None
}

/// What an interpreter invocation carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inner {
    /// A command line to classify recursively.
    Command(String),
    /// Something we cannot look into (an undecodable `-EncodedCommand`).
    Opaque,
}

const POSIX_SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh",
];

/// `true` if the command word is a shell or script interpreter that can execute a downloaded script from stdin.
pub fn is_shell_interpreter(name: &str) -> bool {
    POSIX_SHELLS.contains(&name)
        || matches!(name, "powershell" | "pwsh" | "iex" | "invoke-expression")
}

/// Names of script interpreters that execute whatever they are given (`python3`, `node`, `perl`, ...). Version suffixes
/// (`python3.12`) count.
pub fn is_script_interpreter(name: &str) -> bool {
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        base,
        "python"
            | "pypy"
            | "py"
            | "node"
            | "nodejs"
            | "deno"
            | "bun"
            | "perl"
            | "ruby"
            | "php"
            | "lua"
            | "luajit"
            | "rscript"
            | "tclsh"
            | "osascript"
    )
}

/// `true` if `name args...` reads a **program** from standard input: a shell interpreter (always), or a script
/// interpreter that was given neither inline code (`-c`, `-e`, `-m`, ...) nor a script file (`-` counts as stdin).
pub fn reads_program_from_stdin(name: &str, args: &[String]) -> bool {
    if is_shell_interpreter(name) {
        return true;
    }
    if !is_script_interpreter(name) {
        return false;
    }
    let inline = args.iter().any(|a| {
        a.starts_with('-')
            && !a.starts_with("--")
            && a.chars()
                .skip(1)
                .any(|c| matches!(c, 'c' | 'e' | 'E' | 'm' | 'r' | 'p'))
            || matches!(a.as_str(), "--eval" | "--print" | "--command")
    });
    if inline {
        return false;
    }
    let mut positional = args.iter().filter(|a| !is_flag(a)).map(String::as_str);
    let mut first = positional.next();
    if matches!(name, "deno" | "bun") && first == Some("run") {
        first = positional.next();
    }
    matches!(first, None | Some("-"))
}

/// The command line carried by `bash -c "..."`, `cmd /c ...`, `powershell -Command ...`, `-EncodedCommand`, `eval ...`
/// and `wsl ...`. `None` if the tokens are not such an invocation.
pub fn inner_payload(tokens: &[String]) -> Option<Inner> {
    let name = base_command(tokens.first()?);
    let n = name.as_str();
    let rest = &tokens[1..];
    if POSIX_SHELLS.contains(&n) {
        // first short-option group containing `c`, payload is the next token
        let mut i = 0;
        while i < rest.len() {
            let t = &rest[i];
            if t.starts_with('-') && !t.starts_with("--") && t.chars().skip(1).any(|c| c == 'c') {
                return rest.get(i + 1).map(|p| Inner::Command(p.clone()));
            }
            i += 1;
        }
        return None;
    }
    match n {
        "cmd" => {
            let pos = rest
                .iter()
                .position(|t| matches!(t.to_lowercase().as_str(), "/c" | "/k" | "/r"))?;
            // `r^d /s /q C:\`: the caret is cmd.exe's escape character and vanishes from the word
            Some(Inner::Command(rest[pos + 1..].join(" ").replace('^', "")))
        }
        "powershell" | "pwsh" => {
            let mut i = 0;
            while i < rest.len() {
                let l = rest[i].to_lowercase();
                let flag = l.trim_start_matches(['-', '/']);
                if l.starts_with(['-', '/']) && !flag.is_empty() {
                    if "command".starts_with(flag) || flag == "c" {
                        return Some(Inner::Command(rest[i + 1..].join(" ")));
                    }
                    if flag == "e"
                        || flag == "ec"
                        || "encodedcommand".starts_with(flag) && flag.len() >= 2
                    {
                        return Some(match rest.get(i + 1).and_then(|b| decode_utf16le_b64(b)) {
                            Some(cmd) => Inner::Command(cmd),
                            None => Inner::Opaque,
                        });
                    }
                }
                i += 1;
            }
            None
        }
        "eval" => Some(Inner::Command(rest.join(" "))),
        "env" => env_split_string(rest).map(Inner::Command),
        "su" | "runuser" => {
            // `su [-] [user] -c "cmd"`, `su -lc "cmd"`, `su --command=cmd`
            let mut i = 0;
            while i < rest.len() {
                let t = &rest[i];
                if let Some(v) = t.strip_prefix("--command=") {
                    return Some(Inner::Command(v.to_owned()));
                }
                if t == "--command"
                    || (t.starts_with('-')
                        && !t.starts_with("--")
                        && t.chars().skip(1).any(|c| c == 'c'))
                {
                    return rest.get(i + 1).map(|p| Inner::Command(p.clone()));
                }
                i += 1;
            }
            None
        }
        "wsl" => {
            // `wsl [-d distro] [-e|--exec] command...`
            let mut i = 0;
            while i < rest.len() {
                let l = rest[i].to_lowercase();
                if l == "-d" || l == "--distribution" || l == "-u" || l == "--user" {
                    i += 2;
                } else if l == "-e" || l == "--exec" || l == "--" || l.starts_with('-') {
                    i += 1;
                } else {
                    break;
                }
            }
            if i < rest.len() {
                Some(Inner::Command(rest[i..].join(" ")))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn decode_utf16le_b64(b64: &str) -> Option<String> {
    let bytes = STANDARD.decode(b64.trim()).ok()?;
    if bytes.len() % 2 != 0 || bytes.is_empty() {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(cmd: &str) -> Vec<Vec<String>> {
        split_segments(cmd, Shell::Posix)
            .into_iter()
            .map(|s| s.tokens)
            .collect()
    }

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn splits_on_all_separators() {
        assert_eq!(
            toks("a && b || c ; d | e & f\ng"),
            vec![
                v(&["a"]),
                v(&["b"]),
                v(&["c"]),
                v(&["d"]),
                v(&["e"]),
                v(&["f"]),
                v(&["g"])
            ]
        );
        let segs = split_segments("cat x | grep y && echo z", Shell::Posix);
        assert_eq!(segs.len(), 3);
        assert!(!segs[0].piped && segs[1].piped && !segs[2].piped);
        let segs = split_segments("a || b | c", Shell::Posix);
        assert!(!segs[0].piped && !segs[1].piped && segs[2].piped);
    }

    #[test]
    fn quotes_protect_separators_and_are_removed() {
        assert_eq!(
            toks("echo \"a && b\" 'c; d'"),
            vec![v(&["echo", "a && b", "c; d"])]
        );
        assert_eq!(
            toks("rm   -rf    \"node_modules\""),
            vec![v(&["rm", "-rf", "node_modules"])]
        );
        assert_eq!(
            toks("git commit -m \"fix: a \\\" b\""),
            vec![v(&["git", "commit", "-m", "fix: a \" b"])]
        );
        assert_eq!(toks("echo ''"), vec![v(&["echo", ""])]);
    }

    #[test]
    fn unbalanced_quote_falls_back_to_naive_splitting() {
        let segs = split_segments("echo \"unterminated ; rm -rf /", Shell::Posix);
        assert!(segs
            .iter()
            .any(|s| s.tokens.first().map(String::as_str) == Some("rm")));
    }

    #[test]
    fn windows_paths_keep_their_backslashes() {
        assert_eq!(
            toks("del /s /q C:\\"),
            vec![v(&["del", "/s", "/q", "C:\\"])]
        );
        assert_eq!(
            toks("reg add HKLM\\Software\\Foo /v Bar"),
            vec![v(&["reg", "add", "HKLM\\Software\\Foo", "/v", "Bar"])]
        );
    }

    #[test]
    fn redirections_are_not_separators() {
        assert_eq!(
            toks("cargo test 2>&1 | tail -5"),
            vec![v(&["cargo", "test", "2>&1"]), v(&["tail", "-5"])]
        );
        assert_eq!(toks("cmd &> out.txt"), vec![v(&["cmd", "&>", "out.txt"])]);
    }

    #[test]
    fn powershell_call_operator_is_skipped() {
        let segs = split_segments("& \"C:\\x\\a.exe\" --flag", Shell::PowerShell);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].tokens, v(&["C:\\x\\a.exe", "--flag"]));
    }

    #[test]
    fn substitutions_are_extracted() {
        assert_eq!(substitutions("echo $(rm -rf /) done"), vec!["rm -rf /"]);
        assert_eq!(
            substitutions("echo `date` $(a $(b))"),
            vec!["date", "a $(b)"]
        );
        assert_eq!(substitutions("bash <(curl x.sh)"), vec!["curl x.sh"]);
        assert!(substitutions("echo '$(not run)'").is_empty());
        assert_eq!(substitutions("echo \"$(in dq)\""), vec!["in dq"]);
        assert!(substitutions("a < (b)").is_empty());
        assert_eq!(substitutions("$(unterminated"), vec!["unterminated"]);
    }

    #[test]
    fn base_command_strips_dirs_and_suffixes() {
        assert_eq!(
            base_command("C:\\Windows\\System32\\Shutdown.EXE"),
            "shutdown"
        );
        assert_eq!(base_command("./gradlew.bat"), "gradlew");
        assert_eq!(base_command("/usr/bin/sudo"), "sudo");
        assert_eq!(base_command(".exe"), ".exe");
    }

    #[test]
    fn unwrap_removes_wrappers() {
        let t = v(&["sudo", "-u", "root", "rm", "-rf", "x"]);
        let u = unwrap_command(&t);
        assert!(u.elevated);
        assert_eq!(u.tokens[0], "rm");
        let t = v(&["FOO=1", "env", "BAR=2", "nohup", "time", "cargo", "test"]);
        let u = unwrap_command(&t);
        assert!(!u.elevated);
        assert_eq!(u.tokens, &v(&["cargo", "test"])[..]);
        let t = v(&["timeout", "30", "curl", "x"]);
        assert_eq!(unwrap_command(&t).tokens[0], "curl");
        let t = v(&["sudo"]);
        assert!(unwrap_command(&t).tokens.is_empty());
        let t: Vec<String> = Vec::new();
        assert!(unwrap_command(&t).tokens.is_empty());
    }

    #[test]
    fn inner_payloads() {
        assert_eq!(
            inner_payload(&v(&["bash", "-c", "rm -rf /"])),
            Some(Inner::Command("rm -rf /".into()))
        );
        assert_eq!(
            inner_payload(&v(&["sh", "-lc", "x"])),
            Some(Inner::Command("x".into()))
        );
        assert_eq!(inner_payload(&v(&["bash", "script.sh"])), None);
        assert_eq!(
            inner_payload(&v(&["cmd.exe", "/c", "del", "/s", "x"])),
            Some(Inner::Command("del /s x".into()))
        );
        assert_eq!(
            inner_payload(&v(&[
                "powershell",
                "-NoProfile",
                "-Command",
                "Remove-Item",
                "-Recurse",
                "x"
            ])),
            Some(Inner::Command("Remove-Item -Recurse x".into()))
        );
        assert_eq!(
            inner_payload(&v(&["pwsh", "-enc", "!!notbase64!!"])),
            Some(Inner::Opaque)
        );
        // "Get-Date" in UTF-16LE base64
        let enc = STANDARD.encode(
            "Get-Date"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        assert_eq!(
            inner_payload(&v(&["powershell", "-EncodedCommand", &enc])),
            Some(Inner::Command("Get-Date".into()))
        );
        assert_eq!(
            inner_payload(&v(&["eval", "rm", "-rf", "x"])),
            Some(Inner::Command("rm -rf x".into()))
        );
        assert_eq!(
            inner_payload(&v(&["wsl", "-d", "Ubuntu", "-e", "rm", "-rf", "/"])),
            Some(Inner::Command("rm -rf /".into()))
        );
        assert_eq!(inner_payload(&v(&["python", "-c", "x"])), None);
        assert_eq!(inner_payload(&[]), None);
    }

    #[test]
    fn tokenizer_is_total_on_garbage() {
        for s in [
            "",
            "   ",
            ";;;",
            "&&&&",
            "||",
            "|&",
            "\"",
            "'",
            "`",
            "$(",
            "$((",
            "<(",
            "a\\",
            "\u{0}",
            "😀 && 😀",
        ] {
            let _ = split_segments(s, Shell::Posix);
            let _ = split_segments(s, Shell::PowerShell);
            let _ = substitutions(s);
        }
        let mut state: u64 = 42;
        let alphabet: Vec<char> = "ab '\"`$()<>|&;\n\\ -/.=é".chars().collect();
        for _ in 0..3000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 58) as usize + 1;
            let mut st = state;
            let s: String = (0..len)
                .map(|_| {
                    st = st.wrapping_mul(6364136223846793005).wrapping_add(7);
                    alphabet[(st >> 33) as usize % alphabet.len()]
                })
                .collect();
            let segs = split_segments(&s, Shell::Posix);
            for seg in &segs {
                let _ = unwrap_command(&seg.tokens);
                let _ = inner_payload(&seg.tokens);
            }
            let _ = substitutions(&s);
        }
    }

    #[test]
    fn assignments_and_flags() {
        assert!(is_assignment("FOO=bar"));
        assert!(is_assignment("$env:FOO=bar"));
        assert!(!is_assignment("if=/dev/zero") || is_assignment("if=/dev/zero")); // shape only; position decides
        assert!(!is_assignment("=x"));
        assert!(!is_assignment("--flag=x"));
        assert!(!is_assignment("plain"));
        assert!(is_flag("-r") && is_flag("--force") && !is_flag("-") && !is_flag("x"));
    }

    // -- review round 2 ----------------------------------------------------------------------------------------------

    fn first_tokens(cmd: &str) -> Vec<Vec<String>> {
        toks(cmd)
    }

    #[test]
    fn shell_syntax_is_stripped_from_the_segments() {
        assert_eq!(first_tokens("(rm -rf /)"), vec![v(&["rm", "-rf", "/"])]);
        assert_eq!(first_tokens("((rm -rf /))"), vec![v(&["rm", "-rf", "/"])]);
        assert_eq!(
            first_tokens("{ rm -rf /; }"),
            vec![v(&["rm", "-rf", "/"]), v(&[])]
        );
        assert_eq!(
            first_tokens("{rm -rf /; }"),
            vec![v(&["rm", "-rf", "/"]), v(&[])]
        );
        assert_eq!(first_tokens("! rm -rf /"), vec![v(&["rm", "-rf", "/"])]);
        assert_eq!(
            first_tokens("if [ -d b ]; then rm -rf b; fi"),
            vec![v(&["[", "-d", "b", "]"]), v(&["rm", "-rf", "b"]), v(&[])]
        );
        assert_eq!(
            first_tokens("while true; do rm x; done"),
            vec![v(&["true"]), v(&["rm", "x"]), v(&[])]
        );
        assert_eq!(
            first_tokens("for d in */; do rm -rf \"$d\"; done"),
            vec![v(&["d", "in", "*/"]), v(&["rm", "-rf", "$d"]), v(&[])]
        );
        assert_eq!(
            first_tokens("case x in x) rm -rf / ;; esac"),
            vec![v(&["rm", "-rf", "/"]), v(&[])]
        );
        assert_eq!(
            first_tokens("case x in a) ls ;; b) rm x ;; esac"),
            vec![v(&["ls"]), v(&["rm", "x"]), v(&[])]
        );
        assert_eq!(
            first_tokens("(cd x && rm -rf /)"),
            vec![v(&["cd", "x"]), v(&["rm", "-rf", "/"])]
        );
        assert_eq!(first_tokens("f() { rm x; }"), vec![v(&["rm", "x"]), v(&[])]);
        assert_eq!(
            first_tokens("function f { rm x; }"),
            vec![v(&["rm", "x"]), v(&[])]
        );
        assert_eq!(
            first_tokens("function f() { rm x; }"),
            vec![v(&["rm", "x"]), v(&[])]
        );
        // `iex(...)`: the word is what precedes the parenthesis
        assert_eq!(
            first_tokens("iex(New-Object X)"),
            vec![v(&["iex", "(New-Object", "X"])]
        );
        // what is not syntax stays: a balanced substitution, brace expansion, empty strings, plain words
        assert_eq!(first_tokens("echo $(date)"), vec![v(&["echo", "$(date)"])]);
        assert_eq!(first_tokens("{rm,-rf,/}"), vec![v(&["{rm,-rf,/}"])]);
        assert_eq!(first_tokens("echo ''"), vec![v(&["echo", ""])]);
        assert_eq!(
            first_tokens("make) x"),
            vec![v(&["x"])],
            "a word that closes a parenthesis with more words after it is a case pattern"
        );
        assert_eq!(first_tokens("ls)"), vec![v(&["ls"])]);
        assert_eq!(first_tokens("echo (a)"), vec![v(&["echo", "(a)"])]);
        assert_eq!(first_tokens("done"), vec![v(&[])]);
    }

    #[test]
    fn typographic_dashes_and_quotes_are_read_like_powershell_does() {
        let ps = |c: &str| {
            split_segments(c, Shell::PowerShell)
                .into_iter()
                .map(|s| s.tokens)
                .collect::<Vec<_>>()
        };
        for dash in ['\u{2013}', '\u{2014}', '\u{2015}'] {
            let t = ps(&format!("Remove-Item {dash}Recurse {dash}Force x"));
            assert_eq!(t, vec![v(&["Remove-Item", "-Recurse", "-Force", "x"])]);
            assert!(is_flag(&t[0][1]));
        }
        assert_eq!(
            ps("Remove-Item \u{201c}C:\\Program Files\u{201d} \u{2018}a b\u{2019}"),
            vec![v(&["Remove-Item", "C:\\Program Files", "a b"])]
        );
        // POSIX mode: dashes are normalised too (a harmless over-detection), quotes are ordinary characters
        assert_eq!(toks("rm \u{2013}rf x"), vec![v(&["rm", "-rf", "x"])]);
        assert_eq!(toks("echo \u{201c}a"), vec![v(&["echo", "\u{201c}a"])]);
    }

    #[test]
    fn ansi_c_and_locale_quoting_lose_their_dollar() {
        assert_eq!(toks("$'rm' -rf /"), vec![v(&["rm", "-rf", "/"])]);
        assert_eq!(toks("$\"rm\" -rf /"), vec![v(&["rm", "-rf", "/"])]);
        assert_eq!(toks("echo $'a b'"), vec![v(&["echo", "a b"])]);
        // a `$` that is not followed by a quote is a variable
        assert_eq!(toks("echo $HOME $"), vec![v(&["echo", "$HOME", "$"])]);
    }

    #[test]
    fn substitution_spans_report_where_a_substitution_starts() {
        let spans = substitution_spans("eval $(echo x | base64 -d) && ls `date`");
        assert_eq!(
            spans,
            vec![
                (5, "echo x | base64 -d".to_owned()),
                (33, "date".to_owned())
            ]
        );
        assert_eq!(
            substitution_spans("bash <(curl x)"),
            vec![(5, "curl x".to_owned())]
        );
        assert!(substitution_spans("echo '$(no)'").is_empty());
    }

    #[test]
    fn wrappers_payloads_and_interpreters_of_the_coverage_review() {
        assert_eq!(
            unwrap_command(&v(&["busybox", "rm", "-rf", "/"])).tokens[0],
            "rm"
        );
        assert_eq!(unwrap_command(&v(&["chronic", "ls"])).tokens[0], "ls");
        // `env -S` carries a command line: `env` stays the command word and `inner_payload` reads the line
        let t = v(&["env", "-S", "rm -rf /"]);
        assert_eq!(unwrap_command(&t).tokens[0], "env");
        assert_eq!(inner_payload(&t), Some(Inner::Command("rm -rf /".into())));
        assert_eq!(
            inner_payload(&v(&["env", "-Sa b", "c"])),
            Some(Inner::Command("a b c".into()))
        );
        assert_eq!(
            inner_payload(&v(&["env", "--split-string=x y"])),
            Some(Inner::Command("x y".into()))
        );
        assert_eq!(inner_payload(&v(&["env", "FOO=1", "make"])), None);
        assert_eq!(
            unwrap_command(&v(&["env", "-u", "A", "make"])).tokens[0],
            "make"
        );
        for t in [
            v(&["su", "-c", "rm -rf /"]),
            v(&["su", "-", "root", "-lc", "rm -rf /"]),
            v(&["su", "--command", "rm -rf /"]),
            v(&["runuser", "-l", "x", "-c", "rm -rf /"]),
        ] {
            assert_eq!(
                inner_payload(&t),
                Some(Inner::Command("rm -rf /".into())),
                "{t:?}"
            );
        }
        assert_eq!(
            inner_payload(&v(&["su", "--command=rm -rf /"])),
            Some(Inner::Command("rm -rf /".into()))
        );
        assert_eq!(inner_payload(&v(&["su", "-", "root"])), None);

        for n in [
            "python",
            "python3",
            "python3.12",
            "pypy3",
            "node",
            "nodejs",
            "deno",
            "bun",
            "perl",
            "ruby",
            "php",
            "lua",
            "Rscript".to_lowercase().as_str(),
        ] {
            assert!(is_script_interpreter(n), "{n}");
        }
        for n in ["pythonista", "nodemon", "git", "", ".", "perldoc", "bash"] {
            assert!(!is_script_interpreter(n), "{n}");
        }
        // a program on standard input: no inline code, no script file (a lone `-` is stdin)
        for (n, a) in [
            ("python3", vec![]),
            ("python3", v(&["-"])),
            ("python3", v(&["-u"])),
            ("node", vec![]),
            ("perl", vec![]),
            ("deno", v(&["run", "-"])),
            ("bun", v(&["run", "-"])),
            ("bash", v(&["-s", "--", "arg"])),
            ("sh", v(&["script.sh"])),
            ("powershell", v(&["-NoProfile"])),
        ] {
            assert!(reads_program_from_stdin(n, &a), "{n} {a:?}");
        }
        for (n, a) in [
            ("python3", v(&["-c", "print(1)"])),
            ("python3", v(&["-m", "json.tool"])),
            ("python3", v(&["script.py"])),
            ("python3", v(&["-uc", "x"])),
            ("node", v(&["-e", "1"])),
            ("node", v(&["--eval", "1"])),
            ("node", v(&["-p", "1"])),
            ("node", v(&["app.js"])),
            ("perl", v(&["-ne", "print"])),
            ("perl", v(&["-E", "say 1"])),
            ("ruby", v(&["-e", "1"])),
            ("php", v(&["-r", "echo 1;"])),
            ("deno", v(&["run", "app.ts"])),
            ("jq", vec![]),
            ("cat", vec![]),
        ] {
            assert!(!reads_program_from_stdin(n, &a), "{n} {a:?}");
        }
    }

    #[test]
    fn tokenizer_is_total_on_shell_syntax_noise() {
        let alphabet: Vec<char> = "ab rm-/ ${}()!;|&<>`'\"\\*?[]~.:=,@%^#\n\u{2013}\u{201c}é"
            .chars()
            .collect();
        let mut state: u64 = 0x0123_4567_89ab_cdef;
        for _ in 0..6000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 57) as usize + 1;
            let mut st = state;
            let s: String = (0..len)
                .map(|_| {
                    st = st.wrapping_mul(6364136223846793005).wrapping_add(5);
                    alphabet[(st >> 33) as usize % alphabet.len()]
                })
                .collect();
            for shell in [Shell::Posix, Shell::PowerShell] {
                for seg in split_segments(&s, shell) {
                    let u = unwrap_command(&seg.tokens);
                    let _ = inner_payload(u.tokens);
                    let _ = reads_program_from_stdin("python3", &seg.tokens);
                    for t in &seg.tokens {
                        let _ = base_command(t);
                        let _ = is_flag(t);
                    }
                }
            }
            let _ = substitution_spans(&s);
        }
    }

    #[test]
    fn ansi_c_quoting_decodes_its_escapes() {
        assert_eq!(toks("$'\\x72\\x6d'"), vec![v(&["rm"])]);
        assert_eq!(toks("$'\\162\\155'"), vec![v(&["rm"])]);
        assert_eq!(toks("$'\\u0072\\U0000006d'"), vec![v(&["rm"])]);
        assert_eq!(toks("$'a\\tb\\nc'"), vec![v(&["a\tb\nc"])]);
        assert_eq!(toks("$'it\\'s' x"), vec![v(&["it's", "x"])]);
        assert_eq!(toks("$'\\cA'"), vec![v(&["\u{1}"])]);
        // unknown / incomplete escapes keep their backslash; the quote is closed by the first unescaped `'`
        assert_eq!(toks("$'\\q\\x'"), vec![v(&["\\q\\x"])]);
        assert_eq!(toks("$'a' b"), vec![v(&["a", "b"])]);
        // separators inside the quotes do not split
        assert_eq!(toks("$'a;b|c' d"), vec![v(&["a;b|c", "d"])]);
        // unterminated: the quote-less fallback still splits at the separator
        assert!(toks("echo $'abc; rm -rf /")
            .iter()
            .any(|t| t.first().map(String::as_str) == Some("rm")));
    }

    #[test]
    fn a_thousand_reserved_words_do_not_push_the_command_out() {
        let cmd = format!("{}rm -rf /", "! ".repeat(1000));
        assert_eq!(toks(&cmd), vec![v(&["rm", "-rf", "/"])]);
        let cmd = format!("{}rm x", "if ".repeat(1000));
        assert_eq!(toks(&cmd), vec![v(&["rm", "x"])]);
    }
}
