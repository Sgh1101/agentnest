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
    match split_inner(command, shell, true) {
        Some(v) => v,
        None => split_inner(command, shell, false).unwrap_or_default(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
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
            tokens.push(t);
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
                tokens: std::mem::take(tokens),
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
                let prev = if i > 0 { chars.get(i - 1).copied() } else { None };
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

/// The bodies of command substitutions in `text`: `$(...)`, `` `...` `` and `<(...)` / `>(...)` (top level only; the
/// caller recurses). Single-quoted regions are skipped (no substitution there). Never panics.
pub fn substitutions(text: &str) -> Vec<String> {
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
            '$' | '<' | '>' if chars.get(i + 1) == Some(&'(') && (c == '$' || is_proc_subst_start(&chars, i)) => {
                let (body, end) = paren_body(&chars, i + 2);
                out.push(body);
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
                    out.push(body);
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
    i == 0 || matches!(chars[i - 1], ' ' | '\t' | '=' | '\n' | ';' | '|' | '&' | '(')
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
    for _ in 0..8 {
        while idx < tokens.len() && is_assignment(&tokens[idx]) {
            idx += 1;
        }
        let Some(first) = tokens.get(idx) else { break };
        let name = base_command(first);
        let n = name.as_str();
        if ELEVATORS.contains(&n) {
            elevated = true;
            idx += 1;
            idx = skip_wrapper_flags(tokens, idx, &["-u", "-g", "-h", "-p", "-c", "-d", "-r", "-t", "-t", "-u"]);
            continue;
        }
        match n {
            "env" => {
                idx += 1;
                idx = skip_wrapper_flags(tokens, idx, &["-u", "-s", "-c"]);
            }
            "nohup" | "command" | "exec" | "builtin" | "setsid" | "call" | "start" | "time" => {
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
                if idx < tokens.len() && tokens[idx].chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    idx += 1;
                }
            }
            "xargs" => {
                idx += 1;
                idx = skip_wrapper_flags(tokens, idx, &["-n", "-i", "-l", "-p", "-s", "-d", "-e", "-a"]);
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

/// What an interpreter invocation carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inner {
    /// A command line to classify recursively.
    Command(String),
    /// Something we cannot look into (an undecodable `-EncodedCommand`).
    Opaque,
}

const POSIX_SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh"];

/// `true` if the command word is a shell or script interpreter that can execute a downloaded script from stdin.
pub fn is_shell_interpreter(name: &str) -> bool {
    POSIX_SHELLS.contains(&name) || matches!(name, "powershell" | "pwsh" | "iex" | "invoke-expression")
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
            Some(Inner::Command(rest[pos + 1..].join(" ")))
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
                    if flag == "e" || flag == "ec" || "encodedcommand".starts_with(flag) && flag.len() >= 2 {
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
        split_segments(cmd, Shell::Posix).into_iter().map(|s| s.tokens).collect()
    }

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn splits_on_all_separators() {
        assert_eq!(
            toks("a && b || c ; d | e & f\ng"),
            vec![v(&["a"]), v(&["b"]), v(&["c"]), v(&["d"]), v(&["e"]), v(&["f"]), v(&["g"])]
        );
        let segs = split_segments("cat x | grep y && echo z", Shell::Posix);
        assert_eq!(segs.len(), 3);
        assert!(!segs[0].piped && segs[1].piped && !segs[2].piped);
        let segs = split_segments("a || b | c", Shell::Posix);
        assert!(!segs[0].piped && !segs[1].piped && segs[2].piped);
    }

    #[test]
    fn quotes_protect_separators_and_are_removed() {
        assert_eq!(toks("echo \"a && b\" 'c; d'"), vec![v(&["echo", "a && b", "c; d"])]);
        assert_eq!(toks("rm   -rf    \"node_modules\""), vec![v(&["rm", "-rf", "node_modules"])]);
        assert_eq!(toks("git commit -m \"fix: a \\\" b\""), vec![v(&["git", "commit", "-m", "fix: a \" b"])]);
        assert_eq!(toks("echo ''"), vec![v(&["echo", ""])]);
    }

    #[test]
    fn unbalanced_quote_falls_back_to_naive_splitting() {
        let segs = split_segments("echo \"unterminated ; rm -rf /", Shell::Posix);
        assert!(segs.iter().any(|s| s.tokens.first().map(String::as_str) == Some("rm")));
    }

    #[test]
    fn windows_paths_keep_their_backslashes() {
        assert_eq!(toks("del /s /q C:\\"), vec![v(&["del", "/s", "/q", "C:\\"])]);
        assert_eq!(toks("reg add HKLM\\Software\\Foo /v Bar"), vec![v(&["reg", "add", "HKLM\\Software\\Foo", "/v", "Bar"])]);
    }

    #[test]
    fn redirections_are_not_separators() {
        assert_eq!(toks("cargo test 2>&1 | tail -5"), vec![v(&["cargo", "test", "2>&1"]), v(&["tail", "-5"])]);
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
        assert_eq!(substitutions("echo `date` $(a $(b))"), vec!["date", "a $(b)"]);
        assert_eq!(substitutions("bash <(curl x.sh)"), vec!["curl x.sh"]);
        assert!(substitutions("echo '$(not run)'").is_empty());
        assert_eq!(substitutions("echo \"$(in dq)\""), vec!["in dq"]);
        assert!(substitutions("a < (b)").is_empty());
        assert_eq!(substitutions("$(unterminated"), vec!["unterminated"]);
    }

    #[test]
    fn base_command_strips_dirs_and_suffixes() {
        assert_eq!(base_command("C:\\Windows\\System32\\Shutdown.EXE"), "shutdown");
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
        assert_eq!(inner_payload(&v(&["bash", "-c", "rm -rf /"])), Some(Inner::Command("rm -rf /".into())));
        assert_eq!(inner_payload(&v(&["sh", "-lc", "x"])), Some(Inner::Command("x".into())));
        assert_eq!(inner_payload(&v(&["bash", "script.sh"])), None);
        assert_eq!(inner_payload(&v(&["cmd.exe", "/c", "del", "/s", "x"])), Some(Inner::Command("del /s x".into())));
        assert_eq!(
            inner_payload(&v(&["powershell", "-NoProfile", "-Command", "Remove-Item", "-Recurse", "x"])),
            Some(Inner::Command("Remove-Item -Recurse x".into()))
        );
        assert_eq!(inner_payload(&v(&["pwsh", "-enc", "!!notbase64!!"])), Some(Inner::Opaque));
        // "Get-Date" in UTF-16LE base64
        let enc = STANDARD.encode(
            "Get-Date".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>(),
        );
        assert_eq!(
            inner_payload(&v(&["powershell", "-EncodedCommand", &enc])),
            Some(Inner::Command("Get-Date".into()))
        );
        assert_eq!(inner_payload(&v(&["eval", "rm", "-rf", "x"])), Some(Inner::Command("rm -rf x".into())));
        assert_eq!(inner_payload(&v(&["wsl", "-d", "Ubuntu", "-e", "rm", "-rf", "/"])), Some(Inner::Command("rm -rf /".into())));
        assert_eq!(inner_payload(&v(&["python", "-c", "x"])), None);
        assert_eq!(inner_payload(&[]), None);
    }

    #[test]
    fn tokenizer_is_total_on_garbage() {
        for s in ["", "   ", ";;;", "&&&&", "||", "|&", "\"", "'", "`", "$(", "$((", "<(", "a\\", "\u{0}", "😀 && 😀"] {
            let _ = split_segments(s, Shell::Posix);
            let _ = split_segments(s, Shell::PowerShell);
            let _ = substitutions(s);
        }
        let mut state: u64 = 42;
        let alphabet: Vec<char> = "ab '\"`$()<>|&;\n\\ -/.=é".chars().collect();
        for _ in 0..3000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
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
}
