//! Path helpers for Windows and POSIX paths (security-relevant: the risk classifier and the project resolver both rely
//! on them). Everything here is purely lexical (no file system access, no symlink resolution) and total: no input can
//! make a function panic.
//!
//! Conventions: *normalised* paths use `/` only, have no `.`/`..`/empty segments and no trailing `/` (except a bare
//! root). Case is preserved; comparisons are case-insensitive only when a Windows-style path is involved.

/// `true` if `p` looks like a Windows path (drive letter, UNC prefix or a backslash).
pub fn is_windows_style(p: &str) -> bool {
    has_drive(p) || p.contains('\\') || p.starts_with("//")
}

fn has_drive(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Normalises separators and `.`/`..` segments. See the module docs for the output shape.
///
/// * `C:\dev\..\x\` -> `C:/x`
/// * `\\?\C:\x` -> `C:/x` (extended-length prefix removed)
/// * `/a//b/./c` -> `/a/b/c`
/// * `~/a/../b` -> `~/b`
/// * `../a` (relative) stays `../a`
pub fn normalize(p: &str) -> String {
    let mut s = p.replace('\\', "/");
    for prefix in ["//?/", "//./"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_owned();
            break;
        }
    }
    // prefix detection
    let (prefix, rest): (String, &str) = if has_drive(&s) {
        let drive: String = s[..2].to_owned();
        let rest = &s[2..];
        if rest.starts_with('/') {
            (format!("{drive}/"), rest)
        } else {
            (drive, rest) // drive-relative, e.g. `C:foo`
        }
    } else if let Some(rest) = s.strip_prefix("//") {
        ("//".to_owned(), rest)
    } else if let Some(rest) = s.strip_prefix('/') {
        ("/".to_owned(), rest)
    } else if s == "~" || s.starts_with("~/") {
        ("~/".to_owned(), s[1..].trim_start_matches('/'))
    } else {
        (String::new(), s.as_str())
    };
    let absolute = !prefix.is_empty();
    let mut stack: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if matches!(stack.last(), Some(last) if *last != "..") {
                    stack.pop();
                } else if !absolute {
                    stack.push("..");
                }
                // `..` above an absolute root is dropped
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    if absolute {
        if joined.is_empty() {
            // bare root: `/`, `c:/`, `~`, `//`
            return match prefix.as_str() {
                "~/" => "~".to_owned(),
                other => other.to_owned(),
            };
        }
        let mut out = prefix;
        out.push_str(&joined);
        out
    } else if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// `true` if the (normalised) path is absolute: POSIX root, drive root, UNC or home (`~`).
pub fn is_absolute(normalized: &str) -> bool {
    normalized.starts_with('/')
        || normalized.starts_with('~')
        || (has_drive(normalized) && normalized[2..].starts_with('/'))
}

/// Replaces the shell spellings of the home directory (`$HOME`, `${HOME}`, `%USERPROFILE%`, `$env:USERPROFILE`, ...)
/// at the start of `p` with `~`.
pub fn expand_home_alias(p: &str) -> String {
    let lower = p.to_ascii_lowercase();
    for alias in [
        "$env:userprofile",
        "$env:home",
        "${home}",
        "$home",
        "%userprofile%",
        "%homepath%",
        "%home%",
    ] {
        if lower.starts_with(alias) {
            let rest = &p[alias.len()..];
            if rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\') {
                return format!("~{rest}");
            }
        }
    }
    p.to_owned()
}

/// Resolves `path` against `cwd` and normalises it. Home aliases become `~`. Relative paths without a `cwd` stay
/// relative.
pub fn resolve(path: &str, cwd: Option<&str>) -> String {
    let expanded = expand_home_alias(path);
    let n = normalize(&expanded);
    if is_absolute(&n) {
        return n;
    }
    match cwd {
        Some(c) if !c.is_empty() => {
            normalize(&format!("{}/{}", normalize(&expand_home_alias(c)), n))
        }
        _ => n,
    }
}

/// `true` if the normalised `path` equals `root` or lies below it. Case-insensitive when either path is Windows style.
pub fn is_within(path: &str, root: &str) -> bool {
    let (p, r) = if is_windows_style(path) || is_windows_style(root) {
        (path.to_lowercase(), root.to_lowercase())
    } else {
        (path.to_owned(), root.to_owned())
    };
    if r.is_empty() || r == "." {
        return !is_absolute(&p);
    }
    if p == r {
        return true;
    }
    let boundary = if r.ends_with('/') { r } else { format!("{r}/") };
    p.starts_with(&boundary)
}

/// The path relative to `root` (`/` separators), or `None` if `path` is not below `root`. Both must be normalised.
pub fn relative_to(path: &str, root: &str) -> Option<String> {
    if !is_within(path, root) {
        return None;
    }
    let rest = path.get(root.len()..)?.trim_start_matches('/');
    Some(if rest.is_empty() {
        ".".to_owned()
    } else {
        rest.to_owned()
    })
}

/// The last path segment (after the last `/` or `\`). Empty for empty input or a trailing separator-only path.
pub fn basename(p: &str) -> &str {
    let trimmed = p.trim_end_matches(['/', '\\']);
    match trimmed.rfind(['/', '\\']) {
        Some(i) => &trimmed[i + 1..],
        None => trimmed,
    }
}

/// The non-empty segments of a normalised path, without drive letter or UNC marker.
pub fn segments(normalized: &str) -> Vec<&str> {
    normalized
        .split('/')
        .filter(|s| !s.is_empty() && !(s.len() == 2 && has_drive(s) && s.ends_with(':')))
        .collect()
}

/// The last `n` segments of `p` (any style), in order.
pub fn last_segments(p: &str, n: usize) -> Vec<String> {
    let norm = normalize(p);
    let segs = segments(&norm);
    let start = segs.len().saturating_sub(n);
    segs[start..].iter().map(|s| (*s).to_owned()).collect()
}

/// `…\dev\agentnest` / `…/me/proj`: the last two segments behind an ellipsis, using the separator style of the input
/// (protocol.md 5.1 `path_hint`; the full path never leaves the PC).
pub fn path_hint(p: &str) -> String {
    let sep = if is_windows_style(p) { '\\' } else { '/' };
    let segs = last_segments(p, 2);
    let mut out = String::from("…");
    for s in segs {
        out.push(sep);
        out.push_str(&s);
    }
    out
}

/// The project key: normalised, lower-case, `/` separators (protocol.md 5.1).
pub fn project_key(p: &str) -> String {
    normalize(p).to_lowercase()
}

/// The lower-cased extension of the basename (without the dot), or `""`.
pub fn extension(p: &str) -> String {
    let b = basename(p).to_lowercase();
    match b.rfind('.') {
        Some(i) if i > 0 => b[i + 1..].to_owned(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_handles_both_styles() {
        assert_eq!(normalize("C:\\dev\\..\\x\\"), "C:/x");
        assert_eq!(normalize("c:/dev//agentnest/./src"), "c:/dev/agentnest/src");
        assert_eq!(normalize("\\\\?\\C:\\x"), "C:/x");
        assert_eq!(normalize("/a//b/./c/"), "/a/b/c");
        assert_eq!(normalize("/"), "/");
        assert_eq!(normalize("C:\\"), "C:/");
        assert_eq!(normalize("C:"), "C:");
        assert_eq!(normalize("~/a/../b"), "~/b");
        assert_eq!(normalize("~"), "~");
        assert_eq!(normalize("../a"), "../a");
        assert_eq!(normalize("a/../.."), "..");
        assert_eq!(normalize("/../.."), "/");
        assert_eq!(normalize("C:\\..\\.."), "C:/");
        assert_eq!(normalize(""), ".");
        assert_eq!(normalize("//server/share/x"), "//server/share/x");
    }

    #[test]
    fn resolve_and_containment() {
        let cwd = "C:\\dev\\agentnest";
        assert_eq!(
            resolve("src\\main.rs", Some(cwd)),
            "C:/dev/agentnest/src/main.rs"
        );
        assert_eq!(
            resolve("C:\\dev\\agentnest\\..\\other\\a", Some(cwd)),
            "C:/dev/other/a"
        );
        assert_eq!(resolve("$HOME/.ssh/id_rsa", Some(cwd)), "~/.ssh/id_rsa");
        assert_eq!(resolve("%USERPROFILE%\\x", Some(cwd)), "~/x");
        assert_eq!(resolve("$env:USERPROFILE", None), "~");
        assert_eq!(resolve("rel/x", None), "rel/x");
        let root = normalize(cwd);
        assert!(
            is_within("c:/DEV/agentnest/src", &root),
            "windows paths compare case-insensitively"
        );
        assert!(is_within(&root, &root));
        assert!(
            !is_within("C:/dev/agentnest2/x", &root),
            "prefix without a separator boundary is outside"
        );
        assert!(!is_within("C:/dev/other", &root));
        assert!(
            !is_within("/Home/me/Proj/x", "/home/me/proj"),
            "posix paths are case-sensitive"
        );
        assert!(is_within("/home/me/proj/x", "/home/me/proj"));
        assert!(is_within("/anything", "/"));
        assert_eq!(
            relative_to("C:/dev/agentnest/src/main.rs", "C:/dev/agentnest").as_deref(),
            Some("src/main.rs")
        );
        assert_eq!(
            relative_to("C:/DEV/agentnest/src/main.rs", "c:/dev/agentnest").as_deref(),
            Some("src/main.rs")
        );
        assert_eq!(relative_to("D:/x", "C:/dev"), None);
        assert_eq!(relative_to("/a", "/a").as_deref(), Some("."));
    }

    #[test]
    fn names_and_hints() {
        assert_eq!(basename("C:\\dev\\agentnest\\src\\main.rs"), "main.rs");
        assert_eq!(basename("/a/b/"), "b");
        assert_eq!(basename(""), "");
        assert_eq!(
            last_segments("C:\\dev\\agentnest", 2),
            vec!["dev", "agentnest"]
        );
        assert_eq!(last_segments("/a", 2), vec!["a"]);
        assert_eq!(path_hint("C:\\dev\\agentnest"), "…\\dev\\agentnest");
        assert_eq!(path_hint("/home/me/proj"), "…/me/proj");
        assert_eq!(path_hint("C:\\"), "…");
        assert_eq!(project_key("C:\\Dev\\AgentNest\\"), "c:/dev/agentnest");
        assert_eq!(extension("a/b/Server.PEM"), "pem");
        assert_eq!(extension(".env"), "");
        assert_eq!(extension("noext"), "");
    }

    #[test]
    fn weird_input_never_panics() {
        let samples = [
            "",
            " ",
            "\0",
            "\\",
            "/",
            "//",
            "///",
            "\\\\",
            "\\\\?\\",
            "C:",
            "C:\\",
            "C:foo",
            ":",
            "~",
            "~~",
            "~user/x",
            "..",
            "../..",
            "a/../../..",
            "/../../x",
            "C:\\..\\..\\..",
            "😀/😀\\😀",
            "a\u{202e}b",
            "%userprofile%",
            "$HOME",
            "${HOME}",
            "\\\\server",
            "\\\\server\\share",
            "//?/",
            "//./pipe/x",
            "a//",
            "./",
            "x:y:z",
        ];
        for s in samples {
            let n = normalize(s);
            let _ = resolve(s, Some("C:\\dev\\x"));
            let _ = resolve(s, Some(s));
            let _ = is_within(&n, &normalize(s));
            let _ = relative_to(&n, "/");
            let _ = basename(s);
            let _ = last_segments(s, 2);
            let _ = path_hint(s);
            let _ = project_key(s);
            let _ = extension(s);
            let _ = segments(&n);
            let _ = is_absolute(&n);
            assert_eq!(
                normalize(&n),
                n,
                "normalisation must be idempotent for {s:?}"
            );
        }
    }

    #[test]
    fn pseudo_random_input_never_panics_and_is_idempotent() {
        // Deterministic LCG, no external crates.
        let alphabet: Vec<char> = "ab/\\.:~%$ \u{0}é가😀-_".chars().collect();
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..3000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 60) as usize + 1;
            let mut s = String::new();
            let mut st = state;
            for _ in 0..len {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                s.push(alphabet[((st >> 33) as usize) % alphabet.len()]);
            }
            let n = normalize(&s);
            assert_eq!(normalize(&n), n, "not idempotent for {s:?}");
            let _ = resolve(&s, Some("/home/x"));
            let _ = path_hint(&s);
            let _ = is_within(&n, "/");
        }
    }
}
