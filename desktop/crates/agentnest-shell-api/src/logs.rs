//! Log files of the desktop app: the rolling file writer and `logs_tail(limit)` (docs/desktop.md 3.1).
//!
//! Logging hygiene (security.md 8): the daemon's code never logs tokens, nonces or command lines; on top of that every
//! line the UI gets from [`tail_log_lines`] is masked again with the shared redactor and bounded, so a line written by
//! a future bug still does not carry a secret into the webview.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use agentnest_core::config::LogLevel;
use agentnest_core::logging::RedactingMakeWriter;
use agentnest_core::redact::{clip, mask};
use regex::Regex;
use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

/// Files are `agentnest.<date>.log`.
pub const LOG_FILE_PREFIX: &str = "agentnest";
/// See above.
pub const LOG_FILE_SUFFIX: &str = "log";
/// Daily files kept on disk (the same window as the daemon's logger: docs/security.md 8.2, docs/storage.md 3).
pub const LOG_FILES_KEPT: usize = agentnest_core::logging::LOG_FILES_KEPT;
/// Most lines `logs_tail` returns.
pub const TAIL_MAX_LINES: usize = 1000;
/// One line is cut to this many characters.
pub const LINE_MAX_CHARS: usize = 600;
/// Bytes read from the end of one file.
const READ_WINDOW_BYTES: u64 = 512 * 1024;

/// Errors of setting up logging.
#[derive(Debug, Error)]
pub enum LogInitError {
    /// The log directory or file could not be created.
    #[error("cannot create the log writer")]
    Writer,
    /// A global subscriber is already installed.
    #[error("a global logger is already installed")]
    AlreadyInstalled,
}

/// Keeps the background writer alive; drop it only at process exit (it flushes the last lines).
pub struct LogGuard(#[allow(dead_code)] WorkerGuard);

fn max_level(level: LogLevel) -> tracing::Level {
    match level {
        LogLevel::Error => tracing::Level::ERROR,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Debug => tracing::Level::DEBUG,
    }
}

/// A subscriber that writes plain text lines to the daily rolling file in `logs_dir`. Every line is masked with the
/// shared redactor before it is written (security.md 8.2), exactly like the daemon's own file logger.
pub fn build_file_subscriber(
    logs_dir: &Path,
    level: LogLevel,
) -> Result<
    (
        impl tracing::Subscriber + Send + Sync + 'static,
        WorkerGuard,
    ),
    LogInitError,
> {
    fs::create_dir_all(logs_dir).map_err(|_| LogInitError::Writer)?;
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(LOG_FILE_PREFIX)
        .filename_suffix(LOG_FILE_SUFFIX)
        .max_log_files(LOG_FILES_KEPT)
        .build(logs_dir)
        .map_err(|_| LogInitError::Writer)?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(RedactingMakeWriter::new(writer))
        .with_ansi(false)
        .with_max_level(max_level(level))
        .finish();
    Ok((subscriber, guard))
}

/// Installs the file logger as the process-wide `tracing` subscriber and bridges `log` records (the
/// `tauri-plugin-log` webview console forwarding) into it. Call once at start-up.
pub fn init_global_logging(logs_dir: &Path, level: LogLevel) -> Result<LogGuard, LogInitError> {
    let (subscriber, guard) = build_file_subscriber(logs_dir, level)?;
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| LogInitError::AlreadyInstalled)?;
    // The `log` bridge is best effort: another `log` logger may already be installed.
    let _ = tracing_log::LogTracer::init();
    Ok(LogGuard(guard))
}

fn log_files_newest_first(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.starts_with(&format!("{LOG_FILE_PREFIX}."))
                    && n.ends_with(&format!(".{LOG_FILE_SUFFIX}"))
            })
        })
        .collect();
    // the date is part of the name, so the lexicographic order is the chronological one
    files.sort();
    files.reverse();
    Ok(files)
}

fn read_tail_lines(path: &Path, max_lines: usize) -> io::Result<Vec<String>> {
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(READ_WINDOW_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(READ_WINDOW_BYTES).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !lines.is_empty() {
        // the window began in the middle of a line
        lines.remove(0);
    }
    let skip = lines.len().saturating_sub(max_lines);
    Ok(lines[skip..].iter().map(|l| (*l).to_owned()).collect())
}

/// `Authorization: Bearer <token>` and `Bearer <token>` / `Basic <token>`: the shared redactor masks `Authorization:`
/// but would leave the token after the scheme word, so the log view masks the whole header value itself.
fn auth_header_pattern() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(authorization\s*[:=]\s*)?\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}|authorization\s*[:=]\s*\S+")
            .ok()
    })
    .as_ref()
}

/// Masks and bounds one log line for display.
pub fn sanitize_line(line: &str) -> String {
    let cleaned: String = line
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect();
    let cleaned = match auth_header_pattern() {
        Some(re) => re.replace_all(&cleaned, "<redacted>").into_owned(),
        None => cleaned,
    };
    clip(&mask(&cleaned).text, LINE_MAX_CHARS)
}

/// The last `limit` log lines (oldest first, redacted). `limit` is clamped to `1..=1000`. A missing log directory
/// yields an empty list.
pub fn tail_log_lines(logs_dir: &Path, limit: usize) -> io::Result<Vec<String>> {
    let limit = limit.clamp(1, TAIL_MAX_LINES);
    let files = match log_files_newest_first(logs_dir) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut collected: Vec<String> = Vec::new();
    for file in files {
        let need = limit - collected.len();
        let mut lines = read_tail_lines(&file, need)?;
        // older file's lines go in front of what was collected from newer files
        lines.append(&mut collected);
        collected = lines;
        if collected.len() >= limit {
            break;
        }
    }
    let skip = collected.len().saturating_sub(limit);
    Ok(collected[skip..].iter().map(|l| sanitize_line(l)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, lines: &[String]) {
        fs::write(dir.join(name), lines.join("\n") + "\n").unwrap();
    }

    fn numbered(prefix: &str, n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{prefix} line {i}")).collect()
    }

    #[test]
    fn tail_returns_the_last_lines_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "agentnest.2026-10-15.log", &numbered("a", 300));
        let t = tail_log_lines(dir.path(), 200).unwrap();
        assert_eq!(t.len(), 200);
        assert_eq!(t[0], "a line 100");
        assert_eq!(t[199], "a line 299");
    }

    #[test]
    fn tail_spans_files_newest_last() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "agentnest.2026-10-14.log", &numbered("old", 10));
        write(dir.path(), "agentnest.2026-10-15.log", &numbered("new", 3));
        write(dir.path(), "unrelated.txt", &["x".to_owned()]);
        let t = tail_log_lines(dir.path(), 5).unwrap();
        assert_eq!(
            t,
            vec![
                "old line 8",
                "old line 9",
                "new line 0",
                "new line 1",
                "new line 2"
            ]
        );
    }

    #[test]
    fn tail_masks_secrets_and_bounds_lines() {
        let dir = tempfile::tempdir().unwrap();
        let long = format!("INFO {}", "x".repeat(2000));
        write(
            dir.path(),
            "agentnest.2026-10-15.log",
            &[
                "INFO hook token=abcdef0123456789abcdef0123456789 accepted".to_owned(),
                "WARN Authorization: Bearer abc.def.ghi".to_owned(),
                long,
                "ctl\u{1b}[31mred\u{1b}[0m".to_owned(),
            ],
        );
        let t = tail_log_lines(dir.path(), 10).unwrap();
        assert!(!t[0].contains("abcdef0123456789"), "{}", t[0]);
        assert!(t[0].contains("<redacted>"));
        assert!(!t[1].contains("abc.def.ghi"), "{}", t[1]);
        assert!(t[2].chars().count() <= LINE_MAX_CHARS);
        assert!(!t[3].contains('\u{1b}'));
    }

    #[test]
    fn missing_directory_and_empty_directory_are_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(tail_log_lines(&dir.path().join("nope"), 10)
            .unwrap()
            .is_empty());
        assert!(tail_log_lines(dir.path(), 10).unwrap().is_empty());
    }

    #[test]
    fn a_huge_file_is_read_from_its_end_only() {
        let dir = tempfile::tempdir().unwrap();
        let lines: Vec<String> = (0..60_000)
            .map(|i| format!("INFO filler line number {i} ........................"))
            .collect();
        write(dir.path(), "agentnest.2026-10-15.log", &lines);
        let t = tail_log_lines(dir.path(), 3).unwrap();
        assert_eq!(t.len(), 3);
        assert!(t[2].contains("number 59999"));
        // the first returned line is complete (no half line from the window start)
        assert!(t[0].starts_with("INFO filler line number"));
    }

    #[test]
    fn limit_is_clamped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "agentnest.2026-10-15.log", &numbered("a", 5));
        assert_eq!(tail_log_lines(dir.path(), 0).unwrap().len(), 1);
        assert_eq!(tail_log_lines(dir.path(), 1_000_000).unwrap().len(), 5);
    }

    #[test]
    fn the_file_subscriber_writes_lines_that_tail_can_read() {
        let dir = tempfile::tempdir().unwrap();
        let (subscriber, guard) = build_file_subscriber(dir.path(), LogLevel::Info).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("hello from the shell");
            tracing::debug!("not at info level");
            tracing::warn!(attempt = 3, "something odd");
        });
        drop(guard); // flush
        let t = tail_log_lines(dir.path(), 10).unwrap();
        assert!(
            t.iter().any(|l| l.contains("hello from the shell")),
            "{t:?}"
        );
        assert!(t
            .iter()
            .any(|l| l.contains("something odd") && l.contains("attempt=3")));
        assert!(!t.iter().any(|l| l.contains("not at info level")));
    }

    #[test]
    fn the_log_file_itself_never_holds_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let (subscriber, guard) = build_file_subscriber(dir.path(), LogLevel::Info).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("request with Authorization: Bearer fakeBearerValue123456 failed");
            tracing::error!(
                url = "https://someuser:fakeUrlPassw0rd@example.com/x",
                "fetch failed"
            );
            tracing::info!("login password=fakePasswordValue99 accepted");
        });
        drop(guard); // flush
        let mut raw = String::new();
        for e in fs::read_dir(dir.path()).unwrap().flatten() {
            raw.push_str(&fs::read_to_string(e.path()).unwrap());
        }
        for secret in [
            "fakeBearerValue123456",
            "fakeUrlPassw0rd",
            "fakePasswordValue99",
        ] {
            assert!(!raw.contains(secret), "{secret} reached the file: {raw}");
        }
        assert!(raw.contains("<redacted>"), "{raw}");
        assert!(raw.contains("fetch failed"), "{raw}");
    }

    #[test]
    fn seven_daily_files_are_kept() {
        assert_eq!(LOG_FILES_KEPT, 7);
    }

    #[test]
    fn debug_level_includes_debug_lines() {
        let dir = tempfile::tempdir().unwrap();
        let (subscriber, guard) = build_file_subscriber(dir.path(), LogLevel::Debug).unwrap();
        tracing::subscriber::with_default(subscriber, || tracing::debug!("fine detail"));
        drop(guard);
        assert!(tail_log_lines(dir.path(), 10)
            .unwrap()
            .iter()
            .any(|l| l.contains("fine detail")));
    }
}
