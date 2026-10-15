//! The daemon's file logger (docs/security.md 8.2): one `tracing` subscriber that writes plain text lines to a **daily
//! rolling file** in the data directory's `logs` folder (`agentnest.<date>.log`, the last 7 days kept) at the level of
//! the configuration (`info` by default).
//!
//! # Redacted formatting
//!
//! The daemon's own code only logs identifiers, lengths and error codes (security.md 8.2); on top of that **every line
//! passes through the shared masker** ([`crate::redact::mask`], long-token rule included) before it reaches the file, so a secret
//! that a future log statement or a dependency's message carries (`Authorization: Bearer ...`, `password=...`, a URL
//! with credentials) is replaced by `<redacted>`. Request bodies are never logged at any level.
//!
//! The file size is not capped per day (the appender rotates by date only); the 7-day window bounds the total.
//!
//! The desktop shell may install its own subscriber instead ([`crate::daemon::DaemonOptions::init_logging`] `= false`);
//! a process has one global subscriber, so [`init_file_logging`] reports [`LogError::AlreadyInstalled`] when there
//! already is one.

use std::io::{self, Write};
use std::path::Path;

use thiserror::Error;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::MakeWriter;

use crate::config::LogLevel;
use crate::redact::mask;

/// Files are `agentnest.<date>.log`.
pub const LOG_FILE_PREFIX: &str = "agentnest";
/// See [`LOG_FILE_PREFIX`].
pub const LOG_FILE_SUFFIX: &str = "log";
/// Daily files kept on disk.
pub const LOG_FILES_KEPT: usize = 7;

/// Errors of setting up logging.
#[derive(Debug, Error)]
pub enum LogError {
    /// The log directory or file could not be created.
    #[error("cannot create the log writer")]
    Writer,
    /// A global subscriber is already installed (the desktop shell's, or an earlier call).
    #[error("a global logger is already installed")]
    AlreadyInstalled,
}

/// Keeps the background writer alive; drop it only at process exit (it flushes the last lines).
pub struct LogGuard(#[allow(dead_code)] WorkerGuard);

impl std::fmt::Debug for LogGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogGuard")
    }
}

fn max_level(level: LogLevel) -> tracing::Level {
    match level {
        LogLevel::Error => tracing::Level::ERROR,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Debug => tracing::Level::DEBUG,
    }
}

/// A writer that masks every complete line before handing it on.
struct RedactingWriter<W: Write> {
    inner: W,
    pending: Vec<u8>,
}

impl<W: Write> RedactingWriter<W> {
    fn emit(&mut self, line: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(line);
        // the full masker, long-token rule included: device tokens are bare base64url without any prefix
        let masked = mask(&text);
        self.inner.write_all(masked.text.as_bytes())
    }

    fn drain_lines(&mut self, until_end: bool) -> io::Result<()> {
        while let Some(pos) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            self.emit(&line)?;
        }
        if until_end && !self.pending.is_empty() {
            let rest = std::mem::take(&mut self.pending);
            self.emit(&rest)?;
        }
        Ok(())
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(data);
        self.drain_lines(false)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain_lines(true)?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        // an event whose line did not end with a newline still gets masked and written
        let _ = self.drain_lines(true);
    }
}

#[derive(Clone)]
struct RedactingMakeWriter {
    inner: NonBlocking,
}

impl<'a> MakeWriter<'a> for RedactingMakeWriter {
    type Writer = RedactingWriter<NonBlocking>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.clone(),
            pending: Vec::new(),
        }
    }
}

/// The subscriber that writes to `logs_dir` (not yet installed; tests use it with `with_default`).
pub fn build_file_subscriber(
    logs_dir: &Path,
    level: LogLevel,
) -> Result<(impl tracing::Subscriber + Send + Sync + 'static, LogGuard), LogError> {
    std::fs::create_dir_all(logs_dir).map_err(|_| LogError::Writer)?;
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(LOG_FILE_PREFIX)
        .filename_suffix(LOG_FILE_SUFFIX)
        .max_log_files(LOG_FILES_KEPT)
        .build(logs_dir)
        .map_err(|_| LogError::Writer)?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(RedactingMakeWriter { inner: writer })
        .with_ansi(false)
        .with_max_level(max_level(level))
        .finish();
    Ok((subscriber, LogGuard(guard)))
}

/// Installs the file logger as the process-wide `tracing` subscriber. Keep the returned guard alive for the life of the
/// process.
pub fn init_file_logging(logs_dir: &Path, level: LogLevel) -> Result<LogGuard, LogError> {
    let (subscriber, guard) = build_file_subscriber(logs_dir, level)?;
    tracing::subscriber::set_global_default(subscriber).map_err(|_| LogError::AlreadyInstalled)?;
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_logs(dir: &Path) -> String {
        let mut all = String::new();
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with(LOG_FILE_PREFIX) && name.ends_with(LOG_FILE_SUFFIX) {
                all.push_str(&std::fs::read_to_string(e.path()).unwrap());
            }
        }
        all
    }

    #[test]
    fn the_file_logger_writes_a_dated_file_at_the_configured_level_and_masks_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let (subscriber, guard) = build_file_subscriber(dir.path(), LogLevel::Info).unwrap();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(request_id = "ar_1", "approval request opened");
            tracing::debug!("a debug line below the level");
            tracing::warn!(
                "login password=hunter2hunter2 and Authorization: Bearer abcdefgh12345678"
            );
            tracing::error!(
                url = "https://user:s3cr3tpw@example.com/x?token=ZZZ",
                "request failed"
            );
        });
        drop(guard); // flush
        let text = read_logs(dir.path());
        assert!(
            text.contains("approval request opened") && text.contains("request_id"),
            "{text}"
        );
        assert!(
            !text.contains("below the level"),
            "the level is honoured: {text}"
        );
        for secret in ["hunter2hunter2", "abcdefgh12345678", "s3cr3tpw", "ZZZ"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert!(text.contains("<redacted>"));
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        // agentnest.2026-10-15.log
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("agentnest.") && n.ends_with(".log") && n.len() > 15),
            "{names:?}"
        );
    }

    #[test]
    fn a_line_split_over_several_writes_is_masked_as_a_whole() {
        let mut out = Vec::new();
        {
            let mut w = RedactingWriter {
                inner: &mut out,
                pending: Vec::new(),
            };
            w.write_all(b"token=abc").unwrap();
            w.write_all(b"def123456 tail\nnext line").unwrap();
        } // drop flushes the unterminated rest
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("abcdef123456"), "{text}");
        assert!(text.contains("next line"));
    }
}
