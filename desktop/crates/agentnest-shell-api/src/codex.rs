//! `codex_probe`: a Phase 0 diagnostic for the Codex shared control socket (docs/integrations/codex.md 3, 4).
//!
//! What is checked: the **documented path** `$CODEX_HOME/app-server-control/app-server-control.sock` (default
//! `~/.codex`) [verified in the Codex source] and whether a file system entry exists there. Nothing is sent to the
//! socket. The JSON-RPC `initialize` handshake that would yield `userAgent` and the thread count is
//! `// UNVERIFIED (Phase 0)` (codex.md C1: on Windows the socket kind itself is unconfirmed), lives behind the core's
//! `codex-daemon-observer` feature and is therefore **not** performed here: `user_agent` is always `null` and
//! `threads` is `0` until C1 passes.

use std::path::{Path, PathBuf};

use crate::dto::CodexProbeDto;

/// Relative path of the control socket below the Codex home.
pub const SOCKET_RELATIVE: [&str; 2] = ["app-server-control", "app-server-control.sock"];

/// `$CODEX_HOME` if set and non-empty, else `<home>/.codex`.
pub fn codex_home(env_codex_home: Option<&Path>, home_dir: Option<&Path>) -> Option<PathBuf> {
    match env_codex_home {
        Some(p) if !p.as_os_str().is_empty() => Some(p.to_path_buf()),
        _ => home_dir.map(|h| h.join(".codex")),
    }
}

/// The control socket path below `codex_home`.
pub fn socket_path(codex_home: &Path) -> PathBuf {
    codex_home.join(SOCKET_RELATIVE[0]).join(SOCKET_RELATIVE[1])
}

/// Builds the probe result; `exists` decides whether the socket entry is there.
pub fn probe(codex_home: Option<&Path>, exists: impl Fn(&Path) -> bool) -> CodexProbeDto {
    match codex_home {
        None => CodexProbeDto {
            socket_path: None,
            reachable: false,
            user_agent: None,
            threads: 0,
        },
        Some(home) => {
            let path = socket_path(home);
            let reachable = exists(&path);
            CodexProbeDto {
                socket_path: Some(path.to_string_lossy().into_owned()),
                reachable,
                user_agent: None,
                threads: 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_home_prefers_the_environment_variable() {
        let home = Path::new("/home/kim");
        assert_eq!(
            codex_home(Some(Path::new("/opt/codex")), Some(home)),
            Some(PathBuf::from("/opt/codex"))
        );
        assert_eq!(
            codex_home(None, Some(home)),
            Some(PathBuf::from("/home/kim/.codex"))
        );
        assert_eq!(
            codex_home(Some(Path::new("")), Some(home)),
            Some(PathBuf::from("/home/kim/.codex"))
        );
        assert_eq!(codex_home(None, None), None);
    }

    #[test]
    fn the_socket_path_is_the_documented_one() {
        let p = socket_path(Path::new("/h/.codex"));
        assert!(p.ends_with("app-server-control/app-server-control.sock"));
    }

    #[test]
    fn probe_reports_existence_only() {
        let r = probe(Some(Path::new("/h/.codex")), |_| true);
        assert!(r.reachable);
        assert_eq!(r.user_agent, None);
        assert_eq!(r.threads, 0);
        assert!(r.socket_path.unwrap().contains("app-server-control.sock"));
        let r = probe(Some(Path::new("/h/.codex")), |_| false);
        assert!(!r.reachable);
        assert!(r.socket_path.is_some());
        let r = probe(None, |_| true);
        assert_eq!(r.socket_path, None);
        assert!(!r.reachable);
    }

    #[test]
    fn probe_against_the_real_file_system() {
        let dir = tempfile::tempdir().unwrap();
        let sock_dir = dir.path().join("app-server-control");
        std::fs::create_dir_all(&sock_dir).unwrap();
        assert!(!probe(Some(dir.path()), |p| p.exists()).reachable);
        std::fs::write(sock_dir.join("app-server-control.sock"), b"").unwrap();
        assert!(probe(Some(dir.path()), |p| p.exists()).reachable);
    }
}
