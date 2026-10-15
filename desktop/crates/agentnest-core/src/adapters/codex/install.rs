//! Codex hooks configuration (docs/integrations/codex.md 5.1) and the manual installation text.
//!
//! **UNVERIFIED (Phase 0 C6).** The top-level structure of `~/.codex/hooks.json`, the matcher field names, the
//! `commandWindows` selection rule, the `/hooks` trust procedure and what an empty `PermissionRequest` answer does are
//! all unverified. So this module only **renders the draft** (the desktop shows it with a copy button and the manual
//! steps; the user writes the file and trusts it in the Codex TUI). Writing `hooks.json` from the daemon exists only in
//! builds with the `codex-hooks-approval` feature (which is also what enables a hooks `PermissionRequest` hold), and even
//! then it refuses to overwrite an existing file.

use std::path::Path;

use serde_json::{json, Value};

/// Hook events of the draft and their timeouts in seconds (`PermissionRequest` = TTL + 30).
const EVENTS: [(&str, u32); 8] = [
    ("SessionStart", 5),
    ("UserPromptSubmit", 5),
    ("PreToolUse", 5),
    ("PermissionRequest", 0),
    ("PostToolUse", 5),
    ("Stop", 5),
    ("Interrupt", 2),
    ("SessionEnd", 3),
];

/// The draft `hooks.json` content. `hook_cli` is `agentnest-hook` (or its full path), `hook_cli_windows` the `.exe` form.
/// UNVERIFIED (Phase 0 C6): top-level `hooks` key, `matcher`, `commandWindows`.
pub fn hooks_json_draft(hook_cli: &str, hook_cli_windows: &str, approval_ttl_s: u32) -> Value {
    let mut hooks = serde_json::Map::new();
    for (event, timeout) in EVENTS {
        let timeout = if event == "PermissionRequest" {
            approval_ttl_s + 30
        } else {
            timeout
        };
        hooks.insert(
            event.to_owned(),
            json!([{
                "matcher": "",
                "hooks": [{
                    "type": "command",
                    "command": format!("{hook_cli} codex"),
                    "commandWindows": format!("{hook_cli_windows} codex"),
                    "timeout": timeout,
                }]
            }]),
        );
    }
    json!({ "hooks": Value::Object(hooks) })
}

/// The manual onboarding steps shown on the desktop until C6 is verified (docs/desktop.md 6.1 item 4).
pub fn manual_steps_ko() -> Vec<&'static str> {
    vec![
        "아래 hooks.json 초안을 복사해 %USERPROFILE%\\.codex\\hooks.json 에 저장하세요. (최상위 구조는 Phase 0 C6 확인 전의 초안이에요)",
        "Codex 에서 /hooks 를 열어 AgentNest 항목을 신뢰(trust)하세요. 신뢰하지 않은 훅은 실행되지 않아요.",
        "터미널에서 `agentnest-hook doctor` 로 데몬 도달성과 토큰을 점검하세요.",
        "Codex 에서 명령을 하나 실행해 첫 이벤트가 오는지 확인하세요.",
        "Codex 승인: 관찰만 (C6 확인 전) · 리뷰 결과: 수집 불가 (hooks 모드)",
    ]
}

/// Writes the draft to `path` **only if no file exists there**. UNVERIFIED (Phase 0 C6): only in builds with the
/// `codex-hooks-approval` feature.
#[cfg(feature = "codex-hooks-approval")]
pub fn install_draft(
    path: &Path,
    hook_cli: &str,
    hook_cli_windows: &str,
    approval_ttl_s: u32,
) -> std::io::Result<()> {
    if path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "hooks.json already exists; merge by hand",
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(&hooks_json_draft(
        hook_cli,
        hook_cli_windows,
        approval_ttl_s,
    ))
    .map_err(std::io::Error::other)?;
    std::fs::write(path, text)
}

/// Without the feature the daemon never writes `hooks.json`; this keeps the signature for callers.
#[cfg(not(feature = "codex-hooks-approval"))]
pub fn install_draft(
    _path: &Path,
    _hook_cli: &str,
    _hook_cli_windows: &str,
    _approval_ttl_s: u32,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Codex hooks installation is disabled until Phase 0 C6 (build feature codex-hooks-approval)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_draft_follows_codex_md_5_1() {
        let v = hooks_json_draft("agentnest-hook", "agentnest-hook.exe", 120);
        let hooks = v["hooks"].as_object().unwrap();
        assert_eq!(hooks.len(), 8);
        for event in [
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PermissionRequest",
            "PostToolUse",
            "Stop",
            "Interrupt",
            "SessionEnd",
        ] {
            let h = &hooks[event][0]["hooks"][0];
            assert_eq!(hooks[event][0]["matcher"], "");
            assert_eq!(h["type"], "command");
            assert_eq!(h["command"], "agentnest-hook codex");
            assert_eq!(h["commandWindows"], "agentnest-hook.exe codex");
        }
        assert_eq!(hooks["PermissionRequest"][0]["hooks"][0]["timeout"], 150);
        assert_eq!(hooks["SessionEnd"][0]["hooks"][0]["timeout"], 3);
        assert_eq!(hooks["Interrupt"][0]["hooks"][0]["timeout"], 2);
        // there is no http hook type for Codex and no onFailure / interrupt anywhere
        let text = v.to_string();
        for forbidden in [
            "\"http\"",
            "onFailure",
            "interrupt\":",
            "updatedInput",
            "updatedPermissions",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn manual_steps_mention_the_trust_step_and_the_observe_only_state() {
        let steps = manual_steps_ko().join("\n");
        assert!(steps.contains("/hooks"));
        assert!(steps.contains("관찰만"));
        assert!(steps.contains("doctor"));
    }

    #[cfg(not(feature = "codex-hooks-approval"))]
    #[test]
    fn the_installer_is_disabled_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        let r = install_draft(&path, "agentnest-hook", "agentnest-hook.exe", 120);
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::Unsupported);
        assert!(!path.exists());
    }

    #[cfg(feature = "codex-hooks-approval")]
    #[test]
    fn the_installer_never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        install_draft(&path, "agentnest-hook", "agentnest-hook.exe", 120).unwrap();
        assert!(install_draft(&path, "agentnest-hook", "agentnest-hook.exe", 120).is_err());
    }
}
