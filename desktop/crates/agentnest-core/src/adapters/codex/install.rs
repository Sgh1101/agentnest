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

/// The program of a hook command line: a bare name stays as it is, a path (the installed sidecar lives next to the app
/// executable and is **not** on `PATH`) is wrapped in double quotes so that spaces in the path survive.
/// UNVERIFIED (Phase 0 C6): how Codex splits `command` / `commandWindows`.
pub fn quote_program(program: &str) -> String {
    let is_path = program.contains(['\\', '/', ' ', '\t']);
    if is_path {
        format!("\"{}\"", program.replace('"', "\\\""))
    } else {
        program.to_owned()
    }
}

/// The Windows form of the hook program: the same path, or the bare name with `.exe`.
pub fn windows_program(hook_cli: &str) -> String {
    if hook_cli.to_ascii_lowercase().ends_with(".exe") {
        hook_cli.to_owned()
    } else {
        format!("{hook_cli}.exe")
    }
}

/// The draft for the configured hook program (`hook_cli` = the absolute sidecar path when it exists next to the app,
/// else the bare name) and the current approval TTL; programs are quoted where needed.
pub fn hooks_json_draft_for(hook_cli: &str, approval_ttl_s: u32) -> Value {
    hooks_json_draft(
        &quote_program(hook_cli),
        &quote_program(&windows_program(hook_cli)),
        approval_ttl_s,
    )
}

/// The `doctor` command line the manual steps tell the user to run.
pub fn doctor_command(hook_cli: &str) -> String {
    format!("{} doctor", quote_program(&windows_program(hook_cli)))
}

/// The manual onboarding steps shown on the desktop until C6 is verified (docs/desktop.md 6.1 item 4).
pub fn manual_steps_ko(doctor_command: &str) -> Vec<String> {
    vec![
        "아래 hooks.json 초안을 복사해 %USERPROFILE%\\.codex\\hooks.json 에 저장하세요. (최상위 구조는 Phase 0 C6 확인 전의 초안이에요)".to_owned(),
        "Codex 에서 /hooks 를 열어 AgentNest 항목을 신뢰(trust)하세요. 신뢰하지 않은 훅은 실행되지 않아요.".to_owned(),
        format!("터미널에서 `{doctor_command}` 로 데몬 도달성과 토큰을 점검하세요."),
        "Codex 에서 명령을 하나 실행해 첫 이벤트가 오는지 확인하세요.".to_owned(),
        "Codex 승인: 관찰만 (C6 확인 전) · 리뷰 결과: 수집 불가 (hooks 모드)".to_owned(),
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
        let steps = manual_steps_ko("agentnest-hook.exe doctor").join("\n");
        assert!(steps.contains("/hooks"));
        assert!(steps.contains("관찰만"));
        assert!(steps.contains("`agentnest-hook.exe doctor`"));
    }

    #[test]
    fn an_installed_sidecar_path_is_used_quoted_and_the_timeout_follows_the_ttl() {
        let cli = "C:\\Users\\Kim Lee\\AppData\\Local\\AgentNest\\agentnest-hook.exe";
        let v = hooks_json_draft_for(cli, 90);
        let hooks = v["hooks"].as_object().unwrap();
        for (event, entry) in hooks {
            let h = &entry[0]["hooks"][0];
            let quoted = format!("\"{cli}\" codex");
            assert_eq!(h["command"], quoted.as_str(), "{event}");
            assert_eq!(h["commandWindows"], quoted.as_str(), "{event}");
        }
        assert_eq!(hooks["PermissionRequest"][0]["hooks"][0]["timeout"], 120);
        assert_eq!(
            doctor_command(cli),
            format!("\"{cli}\" doctor"),
            "the doctor line uses the same absolute path"
        );
        // the document is still valid JSON after the path went through it
        let text = serde_json::to_string_pretty(&v).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), v);
    }

    #[test]
    fn the_bare_fallback_name_keeps_the_documented_draft() {
        let v = hooks_json_draft_for("agentnest-hook", 120);
        let h = &v["hooks"]["SessionStart"][0]["hooks"][0];
        assert_eq!(h["command"], "agentnest-hook codex");
        assert_eq!(h["commandWindows"], "agentnest-hook.exe codex");
        assert_eq!(
            doctor_command("agentnest-hook"),
            "agentnest-hook.exe doctor"
        );
        assert_eq!(quote_program("a\"b c"), "\"a\\\"b c\"");
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
