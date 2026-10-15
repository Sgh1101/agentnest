//! Risk rule table (code constants only; no external rule files, security.md I10).
//!
//! The table is Rust code on purpose: there is no `rules.toml`, no JSON rule file and no configuration key that can
//! lower a level (security.md I10, docs/integrations/claude-code.md 7). A new rule needs a fixture case in
//! `protocol/fixtures/risk_cases.json` (CLAUDE.md).
//!
//! Besides the [`Rule`] enum (reason codes, levels, Korean texts) this module holds the **path predicates** that the
//! classifier applies to tool paths and to shell redirection targets.

use agentnest_protocol::{ExtraConfirmation, RiskLevel};

use crate::normalize::path::{basename, extension, segments};

/// Risk level in ascending order (so `max` picks the most severe).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Default card.
    Low,
    /// Blue card, biometrics only.
    Medium,
    /// Orange card, long press.
    High,
    /// Red card, long press plus re-confirmation sheet.
    Critical,
}

impl Level {
    /// The protocol enum.
    pub fn to_risk_level(self) -> RiskLevel {
        match self {
            Level::Low => RiskLevel::Low,
            Level::Medium => RiskLevel::Medium,
            Level::High => RiskLevel::High,
            Level::Critical => RiskLevel::Critical,
        }
    }

    /// One level up, capped at `Critical` (`permission_mode == plan` raise rule).
    pub fn raised(self) -> Level {
        match self {
            Level::Low => Level::Medium,
            Level::Medium => Level::High,
            Level::High | Level::Critical => Level::Critical,
        }
    }

    /// The extra confirmation that goes with the level (security.md / claude-code.md 7).
    pub fn extra_confirmation(self) -> ExtraConfirmation {
        match self {
            Level::Low | Level::Medium => ExtraConfirmation::None,
            Level::High => ExtraConfirmation::Hold,
            Level::Critical => ExtraConfirmation::HoldAndReconfirm,
        }
    }
}

/// One classification rule = one reason code. The variant order is the order in which reasons are reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// `rm -rf /`, `~`, `$HOME`, `C:\`, `%USERPROFILE%`.
    DeleteRoot,
    /// `format`, `diskpart`, `mkfs`, `dd if=`.
    DiskFormat,
    /// `curl ... | sh`, `Invoke-Expression`, undecodable `-EncodedCommand`.
    RemoteCodeExec,
    /// Force push to `main`/`master`/`release*`.
    GitForcePushMain,
    /// `reg add HKLM`, `netsh`, `schtasks /create`, `sc create`, `bcdedit`, `shutdown`, ...
    SystemModify,
    /// Writes below `C:\Windows`, `/etc`, `/usr`, `Program Files`.
    SystemPathWrite,
    /// Writes to `.ssh/`, `.gnupg/`, `id_rsa`, `*.pem`, `*.pfx`, `*.key`.
    SecretPathWrite,
    /// `tool_input` larger than 64 KiB (cannot be reviewed).
    InputTooLarge,
    /// The classifier failed or panicked.
    ClassifierError,
    /// `rm -r`, `rmdir /s`, `Remove-Item -Recurse`.
    RecursiveDelete,
    /// Force push to another branch.
    GitForcePush,
    /// `git reset --hard`, `git clean -fd`, `git checkout -- .`, `git branch -D`.
    GitDestructive,
    /// `npm publish`, `cargo publish`, `gh release create`, `twine upload`, `docker push`.
    Publish,
    /// `sudo`, `runas`, `Start-Process -Verb RunAs`.
    Elevation,
    /// `chmod -R 777`, `icacls ... /grant Everyone`.
    PermissionsWideOpen,
    /// `docker system prune`, `kubectl delete`, `terraform apply|destroy`.
    InfraDestructive,
    /// `.env*`, `credentials`, `secrets`, `.npmrc`, `.pypirc` read.
    SecretPathRead,
    /// Write outside the session working directory.
    WriteOutsideProject,
    /// `git push`, `git commit --amend`, `git rebase`.
    GitHistory,
    /// `npm install`, `pip install`, `cargo install`, `winget install`.
    InstallsDeps,
    /// `curl`, `wget`, `ssh`, `scp`.
    NetworkTool,
    /// `.github/workflows/*`, `*.gradle.kts`, `Cargo.toml`, `package.json`, `.claude/settings*.json`.
    BuildOrPolicyFile,
    /// Reads of `~/.ssh`, `~/.aws`, `%APPDATA%` and of files outside the project.
    ReadSensitive,
    /// An MCP tool or an unknown tool.
    McpUnknown,
    /// Codex `networkApprovalContext`.
    NetworkAccess,
    /// Any other command (the default).
    ShellGeneric,
    /// `command_class` is `test` or `build`.
    TestOrBuild,
    /// Write/Edit inside the project.
    EditInProject,
    /// Read/Grep/Glob inside the project.
    ReadInProject,
    /// `WebFetch` / `WebSearch`.
    NetworkRead,
    /// `Agent`, `TodoWrite`, `AskUserQuestion` and similar internal tools.
    Subagent,
}

impl Rule {
    /// Every rule.
    pub const ALL: [Rule; 31] = [
        Rule::DeleteRoot,
        Rule::DiskFormat,
        Rule::RemoteCodeExec,
        Rule::GitForcePushMain,
        Rule::SystemModify,
        Rule::SystemPathWrite,
        Rule::SecretPathWrite,
        Rule::InputTooLarge,
        Rule::ClassifierError,
        Rule::RecursiveDelete,
        Rule::GitForcePush,
        Rule::GitDestructive,
        Rule::Publish,
        Rule::Elevation,
        Rule::PermissionsWideOpen,
        Rule::InfraDestructive,
        Rule::SecretPathRead,
        Rule::WriteOutsideProject,
        Rule::GitHistory,
        Rule::InstallsDeps,
        Rule::NetworkTool,
        Rule::BuildOrPolicyFile,
        Rule::ReadSensitive,
        Rule::McpUnknown,
        Rule::NetworkAccess,
        Rule::ShellGeneric,
        Rule::TestOrBuild,
        Rule::EditInProject,
        Rule::ReadInProject,
        Rule::NetworkRead,
        Rule::Subagent,
    ];

    /// The reason code on the wire (`risk.reasons[]`).
    pub const fn code(self) -> &'static str {
        match self {
            Rule::DeleteRoot => "delete_root",
            Rule::DiskFormat => "disk_format",
            Rule::RemoteCodeExec => "remote_code_exec",
            Rule::GitForcePushMain => "git_force_push_main",
            Rule::SystemModify => "system_modify",
            Rule::SystemPathWrite => "system_path_write",
            Rule::SecretPathWrite => "secret_path_write",
            Rule::InputTooLarge => "input_too_large",
            Rule::ClassifierError => "classifier_error",
            Rule::RecursiveDelete => "recursive_delete",
            Rule::GitForcePush => "git_force_push",
            Rule::GitDestructive => "git_destructive",
            Rule::Publish => "publish",
            Rule::Elevation => "elevation",
            Rule::PermissionsWideOpen => "permissions_wide_open",
            Rule::InfraDestructive => "infra_destructive",
            Rule::SecretPathRead => "secret_path_read",
            Rule::WriteOutsideProject => "write_outside_project",
            Rule::GitHistory => "git_history",
            Rule::InstallsDeps => "installs_deps",
            Rule::NetworkTool => "network_tool",
            Rule::BuildOrPolicyFile => "build_or_policy_file",
            Rule::ReadSensitive => "read_sensitive",
            Rule::McpUnknown => "mcp_unknown",
            Rule::NetworkAccess => "network_access",
            Rule::ShellGeneric => "shell_generic",
            Rule::TestOrBuild => "test_or_build",
            Rule::EditInProject => "edit_in_project",
            Rule::ReadInProject => "read_in_project",
            Rule::NetworkRead => "network_read",
            Rule::Subagent => "subagent",
        }
    }

    /// The level of the rule (claude-code.md 7).
    pub const fn level(self) -> Level {
        match self {
            Rule::DeleteRoot
            | Rule::DiskFormat
            | Rule::RemoteCodeExec
            | Rule::GitForcePushMain
            | Rule::SystemModify
            | Rule::SystemPathWrite
            | Rule::SecretPathWrite
            | Rule::InputTooLarge
            | Rule::ClassifierError => Level::Critical,
            Rule::RecursiveDelete
            | Rule::GitForcePush
            | Rule::GitDestructive
            | Rule::Publish
            | Rule::Elevation
            | Rule::PermissionsWideOpen
            | Rule::InfraDestructive
            | Rule::SecretPathRead
            | Rule::WriteOutsideProject => Level::High,
            Rule::GitHistory
            | Rule::InstallsDeps
            | Rule::NetworkTool
            | Rule::BuildOrPolicyFile
            | Rule::ReadSensitive
            | Rule::McpUnknown
            | Rule::NetworkAccess
            | Rule::ShellGeneric => Level::Medium,
            Rule::TestOrBuild
            | Rule::EditInProject
            | Rule::ReadInProject
            | Rule::NetworkRead
            | Rule::Subagent => Level::Low,
        }
    }

    /// The Korean explanation shown on the approval card (`risk.reasons_ko[]`).
    pub const fn reason_ko(self) -> &'static str {
        match self {
            Rule::DeleteRoot => "시스템 루트를 지우는 명령이에요",
            Rule::DiskFormat => "디스크를 지우거나 포맷하는 명령이에요",
            Rule::RemoteCodeExec => "인터넷에서 받은 코드를 바로 실행하는 명령이에요",
            Rule::GitForcePushMain => "주요 브랜치(main 등)에 강제로 푸시하는 명령이에요",
            Rule::SystemModify => "시스템 설정을 바꾸거나 PC를 끄는 명령이에요",
            Rule::SystemPathWrite => "시스템 폴더에 파일을 쓰려고 해요",
            Rule::SecretPathWrite => "키나 인증서 파일을 쓰려고 해요",
            Rule::InputTooLarge => "내용이 너무 커서 검토할 수 없어요",
            Rule::ClassifierError => "위험도를 판단하지 못해서 가장 높은 단계로 처리해요",
            Rule::RecursiveDelete => "폴더를 통째로 지우는 명령이에요",
            Rule::GitForcePush => "원격 저장소에 강제로 푸시하는 명령이에요",
            Rule::GitDestructive => "작업 내용을 되돌릴 수 없게 지울 수 있어요",
            Rule::Publish => "외부에 배포하거나 게시하는 명령이에요",
            Rule::Elevation => "관리자 권한으로 실행하려고 해요",
            Rule::PermissionsWideOpen => "모든 사용자에게 권한을 열어 주는 명령이에요",
            Rule::InfraDestructive => "서버나 인프라를 삭제하거나 바꿀 수 있어요",
            Rule::SecretPathRead => "비밀 정보가 담긴 파일을 읽으려고 해요",
            Rule::WriteOutsideProject => "프로젝트 밖에 파일을 쓰려고 해요",
            Rule::GitHistory => "Git 기록을 바꾸거나 원격에 올리는 명령이에요",
            Rule::InstallsDeps => "패키지를 설치해요",
            Rule::NetworkTool => "네트워크로 연결하는 도구예요",
            Rule::BuildOrPolicyFile => "빌드나 설정 파일을 바꾸려고 해요",
            Rule::ReadSensitive => "프로젝트 밖이나 민감한 위치의 파일을 읽으려고 해요",
            Rule::McpUnknown => "알 수 없는 외부 도구예요",
            Rule::NetworkAccess => "네트워크 접근을 요청했어요",
            Rule::ShellGeneric => "일반 명령이에요",
            Rule::TestOrBuild => "빌드나 테스트 명령이에요",
            Rule::EditInProject => "프로젝트 안의 파일을 고쳐요",
            Rule::ReadInProject => "프로젝트 안의 파일을 읽어요",
            Rule::NetworkRead => "웹에서 자료를 읽어요",
            Rule::Subagent => "보조 에이전트나 내부 도구예요",
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Path predicates. All take a *normalised* path (see `normalize::path::normalize`) and compare case-insensitively.
// ---------------------------------------------------------------------------------------------------------------------

fn under(path: &str, prefix: &str) -> bool {
    path == prefix || path.strip_prefix(prefix).is_some_and(|r| r.starts_with('/'))
}

/// System locations: `C:\Windows`, `Program Files`, `/etc`, `/usr`, `/bin`, ... and raw devices below `/dev`.
pub fn is_system_path(path: &str) -> bool {
    let p = path.to_lowercase();
    const POSIX: [&str; 9] = ["/etc", "/usr", "/bin", "/sbin", "/boot", "/lib", "/lib64", "/sys", "/proc"];
    if POSIX.iter().any(|d| under(&p, d)) {
        return true;
    }
    if under(&p, "/dev") {
        // the harmless pseudo devices
        return !matches!(
            p.as_str(),
            "/dev/null" | "/dev/stdout" | "/dev/stderr" | "/dev/stdin" | "/dev/tty" | "/dev/zero"
        );
    }
    // drive-letter paths and WSL mounts: `x:/windows`, `x:/program files`, `/mnt/x/windows`
    let rest = if p.len() >= 3 && p.as_bytes()[0].is_ascii_alphabetic() && p.as_bytes()[1] == b':' && p.as_bytes()[2] == b'/' {
        Some(&p[3..])
    } else if let Some(r) = p.strip_prefix("/mnt/") {
        match r.split_once('/') {
            Some((drive, tail)) if drive.len() == 1 => Some(tail),
            _ => None,
        }
    } else {
        None
    };
    match rest {
        Some(r) => {
            under(r, "windows")
                || under(r, "program files")
                || under(r, "program files (x86)")
                || under(r, "programdata")
        }
        None => false,
    }
}

const KEY_BASENAMES: [&str; 4] = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];

/// Key and certificate material: `.ssh/`, `.gnupg/`, `id_*`, `*.pem`, `*.pfx`, `*.key`, `*.p12`, `*.ppk`.
pub fn is_secret_write_path(path: &str) -> bool {
    let p = path.to_lowercase();
    if segments(&p).iter().any(|s| *s == ".ssh" || *s == ".gnupg") {
        return true;
    }
    let base = basename(&p);
    if KEY_BASENAMES.iter().any(|k| base.starts_with(k)) {
        return true;
    }
    matches!(extension(&p).as_str(), "pem" | "pfx" | "key" | "p12" | "ppk")
}

/// Files that hold secrets: `.env*`, `credentials`, `secrets`, `.npmrc`, `.pypirc`, `.netrc`, private keys.
pub fn is_secret_read_path(path: &str) -> bool {
    let p = path.to_lowercase();
    let base = basename(&p);
    if base == ".env" {
        return true;
    }
    if let Some(rest) = base.strip_prefix(".env.") {
        // templates are meant to be committed
        return !matches!(rest, "example" | "sample" | "template" | "dist" | "defaults");
    }
    if matches!(base, ".npmrc" | ".pypirc" | ".netrc" | "_netrc") {
        return true;
    }
    let stem_ok = |stem: &str| {
        base == stem
            || ["json", "yml", "yaml", "toml", "ini", "xml"]
                .iter()
                .any(|e| base == format!("{stem}.{e}"))
    };
    if stem_ok("credentials") || stem_ok("secrets") {
        return true;
    }
    if KEY_BASENAMES.iter().any(|k| base == *k) {
        return true;
    }
    matches!(extension(&p).as_str(), "key" | "pfx" | "p12" | "ppk")
}

/// Locations whose reads are sensitive but not secrets themselves: `~/.ssh`, `~/.aws`, `%APPDATA%`, ...
pub fn is_read_sensitive_path(path: &str) -> bool {
    let p = path.to_lowercase();
    segments(&p)
        .iter()
        .any(|s| matches!(*s, ".ssh" | ".aws" | ".gnupg" | ".kube" | ".azure" | "appdata"))
}

/// Build and policy files: `.github/workflows/*`, `*.gradle(.kts)`, `Cargo.toml`, `package.json`,
/// `.claude/settings*.json`.
pub fn is_build_or_policy_file(path: &str) -> bool {
    let p = path.to_lowercase();
    let segs = segments(&p);
    if segs.windows(2).any(|w| w[0] == ".github" && w[1] == "workflows") {
        return true;
    }
    let base = basename(&p);
    if base.ends_with(".gradle.kts") || base.ends_with(".gradle") || base == "cargo.toml" || base == "package.json" {
        return true;
    }
    if segs.len() >= 2 && segs[segs.len() - 2] == ".claude" && base.starts_with("settings") && base.ends_with(".json") {
        return true;
    }
    false
}

/// File paths named in an `apply_patch` style patch text (`*** Update File: path`, `*** Add File:`, `*** Delete File:`,
/// `*** Move to:`).
///
/// `// UNVERIFIED (Phase 0 C10)`: the Codex hooks `apply_patch` input format is not verified; the parser is tolerant
/// and returns nothing for text it does not understand.
pub fn apply_patch_paths(tool_input: &serde_json::Value) -> Vec<String> {
    let text = match tool_input {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(map) => ["input", "patch", "command", "content"]
            .iter()
            .find_map(|k| map.get(*k))
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(a) => a
                    .iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => String::new(),
            })
            .unwrap_or_default(),
        _ => String::new(),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        for marker in ["*** Update File:", "*** Add File:", "*** Delete File:", "*** Move to:"] {
            if let Some(rest) = l.strip_prefix(marker) {
                let path = rest.trim();
                if !path.is_empty() && out.len() < 200 {
                    out.push(path.to_owned());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_and_extra_confirmation() {
        assert!(Level::Low < Level::Medium && Level::Medium < Level::High && Level::High < Level::Critical);
        assert_eq!(Level::Low.raised(), Level::Medium);
        assert_eq!(Level::High.raised(), Level::Critical);
        assert_eq!(Level::Critical.raised(), Level::Critical);
        assert_eq!(Level::High.extra_confirmation(), ExtraConfirmation::Hold);
        assert_eq!(Level::Critical.extra_confirmation(), ExtraConfirmation::HoldAndReconfirm);
        assert_eq!(Level::Medium.extra_confirmation(), ExtraConfirmation::None);
    }

    #[test]
    fn rule_table_matches_the_fixture_reason_levels() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../protocol/fixtures/risk_cases.json");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let levels = v["reason_levels"].as_object().unwrap();
        assert_eq!(levels.len(), Rule::ALL.len());
        for r in Rule::ALL {
            let want = levels.get(r.code()).unwrap_or_else(|| panic!("fixture lacks {}", r.code()));
            let got = match r.level() {
                Level::Low => "low",
                Level::Medium => "medium",
                Level::High => "high",
                Level::Critical => "critical",
            };
            assert_eq!(want, got, "{}", r.code());
            assert!(!r.reason_ko().is_empty() && r.reason_ko().chars().count() <= 200);
        }
        // the enum order is the reporting order and must be unique per code
        let mut codes: Vec<&str> = Rule::ALL.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), Rule::ALL.len());
        let mut sorted = Rule::ALL.to_vec();
        sorted.sort();
        assert_eq!(sorted, Rule::ALL.to_vec());
    }

    #[test]
    fn system_paths() {
        for p in ["C:/Windows/System32/x.dll", "c:/windows/system32/x.dll", "/etc/hosts", "/usr/local/bin/tool", "C:/Program Files/App/c.ini", "C:/Program Files (x86)/A", "/mnt/c/Windows/x", "/dev/sda", "D:/Windows"] {
            assert!(is_system_path(p), "{p}");
        }
        for p in ["C:/dev/agentnest/etc/config.toml", "C:/dev/agentnest/docs/windows.md", "/home/me/usr/x", "/dev/null", "/etcetera/x", "/mnt/c/Users/me", "~/etc"] {
            assert!(!is_system_path(p), "{p}");
        }
    }

    #[test]
    fn secret_and_policy_paths() {
        for p in ["C:/Users/me/.ssh/authorized_keys", "/home/me/.gnupg/gpg.conf", "C:/dev/certs/server.pem", "C:/dev/deploy.pfx", "C:/dev/signing.key", "/home/me/.ssh/id_rsa", "/x/id_ed25519.pub"] {
            assert!(is_secret_write_path(p), "{p}");
        }
        for p in ["C:/dev/docs/keys.md", "C:/dev/src/monkey.rs", "C:/dev/src/key.rs"] {
            assert!(!is_secret_write_path(p), "{p}");
        }
        for p in [".env", "C:/dev/.env.local", "~/.npmrc", "C:/Users/me/.pypirc", "/home/me/.aws/credentials", "/x/secrets.yml", "/x/id_rsa", "/x/a.key"] {
            assert!(is_secret_read_path(p), "{p}");
        }
        for p in ["C:/dev/README.md", "C:/dev/docs/environment.md", "/x/.env.example", "/x/credentials-guide.md", "/x/secrets-policy.md", "/x/.envrc"] {
            assert!(!is_secret_read_path(p), "{p}");
        }
        assert!(is_read_sensitive_path("~/.ssh/known_hosts"));
        assert!(is_read_sensitive_path("C:/Users/me/AppData/Roaming/x"));
        assert!(!is_read_sensitive_path("C:/dev/agentnest/src"));
        for p in ["C:/dev/.github/workflows/ci.yml", "C:/dev/app/build.gradle.kts", "C:/dev/Cargo.toml", "C:/dev/package.json", "C:/dev/.claude/settings.json", "C:/dev/.claude/settings.local.json"] {
            assert!(is_build_or_policy_file(p), "{p}");
        }
        for p in ["C:/dev/Cargo.lock", "C:/dev/src/main.rs", "C:/dev/.github/CODEOWNERS", "C:/dev/.claude/commands/x.md"] {
            assert!(!is_build_or_policy_file(p), "{p}");
        }
    }

    #[test]
    fn apply_patch_paths_are_parsed_tolerantly() {
        let patch = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-a\n+b\n*** Add File: docs/n.md\n*** Delete File: old.txt\n*** End Patch";
        assert_eq!(apply_patch_paths(&serde_json::json!(patch)), vec!["src/a.rs", "docs/n.md", "old.txt"]);
        assert_eq!(apply_patch_paths(&serde_json::json!({"input": patch})).len(), 3);
        assert_eq!(apply_patch_paths(&serde_json::json!({"command": ["apply_patch", patch]})).len(), 3);
        assert!(apply_patch_paths(&serde_json::json!(42)).is_empty());
        assert!(apply_patch_paths(&serde_json::json!("garbage")).is_empty());
    }
}
