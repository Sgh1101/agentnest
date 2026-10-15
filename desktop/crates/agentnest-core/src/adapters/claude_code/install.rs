//! Claude Code hook installation: a **merge** into `~/.claude/settings.json` (docs/integrations/claude-code.md 2,
//! security.md I12).
//!
//! # Rules (all covered by golden and merge tests)
//!
//! * The existing file is parsed and merged; it is **never overwritten**. Hooks of the user (and of other tools) are left
//!   untouched. Only entries that are AgentNest's own - HTTP hooks to `http://127.0.0.1:<port>/v1/hooks/claude-code`, or
//!   command hooks that run `agentnest-hook claude-code` - are removed and re-added (install) or removed (uninstall).
//! * A file with comments or any other non-JSON content is **not touched** ([`InstallError::NotPlainJson`]): installation
//!   stops and the user is told.
//! * The token travels as a **literal** `X-AgentNest-Token` header (an environment variable would be replaced by an empty
//!   string in processes that lack it and silently turn every hook into a 401).
//! * `onFailure` is **absent** (= `continue`); it is written as `"block"` only on the `PermissionRequest` hook and only
//!   when `approval.daemon_down_deny` opted in (I12).
//! * `PermissionRequest.timeout = approval.ttl_s + 30` so the daemon always answers before Claude Code gives up; the other
//!   hooks use 5 s, `SessionEnd` 1 s.
//! * `statusLine` is installed only when the user has none; an existing one is reported, never replaced.
//! * The write is atomic (temporary file in the same directory, renamed over the original) after a backup
//!   `settings.json.agentnest-backup-<timestamp>`. A backup **never overwrites** an existing one (a name that is taken
//!   gets `-1`, `-2`, ...), so the first backup - the file as the user wrote it - survives every later install. If
//!   `settings.json` is a **symbolic link** (dotfile managers), the link is kept and the linked file is replaced; the
//!   file's permissions are carried over to the new file.
//!
//! The merged file is re-serialised with two-space indentation and sorted keys (`serde_json` without `preserve_order`);
//! the **content** of unrelated settings is preserved, the key order and whitespace of the file are not. Two things the
//! re-serialisation can change are detected beforehand and reported as warnings
//! ([`InstallWarning::DuplicateKeys`], [`InstallWarning::LargeNumbers`]): a key that appears twice in one object keeps only
//! its last value, and an integer too large for a double loses precision. The backup holds the original either way.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use thiserror::Error;

/// Path of the collector route.
pub const HOOK_PATH: &str = "/v1/hooks/claude-code";
/// Authentication header.
pub const TOKEN_HEADER: &str = "X-AgentNest-Token";
/// Timeout (seconds) of observation hooks.
pub const OBSERVE_TIMEOUT_S: u32 = 5;
/// Timeout of `SessionEnd` (Claude Code gives it about 1.5 s).
pub const SESSION_END_TIMEOUT_S: u32 = 1;
/// The hook timeout exceeds the TTL by this much (seconds).
pub const TIMEOUT_MARGIN_S: u32 = 30;
/// Effective TTL assumed when no installed hook can be read (a default install: 150 - 30).
pub const DEFAULT_EFFECTIVE_TTL_S: u32 = 120;
/// Smallest effective TTL the clamp may produce.
pub const MIN_EFFECTIVE_TTL_S: u32 = 5;

/// The 16 hook events AgentNest registers (unregistered on purpose: `MessageDisplay`, `PostToolBatch`, `PreCompact`,
/// `UserPromptExpansion`).
pub const EVENTS: [&str; 16] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PermissionDenied",
    "PostToolUse",
    "PostToolUseFailure",
    "Notification",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "StopFailure",
    "TaskCreated",
    "TaskCompleted",
    "PostCompact",
    "SessionEnd",
];

/// How the hooks reach the daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookMode {
    /// `type: "http"` hooks (primary, Claude Code 2.1.63+).
    Http,
    /// `type: "command"` hooks running `agentnest-hook claude-code` (fallback where HTTP hooks are forbidden).
    Cli,
}

/// What to install.
#[derive(Clone, Debug)]
pub struct InstallOptions<'a> {
    /// HTTP or command hooks.
    pub mode: HookMode,
    /// Loopback collector port.
    pub hook_port: u16,
    /// The hook token (literal header value). Used only in HTTP mode.
    pub hook_token: &'a str,
    /// `approval.ttl_s`; the `PermissionRequest` timeout is this plus 30.
    pub approval_ttl_s: u32,
    /// Opt-in: `"onFailure":"block"` on the `PermissionRequest` hook (deny when the daemon is down).
    pub daemon_down_deny: bool,
    /// Also install the `statusLine` command if the user has none.
    pub install_statusline: bool,
    /// Path of `agentnest-hook` (command hooks and the statusLine). Plain `agentnest-hook` if it is on `PATH`.
    pub hook_cli: &'a str,
    /// Timestamp for the backup file name (`20261015T091233Z`); the current time if `None`.
    pub backup_stamp: Option<&'a str>,
}

/// Errors of the installer.
#[derive(Debug, Error)]
pub enum InstallError {
    /// File system failure.
    #[error("settings io error: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not plain JSON (comments, trailing commas, ...). Nothing was changed.
    #[error("settings.json is not plain JSON; install aborted without changes")]
    NotPlainJson,
    /// The top level (or `hooks`, or an event entry) has an unexpected type. Nothing was changed.
    #[error("settings.json has an unexpected structure: {0}")]
    UnexpectedStructure(&'static str),
}

/// Things the user should know after an install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallWarning {
    /// The user already has a `statusLine`; AgentNest did not replace it ("AI title / cost collection disabled").
    StatusLineExists,
    /// `allowedHttpHookUrls` is set and does not allow the collector URL: HTTP hooks are blocked by policy.
    AllowedHttpHookUrlsMissing,
    /// The file has an object with the same key twice; re-serialising keeps only the last value of each.
    DuplicateKeys,
    /// The file has an integer with 16 or more digits; re-serialising may round it (it is stored as a double).
    LargeNumbers,
}

impl InstallWarning {
    /// Korean text for the UI.
    pub fn message_ko(&self, port: u16) -> String {
        match self {
            InstallWarning::StatusLineExists => {
                "이미 statusLine 설정이 있어서 건드리지 않았어요. AI 제목·비용 수집은 꺼져 있어요."
                    .to_owned()
            }
            InstallWarning::AllowedHttpHookUrlsMissing => format!(
                "allowedHttpHookUrls 에 http://127.0.0.1:{port}/* 를 추가해야 HTTP 훅이 동작해요."
            ),
            InstallWarning::DuplicateKeys => {
                "settings.json 에 같은 키가 두 번 나오는 객체가 있어, 저장하면 마지막 값만 남아요. 원본은 백업 파일에 있어요."
                    .to_owned()
            }
            InstallWarning::LargeNumbers => {
                "settings.json 에 16자리 이상의 정수가 있어, 저장하면 반올림될 수 있어요. 원본은 백업 파일에 있어요."
                    .to_owned()
            }
        }
    }
}

/// Result of an install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallReport {
    /// The settings file.
    pub path: PathBuf,
    /// The backup that was written (only if the file existed).
    pub backup: Option<PathBuf>,
    /// `PermissionRequest` timeout that was written.
    pub permission_request_timeout_s: u32,
    /// Warnings.
    pub warnings: Vec<InstallWarning>,
}

/// Result of an uninstall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallReport {
    /// The settings file.
    pub path: PathBuf,
    /// Number of AgentNest hook entries removed.
    pub removed: usize,
    /// Whether the `statusLine` was removed (only if it was AgentNest's).
    pub statusline_removed: bool,
}

/// What an existing settings file contains of AgentNest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inspection {
    /// The file exists.
    pub exists: bool,
    /// It parsed as JSON.
    pub parsed: bool,
    /// Events that have an AgentNest hook.
    pub installed_events: Vec<String>,
    /// Timeout of the installed `PermissionRequest` hook, if any.
    pub permission_request_timeout_s: Option<u32>,
    /// Collector port found in an installed HTTP hook URL.
    pub port: Option<u16>,
    /// An AgentNest statusLine is present.
    pub statusline: bool,
}

impl Inspection {
    /// `true` if every registered event has an AgentNest hook.
    pub fn fully_installed(&self) -> bool {
        EVENTS
            .iter()
            .all(|e| self.installed_events.iter().any(|x| x == e))
    }
}

/// `%USERPROFILE%\.claude\settings.json` (the user level settings).
pub fn default_settings_path() -> Option<PathBuf> {
    directories::UserDirs::new().map(|d| d.home_dir().join(".claude").join("settings.json"))
}

/// The effective approval TTL: the configured value, bounded by the installed hook timeout minus 30 s. Without a readable
/// installed hook the default install (150 s) is assumed. Never below [`MIN_EFFECTIVE_TTL_S`].
pub fn effective_ttl_s(configured_ttl_s: u32, installed_timeout_s: Option<u32>) -> u32 {
    let cap = installed_timeout_s
        .map(|t| t.saturating_sub(TIMEOUT_MARGIN_S))
        .unwrap_or(DEFAULT_EFFECTIVE_TTL_S);
    configured_ttl_s.min(cap).max(MIN_EFFECTIVE_TTL_S)
}

fn hook_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}{HOOK_PATH}")
}

fn timeout_for(event: &str, opts: &InstallOptions<'_>) -> u32 {
    match event {
        "PermissionRequest" => opts.approval_ttl_s + TIMEOUT_MARGIN_S,
        "SessionEnd" => SESSION_END_TIMEOUT_S,
        _ => OBSERVE_TIMEOUT_S,
    }
}

/// The hook object of one event.
pub fn hook_entry(event: &str, opts: &InstallOptions<'_>) -> Value {
    let timeout = timeout_for(event, opts);
    let mut hook = match opts.mode {
        HookMode::Http => json!({
            "type": "http",
            "url": hook_url(opts.hook_port),
            "timeout": timeout,
            "headers": { TOKEN_HEADER: opts.hook_token },
        }),
        HookMode::Cli => json!({
            "type": "command",
            "command": opts.hook_cli,
            "args": ["claude-code"],
            "timeout": timeout,
        }),
    };
    if event == "PermissionRequest" {
        if let Value::Object(m) = &mut hook {
            m.insert(
                "statusMessage".to_owned(),
                json!("AgentNest: 휴대폰 승인 대기 중 (트레이에서 '로컬로 처리' 가능)"),
            );
            if opts.daemon_down_deny {
                // I12: block is an opt-in; the default is no key at all (= continue)
                m.insert("onFailure".to_owned(), json!("block"));
            }
        }
    }
    hook
}

/// The complete `hooks` section AgentNest wants: `event -> [ { "hooks": [ entry ] } ]`.
pub fn desired_hooks(opts: &InstallOptions<'_>) -> Map<String, Value> {
    let mut m = Map::new();
    for event in EVENTS {
        m.insert(
            event.to_owned(),
            json!([{ "hooks": [hook_entry(event, opts)] }]),
        );
    }
    m
}

fn statusline_value(opts: &InstallOptions<'_>) -> Value {
    // statusLine commands run through a shell: a path with spaces must be quoted
    let program = if opts.hook_cli.contains(' ') {
        format!("\"{}\"", opts.hook_cli)
    } else {
        opts.hook_cli.to_owned()
    };
    json!({
        "type": "command",
        "command": format!("{program} statusline"),
    })
}

/// `true` for an AgentNest-owned hook object.
pub fn is_agentnest_hook(hook: &Value) -> bool {
    match hook.get("type").and_then(Value::as_str) {
        Some("http") => hook
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(is_agentnest_url),
        Some("command") => {
            let cmd = hook.get("command").and_then(Value::as_str).unwrap_or("");
            let base = cmd.rsplit(['/', '\\']).next().unwrap_or(cmd);
            let is_ours = base == "agentnest-hook" || base == "agentnest-hook.exe";
            let first_arg = hook
                .get("args")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str);
            is_ours && first_arg == Some("claude-code")
        }
        _ => false,
    }
}

fn is_agentnest_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://127.0.0.1:") else {
        return false;
    };
    let Some(port) = rest.strip_suffix(HOOK_PATH) else {
        return false;
    };
    !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
}

fn is_agentnest_statusline(v: &Value) -> bool {
    let Some(cmd) = v.get("command").and_then(Value::as_str) else {
        return false;
    };
    let Some(head) = cmd.trim().strip_suffix(" statusline") else {
        return false;
    };
    let head = head.trim().trim_matches('"');
    let base = head.rsplit(['/', '\\']).next().unwrap_or(head);
    base == "agentnest-hook" || base == "agentnest-hook.exe"
}

fn read_settings(path: &Path) -> Result<Option<Map<String, Value>>, InstallError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(InstallError::Io(e)),
    };
    if text.trim().is_empty() {
        return Ok(Some(Map::new()));
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(m)) => Ok(Some(m)),
        Ok(_) => Err(InstallError::UnexpectedStructure(
            "top level is not an object",
        )),
        Err(_) => Err(InstallError::NotPlainJson),
    }
}

/// Removes AgentNest's hooks from every event array. Returns how many were removed.
fn remove_ours(hooks: &mut Map<String, Value>) -> Result<usize, InstallError> {
    let mut removed = 0;
    let events: Vec<String> = hooks.keys().cloned().collect();
    for event in events {
        let Some(groups) = hooks.get_mut(&event) else {
            continue;
        };
        let Value::Array(groups) = groups else {
            // an event entry of unexpected type is left alone
            continue;
        };
        for group in groups.iter_mut() {
            if let Some(Value::Array(inner)) = group.get_mut("hooks") {
                let before = inner.len();
                inner.retain(|h| !is_agentnest_hook(h));
                removed += before - inner.len();
            }
        }
        // drop groups that only contained our hooks
        groups.retain(|g| !matches!(g.get("hooks"), Some(Value::Array(a)) if a.is_empty()));
        if groups.is_empty() {
            hooks.remove(&event);
        }
    }
    Ok(removed)
}

/// Rejects (by flagging) JSON objects that repeat a key: `serde_json::Value` would silently keep the last value.
struct NoDuplicateKeys(bool);

impl<'de> serde::Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{MapAccess, SeqAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = bool;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<bool, A::Error> {
                let mut seen = std::collections::HashSet::new();
                let mut dup = false;
                while let Some(k) = m.next_key::<String>()? {
                    dup |= !seen.insert(k);
                    dup |= m.next_value::<NoDuplicateKeys>()?.0;
                }
                Ok(dup)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<bool, A::Error> {
                let mut dup = false;
                while let Some(v) = s.next_element::<NoDuplicateKeys>()? {
                    dup |= v.0;
                }
                Ok(dup)
            }
            fn visit_bool<E>(self, _: bool) -> Result<bool, E> {
                Ok(false)
            }
            fn visit_i64<E>(self, _: i64) -> Result<bool, E> {
                Ok(false)
            }
            fn visit_u64<E>(self, _: u64) -> Result<bool, E> {
                Ok(false)
            }
            fn visit_f64<E>(self, _: f64) -> Result<bool, E> {
                Ok(false)
            }
            fn visit_str<E>(self, _: &str) -> Result<bool, E> {
                Ok(false)
            }
            fn visit_unit<E>(self) -> Result<bool, E> {
                Ok(false)
            }
        }
        d.deserialize_any(V).map(NoDuplicateKeys)
    }
}

/// What re-serialising `text` would change silently (see the module docs).
fn lossy_reserialisation_warnings(text: &str) -> Vec<InstallWarning> {
    let mut w = Vec::new();
    if serde_json::from_str::<NoDuplicateKeys>(text).is_ok_and(|d| d.0) {
        w.push(InstallWarning::DuplicateKeys);
    }
    // a run of 16+ digits that is not part of a longer word or a fraction: an integer a double cannot hold exactly
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut large = false;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            // digits inside a string are text, not numbers
            if b == b'\\' {
                i += 1;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
        } else if b == b'"' {
            in_string = true;
            i += 1;
        } else if b.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let before_ok = start == 0 || !matches!(bytes[start - 1], b'.' | b'e' | b'E');
            let after_ok = i >= bytes.len() || !matches!(bytes[i], b'.' | b'e' | b'E');
            if i - start >= 16 && before_ok && after_ok {
                large = true;
            }
        } else {
            i += 1;
        }
    }
    if large {
        w.push(InstallWarning::LargeNumbers);
    }
    w
}

/// Writes `root` atomically. A symbolic link is followed (the linked file is replaced, the link stays), the permissions
/// of the existing file carry over to the new one, and the temporary file lives next to the real target.
fn write_atomic(path: &Path, root: &Map<String, Value>) -> Result<(), InstallError> {
    // follow a symlink so that `rename` replaces the file it points to, not the link itself
    let target = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(path)?,
        _ => path.to_owned(),
    };
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut text = serde_json::to_string_pretty(&Value::Object(root.clone()))
        .map_err(|_| InstallError::UnexpectedStructure("not serialisable"))?;
    text.push('\n');
    let mut tmp = target.as_os_str().to_owned();
    tmp.push(".agentnest-tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, text)?;
    if let Ok(meta) = std::fs::metadata(&target) {
        // keep the mode of the original (a 0600 settings file must not become 0644)
        if let Err(e) = std::fs::set_permissions(&tmp, meta.permissions()) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
    }
    if let Err(e) = std::fs::rename(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Copies `path` to `<path>.agentnest-backup-<stamp>`; a name that exists is never overwritten (`-1`, `-2`, ...).
fn backup(path: &Path, stamp: &str) -> Result<Option<PathBuf>, InstallError> {
    if !path.exists() {
        return Ok(None);
    }
    for n in 0..1000u32 {
        let mut name = path.as_os_str().to_owned();
        if n == 0 {
            name.push(format!(".agentnest-backup-{stamp}"));
        } else {
            name.push(format!(".agentnest-backup-{stamp}-{n}"));
        }
        let dest = PathBuf::from(name);
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest);
        match created {
            Ok(mut out) => {
                let mut src = std::fs::File::open(path)?;
                std::io::copy(&mut src, &mut out)?;
                return Ok(Some(dest));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(InstallError::UnexpectedStructure("too many backup files"))
}

/// Installs (or re-installs) the hooks into `settings_path`.
pub fn install(
    settings_path: &Path,
    opts: &InstallOptions<'_>,
) -> Result<InstallReport, InstallError> {
    let existing = read_settings(settings_path)?;
    let mut root = existing.clone().unwrap_or_default();
    let mut warnings = match std::fs::read_to_string(settings_path) {
        Ok(text) => lossy_reserialisation_warnings(&text),
        Err(_) => Vec::new(),
    };

    let hooks_value = root
        .entry("hooks".to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(hooks) = hooks_value else {
        return Err(InstallError::UnexpectedStructure(
            "\"hooks\" is not an object",
        ));
    };
    for (event, v) in hooks.iter() {
        if !v.is_array() {
            let _ = event;
            return Err(InstallError::UnexpectedStructure(
                "a hook event entry is not an array",
            ));
        }
    }
    remove_ours(hooks)?;
    for (event, groups) in desired_hooks(opts) {
        let Value::Array(new_groups) = groups else {
            continue;
        };
        let slot = hooks
            .entry(event)
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(existing_groups) = slot {
            existing_groups.extend(new_groups);
        }
    }

    // statusLine: a single slot; never replace somebody else's
    if opts.install_statusline {
        match root.get("statusLine") {
            None => {
                root.insert("statusLine".to_owned(), statusline_value(opts));
            }
            Some(v) if is_agentnest_statusline(v) => {
                root.insert("statusLine".to_owned(), statusline_value(opts));
            }
            Some(_) => warnings.push(InstallWarning::StatusLineExists),
        }
    }
    // HTTP hooks can be forbidden by a policy list
    if opts.mode == HookMode::Http {
        if let Some(Value::Array(allowed)) = root.get("allowedHttpHookUrls") {
            let url = hook_url(opts.hook_port);
            let ok = allowed.iter().filter_map(Value::as_str).any(|pat| {
                pat == url
                    || pat
                        .strip_suffix('*')
                        .is_some_and(|prefix| url.starts_with(prefix))
            });
            if !ok {
                warnings.push(InstallWarning::AllowedHttpHookUrlsMissing);
            }
        }
    }

    let stamp = opts
        .backup_stamp
        .map(str::to_owned)
        .unwrap_or_else(|| chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string());
    let backup_path = if existing.is_some() {
        backup(settings_path, &stamp)?
    } else {
        None
    };
    write_atomic(settings_path, &root)?;
    Ok(InstallReport {
        path: settings_path.to_owned(),
        backup: backup_path,
        permission_request_timeout_s: opts.approval_ttl_s + TIMEOUT_MARGIN_S,
        warnings,
    })
}

/// Removes AgentNest's hooks (and its statusLine) and nothing else.
pub fn uninstall(settings_path: &Path) -> Result<UninstallReport, InstallError> {
    let Some(mut root) = read_settings(settings_path)? else {
        return Ok(UninstallReport {
            path: settings_path.to_owned(),
            removed: 0,
            statusline_removed: false,
        });
    };
    let mut removed = 0;
    if let Some(Value::Object(hooks)) = root.get_mut("hooks") {
        removed = remove_ours(hooks)?;
        if hooks.is_empty() {
            root.remove("hooks");
        }
    }
    let statusline_removed = root.get("statusLine").is_some_and(is_agentnest_statusline);
    if statusline_removed {
        root.remove("statusLine");
    }
    if removed > 0 || statusline_removed {
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        backup(settings_path, &stamp)?;
        write_atomic(settings_path, &root)?;
    }
    Ok(UninstallReport {
        path: settings_path.to_owned(),
        removed,
        statusline_removed,
    })
}

/// Reads what AgentNest has installed (read only; used for the status page and the effective-TTL clamp).
pub fn inspect(settings_path: &Path) -> Inspection {
    let mut out = Inspection {
        exists: settings_path.exists(),
        ..Inspection::default()
    };
    let Ok(Some(root)) = read_settings(settings_path) else {
        return out;
    };
    out.parsed = true;
    if let Some(Value::Object(hooks)) = root.get("hooks") {
        for (event, groups) in hooks {
            let Some(groups) = groups.as_array() else {
                continue;
            };
            for group in groups {
                let Some(inner) = group.get("hooks").and_then(Value::as_array) else {
                    continue;
                };
                for h in inner.iter().filter(|h| is_agentnest_hook(h)) {
                    if !out.installed_events.contains(event) {
                        out.installed_events.push(event.clone());
                    }
                    if event == "PermissionRequest" {
                        out.permission_request_timeout_s = h
                            .get("timeout")
                            .and_then(Value::as_u64)
                            .and_then(|t| u32::try_from(t).ok());
                    }
                    if let Some(url) = h.get("url").and_then(Value::as_str) {
                        out.port = url
                            .strip_prefix("http://127.0.0.1:")
                            .and_then(|r| r.strip_suffix(HOOK_PATH))
                            .and_then(|p| p.parse().ok())
                            .or(out.port);
                    }
                }
            }
        }
    }
    out.installed_events.sort();
    out.statusline = root.get("statusLine").is_some_and(is_agentnest_statusline);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts<'a>() -> InstallOptions<'a> {
        InstallOptions {
            mode: HookMode::Http,
            hook_port: 47831,
            hook_token: "an_hk_TESTTOKEN",
            approval_ttl_s: 120,
            daemon_down_deny: false,
            install_statusline: true,
            hook_cli: "agentnest-hook",
            backup_stamp: Some("20261015T091233Z"),
        }
    }

    fn read(path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn a_fresh_install_has_sixteen_events_and_the_documented_timeouts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let report = install(&path, &opts()).unwrap();
        assert_eq!(report.permission_request_timeout_s, 150);
        assert_eq!(report.backup, None);
        let v = read(&path);
        let hooks = v["hooks"].as_object().unwrap();
        assert_eq!(hooks.len(), 16);
        for event in EVENTS {
            let entry = &hooks[event][0]["hooks"][0];
            assert_eq!(entry["type"], "http", "{event}");
            assert_eq!(entry["url"], "http://127.0.0.1:47831/v1/hooks/claude-code");
            assert_eq!(entry["headers"]["X-AgentNest-Token"], "an_hk_TESTTOKEN");
            assert!(
                entry.get("onFailure").is_none(),
                "{event}: onFailure must be absent (I12)"
            );
            let want = match event {
                "PermissionRequest" => 150,
                "SessionEnd" => 1,
                _ => 5,
            };
            assert_eq!(entry["timeout"], want, "{event}");
        }
        assert_eq!(
            v["statusLine"],
            json!({"type": "command", "command": "agentnest-hook statusline"})
        );
    }

    #[test]
    fn on_failure_block_is_an_opt_in_on_the_permission_request_hook_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let mut o = opts();
        o.daemon_down_deny = true;
        install(&path, &o).unwrap();
        let v = read(&path);
        for event in EVENTS {
            let entry = &v["hooks"][event][0]["hooks"][0];
            if event == "PermissionRequest" {
                assert_eq!(entry["onFailure"], "block");
            } else {
                assert!(entry.get("onFailure").is_none(), "{event}");
            }
        }
        // turning the opt-in off again removes it
        install(&path, &opts()).unwrap();
        assert!(read(&path)["hooks"]["PermissionRequest"][0]["hooks"][0]
            .get("onFailure")
            .is_none());
    }

    #[test]
    fn the_permission_request_timeout_follows_the_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let mut o = opts();
        o.approval_ttl_s = 90;
        assert_eq!(
            install(&path, &o).unwrap().permission_request_timeout_s,
            120
        );
        assert_eq!(
            read(&path)["hooks"]["PermissionRequest"][0]["hooks"][0]["timeout"],
            120
        );
        let i = inspect(&path);
        assert_eq!(i.permission_request_timeout_s, Some(120));
        assert_eq!(i.port, Some(47831));
        assert!(i.fully_installed());
        assert!(i.statusline);
    }

    #[test]
    fn merging_preserves_unrelated_settings_and_hooks_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = json!({
            "model": "opus",
            "permissions": {"allow": ["Bash(git status)"], "deny": ["Read(.env)"]},
            "env": {"FOO": "bar"},
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter", "timeout": 10}]},
                    {"hooks": [{"type": "http", "url": "http://127.0.0.1:9000/other", "timeout": 5}]}
                ],
                "Stop": [{"hooks": [{"type": "command", "command": "notify-me"}]}],
                "ConfigChange": [{"hooks": [{"type": "command", "command": "audit"}]}]
            },
            "statusLine": {"type": "command", "command": "my-status-script"}
        });
        std::fs::write(&path, serde_json::to_string_pretty(&original).unwrap()).unwrap();
        let report = install(&path, &opts()).unwrap();
        assert!(
            report.backup.is_some(),
            "an existing file is backed up once"
        );
        assert_eq!(report.warnings, vec![InstallWarning::StatusLineExists]);
        let backup = read(report.backup.as_ref().unwrap());
        assert_eq!(backup, original, "the backup is the untouched original");
        let v = read(&path);
        assert_eq!(v["model"], "opus");
        assert_eq!(v["permissions"], original["permissions"]);
        assert_eq!(v["env"], original["env"]);
        assert_eq!(
            v["statusLine"], original["statusLine"],
            "somebody else's statusLine is kept"
        );
        assert_eq!(
            v["hooks"]["ConfigChange"],
            original["hooks"]["ConfigChange"]
        );
        // user hooks stay, ours are appended
        let pre = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 3);
        assert_eq!(pre[0], original["hooks"]["PreToolUse"][0]);
        assert_eq!(pre[1], original["hooks"]["PreToolUse"][1]);
        assert_eq!(
            pre[2]["hooks"][0]["url"],
            "http://127.0.0.1:47831/v1/hooks/claude-code"
        );
        assert_eq!(v["hooks"]["Stop"][0], original["hooks"]["Stop"][0]);
        assert_eq!(v["hooks"]["Stop"].as_array().unwrap().len(), 2);
        // idempotent: a second install changes nothing but the (new) backup
        install(&path, &opts()).unwrap();
        assert_eq!(read(&path), v, "no duplicates after reinstall");
        // a port change replaces our entries
        let mut o = opts();
        o.hook_port = 47833;
        install(&path, &o).unwrap();
        let v2 = read(&path);
        assert_eq!(v2["hooks"]["PreToolUse"].as_array().unwrap().len(), 3);
        assert_eq!(
            v2["hooks"]["PreToolUse"][2]["hooks"][0]["url"],
            "http://127.0.0.1:47833/v1/hooks/claude-code"
        );
    }

    #[test]
    fn uninstall_removes_only_agentnest_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = json!({
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}],
                "Stop": [{"hooks": [{"type": "command", "command": "notify-me"}]}]
            },
            "theme": "dark"
        });
        std::fs::write(&path, original.to_string()).unwrap();
        install(&path, &opts()).unwrap();
        let report = uninstall(&path).unwrap();
        assert_eq!(report.removed, 16);
        assert!(report.statusline_removed);
        assert_eq!(
            read(&path),
            original,
            "exactly the original content is back"
        );
        // uninstall twice / without a file is harmless
        assert_eq!(uninstall(&path).unwrap().removed, 0);
        assert_eq!(uninstall(&dir.path().join("none.json")).unwrap().removed, 0);
        // a mixed group keeps the user's hook
        let mixed = json!({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": "keep-me"},
            {"type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code", "timeout": 5}
        ]}]}});
        std::fs::write(&path, mixed.to_string()).unwrap();
        assert_eq!(uninstall(&path).unwrap().removed, 1);
        assert_eq!(
            read(&path),
            json!({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "keep-me"}]}]}})
        );
    }

    #[test]
    fn an_agentnest_statusline_is_updated_and_removed_with_the_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        install(&path, &opts()).unwrap();
        let mut o = opts();
        o.hook_cli = "C:\\Program Files\\AgentNest\\agentnest-hook.exe";
        let report = install(&path, &o).unwrap();
        assert!(
            report.warnings.is_empty(),
            "our own statusLine is not a conflict"
        );
        assert!(read(&path)["statusLine"]["command"]
            .as_str()
            .unwrap()
            .contains("Program Files"));
        assert!(uninstall(&path).unwrap().statusline_removed);
        assert!(read(&path).get("statusLine").is_none());
    }

    #[test]
    fn jsonc_or_broken_files_are_never_touched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        for bad in [
            "{\n  // comment\n  \"model\": \"opus\"\n}",
            "{\"hooks\": {},}",
            "not json at all",
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(
                matches!(install(&path, &opts()), Err(InstallError::NotPlainJson)),
                "{bad}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                bad,
                "the file is unchanged"
            );
            assert!(matches!(uninstall(&path), Err(InstallError::NotPlainJson)));
        }
        std::fs::write(&path, "[1,2]").unwrap();
        assert!(matches!(
            install(&path, &opts()),
            Err(InstallError::UnexpectedStructure(_))
        ));
        std::fs::write(&path, r#"{"hooks": []}"#).unwrap();
        assert!(matches!(
            install(&path, &opts()),
            Err(InstallError::UnexpectedStructure(_))
        ));
        std::fs::write(&path, r#"{"hooks": {"Stop": {"not": "an array"}}}"#).unwrap();
        assert!(matches!(
            install(&path, &opts()),
            Err(InstallError::UnexpectedStructure(_))
        ));
        // an empty file is an empty object
        std::fs::write(&path, "  \n").unwrap();
        install(&path, &opts()).unwrap();
    }

    #[test]
    fn command_mode_writes_exec_form_hooks_and_is_recognised_as_ours() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let mut o = opts();
        o.mode = HookMode::Cli;
        o.hook_cli = "C:\\Program Files\\AgentNest\\agentnest-hook.exe";
        o.install_statusline = false;
        install(&path, &o).unwrap();
        let v = read(&path);
        let entry = &v["hooks"]["PermissionRequest"][0]["hooks"][0];
        assert_eq!(entry["type"], "command");
        assert_eq!(
            entry["command"],
            "C:\\Program Files\\AgentNest\\agentnest-hook.exe"
        );
        assert_eq!(entry["args"], json!(["claude-code"]));
        assert_eq!(entry["timeout"], 150);
        assert!(
            entry.get("headers").is_none(),
            "no token in command mode: the CLI reads daemon.json"
        );
        assert!(v.get("statusLine").is_none());
        assert!(is_agentnest_hook(entry));
        assert_eq!(uninstall(&path).unwrap().removed, 16);
        // switching modes replaces the entries
        install(&path, &opts()).unwrap();
        install(&path, &o).unwrap();
        assert_eq!(inspect(&path).installed_events.len(), 16);
        assert_eq!(read(&path)["hooks"]["Stop"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn only_loopback_collector_urls_count_as_agentnest() {
        assert!(is_agentnest_hook(
            &json!({"type": "http", "url": "http://127.0.0.1:47831/v1/hooks/claude-code"})
        ));
        assert!(is_agentnest_hook(
            &json!({"type": "http", "url": "http://127.0.0.1:9/v1/hooks/claude-code"})
        ));
        for url in [
            "http://127.0.0.1:47831/v1/hooks/codex",
            "http://evil.example:47831/v1/hooks/claude-code",
            "http://127.0.0.1:/v1/hooks/claude-code",
            "http://127.0.0.1:abc/v1/hooks/claude-code",
            "https://127.0.0.1:47831/v1/hooks/claude-code",
            "http://127.0.0.1:47831/v1/hooks/claude-code/extra",
        ] {
            assert!(
                !is_agentnest_hook(&json!({"type": "http", "url": url})),
                "{url}"
            );
        }
        assert!(!is_agentnest_hook(
            &json!({"type": "command", "command": "agentnest-hook", "args": ["codex"]})
        ));
        assert!(!is_agentnest_hook(&json!({"type": "prompt"})));
    }

    #[test]
    fn allowed_http_hook_urls_policy_is_reported_not_edited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"allowedHttpHookUrls": ["https://example.com/*"]}"#,
        )
        .unwrap();
        let r = install(&path, &opts()).unwrap();
        assert_eq!(r.warnings, vec![InstallWarning::AllowedHttpHookUrlsMissing]);
        assert_eq!(
            read(&path)["allowedHttpHookUrls"],
            json!(["https://example.com/*"])
        );
        std::fs::write(
            &path,
            r#"{"allowedHttpHookUrls": ["http://127.0.0.1:47831/*"]}"#,
        )
        .unwrap();
        assert!(install(&path, &opts()).unwrap().warnings.is_empty());
        assert!(InstallWarning::AllowedHttpHookUrlsMissing
            .message_ko(47831)
            .contains("47831"));
    }

    #[test]
    fn effective_ttl_is_bounded_by_the_installed_timeout() {
        assert_eq!(effective_ttl_s(120, Some(150)), 120);
        assert_eq!(
            effective_ttl_s(180, Some(150)),
            120,
            "TTL raised without reinstalling is clamped"
        );
        assert_eq!(effective_ttl_s(60, Some(150)), 60);
        assert_eq!(effective_ttl_s(180, Some(210)), 180);
        assert_eq!(
            effective_ttl_s(180, None),
            120,
            "no readable hook: the default install is assumed"
        );
        assert_eq!(effective_ttl_s(90, None), 90);
        assert_eq!(
            effective_ttl_s(120, Some(20)),
            MIN_EFFECTIVE_TTL_S,
            "never zero"
        );
    }

    #[test]
    fn inspect_reports_absent_and_unreadable_files() {
        let dir = tempfile::tempdir().unwrap();
        let none = inspect(&dir.path().join("nope.json"));
        assert!(!none.exists && !none.parsed && !none.fully_installed());
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "// x").unwrap();
        let i = inspect(&bad);
        assert!(i.exists && !i.parsed);
        assert_eq!(i.permission_request_timeout_s, None);
    }

    // -- review item 13: symlinks, modes, backups, lossy re-serialisation ---------------------------------------------

    #[cfg(unix)]
    #[test]
    fn a_symlinked_settings_file_stays_a_link_and_its_target_is_updated_with_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("dotfiles").join("claude-settings.json");
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, r#"{"model":"opus"}"#).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("settings.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        install(&link, &opts()).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link is still a link"
        );
        assert_eq!(read(&real)["model"], "opus");
        assert!(
            inspect(&real).fully_installed(),
            "the linked file got the hooks"
        );
        assert_eq!(
            std::fs::metadata(&real).unwrap().permissions().mode() & 0o777,
            0o600,
            "the mode of the original is kept"
        );
        // uninstall goes through the link as well
        uninstall(&link).unwrap();
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!inspect(&real).exists || inspect(&real).installed_events.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_mode_of_an_existing_settings_file_is_kept() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        install(&path, &opts()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn backups_never_overwrite_each_other_and_the_first_one_is_the_original() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"model":"pristine"}"#).unwrap();
        // the same timestamp three times (a 1 s resolution used to collide)
        let first = install(&path, &opts()).unwrap().backup.unwrap();
        let second = install(&path, &opts()).unwrap().backup.unwrap();
        let third = install(&path, &opts()).unwrap().backup.unwrap();
        assert_ne!(first, second);
        assert_ne!(second, third);
        assert!(first
            .to_string_lossy()
            .ends_with(".agentnest-backup-20261015T091233Z"));
        assert!(second.to_string_lossy().ends_with("-1"));
        assert_eq!(
            std::fs::read_to_string(&first).unwrap(),
            r#"{"model":"pristine"}"#,
            "the pristine original survives later installs"
        );
        assert!(std::fs::read_to_string(&second)
            .unwrap()
            .contains("agentnest"));
    }

    #[test]
    fn lossy_reserialisation_is_reported_as_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"a":1,"a":2,"nested":{"x":1,"x":3},"big":12345678901234567890123}"#,
        )
        .unwrap();
        let w = install(&path, &opts()).unwrap().warnings;
        assert!(w.contains(&InstallWarning::DuplicateKeys), "{w:?}");
        assert!(w.contains(&InstallWarning::LargeNumbers), "{w:?}");
        assert!(w.iter().all(|x| !x.message_ko(47831).is_empty()));
        // an ordinary file raises neither
        let clean = dir.path().join("clean.json");
        std::fs::write(&clean, r#"{"a":1,"b":{"a":2},"list":[{"a":1},{"a":2}],"id":"12345678901234567890","n":1.5e300}"#).unwrap();
        let w = install(&clean, &opts()).unwrap().warnings;
        assert!(
            !w.contains(&InstallWarning::DuplicateKeys)
                && !w.contains(&InstallWarning::LargeNumbers),
            "{w:?}"
        );
    }
}
