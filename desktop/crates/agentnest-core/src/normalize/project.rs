//! Project resolution from a working directory, without shelling out to git.
//!
//! The project root is the nearest ancestor of `cwd` that contains a `.git` entry (directory, or file for worktrees
//! and submodules). The name is the root's basename, the key its lower-cased `/` path. `repo` (`owner/name`) comes from
//! the `origin` remote in `.git/config`, `branch` from `.git/HEAD`; both are read with plain file reads and are best
//! effort. Credentials in remote URLs are never carried over: only `owner/name` is kept.
//!
//! File system access goes through [`FsProbe`] so tests can run with an in-memory file system (and with Windows-style
//! paths on Linux).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use agentnest_protocol::ProjectRef;

use super::path;
use crate::state::timers::{Clock, SystemClock};

/// Minimal file system view used by the resolver.
pub trait FsProbe: Send + Sync {
    /// `true` if a file or directory exists at `path` (a `/`-separated path).
    fn exists(&self, path: &str) -> bool;
    /// Reads a small text file. `None` for directories, missing files and files larger than `max_bytes`.
    fn read_small_file(&self, path: &str, max_bytes: u64) -> Option<String>;
}

/// The real file system.
#[derive(Clone, Copy, Debug, Default)]
pub struct RealFs;

impl FsProbe for RealFs {
    fn exists(&self, p: &str) -> bool {
        std::fs::symlink_metadata(p).is_ok()
    }

    fn read_small_file(&self, p: &str, max_bytes: u64) -> Option<String> {
        let meta = std::fs::metadata(p).ok()?;
        if !meta.is_file() || meta.len() > max_bytes {
            return None;
        }
        std::fs::read_to_string(p).ok()
    }
}

const MAX_WALK: usize = 64;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const CACHE_TTL_MS: i64 = 30_000;
const CACHE_MAX: usize = 256;

fn join(dir: &str, child: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{child}")
    } else {
        format!("{dir}/{child}")
    }
}

/// The parent of a normalised absolute directory, or `None` at the root.
fn parent(dir: &str) -> Option<String> {
    let trimmed = dir.trim_end_matches('/');
    let idx = trimmed.rfind('/')?;
    if idx == 0 {
        return if trimmed.len() > 1 {
            Some("/".to_owned())
        } else {
            None
        };
    }
    let p = &trimmed[..idx];
    // `c:` -> `c:/`
    if p.len() == 2 && p.ends_with(':') {
        return Some(format!("{p}/"));
    }
    Some(p.to_owned())
}

/// Walks up from `cwd` (normalised) looking for a `.git` entry. Returns the root directory.
pub fn find_git_root(fs: &dyn FsProbe, cwd: &str) -> Option<String> {
    let mut dir = cwd.to_owned();
    for _ in 0..MAX_WALK {
        if fs.exists(&join(&dir, ".git")) {
            return Some(dir);
        }
        dir = parent(&dir)?;
    }
    None
}

/// `owner/name` from a git remote URL (`https://github.com/o/r.git`, `git@github.com:o/r.git`, `ssh://git@h/o/r`).
/// Credentials, host and everything but the last two path segments are dropped.
pub fn parse_remote_url(url: &str) -> Option<String> {
    let u = url.trim();
    let tail = if let Some(i) = u.find("://") {
        let after = &u[i + 3..];
        after.split_once('/').map(|(_, p)| p)?
    } else if let Some((_, p)) = u.split_once(':') {
        // scp-like: git@github.com:owner/name.git
        p
    } else {
        return None;
    };
    let tail = tail.split(['?', '#']).next().unwrap_or("");
    let tail = tail.trim_matches('/');
    let tail = tail.strip_suffix(".git").unwrap_or(tail);
    let segs: Vec<&str> = tail.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() < 2 {
        return None;
    }
    let (owner, name) = (segs[segs.len() - 2], segs[segs.len() - 1]);
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    (ok(owner) && ok(name)).then(|| format!("{owner}/{name}"))
}

/// The `url` of `[remote "origin"]` (or of the first remote) in a git config text.
pub fn origin_url_from_config(config: &str) -> Option<String> {
    let mut section = String::new();
    let mut first: Option<String> = None;
    for line in config.lines() {
        let l = line.trim();
        if l.starts_with('[') && l.ends_with(']') {
            section = l[1..l.len() - 1].trim().to_owned();
            continue;
        }
        if !section.starts_with("remote ") {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            if k.trim() == "url" {
                let v = v.trim().to_owned();
                if section == "remote \"origin\"" {
                    return Some(v);
                }
                first.get_or_insert(v);
            }
        }
    }
    first
}

/// The branch from the text of `.git/HEAD` (`ref: refs/heads/feat/x` -> `feat/x`; a detached HEAD yields the short hash).
pub fn branch_from_head(head: &str) -> Option<String> {
    let h = head.trim();
    if let Some(r) = h.strip_prefix("ref:") {
        let r = r.trim();
        let b = r.strip_prefix("refs/heads/").unwrap_or(r);
        return Some(b.chars().take(100).collect()).filter(|s: &String| !s.is_empty());
    }
    if h.len() >= 7 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(h[..7].to_owned());
    }
    None
}

fn read_git_info(fs: &dyn FsProbe, root: &str) -> (Option<String>, Option<String>) {
    let dot_git = join(root, ".git");
    let (gitdir, common): (String, String) = match fs.read_small_file(&join(&dot_git, "HEAD"), 4096)
    {
        Some(_) => (dot_git.clone(), dot_git.clone()),
        None => {
            // `.git` is a file in worktrees and submodules: `gitdir: <path>`
            let Some(text) = fs.read_small_file(&dot_git, 4096) else {
                return (None, None);
            };
            let Some(target) = text.trim().strip_prefix("gitdir:").map(str::trim) else {
                return (None, None);
            };
            let gitdir = path::resolve(target, Some(root));
            let common = fs
                .read_small_file(&join(&gitdir, "commondir"), 1024)
                .map(|c| path::resolve(c.trim(), Some(&gitdir)))
                .unwrap_or_else(|| gitdir.clone());
            (gitdir, common)
        }
    };
    let branch = fs
        .read_small_file(&join(&gitdir, "HEAD"), 4096)
        .and_then(|h| branch_from_head(&h));
    let repo = fs
        .read_small_file(&join(&common, "config"), MAX_CONFIG_BYTES)
        .and_then(|c| origin_url_from_config(&c))
        .and_then(|u| parse_remote_url(&u));
    (repo, branch)
}

/// Builds the project reference for `root` without any file system access.
pub fn project_from_root(root: &str, repo: Option<String>, branch: Option<String>) -> ProjectRef {
    let norm = path::normalize(root);
    let base = path::basename(&norm);
    let name = if base.is_empty() || base == "." || (base.len() == 2 && base.ends_with(':')) {
        if norm.is_empty() || norm == "." {
            "프로젝트".to_owned()
        } else {
            norm.clone()
        }
    } else {
        base.to_owned()
    };
    ProjectRef {
        project_key: path::project_key(&norm),
        name: name.chars().take(100).collect(),
        path_hint: Some(path::path_hint(&norm)),
        repo,
        branch,
    }
}

/// Resolves and caches projects. Cheap to call on every event: results are cached for 30 seconds (the branch can
/// change) and the cache is bounded.
pub struct ProjectResolver {
    fs: Box<dyn FsProbe>,
    clock: Arc<dyn Clock>,
    cache: Mutex<HashMap<String, (i64, ProjectRef)>>,
}

impl std::fmt::Debug for ProjectResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectResolver").finish_non_exhaustive()
    }
}

impl Default for ProjectResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProjectResolver {
    /// The real file system and the wall clock.
    pub fn new() -> Self {
        Self::with_probe(Box::new(RealFs), Arc::new(SystemClock))
    }

    /// A resolver over any [`FsProbe`] and [`Clock`] (tests).
    pub fn with_probe(fs: Box<dyn FsProbe>, clock: Arc<dyn Clock>) -> Self {
        Self {
            fs,
            clock,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// `true` if a path (Windows or POSIX style) exists in the file system view; used to tell a new file from an
    /// overwrite for `Write` summaries.
    pub fn path_exists(&self, p: &str) -> bool {
        self.fs.exists(&path::normalize(p))
    }

    /// The project of a working directory (Windows or POSIX style). Without a `.git` ancestor the working directory
    /// itself is the project.
    pub fn resolve(&self, cwd: &str) -> ProjectRef {
        let norm = path::normalize(&path::expand_home_alias(cwd));
        let now = self.clock.now_ms();
        if let Ok(cache) = self.cache.lock() {
            if let Some((at, p)) = cache.get(&norm) {
                if now - *at < CACHE_TTL_MS {
                    return p.clone();
                }
            }
        }
        let project = match find_git_root(self.fs.as_ref(), &norm) {
            Some(root) => {
                let (repo, branch) = read_git_info(self.fs.as_ref(), &root);
                project_from_root(&root, repo, branch)
            }
            None => project_from_root(&norm, None, None),
        };
        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() >= CACHE_MAX {
                cache.clear();
            }
            cache.insert(norm, (now, project.clone()));
        }
        project
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// An in-memory file system: `files` maps `/`-separated paths to contents; directories are implied by `dirs`.
    #[derive(Default)]
    pub struct FakeFs {
        pub files: HashMap<String, String>,
        pub dirs: Vec<String>,
    }

    impl FsProbe for FakeFs {
        fn exists(&self, p: &str) -> bool {
            self.dirs.iter().any(|d| d == p) || self.files.contains_key(p)
        }
        fn read_small_file(&self, p: &str, max_bytes: u64) -> Option<String> {
            self.files
                .get(p)
                .filter(|c| c.len() as u64 <= max_bytes)
                .cloned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeFs;
    use super::*;
    use crate::state::timers::ManualClock;

    fn resolver(fs: FakeFs) -> (ProjectResolver, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new(0));
        (
            ProjectResolver::with_probe(Box::new(fs), clock.clone()),
            clock,
        )
    }

    #[test]
    fn finds_the_git_root_of_a_windows_cwd() {
        let mut fs = FakeFs::default();
        fs.dirs.push("C:/dev/agentnest/.git".to_owned());
        fs.files.insert(
            "C:/dev/agentnest/.git/HEAD".to_owned(),
            "ref: refs/heads/feat/pairing\n".to_owned(),
        );
        fs.files.insert(
            "C:/dev/agentnest/.git/config".to_owned(),
            "[core]\n\turl = nope\n[remote \"origin\"]\n\turl = https://token:x@github.com/owner/agentnest.git\n".to_owned(),
        );
        let (r, _) = resolver(fs);
        let p = r.resolve("C:\\dev\\agentnest\\desktop\\crates");
        assert_eq!(p.project_key, "c:/dev/agentnest");
        assert_eq!(p.name, "agentnest");
        assert_eq!(p.path_hint.as_deref(), Some("…\\dev\\agentnest"));
        assert_eq!(p.repo.as_deref(), Some("owner/agentnest"));
        assert_eq!(p.branch.as_deref(), Some("feat/pairing"));
    }

    #[test]
    fn falls_back_to_the_cwd_without_git() {
        let (r, _) = resolver(FakeFs::default());
        let p = r.resolve("/home/me/scratch/");
        assert_eq!(p.project_key, "/home/me/scratch");
        assert_eq!(p.name, "scratch");
        assert_eq!(p.path_hint.as_deref(), Some("…/me/scratch"));
        assert!(p.repo.is_none() && p.branch.is_none());
        let p = r.resolve("C:\\");
        assert_eq!(p.project_key, "c:/");
        assert_eq!(p.name, "C:/");
        let p = r.resolve("");
        assert_eq!(p.name, "프로젝트");
    }

    #[test]
    fn worktrees_follow_the_gitdir_file() {
        let mut fs = FakeFs::default();
        fs.files.insert(
            "/w/feature/.git".to_owned(),
            "gitdir: /main/.git/worktrees/feature\n".to_owned(),
        );
        fs.files.insert(
            "/main/.git/worktrees/feature/HEAD".to_owned(),
            "ref: refs/heads/feature\n".to_owned(),
        );
        fs.files.insert(
            "/main/.git/worktrees/feature/commondir".to_owned(),
            "../..\n".to_owned(),
        );
        fs.files.insert(
            "/main/.git/config".to_owned(),
            "[remote \"origin\"]\nurl = git@github.com:o/r.git\n".to_owned(),
        );
        let (r, _) = resolver(fs);
        let p = r.resolve("/w/feature/src");
        assert_eq!(p.name, "feature");
        assert_eq!(p.branch.as_deref(), Some("feature"));
        assert_eq!(p.repo.as_deref(), Some("o/r"));
    }

    #[test]
    fn results_are_cached_for_30_seconds() {
        let mut fs = FakeFs::default();
        fs.dirs.push("/p/.git".to_owned());
        fs.files
            .insert("/p/.git/HEAD".to_owned(), "ref: refs/heads/a\n".to_owned());
        let (r, clock) = resolver(fs);
        assert_eq!(r.resolve("/p").branch.as_deref(), Some("a"));
        clock.advance(10_000);
        assert_eq!(r.resolve("/p/src").branch.as_deref(), Some("a"));
        clock.advance(31_000);
        assert_eq!(r.resolve("/p").branch.as_deref(), Some("a"));
    }

    #[test]
    fn remote_url_forms() {
        for (u, want) in [
            ("https://github.com/o/r.git", Some("o/r")),
            ("https://user:pw@github.com/o/r", Some("o/r")),
            ("git@github.com:o/r.git", Some("o/r")),
            (
                "ssh://git@host.example:2222/org/team/repo.git",
                Some("team/repo"),
            ),
            ("file:///srv/git/r.git", Some("git/r")),
            ("https://github.com/only", None),
            ("not a url", None),
            ("", None),
            ("https://github.com/o/r with space", None),
        ] {
            assert_eq!(parse_remote_url(u).as_deref(), want, "{u}");
        }
    }

    #[test]
    fn head_forms() {
        assert_eq!(
            branch_from_head("ref: refs/heads/main\n").as_deref(),
            Some("main")
        );
        assert_eq!(
            branch_from_head("0123456789abcdef0123456789abcdef01234567").as_deref(),
            Some("0123456")
        );
        assert_eq!(branch_from_head("garbage"), None);
        assert_eq!(branch_from_head(""), None);
        assert_eq!(
            origin_url_from_config("[remote \"up\"]\nurl = u1\n[remote \"origin\"]\nurl = u2\n")
                .as_deref(),
            Some("u2")
        );
        assert_eq!(
            origin_url_from_config("[remote \"up\"]\nurl = u1\n").as_deref(),
            Some("u1")
        );
        assert_eq!(origin_url_from_config("[core]\nurl = x\n"), None);
    }

    #[test]
    fn walking_up_terminates_on_every_input() {
        let fs = FakeFs::default();
        for cwd in ["", "/", "C:", "C:/", "//", "a", "a/b/c", &"x/".repeat(200)] {
            let n = path::normalize(cwd);
            let _ = find_git_root(&fs, &n);
        }
    }

    #[test]
    fn real_fs_smoke() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("repo/.git")).unwrap();
        std::fs::create_dir_all(dir.path().join("repo/src/deep")).unwrap();
        std::fs::write(dir.path().join("repo/.git/HEAD"), "ref: refs/heads/dev\n").unwrap();
        let r = ProjectResolver::new();
        let p = r.resolve(dir.path().join("repo/src/deep").to_str().unwrap());
        assert_eq!(p.name, "repo");
        assert_eq!(p.branch.as_deref(), Some("dev"));
    }
}
