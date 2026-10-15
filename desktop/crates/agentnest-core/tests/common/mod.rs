//! Helpers shared by the integration tests of `agentnest-core` (not a test target itself).
#![allow(dead_code)]

pub mod harness;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentnest_core::normalize::{FsProbe, NormalizeEnv, ProjectResolver, SequentialIdGen};
use agentnest_core::state::timers::ManualClock;
use jsonschema::{Registry, Validator};
use serde_json::Value;

/// `<repo>/protocol`.
pub fn protocol_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../protocol")
}

/// `tests/fixtures`.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Reads a JSON file.
pub fn read_json(path: &Path) -> Value {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// All `*.json` files directly in `dir`, sorted.
pub fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    v.sort();
    v
}

/// An in-memory file system view for project resolution.
#[derive(Default, Clone)]
pub struct MapFs {
    pub entries: HashMap<String, Option<String>>,
}

impl MapFs {
    pub fn dir(mut self, p: &str) -> Self {
        self.entries.insert(p.to_owned(), None);
        self
    }

    pub fn file(mut self, p: &str, content: &str) -> Self {
        self.entries.insert(p.to_owned(), Some(content.to_owned()));
        self
    }
}

impl FsProbe for MapFs {
    fn exists(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }

    fn read_small_file(&self, path: &str, max_bytes: u64) -> Option<String> {
        self.entries
            .get(path)
            .cloned()
            .flatten()
            .filter(|c| c.len() as u64 <= max_bytes)
    }
}

/// The file system of the golden tests: `C:\dev\agentnest` is a git checkout on `main` (origin `owner/agentnest`) with a
/// README and a source file.
pub fn golden_fs() -> MapFs {
    MapFs::default()
        .dir("C:/dev/agentnest/.git")
        .file("C:/dev/agentnest/.git/HEAD", "ref: refs/heads/main\n")
        .file(
            "C:/dev/agentnest/.git/config",
            "[remote \"origin\"]\n\turl = https://github.com/owner/agentnest.git\n",
        )
        .file("C:/dev/agentnest/README.md", "# AgentNest\n")
        .file("C:/dev/agentnest/src/main.rs", "fn main() {}\n")
}

/// Fixed clock (`2026-10-15T09:12:33.120Z`), sequential ids and the given file system.
pub fn golden_env(fs: MapFs) -> NormalizeEnv {
    let clock = Arc::new(ManualClock::new(1_792_055_553_120));
    NormalizeEnv::new(
        clock.clone(),
        Arc::new(SequentialIdGen::default()),
        Arc::new(ProjectResolver::with_probe(Box::new(fs), clock)),
    )
}

/// The protocol JSON schemas, compiled once.
pub struct Schemas {
    registry: &'static Registry<'static>,
    docs: BTreeMap<String, &'static Value>,
}

impl Schemas {
    pub fn load() -> Self {
        let dir = protocol_dir().join("schema");
        let mut docs = BTreeMap::new();
        let mut builder = Registry::new();
        fn walk(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            entries.sort();
            for p in entries {
                if p.is_dir() {
                    walk(base, &p, out);
                } else if p.extension().is_some_and(|e| e == "json") {
                    out.push(p.strip_prefix(base).unwrap().to_path_buf());
                }
            }
        }
        let mut files = Vec::new();
        walk(&dir, &dir, &mut files);
        for rel in files {
            let value: &'static Value = Box::leak(Box::new(read_json(&dir.join(&rel))));
            let id = value["$id"].as_str().unwrap().to_owned();
            builder = builder.add(id.as_str(), value).unwrap();
            docs.insert(rel.to_string_lossy().replace('\\', "/"), value);
        }
        let registry: &'static Registry<'static> = Box::leak(Box::new(builder.prepare().unwrap()));
        Schemas { registry, docs }
    }

    pub fn validator(&self, rel: &str) -> Validator {
        let schema = self
            .docs
            .get(rel)
            .unwrap_or_else(|| panic!("no schema {rel}"));
        jsonschema::options()
            .with_registry(self.registry)
            .build(schema)
            .unwrap()
    }
}

/// Validates an `AgentEvent` JSON value (with a `seq` injected, the schema requires one) and returns the errors.
pub fn agent_event_errors(validator: &Validator, event: &Value) -> Vec<String> {
    let mut v = event.clone();
    if let Value::Object(m) = &mut v {
        m.entry("seq").or_insert(serde_json::json!(1));
    }
    validator
        .iter_errors(&v)
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect()
}

/// `true` if every key of `expected` is present in `actual` with a matching value (objects recursively; `null` in
/// `expected` matches an absent or null value).
pub fn subset(expected: &Value, actual: &Value) -> Result<(), String> {
    match (expected, actual) {
        (Value::Null, Value::Null) => Ok(()),
        (Value::Object(e), Value::Object(a)) => {
            for (k, ev) in e {
                match a.get(k) {
                    Some(av) => subset(ev, av).map_err(|m| format!("{k}.{m}"))?,
                    None if ev.is_null() => {}
                    None => return Err(format!("{k}: missing (want {ev})")),
                }
            }
            Ok(())
        }
        (e, a) if e == a => Ok(()),
        (e, a) => Err(format!("want {e}, got {a}")),
    }
}

fn str_len_at(v: &Value, dotted: &str) -> Option<usize> {
    let mut cur = v;
    for part in dotted.split('.') {
        cur = cur.get(part)?;
    }
    cur.as_str().map(|s| s.chars().count())
}

/// Checks one produced event against its expectation: schema, size limits and a subset match on the fields that matter
/// (`kind`, `category`, `severity`, `state_hint`, `headline`, `summary_detail`, `detail`, `actor`, `native_ids`,
/// `native_event`, `channel`, `project`, `redacted`, plus `max_lengths` on dotted paths). Returns the problems and the
/// serialised event (for the forbidden-substring check).
pub fn check_event(
    name: &str,
    index: usize,
    event: &agentnest_protocol::AgentEvent,
    want: &Value,
    validator: &Validator,
) -> (Vec<String>, String) {
    let mut problems = Vec::new();
    let actual = serde_json::to_value(event).unwrap();
    let errs = agent_event_errors(validator, &actual);
    if !errs.is_empty() {
        problems.push(format!("{name}[{index}]: schema errors {errs:?}\n{actual}"));
    }
    if serde_json::to_vec(&event.detail).unwrap().len() > 8192 {
        problems.push(format!("{name}[{index}]: detail over 8 KiB"));
    }
    if event.summary.headline.chars().count() > 40
        || event
            .summary
            .detail
            .as_deref()
            .is_some_and(|d| d.chars().count() > 200)
    {
        problems.push(format!("{name}[{index}]: summary over its limit"));
    }
    let mut view = serde_json::Map::new();
    let null = Value::Null;
    for (k, v) in [
        ("kind", &actual["kind"]),
        ("category", &actual["category"]),
        ("severity", &actual["severity"]),
        ("state_hint", actual.get("state_hint").unwrap_or(&null)),
        ("headline", &actual["summary"]["headline"]),
        (
            "summary_detail",
            actual["summary"].get("detail").unwrap_or(&null),
        ),
        ("detail", &actual["detail"]),
        ("actor", actual.get("actor").unwrap_or(&null)),
        ("native_ids", &actual["source"]["native_ids"]),
        (
            "native_event",
            actual["source"].get("native_event").unwrap_or(&null),
        ),
        ("channel", &actual["source"]["channel"]),
        ("project", actual.get("project").unwrap_or(&null)),
        ("redacted", &actual["redacted"]),
    ] {
        view.insert(k.to_owned(), v.clone());
    }
    let mut want_obj = want.clone();
    let max_lengths = want_obj
        .as_object_mut()
        .and_then(|m| m.remove("max_lengths"));
    if let Err(m) = subset(&want_obj, &Value::Object(view)) {
        problems.push(format!("{name}[{index}] {}: {m}", event.kind));
    }
    if let Some(Value::Object(limits)) = max_lengths {
        for (path, max) in limits {
            let max = max.as_u64().unwrap() as usize;
            let len = match path.strip_prefix("summary.") {
                Some(rest) => str_len_at(&actual["summary"], rest),
                None => str_len_at(&actual, &path),
            };
            match len {
                Some(l) if l <= max => {}
                other => problems.push(format!(
                    "{name}[{index}]: {path} length {other:?} exceeds {max}"
                )),
            }
        }
    }
    (problems, actual.to_string())
}
