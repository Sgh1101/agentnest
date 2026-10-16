//! security.md I5 / 12 #6: an `ApprovalReply` allow exists only behind an `ApplyProof`, and `ApplyProof::mint` has exactly
//! one non-test call site (the success branch of `Broker::apply_decision`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name == "node_modules" || name == "tests" {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Non-test source: everything before the first `#[cfg(test)]`, without comment lines.
fn production_lines(path: &Path) -> Vec<(usize, String)> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        out.push((i + 1, line.to_owned()));
    }
    out
}

fn desktop_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn exactly_one_non_test_site_mints_a_proof_and_creates_an_allow_reply() {
    let mut files = Vec::new();
    rust_files(&desktop_root().join("crates"), &mut files);
    rust_files(&desktop_root().join("apps"), &mut files);
    assert!(files.len() > 30, "the scan found the sources");
    let mut mints = Vec::new();
    let mut allows = Vec::new();
    let mut test_helpers = Vec::new();
    for f in &files {
        // Compare paths with `/` on every platform (Windows yields `\`).
        let shown = f.display().to_string().replace('\\', "/");
        for (n, line) in production_lines(f) {
            if line.contains("ApplyProof::mint(") {
                mints.push(format!("{shown}:{n}"));
            }
            if line.contains("ApprovalReply::allow(") {
                allows.push(format!("{shown}:{n}"));
            }
            if (line.contains("allow_for_test(") || line.contains("mint_for_test("))
                && !f.ends_with("reply.rs")
            {
                test_helpers.push(format!("{shown}:{n}"));
            }
        }
    }
    assert_eq!(mints.len(), 1, "ApplyProof::mint call sites: {mints:?}");
    assert_eq!(
        allows.len(),
        1,
        "ApprovalReply::allow call sites: {allows:?}"
    );
    assert!(mints[0].contains("approvals/broker.rs"), "{mints:?}");
    assert!(allows[0].contains("approvals/broker.rs"), "{allows:?}");
    assert!(
        test_helpers.is_empty(),
        "test-only constructors used in production code: {test_helpers:?}"
    );
    // and the mint call carries the visible lint exception
    let text = std::fs::read_to_string(
        desktop_root().join("crates/agentnest-core/src/approvals/broker.rs"),
    )
    .unwrap();
    let at = text.find("ApplyProof::mint(").unwrap();
    assert!(text[..at]
        .rfind("#[allow(clippy::disallowed_methods)]")
        .is_some_and(|p| at - p < 200));
}

#[test]
fn the_release_dependency_graph_does_not_enable_the_adapter_test_util_feature() {
    // core / hook / desktop depend on adapter-api without `test-util`; only dev-dependencies could turn it on
    for manifest in [
        "crates/agentnest-core/Cargo.toml",
        "crates/agentnest-hook/Cargo.toml",
        "apps/desktop/src-tauri/Cargo.toml",
    ] {
        let path = desktop_root().join(manifest);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let normal = text.split("[dev-dependencies]").next().unwrap();
        assert!(
            !normal.contains("test-util"),
            "{manifest} enables test-util in a normal dependency"
        );
    }
}
