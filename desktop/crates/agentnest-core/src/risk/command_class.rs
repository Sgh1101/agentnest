//! `command_class`: the coarse class of a shell command (protocol.md 5.2), shared by the risk classifier (rule
//! `test_or_build`), the normalisers (`command_started.detail.command_class`, `test_run`/`test_passed`/`test_failed`
//! decisions) and the state reducer (`testing` for `test`/`build`).
//!
//! The class of a *command line* is derived from its segments: `test` if any segment is a test run, otherwise `build`
//! if any segment is a build, otherwise the class of the first segment that is not neutral (`cd`, `echo`, `export`, a
//! filter after a pipe, ...). Wrappers (`sudo`, `env`, `time`, ...) and interpreter payloads (`bash -c "..."`) are looked
//! through.

use agentnest_protocol::CommandClass;

use super::tokenizer::{
    base_command, inner_payload, is_assignment, is_flag, split_segments, unwrap_command, Inner,
    Segment, Shell,
};

/// Network fetchers: their output must not be piped into a shell (`remote_code_exec`).
pub const FETCH_TOOLS: &[&str] = &[
    "curl",
    "wget",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
];

/// Tools of class `network` (protocol.md 5.2) and rule `network_tool`.
pub const NETWORK_TOOLS: &[&str] = &[
    "curl",
    "wget",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
    "ssh",
    "scp",
    "sftp",
];

const FS_TOOLS: &[&str] = &[
    "ls",
    "cat",
    "find",
    "rg",
    "grep",
    "dir",
    "get-childitem",
    "gci",
    "type",
    "get-content",
    "gc",
    "head",
    "tail",
    "wc",
    "tree",
    "stat",
    "fd",
    "findstr",
    "select-string",
    "sls",
    "less",
    "more",
];

const BUILD_TOOLS: &[&str] = &[
    "tsc", "webpack", "esbuild", "rollup", "eslint", "prettier", "rustfmt", "rustc", "javac",
    "gcc", "g++", "clang", "clang++", "biome",
];

const TEST_TOOLS: &[&str] = &[
    "pytest", "py.test", "tox", "nox", "vitest", "jest", "ctest", "phpunit", "rspec", "mocha",
    "karma", "ava",
];

const PACKAGE_MANAGERS: &[&str] = &[
    "winget", "choco", "scoop", "brew", "apt", "apt-get", "yum", "dnf", "pacman", "zypper", "apk",
    "gem", "conda", "mamba", "nuget", "composer", "pipx",
];

/// Segments that do not say anything about what the command does (`cd`, `echo`, assignments, ...).
const NEUTRAL: &[&str] = &[
    "cd",
    "pushd",
    "popd",
    "chdir",
    "set-location",
    "sl",
    "export",
    "unset",
    "echo",
    "printf",
    "write-host",
    "write-output",
    "true",
    "false",
    ":",
    "sleep",
    "exit",
];

/// Read-only text filters that are neutral when they consume a pipe (`cargo test | tail -5`).
const PIPE_FILTERS: &[&str] = &[
    "head",
    "tail",
    "wc",
    "sort",
    "uniq",
    "cut",
    "tr",
    "tee",
    "grep",
    "rg",
    "awk",
    "sed",
    "less",
    "more",
    "jq",
    "select-string",
    "sls",
    "out-string",
    "out-host",
    "format-table",
    "ft",
    "select-object",
    "where-object",
    "measure-object",
];

/// The class of a command line written for `Bash` (and anything unknown).
pub fn command_class(command: &str) -> CommandClass {
    command_class_for(command, Shell::Posix)
}

/// The class of a command line written for `shell`.
pub fn command_class_for(command: &str, shell: Shell) -> CommandClass {
    let mut classes = Vec::new();
    collect_classes(command, shell, 0, &mut classes);
    pick(&classes)
}

fn pick(classes: &[CommandClass]) -> CommandClass {
    if classes.contains(&CommandClass::Test) {
        CommandClass::Test
    } else if classes.contains(&CommandClass::Build) {
        CommandClass::Build
    } else {
        classes.first().cloned().unwrap_or(CommandClass::Shell)
    }
}

fn collect_classes(command: &str, shell: Shell, depth: u8, out: &mut Vec<CommandClass>) {
    for seg in split_segments(command, shell) {
        if is_neutral_segment(&seg) {
            continue;
        }
        let unwrapped = unwrap_command(&seg.tokens);
        if depth < 3 {
            if let Some(Inner::Command(inner)) = inner_payload(unwrapped.tokens) {
                collect_classes(&inner, shell, depth + 1, out);
                continue;
            }
        }
        out.push(segment_class(&seg.tokens));
    }
}

/// `true` if the segment contributes neither a rule nor a class (see the module docs).
pub fn is_neutral_segment(seg: &Segment) -> bool {
    let u = unwrap_command(&seg.tokens);
    let Some(first) = u.tokens.first() else {
        // nothing but assignments, or nothing at all once shell syntax (`fi`, `done`, `}`) was removed; a bare wrapper
        // (`sudo`) is not neutral
        return seg.tokens.iter().all(|t| is_assignment(t));
    };
    let name = base_command(first);
    if seg.piped && PIPE_FILTERS.contains(&name.as_str()) {
        return true;
    }
    NEUTRAL.contains(&name.as_str())
}

/// The class of one segment (given as tokens).
pub fn segment_class(tokens: &[String]) -> CommandClass {
    class_of(tokens, 0)
}

fn lower(tokens: &[String]) -> Vec<String> {
    tokens.iter().map(|t| t.to_lowercase()).collect()
}

/// The first token that is not a flag (and not the value of one of `value_flags`).
fn first_non_flag<'a>(args: &'a [String], value_flags: &[&str]) -> Option<(usize, &'a str)> {
    let mut i = 0;
    while i < args.len() {
        let t = &args[i];
        if t.starts_with('+') {
            i += 1; // cargo +nightly
        } else if is_flag(t) {
            if value_flags.contains(&t.as_str()) {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            return Some((i, t.as_str()));
        }
    }
    None
}

fn script_class(script: &str) -> CommandClass {
    let s = script.to_lowercase();
    let starts = |p: &[&str]| p.iter().any(|x| s.starts_with(x));
    if starts(&["test", "jest", "vitest", "e2e", "spec"]) {
        CommandClass::Test
    } else if starts(&[
        "build",
        "typecheck",
        "type-check",
        "lint",
        "check",
        "compile",
        "format",
        "fmt",
        "tsc",
        "prettier",
        "eslint",
    ]) {
        CommandClass::Build
    } else {
        CommandClass::Shell
    }
}

fn class_of(tokens: &[String], depth: u8) -> CommandClass {
    let u = unwrap_command(tokens);
    let t = u.tokens;
    let Some(first) = t.first() else {
        return CommandClass::Shell;
    };
    let name = base_command(first);
    let n = name.as_str();
    let args = &t[1..];
    let args_lc = lower(args);

    if NETWORK_TOOLS.contains(&n) {
        return CommandClass::Network;
    }
    if FS_TOOLS.contains(&n) {
        return CommandClass::Fs;
    }
    if TEST_TOOLS.contains(&n) {
        return CommandClass::Test;
    }
    if BUILD_TOOLS.contains(&n) {
        return CommandClass::Build;
    }
    if PACKAGE_MANAGERS.contains(&n) {
        return match first_non_flag(&args_lc, &[]).map(|(_, s)| s) {
            Some("install" | "add" | "remove" | "uninstall" | "upgrade" | "i") => {
                CommandClass::Package
            }
            _ => CommandClass::Shell,
        };
    }
    match n {
        "git" | "gh" => CommandClass::Vcs,
        "cargo" => match first_non_flag(&args_lc, &[]).map(|(_, s)| s) {
            Some("test" | "t" | "nextest") => CommandClass::Test,
            Some("build" | "b" | "check" | "c" | "clippy" | "fmt" | "doc" | "bench") => {
                CommandClass::Build
            }
            Some("add" | "install" | "remove" | "rm" | "uninstall" | "update") => {
                CommandClass::Package
            }
            _ => CommandClass::Shell,
        },
        "npm" | "pnpm" | "yarn" | "bun" => {
            let value_flags = [
                "--filter",
                "-f",
                "-c",
                "--dir",
                "--prefix",
                "-w",
                "--workspace",
                "--cwd",
            ];
            let Some((idx, sub)) = first_non_flag(&args_lc, &value_flags) else {
                return CommandClass::Shell;
            };
            match sub {
                "test" | "t" | "tst" => CommandClass::Test,
                "install" | "i" | "ci" | "add" | "remove" | "rm" | "uninstall" | "un"
                | "update" | "up" | "link" | "unlink" => CommandClass::Package,
                "run" | "run-script" => first_non_flag(&args[idx + 1..], &[])
                    .map(|(_, s)| script_class(s))
                    .unwrap_or(CommandClass::Shell),
                "exec" | "dlx" | "x" if depth < 3 => class_of(&args[idx + 1..], depth + 1),
                other => match script_class(other) {
                    CommandClass::Test => CommandClass::Shell, // `pnpm testfoo` is not necessarily a test
                    c => c,
                },
            }
        }
        "npx" | "bunx" | "pnpx" if depth < 3 => {
            let rest = skip_npx_flags(args);
            class_of(rest, depth + 1)
        }
        "python" | "python3" | "py" | "pypy" | "pypy3" => {
            let Some(pos) = args_lc.iter().position(|a| a == "-m") else {
                return CommandClass::Shell;
            };
            match args_lc.get(pos + 1).map(String::as_str) {
                Some("pytest" | "unittest" | "tox" | "nox") => CommandClass::Test,
                Some("pip" | "ensurepip") => match args_lc.get(pos + 2).map(String::as_str) {
                    Some("install" | "uninstall") => CommandClass::Package,
                    _ => CommandClass::Shell,
                },
                Some("build" | "compileall") => CommandClass::Build,
                _ => CommandClass::Shell,
            }
        }
        "pip" | "pip3" => match first_non_flag(&args_lc, &[]).map(|(_, s)| s) {
            Some("install" | "uninstall") => CommandClass::Package,
            _ => CommandClass::Shell,
        },
        "uv" | "poetry" | "pdm" | "hatch" => match first_non_flag(&args_lc, &[]) {
            Some((_, "add" | "sync" | "pip" | "remove" | "install" | "update" | "lock")) => {
                CommandClass::Package
            }
            Some((i, "run")) if depth < 3 => class_of(&args[i + 1..], depth + 1),
            _ => CommandClass::Shell,
        },
        "go" => match first_non_flag(&args_lc, &["-c"]).map(|(_, s)| s) {
            Some("test") => CommandClass::Test,
            Some("build" | "vet" | "fmt") => CommandClass::Build,
            Some("get" | "install" | "mod") => CommandClass::Package,
            _ => CommandClass::Shell,
        },
        "mvn" | "mvnw" => {
            if args_lc.iter().any(|a| a == "test") {
                CommandClass::Test
            } else if args_lc.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "compile" | "package" | "verify" | "install" | "clean" | "assemble"
                )
            }) {
                CommandClass::Build
            } else {
                CommandClass::Shell
            }
        }
        "dotnet" => match first_non_flag(&args_lc, &[]).map(|(_, s)| s) {
            Some("test") => CommandClass::Test,
            Some("build" | "msbuild" | "clean") => CommandClass::Build,
            Some("add" | "restore") => CommandClass::Package,
            _ => CommandClass::Shell,
        },
        "gradlew" | "gradle" => {
            if args_lc.iter().any(|a| a.contains("test")) {
                CommandClass::Test
            } else if args_lc.iter().any(|a| {
                [
                    "assemble", "build", "lint", "compile", "jar", "bundle", "check", "detekt",
                    "ktlint", "spotless",
                ]
                .iter()
                .any(|k| a.contains(k))
            }) {
                CommandClass::Build
            } else {
                CommandClass::Shell
            }
        }
        "make" | "gmake" | "nmake" => {
            if args_lc
                .iter()
                .any(|a| matches!(a.as_str(), "test" | "tests" | "check"))
            {
                CommandClass::Test
            } else {
                CommandClass::Build
            }
        }
        "ninja" | "cmake" | "msbuild" | "xcodebuild" => CommandClass::Build,
        "vite" => match first_non_flag(&args_lc, &[]).map(|(_, s)| s) {
            Some("build") => CommandClass::Build,
            _ => CommandClass::Shell,
        },
        _ => CommandClass::Shell,
    }
}

fn skip_npx_flags(args: &[String]) -> &[String] {
    let mut i = 0;
    while i < args.len() {
        let l = args[i].to_lowercase();
        if l == "-p" || l == "--package" || l == "-c" || l == "--call" {
            i += 2;
        } else if is_flag(&l) {
            i += 1;
        } else {
            break;
        }
    }
    &args[i.min(args.len())..]
}

/// The tool that runs the tests of a `test` command line (`cargo`, `pytest`, `pnpm`, `gradlew`, ...), if any segment is
/// a test run.
pub fn runner(command: &str, shell: Shell) -> Option<String> {
    for seg in split_segments(command, shell) {
        let u = unwrap_command(&seg.tokens);
        if let Some(Inner::Command(inner)) = inner_payload(u.tokens) {
            if let Some(r) = runner(&inner, shell) {
                return Some(r);
            }
            continue;
        }
        if segment_class(&seg.tokens) != CommandClass::Test {
            continue;
        }
        let Some(first) = u.tokens.first() else {
            continue;
        };
        let name = base_command(first);
        let args = &u.tokens[1..];
        return Some(match name.as_str() {
            "python" | "python3" | "py" => {
                let pos = args.iter().position(|a| a.eq_ignore_ascii_case("-m"));
                pos.and_then(|p| args.get(p + 1))
                    .map(|m| base_command(m))
                    .unwrap_or(name)
            }
            "npx" | "bunx" | "pnpx" => skip_npx_flags(args)
                .first()
                .map(|t| base_command(t))
                .unwrap_or(name),
            _ => name,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use CommandClass as C;

    fn cls(cmd: &str) -> CommandClass {
        command_class(cmd)
    }

    #[test]
    fn documented_classes() {
        // test
        for c in [
            "cargo test -p core",
            "pytest -q",
            "python -m pytest",
            "npm test",
            "pnpm test",
            "npm run test:unit",
            "vitest run",
            "jest",
            "./gradlew :core:test",
            ".\\gradlew.bat testDebugUnitTest",
            "go test ./...",
            "mvn test",
            "dotnet test",
            "ctest --output-on-failure",
            "npx vitest run",
            "pnpm exec vitest",
            "pnpm --filter desktop test",
            "make test",
        ] {
            assert_eq!(cls(c), C::Test, "{c}");
        }
        // build
        for c in [
            "cargo build",
            "cargo check",
            "cargo clippy --workspace",
            "cargo fmt --all",
            "npm run build",
            "pnpm build",
            "pnpm typecheck",
            "pnpm lint",
            "./gradlew assembleDebug",
            "gradlew build",
            "tsc",
            "tsc --noEmit",
            "vite build",
            "make",
            "cargo +nightly fmt",
        ] {
            assert_eq!(cls(c), C::Build, "{c}");
        }
        assert_eq!(cls("git status"), C::Vcs);
        assert_eq!(cls("gh pr list"), C::Vcs);
        for c in [
            "npm i",
            "npm install",
            "npm ci",
            "pnpm add zod",
            "pnpm install",
            "pip install x",
            "cargo add serde",
            "cargo install ripgrep",
            "winget install Git.Git",
        ] {
            assert_eq!(cls(c), C::Package, "{c}");
        }
        for c in [
            "ls -la",
            "cat x",
            "find . -name x",
            "rg foo",
            "grep -r x .",
            "dir",
            "Get-ChildItem -Recurse",
            "type a.txt",
        ] {
            assert_eq!(cls(c), C::Fs, "{c}");
        }
        for c in [
            "curl https://x",
            "wget x",
            "Invoke-WebRequest x",
            "irm x",
            "iwr x",
            "ssh a@b",
            "scp a b:c",
        ] {
            assert_eq!(cls(c), C::Network, "{c}");
        }
        for c in ["echo hi", "rm -rf x", "docker ps", "Get-Date", "", "   "] {
            assert_eq!(cls(c), C::Shell, "{c}");
        }
    }

    #[test]
    fn command_lines_use_test_over_build_over_first() {
        assert_eq!(cls("cd desktop && cargo test -p core"), C::Test);
        assert_eq!(cls("cargo fmt --all --check && cargo test"), C::Test);
        assert_eq!(cls("cargo build && cargo test | tail -5"), C::Test);
        assert_eq!(cls("rm -rf target && cargo build"), C::Build);
        assert_eq!(cls("git add . && git commit -m x"), C::Vcs);
        assert_eq!(cls("CI=1 RUST_LOG=debug cargo test"), C::Test);
        assert_eq!(
            cls("cd a && cd \"b c\" && env CI=1 NODE_ENV=test cargo build"),
            C::Build
        );
        assert_eq!(cls("sudo cargo test"), C::Test);
        assert_eq!(cls("bash -c \"cargo test\""), C::Test);
        assert_eq!(cls("cargo test 2>&1 | tee out.log"), C::Test);
        assert_eq!(cls("echo done"), C::Shell);
    }

    #[test]
    fn neutral_segments() {
        let seg = |c: &str| split_segments(c, Shell::Posix).remove(0);
        assert!(is_neutral_segment(&seg("cd x")));
        assert!(is_neutral_segment(&seg("echo hi")));
        assert!(is_neutral_segment(&seg("FOO=1")));
        assert!(!is_neutral_segment(&seg("cat x")));
        let piped = split_segments("a | tail -3", Shell::Posix);
        assert!(is_neutral_segment(&piped[1]));
        assert!(!is_neutral_segment(&piped[0]));
    }

    #[test]
    fn runners() {
        assert_eq!(runner("cargo test", Shell::Posix).as_deref(), Some("cargo"));
        assert_eq!(
            runner("python -m pytest -q", Shell::Posix).as_deref(),
            Some("pytest")
        );
        assert_eq!(
            runner("npx vitest run", Shell::Posix).as_deref(),
            Some("vitest")
        );
        assert_eq!(
            runner("cd x && pnpm test", Shell::Posix).as_deref(),
            Some("pnpm")
        );
        assert_eq!(
            runner("./gradlew.bat :core:test", Shell::Posix).as_deref(),
            Some("gradlew")
        );
        assert_eq!(runner("cargo build", Shell::Posix), None);
        assert_eq!(runner("", Shell::Posix), None);
    }

    #[test]
    fn shell_syntax_around_a_command_does_not_change_its_class() {
        for (cmd, want) in [
            ("(cargo test)", CommandClass::Test),
            ("(cd x && cargo build)", CommandClass::Build),
            ("{ cargo test; }", CommandClass::Test),
            ("if cargo test; then echo ok; fi", CommandClass::Test),
            ("for d in a b; do npm test; done", CommandClass::Test),
            ("while true; do pytest; done", CommandClass::Test),
            ("! cargo build", CommandClass::Build),
            ("f() { cargo test; }; f", CommandClass::Test),
        ] {
            assert_eq!(command_class(cmd), want, "{cmd}");
        }
        // closing words (`fi`, `done`, `}`) are neutral
        assert_eq!(command_class("if true; then ls; fi"), CommandClass::Fs);
        assert_eq!(command_class("fi"), CommandClass::Shell);
    }
}
