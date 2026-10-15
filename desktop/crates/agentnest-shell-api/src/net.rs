//! Windows firewall rule and network profile (docs/security.md 3.1, docs/desktop.md 3).
//!
//! The scope of the rule is fixed here and nowhere else: **inbound, TCP, the WSS port, `profile=private`,
//! `remoteip=localsubnet`, `program=<this exe>`**. Changing the firewall needs admin rights, so the app itself stays a
//! normal user process and runs one **elevated** PowerShell child (UAC prompt, user consent each time); a declined
//! prompt is [`ElevatedOutcome::Denied`] and surfaces as `ELEVATION_DENIED`.
//!
//! Everything is behind [`NetworkOps`]. [`WindowsNetwork`] implements it with PowerShell / `netsh` through a
//! [`ProcessRunner`], so the scripts and the output parsing are unit tested on Linux with a fake runner; on other
//! platforms [`UnsupportedNetwork`] reports "unknown" and refuses to change anything.
//!
//! Reading uses the PowerShell NetSecurity cmdlets and emits fixed `KEY|value` lines built from .NET enum names, so the
//! parsing does not depend on the Windows display language (the `netsh show rule` output is localised). Writing uses
//! `netsh advfirewall firewall`, the form documented in security.md 3.1. The exact cmdlet and netsh behaviour on a
//! clean Windows 11 is verified in Phase 0 P15; until then it is `[추정]`.

use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// The WSS port the documentation names; the rule name carries the actual port.
pub const DEFAULT_LINK_PORT: u16 = agentnest_protocol::limits::LINK_PORT;
/// Every rule this app creates starts with this name (the matching `netsh` delete by name uses the full name).
pub const RULE_NAME_PREFIX: &str = "AgentNest Link";
/// PowerShell exit code meaning "the user declined the UAC prompt" (`ERROR_CANCELLED`).
pub const EXIT_ELEVATION_DENIED: i32 = 1223;

/// `AgentNest Link (TCP <port>)`.
pub fn rule_name(port: u16) -> String {
    format!("{RULE_NAME_PREFIX} (TCP {port})")
}

/// Network category of the interface the listener is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkProfile {
    /// "Private": the only profile the rule opens.
    Private,
    /// "Public": the Windows firewall blocks quietly here.
    Public,
    /// Domain-authenticated.
    Domain,
    /// Not determined (non-Windows, loopback, a failing query).
    Unknown,
}

impl NetworkProfile {
    /// The `diagnostics_run` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkProfile::Private => "private",
            NetworkProfile::Public => "public",
            NetworkProfile::Domain => "domain",
            NetworkProfile::Unknown => "unknown",
        }
    }
}

/// What the firewall says about this app.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FirewallState {
    /// An enabled inbound allow rule for this app exists.
    pub rule_present: bool,
    /// ...and one of them has exactly the documented scope.
    pub scoped_ok: bool,
    /// An enabled inbound block rule for this app exists (the user pressed "Cancel" in the Windows prompt).
    pub block_rule_present: bool,
    /// The rules could not be read (the other fields are then `false`, not "known absent").
    pub check_failed: bool,
}

/// How an elevated change ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElevatedOutcome {
    /// The elevated script exited 0.
    Done,
    /// The user declined the UAC prompt.
    Denied,
    /// The elevated script ran and failed (or timed out).
    Failed,
    /// The process could not be started at all, or the platform has no firewall to change.
    NotStarted,
}

/// Network profile and firewall operations. Blocking (they start processes); call from `spawn_blocking`.
pub trait NetworkOps: Send + Sync + 'static {
    /// The profile of the interface that owns `local_addr`.
    fn network_profile(&self, local_addr: IpAddr) -> NetworkProfile;
    /// Reads the firewall state for `exe` and the WSS `port`.
    fn firewall_state(&self, exe: &Path, port: u16) -> FirewallState;
    /// Creates (replaces) the scoped allow rule, elevated.
    fn create_rule(&self, exe: &Path, port: u16) -> ElevatedOutcome;
    /// Removes the allow rule and every rule for this exe (including block rules), elevated.
    fn remove_rules(&self, exe: &Path, port: u16) -> ElevatedOutcome;
}

/// The fallback on platforms without the Windows firewall.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedNetwork;

impl NetworkOps for UnsupportedNetwork {
    fn network_profile(&self, _local_addr: IpAddr) -> NetworkProfile {
        NetworkProfile::Unknown
    }

    fn firewall_state(&self, _exe: &Path, _port: u16) -> FirewallState {
        FirewallState {
            check_failed: true,
            ..FirewallState::default()
        }
    }

    fn create_rule(&self, _exe: &Path, _port: u16) -> ElevatedOutcome {
        ElevatedOutcome::NotStarted
    }

    fn remove_rules(&self, _exe: &Path, _port: u16) -> ElevatedOutcome {
        ElevatedOutcome::NotStarted
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// process running
// ---------------------------------------------------------------------------------------------------------------------

/// What a finished child process left behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessOutput {
    /// Exit code (`None` if it was killed by a signal or the timeout).
    pub code: Option<i32>,
    /// Captured standard output (lossy UTF-8).
    pub stdout: String,
}

/// Runs a program and captures its output.
pub trait ProcessRunner: Send + Sync + 'static {
    /// Runs `program args...`; kills it after `timeout`.
    fn run(&self, program: &str, args: &[String], timeout: Duration) -> io::Result<ProcessOutput>;
}

/// `std::process::Command` with no console window on Windows.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

impl ProcessRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String], timeout: Duration) -> io::Result<ProcessOutput> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = cmd.spawn()?;
        let mut stdout = child.stdout.take();
        let reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(out) = stdout.as_mut() {
                let _ = out.take(1 << 20).read_to_end(&mut buf);
            }
            buf
        });
        let started = Instant::now();
        let code = loop {
            if let Some(status) = child.try_wait()? {
                break status.code();
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let bytes = reader.join().unwrap_or_default();
        Ok(ProcessOutput {
            code,
            stdout: String::from_utf8_lossy(&bytes).into_owned(),
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// script building (pure)
// ---------------------------------------------------------------------------------------------------------------------

/// Why an exe path cannot go into a script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// Not an absolute Windows path.
    NotAbsolute,
    /// Contains a quote, a control character or is absurdly long.
    Unsafe,
}

fn is_windows_absolute(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || s.starts_with("\\\\")
}

/// Accepts only an absolute Windows path without quotes or control characters, so it can be embedded in a `netsh`
/// command line and a PowerShell string without any injection.
pub fn validate_exe_path(exe: &str) -> Result<(), PathError> {
    if exe.len() > 520 || exe.chars().any(|c| c.is_control() || c == '"' || c == '`') {
        return Err(PathError::Unsafe);
    }
    if !is_windows_absolute(exe) {
        return Err(PathError::NotAbsolute);
    }
    Ok(())
}

/// A PowerShell single-quoted string literal.
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The `netsh` argument string that creates the rule (docs/security.md 3.1).
pub fn netsh_add_rule_args(exe: &str, port: u16) -> String {
    format!(
        "advfirewall firewall add rule name=\"{}\" dir=in action=allow protocol=TCP localport={port} profile=private remoteip=localsubnet program=\"{exe}\" enable=yes",
        rule_name(port)
    )
}

/// The `netsh` argument string that deletes the rule by name.
pub fn netsh_delete_by_name_args(port: u16) -> String {
    format!(
        "advfirewall firewall delete rule name=\"{}\"",
        rule_name(port)
    )
}

/// The `netsh` argument string that deletes every inbound rule of `exe` (allow and block).
pub fn netsh_delete_by_program_args(exe: &str) -> String {
    format!("advfirewall firewall delete rule name=all dir=in program=\"{exe}\"")
}

/// UTF-16LE + base64, the format of `powershell -EncodedCommand`.
pub fn encode_powershell(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    STANDARD.encode(bytes)
}

/// Decodes [`encode_powershell`] (tests).
pub fn decode_powershell(encoded: &str) -> Option<String> {
    let bytes = STANDARD.decode(encoded).ok()?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// The script run **inside** the elevated PowerShell: it executes the given netsh argument strings one after another
/// and exits with the code of the last one.
fn elevated_inner_script(netsh_args: &[String]) -> String {
    let mut s = String::from("$ErrorActionPreference = 'Stop'\r\n$code = 0\r\n");
    for args in netsh_args {
        s.push_str(&format!(
            "$p = Start-Process -FilePath 'netsh.exe' -ArgumentList {} -Wait -PassThru -WindowStyle Hidden\r\n$code = $p.ExitCode\r\n",
            ps_quote(args)
        ));
    }
    s.push_str("exit $code\r\n");
    s
}

/// The script run by the normal (non-elevated) PowerShell: it starts the elevated child with the `runas` verb and
/// translates a declined UAC prompt into [`EXIT_ELEVATION_DENIED`].
fn elevation_launcher_script(inner_script: &str) -> String {
    let encoded = encode_powershell(inner_script);
    format!(
        "$ErrorActionPreference = 'Stop'\r\n\
         try {{\r\n\
         \x20 $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','{encoded}') -Verb RunAs -Wait -PassThru -WindowStyle Hidden\r\n\
         \x20 exit $p.ExitCode\r\n\
         }} catch {{\r\n\
         \x20 $c = 0\r\n\
         \x20 if ($_.Exception -is [System.ComponentModel.Win32Exception]) {{ $c = $_.Exception.NativeErrorCode }}\r\n\
         \x20 elseif ($_.Exception.InnerException -is [System.ComponentModel.Win32Exception]) {{ $c = $_.Exception.InnerException.NativeErrorCode }}\r\n\
         \x20 if ($c -eq {EXIT_ELEVATION_DENIED}) {{ exit {EXIT_ELEVATION_DENIED} }} else {{ exit 1 }}\r\n\
         }}\r\n"
    )
}

/// `powershell.exe` arguments for a script (hidden, non-interactive, no profile).
fn powershell_args(script: &str) -> Vec<String> {
    vec![
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-EncodedCommand".into(),
        encode_powershell(script),
    ]
}

fn profile_script(addr: IpAddr) -> String {
    // `IpAddr::to_string` only produces digits, hex digits, `.` and `:`
    format!(
        "$ErrorActionPreference = 'Stop'\r\n\
         try {{\r\n\
         \x20 $idx = (Get-NetIPAddress -IPAddress '{addr}' | Select-Object -First 1).InterfaceIndex\r\n\
         \x20 $cat = (Get-NetConnectionProfile -InterfaceIndex $idx | Select-Object -First 1).NetworkCategory\r\n\
         \x20 [Console]::Out.Write('PROFILE|' + $cat.ToString())\r\n\
         }} catch {{ [Console]::Out.Write('PROFILE|Unknown') }}\r\n"
    )
}

fn firewall_query_script(exe: &str) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\r\n\
         try {{\r\n\
         \x20 $exe = {exe_q}\r\n\
         \x20 $named = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{ $_.DisplayName -like '{RULE_NAME_PREFIX}*' }}\r\n\
         \x20 $byApp = Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object {{ $_.Program -ieq $exe }} | Get-NetFirewallRule -ErrorAction SilentlyContinue\r\n\
         \x20 foreach ($r in @($named) + @($byApp)) {{\r\n\
         \x20   if ($null -eq $r) {{ continue }}\r\n\
         \x20   $app = $r | Get-NetFirewallApplicationFilter\r\n\
         \x20   $port = $r | Get-NetFirewallPortFilter\r\n\
         \x20   $addr = $r | Get-NetFirewallAddressFilter\r\n\
         \x20   ('RULE|{{0}}|{{1}}|{{2}}|{{3}}|{{4}}|{{5}}|{{6}}|{{7}}|{{8}}|{{9}}' -f $r.Name, $r.DisplayName.Replace('|','/'), $r.Action, $r.Enabled, $r.Direction, $r.Profile, $port.Protocol, $port.LocalPort, ($addr.RemoteAddress -join ','), $app.Program)\r\n\
         \x20 }}\r\n\
         \x20 'DONE'\r\n\
         }} catch {{ 'ERROR' }}\r\n",
        exe_q = ps_quote(exe)
    )
}

// ---------------------------------------------------------------------------------------------------------------------
// output parsing (pure)
// ---------------------------------------------------------------------------------------------------------------------

/// Parses the `PROFILE|<category>` line.
pub fn parse_profile(output: &str) -> NetworkProfile {
    let Some(line) = output
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("PROFILE|"))
    else {
        return NetworkProfile::Unknown;
    };
    match line["PROFILE|".len()..].trim() {
        "Private" => NetworkProfile::Private,
        "Public" => NetworkProfile::Public,
        "DomainAuthenticated" | "Domain" => NetworkProfile::Domain,
        _ => NetworkProfile::Unknown,
    }
}

fn norm_path(p: &str) -> String {
    p.trim().replace('/', "\\").to_lowercase()
}

/// Parses the `RULE|...` lines of the firewall query for `exe` and `port`.
pub fn parse_firewall_report(output: &str, exe: &str, port: u16) -> FirewallState {
    if !output.lines().any(|l| l.trim() == "DONE") {
        return FirewallState {
            check_failed: true,
            ..FirewallState::default()
        };
    }
    let exe_norm = norm_path(exe);
    let mut seen: Vec<String> = Vec::new();
    let mut state = FirewallState::default();
    for line in output.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("RULE|") else {
            continue;
        };
        let f: Vec<&str> = rest.split('|').collect();
        if f.len() < 9 {
            continue;
        }
        let (name, display, action, enabled, direction, profile, protocol, local_port, remote) =
            (f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]);
        let program = f.get(9).copied().unwrap_or("");
        // the same rule can be listed once by name and once by program
        if seen.iter().any(|n| n == name) {
            continue;
        }
        seen.push(name.to_owned());
        let enabled = enabled.eq_ignore_ascii_case("true");
        let inbound = direction.eq_ignore_ascii_case("inbound");
        let ours_by_program = norm_path(program) == exe_norm;
        let ours_by_name = display.starts_with(RULE_NAME_PREFIX);
        if !enabled || !inbound || !(ours_by_program || ours_by_name) {
            continue;
        }
        if action.eq_ignore_ascii_case("block") && ours_by_program {
            state.block_rule_present = true;
        }
        if action.eq_ignore_ascii_case("allow") {
            state.rule_present = true;
            let exact = ours_by_name
                && ours_by_program
                && protocol.eq_ignore_ascii_case("tcp")
                && local_port == port.to_string()
                && profile.eq_ignore_ascii_case("private")
                && remote.eq_ignore_ascii_case("localsubnet");
            if exact {
                state.scoped_ok = true;
            }
        }
    }
    state
}

/// Maps a PowerShell launcher exit code to an outcome.
pub fn outcome_from_exit(code: Option<i32>) -> ElevatedOutcome {
    match code {
        Some(0) => ElevatedOutcome::Done,
        Some(EXIT_ELEVATION_DENIED) => ElevatedOutcome::Denied,
        _ => ElevatedOutcome::Failed,
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// the Windows implementation
// ---------------------------------------------------------------------------------------------------------------------

/// PowerShell / `netsh` based [`NetworkOps`].
pub struct WindowsNetwork<R: ProcessRunner> {
    runner: R,
    /// Timeout of the read-only queries.
    pub query_timeout: Duration,
    /// How long the user gets for the UAC prompt and the change.
    pub elevated_timeout: Duration,
}

impl<R: ProcessRunner> WindowsNetwork<R> {
    /// A Windows implementation on top of `runner`.
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            query_timeout: Duration::from_secs(20),
            elevated_timeout: Duration::from_secs(120),
        }
    }

    fn powershell(&self, script: &str, timeout: Duration) -> io::Result<ProcessOutput> {
        self.runner
            .run("powershell.exe", &powershell_args(script), timeout)
    }

    fn elevated(&self, netsh_args: &[String]) -> ElevatedOutcome {
        let launcher = elevation_launcher_script(&elevated_inner_script(netsh_args));
        match self.powershell(&launcher, self.elevated_timeout) {
            Ok(out) => outcome_from_exit(out.code),
            Err(_) => ElevatedOutcome::NotStarted,
        }
    }
}

impl<R: ProcessRunner> NetworkOps for WindowsNetwork<R> {
    fn network_profile(&self, local_addr: IpAddr) -> NetworkProfile {
        match self.powershell(&profile_script(local_addr), self.query_timeout) {
            Ok(out) => parse_profile(&out.stdout),
            Err(_) => NetworkProfile::Unknown,
        }
    }

    fn firewall_state(&self, exe: &Path, port: u16) -> FirewallState {
        let exe = exe.to_string_lossy();
        if validate_exe_path(&exe).is_err() {
            return FirewallState {
                check_failed: true,
                ..FirewallState::default()
            };
        }
        match self.powershell(&firewall_query_script(&exe), self.query_timeout) {
            Ok(out) => parse_firewall_report(&out.stdout, &exe, port),
            Err(_) => FirewallState {
                check_failed: true,
                ..FirewallState::default()
            },
        }
    }

    fn create_rule(&self, exe: &Path, port: u16) -> ElevatedOutcome {
        let exe = exe.to_string_lossy();
        if validate_exe_path(&exe).is_err() {
            return ElevatedOutcome::NotStarted;
        }
        // replace an older rule of ours (other port, moved exe) instead of leaving two
        self.elevated(&[
            netsh_delete_by_name_args(port),
            netsh_add_rule_args(&exe, port),
        ])
    }

    fn remove_rules(&self, exe: &Path, port: u16) -> ElevatedOutcome {
        let exe = exe.to_string_lossy();
        if validate_exe_path(&exe).is_err() {
            return ElevatedOutcome::NotStarted;
        }
        self.elevated(&[
            netsh_delete_by_name_args(DEFAULT_LINK_PORT),
            netsh_delete_by_name_args(port),
            netsh_delete_by_program_args(&exe),
        ])
    }
}

#[cfg(test)]
pub(crate) mod fakes {
    use super::*;
    use std::sync::Mutex;

    /// A runner that returns canned output and records what it was asked to run.
    pub struct FakeRunner {
        pub output: Mutex<io::Result<ProcessOutput>>,
        pub calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl FakeRunner {
        pub fn new(code: Option<i32>, stdout: &str) -> Self {
            Self {
                output: Mutex::new(Ok(ProcessOutput {
                    code,
                    stdout: stdout.to_owned(),
                })),
                calls: Mutex::new(Vec::new()),
            }
        }

        pub fn failing() -> Self {
            Self {
                output: Mutex::new(Err(io::Error::other("no powershell"))),
                calls: Mutex::new(Vec::new()),
            }
        }

        /// The decoded `-EncodedCommand` script of call `i`.
        pub fn script(&self, i: usize) -> String {
            let calls = self.calls.lock().unwrap();
            let args = &calls[i].1;
            let pos = args.iter().position(|a| a == "-EncodedCommand").unwrap();
            decode_powershell(&args[pos + 1]).unwrap()
        }
    }

    impl ProcessRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String], _t: Duration) -> io::Result<ProcessOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_owned(), args.to_vec()));
            match &*self.output.lock().unwrap() {
                Ok(o) => Ok(o.clone()),
                Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
            }
        }
    }

    /// A scripted [`NetworkOps`] for the diagnostics / API tests.
    #[derive(Clone)]
    pub struct FakeNetwork {
        pub profile: NetworkProfile,
        pub state: std::sync::Arc<Mutex<FirewallState>>,
        pub create: ElevatedOutcome,
        pub remove: ElevatedOutcome,
        pub log: std::sync::Arc<Mutex<Vec<String>>>,
    }

    impl FakeNetwork {
        pub fn new() -> Self {
            Self {
                profile: NetworkProfile::Private,
                state: std::sync::Arc::new(Mutex::new(FirewallState::default())),
                create: ElevatedOutcome::Done,
                remove: ElevatedOutcome::Done,
                log: std::sync::Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl NetworkOps for FakeNetwork {
        fn network_profile(&self, addr: IpAddr) -> NetworkProfile {
            self.log.lock().unwrap().push(format!("profile {addr}"));
            self.profile
        }

        fn firewall_state(&self, _exe: &Path, port: u16) -> FirewallState {
            self.log.lock().unwrap().push(format!("state {port}"));
            *self.state.lock().unwrap()
        }

        fn create_rule(&self, _exe: &Path, port: u16) -> ElevatedOutcome {
            self.log.lock().unwrap().push(format!("create {port}"));
            if self.create == ElevatedOutcome::Done {
                *self.state.lock().unwrap() = FirewallState {
                    rule_present: true,
                    scoped_ok: true,
                    ..FirewallState::default()
                };
            }
            self.create
        }

        fn remove_rules(&self, _exe: &Path, port: u16) -> ElevatedOutcome {
            self.log.lock().unwrap().push(format!("remove {port}"));
            if self.remove == ElevatedOutcome::Done {
                *self.state.lock().unwrap() = FirewallState::default();
            }
            self.remove
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fakes::*;
    use super::*;

    const EXE: &str = "C:\\Program Files\\AgentNest\\AgentNest.exe";

    #[test]
    fn the_rule_has_exactly_the_documented_scope() {
        let args = netsh_add_rule_args(EXE, 47832);
        assert_eq!(
            args,
            "advfirewall firewall add rule name=\"AgentNest Link (TCP 47832)\" dir=in action=allow protocol=TCP localport=47832 profile=private remoteip=localsubnet program=\"C:\\Program Files\\AgentNest\\AgentNest.exe\" enable=yes"
        );
        // never broader than security.md 3.1 allows
        for forbidden in [
            "profile=any",
            "profile=public",
            "profile=domain",
            "remoteip=any",
            "protocol=UDP",
            "localport=any",
        ] {
            assert!(!args.contains(forbidden), "{forbidden}");
        }
        assert_eq!(
            netsh_delete_by_name_args(47832),
            "advfirewall firewall delete rule name=\"AgentNest Link (TCP 47832)\""
        );
        assert_eq!(
            netsh_delete_by_program_args(EXE),
            "advfirewall firewall delete rule name=all dir=in program=\"C:\\Program Files\\AgentNest\\AgentNest.exe\""
        );
    }

    #[test]
    fn exe_paths_are_validated_before_they_reach_a_script() {
        assert_eq!(validate_exe_path(EXE), Ok(()));
        assert_eq!(validate_exe_path("D:/x/a.exe"), Ok(()));
        assert_eq!(validate_exe_path("\\\\host\\share\\a.exe"), Ok(()));
        assert_eq!(
            validate_exe_path("relative\\a.exe"),
            Err(PathError::NotAbsolute)
        );
        assert_eq!(validate_exe_path("/usr/bin/a"), Err(PathError::NotAbsolute));
        assert_eq!(validate_exe_path(""), Err(PathError::NotAbsolute));
        for bad in [
            "C:\\a\" & calc & \"b.exe",
            "C:\\a`b.exe",
            "C:\\a\r\nb.exe",
            "C:\\a\0b.exe",
        ] {
            assert_eq!(validate_exe_path(bad), Err(PathError::Unsafe), "{bad:?}");
        }
        assert_eq!(
            validate_exe_path(&format!("C:\\{}", "a".repeat(600))),
            Err(PathError::Unsafe)
        );
    }

    #[test]
    fn powershell_encoding_round_trips() {
        let s = "Write-Host '한글 ünï'\r\n";
        assert_eq!(decode_powershell(&encode_powershell(s)).as_deref(), Some(s));
        // a known vector: "A" in UTF-16LE is 41 00
        assert_eq!(encode_powershell("A"), "QQA=");
    }

    #[test]
    fn single_quotes_in_the_path_cannot_break_out_of_the_literal() {
        assert_eq!(ps_quote("C:\\O'Neil\\a.exe"), "'C:\\O''Neil\\a.exe'");
        let q = firewall_query_script("C:\\O'Neil\\a.exe");
        assert!(q.contains("$exe = 'C:\\O''Neil\\a.exe'"));
    }

    #[test]
    fn the_elevated_script_runs_the_netsh_commands_and_reports_a_declined_prompt() {
        let runner = FakeRunner::new(Some(0), "");
        let net = WindowsNetwork::new(runner);
        assert_eq!(
            net.create_rule(Path::new(EXE), 47832),
            ElevatedOutcome::Done
        );
        let runner = &net.runner;
        assert_eq!(runner.calls.lock().unwrap()[0].0, "powershell.exe");
        let launcher = runner.script(0);
        assert!(launcher.contains("-Verb RunAs"));
        assert!(launcher.contains("1223"));
        // pull the inner script out of the launcher and check the netsh commands
        let start = launcher.find("'-EncodedCommand','").unwrap() + "'-EncodedCommand','".len();
        let end = launcher[start..].find('\'').unwrap() + start;
        let inner = decode_powershell(&launcher[start..end]).unwrap();
        assert!(inner.contains("-FilePath 'netsh.exe'"));
        let add = netsh_add_rule_args(EXE, 47832);
        assert!(inner.contains(&ps_quote(&add)), "{inner}");
        assert!(inner.contains(&ps_quote(&netsh_delete_by_name_args(47832))));
        assert!(inner.trim_end().ends_with("exit $code"));
        // the delete runs before the add
        assert!(inner.find("delete rule").unwrap() < inner.find("add rule").unwrap());
    }

    #[test]
    fn remove_deletes_by_name_and_by_program() {
        let net = WindowsNetwork::new(FakeRunner::new(Some(0), ""));
        assert_eq!(
            net.remove_rules(Path::new(EXE), 47841),
            ElevatedOutcome::Done
        );
        let launcher = net.runner.script(0);
        let start = launcher.find("'-EncodedCommand','").unwrap() + "'-EncodedCommand','".len();
        let end = launcher[start..].find('\'').unwrap() + start;
        let inner = decode_powershell(&launcher[start..end]).unwrap();
        assert!(
            inner.contains("name=\"\"AgentNest Link (TCP 47832)\"\"")
                || inner.contains("AgentNest Link (TCP 47832)")
        );
        assert!(inner.contains("AgentNest Link (TCP 47841)"));
        assert!(inner.contains("name=all dir=in program="));
    }

    #[test]
    fn exit_codes_map_to_outcomes() {
        assert_eq!(outcome_from_exit(Some(0)), ElevatedOutcome::Done);
        assert_eq!(outcome_from_exit(Some(1223)), ElevatedOutcome::Denied);
        assert_eq!(outcome_from_exit(Some(1)), ElevatedOutcome::Failed);
        assert_eq!(outcome_from_exit(None), ElevatedOutcome::Failed);
        let net = WindowsNetwork::new(FakeRunner::new(Some(1223), ""));
        assert_eq!(
            net.create_rule(Path::new(EXE), 47832),
            ElevatedOutcome::Denied
        );
        let net = WindowsNetwork::new(FakeRunner::failing());
        assert_eq!(
            net.create_rule(Path::new(EXE), 47832),
            ElevatedOutcome::NotStarted
        );
    }

    #[test]
    fn an_unsafe_exe_path_never_starts_a_process() {
        let net = WindowsNetwork::new(FakeRunner::new(Some(0), ""));
        assert_eq!(
            net.create_rule(Path::new("C:\\a\"b.exe"), 47832),
            ElevatedOutcome::NotStarted
        );
        assert_eq!(
            net.remove_rules(Path::new("relative.exe"), 47832),
            ElevatedOutcome::NotStarted
        );
        assert!(net.firewall_state(Path::new("x"), 1).check_failed);
        assert!(net.runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn the_profile_is_parsed_from_the_fixed_marker() {
        assert_eq!(parse_profile("PROFILE|Private"), NetworkProfile::Private);
        assert_eq!(
            parse_profile("noise\r\nPROFILE|Public\r\n"),
            NetworkProfile::Public
        );
        assert_eq!(
            parse_profile("PROFILE|DomainAuthenticated"),
            NetworkProfile::Domain
        );
        assert_eq!(parse_profile("PROFILE|Unknown"), NetworkProfile::Unknown);
        assert_eq!(parse_profile("PROFILE|Something"), NetworkProfile::Unknown);
        assert_eq!(parse_profile(""), NetworkProfile::Unknown);
        let net = WindowsNetwork::new(FakeRunner::new(Some(0), "PROFILE|Public"));
        assert_eq!(
            net.network_profile("192.168.0.10".parse().unwrap()),
            NetworkProfile::Public
        );
        assert!(net.runner.script(0).contains("'192.168.0.10'"));
        let net = WindowsNetwork::new(FakeRunner::failing());
        assert_eq!(
            net.network_profile("192.168.0.10".parse().unwrap()),
            NetworkProfile::Unknown
        );
    }

    fn rule(
        name: &str,
        display: &str,
        action: &str,
        profile: &str,
        remote: &str,
        program: &str,
    ) -> String {
        format!("RULE|{name}|{display}|{action}|True|Inbound|{profile}|TCP|47832|{remote}|{program}\r\n")
    }

    #[test]
    fn a_correctly_scoped_rule_is_ok() {
        let out = format!(
            "{}DONE\r\n",
            rule(
                "{A}",
                "AgentNest Link (TCP 47832)",
                "Allow",
                "Private",
                "LocalSubnet",
                EXE
            )
        );
        let s = parse_firewall_report(&out, EXE, 47832);
        assert_eq!(
            s,
            FirewallState {
                rule_present: true,
                scoped_ok: true,
                block_rule_present: false,
                check_failed: false
            }
        );
        // the exe comparison ignores case and slash direction
        let s = parse_firewall_report(&out, "c:/program files/agentnest/AGENTNEST.EXE", 47832);
        assert!(s.scoped_ok);
    }

    #[test]
    fn too_broad_or_wrong_rules_are_present_but_not_scoped() {
        for (profile, remote, program, port) in [
            ("Any", "LocalSubnet", EXE, 47832),
            ("Public, Private", "LocalSubnet", EXE, 47832),
            ("Private", "Any", EXE, 47832),
            ("Private", "LocalSubnet", "C:\\Other\\a.exe", 47832),
            ("Private", "LocalSubnet", EXE, 47999),
        ] {
            let out = format!(
                "{}DONE\r\n",
                rule(
                    "{A}",
                    "AgentNest Link (TCP 47832)",
                    "Allow",
                    profile,
                    remote,
                    program
                )
            );
            let s = parse_firewall_report(&out, EXE, port);
            assert!(!s.scoped_ok, "{profile} {remote} {program} {port}");
        }
        // a Windows-prompt rule for this exe is an allow rule but not ours
        let prompt = format!(
            "{}DONE\r\n",
            rule("{B}", "agentnest", "Allow", "Any", "Any", EXE)
        );
        let s = parse_firewall_report(&prompt, EXE, 47832);
        assert!(s.rule_present && !s.scoped_ok);
    }

    #[test]
    fn a_block_rule_for_this_exe_is_detected_and_other_programs_are_ignored() {
        let out = format!(
            "{}{}{}DONE\r\n",
            rule("{C}", "agentnest", "Block", "Any", "Any", EXE),
            rule("{D}", "other", "Block", "Any", "Any", "C:\\Other\\x.exe"),
            rule("{E}", "other", "Allow", "Any", "Any", "C:\\Other\\x.exe"),
        );
        let s = parse_firewall_report(&out, EXE, 47832);
        assert!(s.block_rule_present);
        assert!(!s.rule_present, "another program's rule does not count");
    }

    #[test]
    fn disabled_and_outbound_rules_do_not_count() {
        let out = format!(
            "RULE|{{F}}|AgentNest Link (TCP 47832)|Allow|False|Inbound|Private|TCP|47832|LocalSubnet|{EXE}\r\n\
             RULE|{{G}}|AgentNest Link (TCP 47832)|Allow|True|Outbound|Private|TCP|47832|LocalSubnet|{EXE}\r\nDONE\r\n"
        );
        assert_eq!(
            parse_firewall_report(&out, EXE, 47832),
            FirewallState::default()
        );
    }

    #[test]
    fn a_rule_listed_twice_is_counted_once_and_garbage_is_ignored() {
        let one = rule(
            "{A}",
            "AgentNest Link (TCP 47832)",
            "Allow",
            "Private",
            "LocalSubnet",
            EXE,
        );
        let out = format!("{one}{one}RULE|short\r\nrandom\r\nDONE\r\n");
        assert!(parse_firewall_report(&out, EXE, 47832).scoped_ok);
    }

    #[test]
    fn a_failed_query_is_unknown_not_absent() {
        for out in [
            "",
            "ERROR",
            "RULE|{A}|x|Allow|True|Inbound|Private|TCP|1|LocalSubnet|p",
        ] {
            let s = parse_firewall_report(out, EXE, 47832);
            assert!(s.check_failed, "{out:?}");
            assert!(!s.rule_present && !s.scoped_ok && !s.block_rule_present);
        }
        let net = WindowsNetwork::new(FakeRunner::failing());
        assert!(net.firewall_state(Path::new(EXE), 47832).check_failed);
    }

    #[test]
    fn the_unsupported_platform_changes_nothing() {
        let n = UnsupportedNetwork;
        assert_eq!(
            n.network_profile("10.0.0.1".parse().unwrap()),
            NetworkProfile::Unknown
        );
        assert!(n.firewall_state(Path::new(EXE), 47832).check_failed);
        assert_eq!(
            n.create_rule(Path::new(EXE), 47832),
            ElevatedOutcome::NotStarted
        );
        assert_eq!(
            n.remove_rules(Path::new(EXE), 47832),
            ElevatedOutcome::NotStarted
        );
    }

    #[test]
    fn the_query_script_reads_only() {
        let q = firewall_query_script(EXE);
        for write in [
            "New-NetFirewallRule",
            "Set-NetFirewallRule",
            "Remove-NetFirewallRule",
            "netsh",
            "Enable-",
            "Disable-",
        ] {
            assert!(!q.contains(write), "{write}");
        }
        let p = profile_script("192.168.0.10".parse().unwrap());
        assert!(
            !p.contains("Set-NetConnectionProfile"),
            "the profile is never changed (security.md 3.1)"
        );
    }
}
