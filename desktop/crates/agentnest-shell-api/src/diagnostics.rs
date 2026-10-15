//! The connection diagnostics report (`diagnostics_run`, docs/security.md 3.1, docs/desktop.md 6): the first thing the
//! user opens when the phone cannot reach the PC. No secret values; every failure comes with a Korean hint.

use std::net::SocketAddr;

use serde::Serialize;

use crate::net::{FirewallState, NetworkProfile};

/// Everything measured for one report.
#[derive(Clone, Debug)]
pub struct DiagnosticsInput {
    /// `link.enabled`.
    pub link_enabled: bool,
    /// The WSS listener address if it is bound.
    pub listener: Option<SocketAddr>,
    /// Profile of the listener's interface.
    pub profile: NetworkProfile,
    /// Firewall state for this app.
    pub firewall: FirewallState,
    /// Whether the firewall / profile checks exist on this platform.
    pub platform_checks: bool,
    /// The latest unauthenticated connection attempt (time, masked address).
    pub last_preauth: Option<(String, String)>,
    /// A TCP connect to the LAN address worked (a firewall does not block this).
    pub self_connect_ok: bool,
    /// Advertised LAN addresses.
    pub hosts: Vec<String>,
}

/// `diagnostics_run.listener`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ListenerDto {
    /// The listener is bound.
    pub bound: bool,
    /// Bound address (without port).
    pub addr: Option<String>,
    /// Bound port.
    pub port: Option<u16>,
}

/// `diagnostics_run.firewall`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FirewallDto {
    /// An allow rule exists.
    pub rule_present: bool,
    /// It has the documented scope.
    pub scoped_ok: bool,
    /// A block rule for this app exists.
    pub block_rule_present: bool,
}

/// `diagnostics_run.last_preauth_attempt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PreAuthDto {
    /// Time (RFC 3339).
    pub at: String,
    /// Masked source address (`192.168.0.x`).
    pub ip_masked: String,
}

/// The `diagnostics_run` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosticsReport {
    /// Listener.
    pub listener: ListenerDto,
    /// `private | public | domain | unknown`.
    pub network_profile: &'static str,
    /// Firewall.
    pub firewall: FirewallDto,
    /// Last unauthenticated attempt, if any.
    pub last_preauth_attempt: Option<PreAuthDto>,
    /// The PC reached its own LAN address.
    pub self_connect_ok: bool,
    /// Advertised addresses.
    pub hosts: Vec<String>,
    /// Korean next steps, most important first.
    pub hints_ko: Vec<String>,
}

/// Builds the report and its hints from the measurements.
pub fn build_report(i: &DiagnosticsInput) -> DiagnosticsReport {
    let bound = i.listener.is_some();
    let mut hints: Vec<String> = Vec::new();

    if !i.link_enabled {
        hints.push("휴대폰 연결이 꺼져 있어요. 연결을 켜야 휴대폰이 접속할 수 있어요.".into());
    } else if !bound {
        hints.push(
            "휴대폰 연결용 포트를 열지 못했어요. 다른 프로그램이 같은 포트를 쓰는지, 네트워크에 연결돼 있는지 확인해 주세요."
                .into(),
        );
    }
    if i.link_enabled && i.hosts.is_empty() {
        hints.push("PC의 LAN 주소를 찾지 못했어요. Wi-Fi나 이더넷 연결을 확인해 주세요.".into());
    }
    if i.platform_checks && i.link_enabled {
        match i.profile {
            NetworkProfile::Public => hints.push(
                "이 네트워크가 '공용'이라 휴대폰이 연결하지 못해요. Windows 설정 → 네트워크 → 속성에서 '개인'으로 바꾸거나, 공용 Wi-Fi라면 휴대폰 연결을 끄세요."
                    .into(),
            ),
            NetworkProfile::Domain => hints.push(
                "도메인 네트워크예요. 방화벽 규칙은 '개인' 네트워크에만 열려 있어서 휴대폰이 연결하지 못할 수 있어요."
                    .into(),
            ),
            NetworkProfile::Unknown => {
                hints.push("네트워크 종류('개인'/'공용')를 확인하지 못했어요.".into());
            }
            NetworkProfile::Private => {}
        }
        let f = &i.firewall;
        if f.check_failed {
            hints.push("방화벽 규칙을 확인하지 못했어요.".into());
        } else if f.block_rule_present {
            hints.push(
                "Windows 방화벽이 이 앱의 연결을 차단하고 있어요. [방화벽 규칙 제거] 후 [규칙 만들기]를 눌러 주세요."
                    .into(),
            );
        } else if !f.rule_present {
            hints.push(
                "방화벽 규칙이 없어요. [규칙 만들기]로 '개인' 네트워크의 같은 Wi-Fi에서만 허용하는 규칙을 만들어 주세요."
                    .into(),
            );
        } else if !f.scoped_ok {
            hints.push(
                "방화벽 규칙이 예상한 범위(개인 네트워크·같은 서브넷·이 앱)가 아니에요. 규칙을 제거한 뒤 다시 만들어 주세요."
                    .into(),
            );
        }
    }
    if bound && !i.self_connect_ok {
        hints.push(
            "PC에서 자기 주소로도 연결되지 않아요. 보안 프로그램이나 VPN이 막고 있지 않은지 확인해 주세요."
                .into(),
        );
    }
    if i.link_enabled && i.last_preauth.is_none() {
        hints.push(
            "휴대폰이 PC에 닿지 못했어요. 같은 Wi-Fi에 연결돼 있는지, 방화벽을 확인해 주세요.".into(),
        );
    }

    DiagnosticsReport {
        listener: ListenerDto {
            bound,
            addr: i.listener.map(|a| a.ip().to_string()),
            port: i.listener.map(|a| a.port()),
        },
        network_profile: i.profile.as_str(),
        firewall: FirewallDto {
            rule_present: i.firewall.rule_present,
            scoped_ok: i.firewall.scoped_ok,
            block_rule_present: i.firewall.block_rule_present,
        },
        last_preauth_attempt: i.last_preauth.as_ref().map(|(at, ip)| PreAuthDto {
            at: at.clone(),
            ip_masked: ip.clone(),
        }),
        self_connect_ok: i.self_connect_ok,
        hosts: i.hosts.clone(),
        hints_ko: hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> DiagnosticsInput {
        DiagnosticsInput {
            link_enabled: true,
            listener: Some("192.168.0.10:47832".parse().unwrap()),
            profile: NetworkProfile::Private,
            firewall: FirewallState {
                rule_present: true,
                scoped_ok: true,
                ..FirewallState::default()
            },
            platform_checks: true,
            last_preauth: Some(("2026-10-15T09:00:00.000Z".into(), "192.168.0.x".into())),
            self_connect_ok: true,
            hosts: vec!["192.168.0.10".into()],
        }
    }

    #[test]
    fn a_healthy_setup_has_no_hints_and_the_contract_shape() {
        let r = build_report(&healthy());
        assert!(r.hints_ko.is_empty(), "{:?}", r.hints_ko);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["listener"], serde_json::json!({"bound": true, "addr": "192.168.0.10", "port": 47832}));
        assert_eq!(v["network_profile"], "private");
        assert_eq!(
            v["firewall"],
            serde_json::json!({"rule_present": true, "scoped_ok": true, "block_rule_present": false})
        );
        assert_eq!(
            v["last_preauth_attempt"],
            serde_json::json!({"at": "2026-10-15T09:00:00.000Z", "ip_masked": "192.168.0.x"})
        );
        assert_eq!(v["self_connect_ok"], true);
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "firewall",
                "hints_ko",
                "hosts",
                "last_preauth_attempt",
                "listener",
                "network_profile",
                "self_connect_ok"
            ]
        );
    }

    #[test]
    fn a_public_network_gets_the_documented_advice() {
        let mut i = healthy();
        i.profile = NetworkProfile::Public;
        let r = build_report(&i);
        assert_eq!(r.network_profile, "public");
        assert!(r.hints_ko.iter().any(|h| h.contains("'공용'") && h.contains("'개인'")));
    }

    #[test]
    fn every_firewall_state_has_its_own_hint() {
        let mut i = healthy();
        i.firewall = FirewallState::default();
        assert!(build_report(&i).hints_ko.iter().any(|h| h.contains("규칙 만들기")));
        i.firewall = FirewallState {
            rule_present: true,
            ..FirewallState::default()
        };
        assert!(build_report(&i).hints_ko.iter().any(|h| h.contains("범위")));
        i.firewall = FirewallState {
            block_rule_present: true,
            ..FirewallState::default()
        };
        assert!(build_report(&i).hints_ko.iter().any(|h| h.contains("차단")));
        i.firewall = FirewallState {
            check_failed: true,
            ..FirewallState::default()
        };
        assert!(build_report(&i).hints_ko.iter().any(|h| h.contains("확인하지 못했어요")));
    }

    #[test]
    fn no_phone_attempt_means_the_phone_cannot_reach_the_pc() {
        let mut i = healthy();
        i.last_preauth = None;
        let r = build_report(&i);
        assert!(r.last_preauth_attempt.is_none());
        assert!(r.hints_ko.iter().any(|h| h.contains("휴대폰이 PC에 닿지 못했어요")));
    }

    #[test]
    fn a_disabled_link_or_a_missing_listener_is_explained() {
        let mut i = healthy();
        i.link_enabled = false;
        i.listener = None;
        let r = build_report(&i);
        assert!(!r.listener.bound);
        assert_eq!(r.listener.addr, None);
        assert!(r.hints_ko[0].contains("꺼져"));
        // a disabled link is not a firewall problem
        assert!(!r.hints_ko.iter().any(|h| h.contains("방화벽")));
        let mut i = healthy();
        i.listener = None;
        assert!(build_report(&i).hints_ko[0].contains("포트를 열지 못했어요"));
    }

    #[test]
    fn a_failed_self_connect_and_missing_hosts_are_reported() {
        let mut i = healthy();
        i.self_connect_ok = false;
        i.hosts.clear();
        let r = build_report(&i);
        assert!(r.hints_ko.iter().any(|h| h.contains("자기 주소")));
        assert!(r.hints_ko.iter().any(|h| h.contains("LAN 주소")));
    }

    #[test]
    fn platforms_without_firewall_checks_do_not_blame_the_firewall() {
        let mut i = healthy();
        i.platform_checks = false;
        i.profile = NetworkProfile::Unknown;
        i.firewall = FirewallState {
            check_failed: true,
            ..FirewallState::default()
        };
        assert!(build_report(&i).hints_ko.is_empty());
    }

    #[test]
    fn hints_never_contain_secrets_or_paths() {
        let mut i = healthy();
        i.profile = NetworkProfile::Public;
        i.firewall = FirewallState::default();
        i.last_preauth = None;
        let text = build_report(&i).hints_ko.join(" ");
        assert!(!text.contains("C:\\") && !text.contains("token") && !text.contains("sha256"));
    }
}
