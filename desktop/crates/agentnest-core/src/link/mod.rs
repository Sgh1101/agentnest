//! The WSS link to the phones (docs/protocol.md 1-4, 8, 9; docs/security.md 3, 4, 11, I1, I2, I6, I7).
//!
//! * [`LinkServer`]: a TLS (rustls, ring) listener bound to **one LAN interface address** (never `0.0.0.0`), serving
//!   `GET /v1/link` as a WebSocket with the sub-protocol `agentnest.v1`. Only private-range (and loopback) source
//!   addresses are accepted (`link.private_sources_only`, not switchable before Phase 3).
//! * [`session`]: the per-connection state machine `PreAuth -> PairPending / Authenticated`. Before authentication the
//!   server sends the `challenge` and nothing else (I1).
//! * [`registry`]: connection table, live stream fan-out, kick on revocation.
//! * [`snapshot`]: snapshot within the byte budget.
//!
//! Everything a phone can do ends in the broker, the device registry or the store; the link never decides.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use tokio::task::JoinHandle;

use crate::approvals::broker::Broker;
use crate::audit::Audit;
use crate::auth::challenge::AdmissionControl;
use crate::auth::devices::DeviceRegistry;
use crate::auth::pairing::PairingManager;
use crate::events::EventBus;
use crate::identity::ServerIdentity;
use crate::pipeline::Pipeline;
use crate::state::timers::Clock;
use crate::store::Store;

pub mod registry;
pub mod session;
pub mod snapshot;

pub use registry::{ConnCommand, Published, Registry};

/// WebSocket sub-protocol token.
pub use agentnest_protocol::limits::WS_SUBPROTOCOL;
/// Route of the link.
pub const LINK_PATH: &str = "/v1/link";

/// Protocol timing. The defaults are the documented values; tests shorten them.
#[derive(Clone, Debug)]
pub struct Timing {
    /// Time to send a valid `pair` / `hello` after the connection opened (security.md 11: 5 s).
    pub preauth_ms: u64,
    /// Time the PC user has to confirm a pairing (60 s).
    pub pair_confirm_ms: u64,
    /// Delay before a failed authentication is answered (1 s).
    pub auth_fail_delay_ms: u64,
    /// A connection without any frame for this long is closed with 4008 (90 s).
    pub idle_close_ms: u64,
    /// Wait for the `ack` of an `approval_request` before re-sending it (5 s).
    pub ack_retry_ms: u64,
    /// Number of re-sends before the delivery counts as failed (3).
    pub ack_retries: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            preauth_ms: 5_000,
            pair_confirm_ms: 60_000,
            auth_fail_delay_ms: 1_000,
            idle_close_ms: 90_000,
            ack_retry_ms: 5_000,
            ack_retries: 3,
        }
    }
}

/// Policy values the phone is told in `welcome` (owned by the PC settings).
#[derive(Debug)]
pub struct LinkPolicy {
    /// `approval.deny_requires_auth`.
    pub deny_requires_auth: AtomicBool,
    /// `approval.critical_remote == local_only`.
    pub critical_local_only: AtomicBool,
    /// Effective approval TTL in seconds (`welcome.limits.approval_ttl_s`).
    pub effective_ttl_s: AtomicU32,
}

impl LinkPolicy {
    /// A policy.
    pub fn new(deny_requires_auth: bool, critical_local_only: bool, effective_ttl_s: u32) -> Self {
        Self {
            deny_requires_auth: AtomicBool::new(deny_requires_auth),
            critical_local_only: AtomicBool::new(critical_local_only),
            effective_ttl_s: AtomicU32::new(effective_ttl_s),
        }
    }
}

/// What the phone is told about this PC.
#[derive(Clone, Debug)]
pub struct PcInfo {
    /// `pc_...`.
    pub pc_id: String,
    /// Display name.
    pub name: String,
    /// LAN addresses.
    pub hosts: Vec<String>,
    /// WSS port.
    pub port: u16,
}

/// Everything the link needs. Cheap to share.
pub struct LinkContext {
    /// Storage.
    pub store: Store,
    /// Clock.
    pub clock: Arc<dyn Clock>,
    /// Connections and live fan-out.
    pub registry: Arc<Registry>,
    /// Event pipeline.
    pub pipeline: Arc<Pipeline>,
    /// Approval broker.
    pub broker: Arc<Broker>,
    /// Device registry.
    pub devices: DeviceRegistry,
    /// Pairing.
    pub pairing: PairingManager,
    /// Admission control (connection caps, failure rate limit).
    pub admission: AdmissionControl,
    /// Audit.
    pub audit: Audit,
    /// Desktop events.
    pub bus: EventBus,
    /// This PC.
    pub pc: RwLock<PcInfo>,
    /// Policy.
    pub policy: Arc<LinkPolicy>,
    /// Timing.
    pub timing: Timing,
    /// Only accept private-range source addresses.
    pub private_sources_only: bool,
}

impl std::fmt::Debug for LinkContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkContext").finish_non_exhaustive()
    }
}

impl LinkContext {
    /// Updates the advertised addresses (after an address change) and tells every connected phone (`hosts_update`).
    pub fn set_hosts(&self, hosts: Vec<String>) {
        let port = {
            let mut pc = match self.pc.write() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            pc.hosts = hosts.clone();
            pc.port
        };
        self.registry.send_all(|| {
            ConnCommand::Send(agentnest_protocol::Message::HostsUpdate(
                agentnest_protocol::HostsUpdatePayload {
                    addresses: hosts.clone(),
                    port,
                },
            ))
        });
    }

    /// A copy of the PC info.
    pub fn pc_info(&self) -> PcInfo {
        match self.pc.read() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }
}

/// `true` for the source addresses a phone on the LAN can have: loopback (local tests and the self-connect
/// diagnostic), RFC 1918, CGNAT `100.64.0.0/10`, IPv4 link-local, IPv6 unique-local and link-local.
pub fn is_private_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_source(IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

fn offers_subprotocol(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|p| p.trim() == WS_SUBPROTOCOL)
}

async fn ws_handler(
    State(ctx): State<Arc<LinkContext>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // sub-protocol mismatch: the handshake is refused (protocol.md 1)
    if !offers_subprotocol(&headers) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if ctx.private_sources_only && !is_private_source(addr.ip()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let max = agentnest_protocol::limits::MAX_FRAME_S2C_BYTES;
    ws.protocols([WS_SUBPROTOCOL])
        // our own 32 KiB check (c2s limit) runs in the session; the transport limit only guards memory
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| session::run(socket, ctx, addr.ip()))
}

/// Binds the WSS listener to one LAN interface address. The unspecified address (`0.0.0.0`, `::`) is refused.
pub fn bind_link(addr: IpAddr, port: u16) -> std::io::Result<std::net::TcpListener> {
    if addr.is_unspecified() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the link must not listen on every interface",
        ));
    }
    let l = std::net::TcpListener::bind(SocketAddr::new(addr, port))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// The running WSS listener.
pub struct LinkServer {
    /// The bound address.
    pub addr: SocketAddr,
    handle: Handle<SocketAddr>,
    tls: RustlsConfig,
    task: JoinHandle<()>,
    ctx: Arc<LinkContext>,
}

impl std::fmt::Debug for LinkServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkServer")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl LinkServer {
    /// Starts serving on `listener` with the TLS identity. Must run inside a tokio runtime.
    pub fn start(
        ctx: Arc<LinkContext>,
        identity: &ServerIdentity,
        listener: std::net::TcpListener,
    ) -> Result<Self, crate::identity::IdentityError> {
        let addr = listener
            .local_addr()
            .map_err(crate::identity::IdentityError::Io)?;
        let tls = RustlsConfig::from_config(identity.rustls_server_config()?);
        let app = Router::new()
            .route(LINK_PATH, get(ws_handler))
            .with_state(ctx.clone());
        let handle: Handle<SocketAddr> = Handle::new();
        let server = axum_server::from_tcp_rustls(listener, tls.clone())
            .map_err(crate::identity::IdentityError::Io)?
            // no `http1_only()`: axum-server then serves the connection without upgrade support and every WebSocket handshake
            // would end right after the 101 (ALPN already offers only http/1.1)
            .handle(handle.clone());
        let task = tokio::spawn(async move {
            if let Err(e) = server
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                tracing::warn!(error = %e, "the link listener stopped");
            }
        });
        Ok(Self {
            addr,
            handle,
            tls,
            task,
            ctx,
        })
    }

    /// Swaps the certificate (same key, new SANs) without dropping connections.
    pub fn reload_identity(
        &self,
        identity: &ServerIdentity,
    ) -> Result<(), crate::identity::IdentityError> {
        self.tls
            .reload_from_config(identity.rustls_server_config()?);
        Ok(())
    }

    /// Number of open TLS connections.
    pub fn connection_count(&self) -> usize {
        self.handle.connection_count()
    }

    /// Stops the listener: every connected phone gets `bye{reason}` first, then the listener and the connections close.
    /// `reconnect == false` makes the phone back off for minutes (`link.enabled=false`).
    pub async fn stop(
        self,
        reason: agentnest_protocol::ByeReason,
        reconnect: bool,
        message_ko: &str,
        close_code: u16,
    ) {
        let msg = message_ko.to_owned();
        self.ctx.registry.send_all(|| ConnCommand::Bye {
            reason: reason.clone(),
            reconnect,
            message_ko: msg.clone(),
            close_code,
        });
        // give the sessions a moment to flush their close frames
        for _ in 0..20 {
            if self.ctx.registry.online_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.handle.graceful_shutdown(Some(Duration::from_secs(2)));
        let _ = tokio::time::timeout(Duration::from_secs(3), self.task).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_sources_are_lan_and_loopback_only() {
        for ok in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.10",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.3.4",
            "::1",
            "fd00::5",
            "fc00::1",
            "fe80::1",
            "::ffff:192.168.0.10",
        ] {
            assert!(is_private_source(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "192.169.0.1",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_private_source(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn the_unspecified_address_cannot_be_bound() {
        assert!(bind_link("0.0.0.0".parse().unwrap(), 0).is_err());
        assert!(bind_link("::".parse().unwrap(), 0).is_err());
        let l = bind_link("127.0.0.1".parse().unwrap(), 0).unwrap();
        assert!(l.local_addr().unwrap().ip().is_loopback());
    }

    #[test]
    fn the_default_timing_is_the_documented_one() {
        let t = Timing::default();
        assert_eq!(t.preauth_ms, 5_000);
        assert_eq!(t.pair_confirm_ms, 60_000);
        assert_eq!(t.auth_fail_delay_ms, 1_000);
        assert_eq!(t.idle_close_ms, 90_000);
        assert_eq!((t.ack_retry_ms, t.ack_retries), (5_000, 3));
    }
}
