//! Loopback axum router for hook collection: `POST /v1/hooks/{claude-code,codex}`, `POST /v1/statusline/claude-code`,
//! `GET /v1/health`, `GET /v1/daemon` (docs/integrations/claude-code.md 4, security.md I8).
//!
//! The listener is bound to `127.0.0.1` and, if available, `[::1]` **in code**; the address is not configurable (I10).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub mod guard;
pub mod hooks;

pub use guard::{GuardState, HookTokenVerifier, MAX_BODY_BYTES};
pub use hooks::{DaemonInfo, HttpContext, HttpSettings};

/// The router with the guard in front of every route.
pub fn router(ctx: Arc<HttpContext>, guard_state: Arc<GuardState>) -> Router {
    Router::new()
        .route("/v1/hooks/claude-code", post(hooks::claude_hook))
        .route("/v1/hooks/codex", post(hooks::codex_hook))
        .route("/v1/statusline/claude-code", post(hooks::statusline_hook))
        .route("/v1/health", get(hooks::health))
        .route("/v1/daemon", get(hooks::daemon))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(guard_state, guard::guard))
        .with_state(ctx)
}

/// The running collector.
#[derive(Debug)]
pub struct HttpServer {
    /// The bound loopback addresses (`127.0.0.1:port` and, if available, `[::1]:port`).
    pub addrs: Vec<SocketAddr>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl HttpServer {
    /// The port both listeners share.
    pub fn port(&self) -> u16 {
        self.addrs.first().map(SocketAddr::port).unwrap_or(0)
    }

    /// Stops accepting and waits (at most `grace`) for open requests; held requests must have been ended before.
    pub async fn shutdown(self, grace: std::time::Duration) {
        let _ = self.shutdown.send(true);
        for t in self.tasks {
            let _ = tokio::time::timeout(grace, t).await;
        }
    }
}

/// Binds `127.0.0.1:port` (and `[::1]` on the same port) without starting the server. `port == 0` picks a free port.
/// Returns the IPv4 listener and the optional IPv6 one.
pub fn bind_loopback(port: u16) -> io::Result<(std::net::TcpListener, Option<std::net::TcpListener>)> {
    let v4 = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    v4.set_nonblocking(true)?;
    let actual = v4.local_addr()?.port();
    let v6 = std::net::TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, actual)))
        .and_then(|l| {
            l.set_nonblocking(true)?;
            Ok(l)
        })
        .ok();
    Ok((v4, v6))
}

/// Serves `router` on the given listeners (must run inside a tokio runtime).
pub fn serve(
    router: Router,
    v4: std::net::TcpListener,
    v6: Option<std::net::TcpListener>,
) -> io::Result<HttpServer> {
    let (tx, rx) = watch::channel(false);
    let mut addrs = vec![v4.local_addr()?];
    let mut tasks = Vec::new();
    let mut listeners = vec![TcpListener::from_std(v4)?];
    if let Some(v6) = v6 {
        addrs.push(v6.local_addr()?);
        listeners.push(TcpListener::from_std(v6)?);
    }
    for listener in listeners {
        let app = router.clone();
        let mut shutdown = rx.clone();
        tasks.push(tokio::spawn(async move {
            let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
                let _ = shutdown.wait_for(|v| *v).await;
            });
            if let Err(e) = serve.await {
                tracing::warn!(error = %e, "hook collector stopped");
            }
        }));
    }
    Ok(HttpServer {
        addrs,
        shutdown: tx,
        tasks,
    })
}
