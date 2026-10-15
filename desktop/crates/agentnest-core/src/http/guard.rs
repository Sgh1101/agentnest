//! The guard of the loopback hook collector (docs/security.md I8, docs/integrations/claude-code.md 4).
//!
//! In this order, for **every** route:
//!
//! 1. an `Origin` or `Sec-Fetch-Site` header makes the request a browser request: **403** (a web page must never be able to
//!    post hook data, even to `127.0.0.1`); so does a `Host` header that is not a loopback literal (DNS rebinding);
//! 2. every route except `GET /v1/health` needs the `X-AgentNest-Token` header; the comparison is constant time (it compares
//!    SHA-256 digests with `subtle`, so even the length of the token is not revealed): **401** with an empty body, the token
//!    value is never logged;
//! 3. a declared body larger than 1 MiB is **413** (a body without a length is cut by the body limit layer of the router).
//!
//! The collector is bound to `127.0.0.1` (and `[::1]`) in code. There is no setting for the address (I10).

use std::sync::{Arc, RwLock};

use agentnest_protocol::canonical::sha256;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::redact::HookToken;

/// Largest accepted request body.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// The authentication header.
pub const TOKEN_HEADER: &str = "x-agentnest-token";
/// The one route that needs no token.
pub const HEALTH_PATH: &str = "/v1/health";

/// Verifies hook tokens. The token itself is never stored in memory by the verifier, only its SHA-256.
#[derive(Debug)]
pub struct HookTokenVerifier {
    hash: RwLock<[u8; 32]>,
}

impl HookTokenVerifier {
    /// A verifier for `token`.
    pub fn new(token: &HookToken) -> Self {
        Self {
            hash: RwLock::new(sha256(token.expose().as_bytes())),
        }
    }

    /// Replaces the accepted token ("reissue hook token").
    pub fn rotate(&self, token: &HookToken) {
        let h = sha256(token.expose().as_bytes());
        match self.hash.write() {
            Ok(mut g) => *g = h,
            Err(e) => *e.into_inner() = h,
        }
    }

    /// `true` if `candidate` is the current token. Constant time.
    pub fn verify(&self, candidate: &str) -> bool {
        let want = match self.hash.read() {
            Ok(g) => *g,
            Err(e) => *e.into_inner(),
        };
        let got = sha256(candidate.as_bytes());
        got.ct_eq(&want).into()
    }
}

/// State of the guard middleware.
#[derive(Debug)]
pub struct GuardState {
    /// Token verification.
    pub tokens: HookTokenVerifier,
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim();
    let name = if let Some(rest) = h.strip_prefix('[') {
        // [::1]:47831
        match rest.split_once(']') {
            Some((addr, _)) => addr,
            None => return false,
        }
    } else {
        h.rsplit_once(':').map(|(n, _)| n).unwrap_or(h)
    };
    matches!(name, "127.0.0.1" | "::1" | "localhost")
}

fn browser_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(header::ORIGIN) || headers.contains_key("sec-fetch-site")
}

/// The guard middleware (see the module docs for the order of the checks).
pub async fn guard(State(g): State<Arc<GuardState>>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    if browser_headers(headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let host_ok = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_none_or(is_loopback_host);
    if !host_ok {
        return StatusCode::FORBIDDEN.into_response();
    }
    if req.uri().path() != HEALTH_PATH {
        let ok = headers
            .get(TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| g.tokens.verify(t));
        if !ok {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    let too_big = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > MAX_BODY_BYTES);
    if too_big {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_verifier_accepts_exactly_the_current_token() {
        let v = HookTokenVerifier::new(&HookToken::new("an_hk_abc"));
        assert!(v.verify("an_hk_abc"));
        for bad in ["", "an_hk_abd", "an_hk_ab", "an_hk_abc ", "AN_HK_ABC"] {
            assert!(!v.verify(bad), "{bad:?}");
        }
        v.rotate(&HookToken::new("an_hk_new"));
        assert!(!v.verify("an_hk_abc"));
        assert!(v.verify("an_hk_new"));
    }

    #[test]
    fn host_header_must_be_a_loopback_literal() {
        for ok in ["127.0.0.1:47831", "127.0.0.1", "[::1]:47831", "localhost:47831"] {
            assert!(is_loopback_host(ok), "{ok}");
        }
        for bad in ["evil.example:47831", "192.168.0.10:47831", "127.0.0.1.evil.com", "[::2]:1", "[::1"] {
            assert!(!is_loopback_host(bad), "{bad}");
        }
    }
}
