//! The guard of the loopback hook collector (docs/security.md I8, docs/integrations/claude-code.md 4).
//!
//! In this order, for **every** route:
//!
//! 1. an `Origin` or `Sec-Fetch-Site` header makes the request a browser request: **403** (a web page must never be able to
//!    post hook data, even to `127.0.0.1`); so does a `Host` header that is not a loopback literal (DNS rebinding);
//! 2. every route except `GET /v1/health` needs either the `X-AgentNest-Token` header (Claude Code's `type: "http"` hooks;
//!    the comparison is constant time: it compares SHA-256 digests with `subtle`, so even the length of the token is not
//!    revealed) **or** the relay's one-time proof (`agentnest-hook`, see [`agentnest_protocol::hook_auth`]: timestamp, nonce
//!    and an HMAC over them; the token itself is never sent, each nonce is accepted once): **401** with an empty body,
//!    the token value is never logged. An answer to a **proven** request carries `X-AgentNest-Sig`, so the relay can tell
//!    the daemon from anything else that listens on the port (an HTTP hook cannot, see security.md 1.2). Both the proof and
//!    the signature cover `SHA-256(request body)` (and the proof also `X-AgentNest-Via`), so neither a body swapped in front
//!    of a valid proof nor a signed answer relayed for another body works. The guard reads such a body once (at most
//!    1 MiB) and hands it on to the handler;
//!    **which channel a request used is decided here, not by a header**: a request that passed the relay proof carries
//!    [`HookAuth::RelayProof`] as a request extension, everything else is [`HookAuth::Token`] (the literal token of Claude
//!    Code's `type: "http"` hooks);
//! 3. a declared body larger than 1 MiB is **413** (a body without a length is cut by the body limit layer of the router).
//!
//! The collector is bound to `127.0.0.1` (and `[::1]`) in code. There is no setting for the address (I10).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use agentnest_protocol::canonical::sha256;
use agentnest_protocol::hook_auth;
use axum::body::Body;
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
/// Header the relay sets to name its channel. It is bound into the proof but never trusted on its own ([`HookAuth`]).
pub const VIA_HEADER: &str = "x-agentnest-via";
/// The one route that needs no token.
pub const HEALTH_PATH: &str = "/v1/health";

/// Most nonces remembered at once. A legitimate relay needs a handful per second at most; when the table is full new
/// proofs are refused (fail closed) until old entries age out.
const MAX_REMEMBERED_NONCES: usize = 20_000;
/// How long a nonce is remembered (more than twice the accepted clock skew).
const NONCE_MEMORY_MS: i64 = 5 * 60_000;

/// How a request proved itself to the guard. Inserted into the request extensions by [`guard`]; the handlers read it
/// instead of trusting any header to tell the channels apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookAuth {
    /// No authentication was required (`GET /v1/health`).
    None,
    /// The literal `X-AgentNest-Token` of an HTTP hook. The answer cannot be authenticated back (security.md 1.2).
    Token,
    /// The relay's one-time proof (`agentnest-hook`): the answer is signed.
    RelayProof,
}

/// Verifies hook tokens and relay proofs. The token itself is never stored in memory by the verifier, only its SHA-256
/// and the key derived from it for the relay protocol.
pub struct HookTokenVerifier {
    state: RwLock<([u8; 32], [u8; 32])>,
    nonces: Mutex<HashMap<String, i64>>,
}

impl std::fmt::Debug for HookTokenVerifier {
    /// Never prints the token hash, the HMAC key or the remembered nonces.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookTokenVerifier")
            .field("state", &"[redacted]")
            .field("nonces", &"[redacted]")
            .finish()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

impl HookTokenVerifier {
    /// A verifier for `token`.
    pub fn new(token: &HookToken) -> Self {
        Self {
            state: RwLock::new((
                sha256(token.expose().as_bytes()),
                hook_auth::derive_key(token.expose()),
            )),
            nonces: Mutex::new(HashMap::new()),
        }
    }

    /// Replaces the accepted token ("reissue hook token"). Remembered nonces of the old token are dropped.
    pub fn rotate(&self, token: &HookToken) {
        let v = (
            sha256(token.expose().as_bytes()),
            hook_auth::derive_key(token.expose()),
        );
        match self.state.write() {
            Ok(mut g) => *g = v,
            Err(e) => *e.into_inner() = v,
        }
        self.nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    fn snapshot(&self) -> ([u8; 32], [u8; 32]) {
        match self.state.read() {
            Ok(g) => *g,
            Err(e) => *e.into_inner(),
        }
    }

    /// `true` if `candidate` is the current token. Constant time.
    pub fn verify(&self, candidate: &str) -> bool {
        let want = self.snapshot().0;
        let got = sha256(candidate.as_bytes());
        got.ct_eq(&want).into()
    }

    /// `true` if the relay's proof is valid for the current token and for exactly this request (method, path, `via` and
    /// body digest), the timestamp is within the accepted skew and the nonce has not been seen before (a replayed proof
    /// is refused). The nonce is remembered only after the proof checked out, so unauthenticated callers cannot fill the
    /// table.
    pub fn verify_proof(&self, binding: &hook_auth::RequestBinding<'_>, proof_b64: &str) -> bool {
        self.verify_proof_at(now_ms(), binding, proof_b64)
    }

    fn verify_proof_at(
        &self,
        now: i64,
        binding: &hook_auth::RequestBinding<'_>,
        proof_b64: &str,
    ) -> bool {
        let nonce = binding.nonce;
        if !(16..=64).contains(&nonce.len()) || nonce.chars().any(|c| c.is_control()) {
            return false;
        }
        let Ok(ts_ms) = binding.ts.parse::<i64>() else {
            return false;
        };
        if (now - ts_ms).abs() > hook_auth::MAX_SKEW_MS {
            return false;
        }
        let key = self.snapshot().1;
        if !hook_auth::verify_request_proof(&key, binding, proof_b64) {
            return false;
        }
        let mut seen = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        if seen.len() >= MAX_REMEMBERED_NONCES / 2 {
            seen.retain(|_, t| now - *t < NONCE_MEMORY_MS);
        }
        if seen.len() >= MAX_REMEMBERED_NONCES || seen.contains_key(nonce) {
            return false;
        }
        seen.insert(nonce.to_owned(), now);
        true
    }

    /// The `X-AgentNest-Sig` value for an answer to a proven request. `request_body_sha256` is the digest of the request
    /// body the proof was verified against.
    pub fn sign_response(
        &self,
        nonce: &str,
        request_body_sha256: &[u8; 32],
        status: u16,
        body: &[u8],
    ) -> String {
        hook_auth::response_sig(&self.snapshot().1, nonce, request_body_sha256, status, body)
    }
}

/// State of the guard middleware.
#[derive(Debug)]
pub struct GuardState {
    /// Token verification.
    pub tokens: HookTokenVerifier,
}

/// `":47831"` or nothing: the only thing that may follow the host name (a userinfo trick such as
/// `127.0.0.1:1@evil.com` is a different host and fails here).
fn only_port(rest: &str) -> bool {
    match rest.strip_prefix(':') {
        None => rest.is_empty(),
        Some(p) => !p.is_empty() && p.len() <= 5 && p.chars().all(|c| c.is_ascii_digit()),
    }
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim();
    let name = if let Some(rest) = h.strip_prefix('[') {
        // [::1]:47831
        match rest.split_once(']') {
            Some((addr, tail)) if only_port(tail) => addr,
            _ => return false,
        }
    } else {
        match h.rsplit_once(':') {
            Some((n, port)) if only_port(&format!(":{port}")) => n,
            Some(_) => return false,
            None => h,
        }
    };
    matches!(name, "127.0.0.1" | "::1" | "localhost")
}

fn browser_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(header::ORIGIN) || headers.contains_key("sec-fetch-site")
}

/// What a proven request needs for signing its answer.
struct Proven {
    nonce: String,
    body_sha256: [u8; 32],
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
    let too_big = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > MAX_BODY_BYTES);
    let mut req = req;
    // the nonce and the body digest of a proven request: the answer is signed with them
    let mut proven: Option<Proven> = None;
    let mut auth = HookAuth::None;
    if req.uri().path() != HEALTH_PATH {
        let headers = req.headers();
        let token_ok = headers
            .get(TOKEN_HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| g.tokens.verify(t));
        if token_ok {
            auth = HookAuth::Token;
        } else {
            let h = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
            let (Some(ts), Some(nonce), Some(proof), via) = (
                h(hook_auth::HEADER_TS),
                h(hook_auth::HEADER_NONCE),
                h(hook_auth::HEADER_PROOF),
                h(VIA_HEADER).unwrap_or(""),
            ) else {
                return StatusCode::UNAUTHORIZED.into_response();
            };
            if too_big {
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            }
            let (ts, nonce, proof, via) = (
                ts.to_owned(),
                nonce.to_owned(),
                proof.to_owned(),
                via.to_owned(),
            );
            // the proof covers the body: read it once (bounded), verify, then hand the same bytes on
            let (parts, body) = req.into_parts();
            let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            };
            let body_sha256 = hook_auth::body_digest(&bytes);
            let binding = hook_auth::RequestBinding {
                method: parts.method.as_str(),
                path: parts.uri.path(),
                ts: &ts,
                nonce: &nonce,
                via: &via,
                body_sha256,
            };
            if !g.tokens.verify_proof(&binding, &proof) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            req = Request::from_parts(parts, Body::from(bytes));
            auth = HookAuth::RelayProof;
            proven = Some(Proven { nonce, body_sha256 });
        }
    }
    if too_big {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    req.extensions_mut().insert(auth);
    let response = next.run(req).await;
    let Some(p) = proven else {
        return response;
    };
    sign(&g.tokens, &p, response).await
}

/// Signs the answer to a proven request (`X-AgentNest-Sig`). A body that cannot be read becomes an empty `500` so that no
/// unsigned answer is mistaken for a signed one.
async fn sign(tokens: &HookTokenVerifier, proven: &Proven, response: Response) -> Response {
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let sig = tokens.sign_response(
        &proven.nonce,
        &proven.body_sha256,
        parts.status.as_u16(),
        &bytes,
    );
    if let Ok(v) = header::HeaderValue::from_str(&sig) {
        parts.headers.insert(hook_auth::HEADER_SIG, v);
    }
    Response::from_parts(parts, Body::from(bytes))
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

    fn binding<'a>(ts: &'a str, nonce: &'a str, body: &[u8]) -> hook_auth::RequestBinding<'a> {
        hook_auth::RequestBinding {
            method: "POST",
            path: "/v1/hooks/claude-code",
            ts,
            nonce,
            via: "cli",
            body_sha256: hook_auth::body_digest(body),
        }
    }

    #[test]
    fn relay_proofs_are_one_time_fresh_and_bound_to_the_request() {
        let v = HookTokenVerifier::new(&HookToken::new("an_hk_abc"));
        let key = hook_auth::derive_key("an_hk_abc");
        let now = 1_800_000_000_000_i64;
        let body = b"{\"hook_event_name\":\"PermissionRequest\"}";
        let proof = |ts: i64, nonce: &str| {
            hook_auth::request_proof(&key, &binding(&ts.to_string(), nonce, body))
        };
        let n1 = "nonce-0123456789ab";
        let nows = now.to_string();
        let p = proof(now, n1);
        assert!(v.verify_proof_at(now, &binding(&nows, n1, body), &p));
        // replay of the same proof
        assert!(!v.verify_proof_at(now, &binding(&nows, n1, body), &p));
        // stale / future timestamps, short nonces, wrong path, wrong token
        let n2 = "nonce-0123456789ac";
        let old = now - hook_auth::MAX_SKEW_MS - 1;
        assert!(!v.verify_proof_at(now, &binding(&old.to_string(), n2, body), &proof(old, n2)));
        let future = now + hook_auth::MAX_SKEW_MS + 1;
        assert!(!v.verify_proof_at(
            now,
            &binding(&future.to_string(), n2, body),
            &proof(future, n2)
        ));
        assert!(!v.verify_proof_at(now, &binding(&nows, "short", body), &proof(now, "short")));
        let other_path = hook_auth::RequestBinding {
            path: "/v1/hooks/codex",
            ..binding(&nows, n2, body)
        };
        assert!(!v.verify_proof_at(now, &other_path, &proof(now, n2)));
        let other =
            hook_auth::request_proof(&hook_auth::derive_key("x"), &binding(&nows, n2, body));
        assert!(!v.verify_proof_at(now, &binding(&nows, n2, body), &other));
        // a body swapped in front of a valid proof (the squatter's trick) fails and does not burn the nonce
        assert!(!v.verify_proof_at(
            now,
            &binding(
                &nows,
                n2,
                b"{\"hook_event_name\":\"PermissionRequest\",\"x\":1}"
            ),
            &proof(now, n2)
        ));
        let other_via = hook_auth::RequestBinding {
            via: "",
            ..binding(&nows, n2, body)
        };
        assert!(!v.verify_proof_at(now, &other_via, &proof(now, n2)));
        // a failed attempt does not burn the nonce
        assert!(v.verify_proof_at(now, &binding(&nows, n2, body), &proof(now, n2)));
        // rotation invalidates old proofs and forgets nonces
        v.rotate(&HookToken::new("an_hk_new"));
        let n3 = "nonce-0123456789ad";
        assert!(!v.verify_proof_at(now, &binding(&nows, n3, body), &proof(now, n3)));
    }

    #[test]
    fn debug_output_hides_the_key_material() {
        let v = HookTokenVerifier::new(&HookToken::new("an_hk_debug_secret_value"));
        let key = hook_auth::derive_key("an_hk_debug_secret_value");
        let g = GuardState { tokens: v };
        let text = format!("{g:?}");
        assert!(text.contains("redacted"), "{text}");
        assert!(!text.contains("an_hk_debug"), "{text}");
        assert!(!text.contains(&format!("{key:?}")), "{text}");
        assert!(!text.contains(&format!("{:?}", &key[..4])), "{text}");
    }

    #[test]
    fn host_header_must_be_a_loopback_literal() {
        for ok in [
            "127.0.0.1:47831",
            "127.0.0.1",
            "[::1]:47831",
            "localhost:47831",
        ] {
            assert!(is_loopback_host(ok), "{ok}");
        }
        for bad in [
            "evil.example:47831",
            "192.168.0.10:47831",
            "127.0.0.1.evil.com",
            "[::2]:1",
            "[::1",
            "127.0.0.1:1@evil.com",
            "127.0.0.1:47831@evil.com:80",
            "localhost:80@evil.com",
            "[::1]:1@evil.com",
            "[::1]evil",
            "127.0.0.1:",
            "127.0.0.1:99999999",
            "user@127.0.0.1",
        ] {
            assert!(!is_loopback_host(bad), "{bad}");
        }
    }
}
