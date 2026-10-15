//! Authentication of the loopback hook channel between `agentnest-hook` (the command-hook relay) and the daemon
//! (docs/security.md 1.2, docs/integrations/claude-code.md 3/4).
//!
//! Claude Code's own `type: "http"` hooks send the token in a literal header and cannot verify the answer: whoever
//! listens on the port can answer. The relay CLI can do better, and these helpers are its protocol:
//!
//! * The relay **never sends the hook token**. It derives a key from it ([`derive_key`]) and sends only a one-time proof
//!   ([`request_proof`]) over `(method, path, timestamp, nonce)`. A process that squats the port sees a proof it cannot
//!   replay (the daemon remembers nonces) and cannot turn into a valid answer.
//! * The daemon answers with `X-AgentNest-Sig = base64(HMAC-SHA256(key, "resp" || nonce || status || body))`
//!   ([`response_sig`]). The relay prints nothing (= "no decision") for any answer whose signature does not verify.
//!
//! Everything is HMAC-SHA256 over `ring`; comparisons are `ring::hmac::verify` (constant time).

use ring::hmac;

use crate::canonical::sha256;
use crate::qr::{b64_decode, b64_encode};

/// Header: random one-time value chosen by the relay (base64url or any printable text, 16..=64 chars).
pub const HEADER_NONCE: &str = "x-agentnest-nonce";
/// Header: relay time in milliseconds since the Unix epoch (decimal).
pub const HEADER_TS: &str = "x-agentnest-ts";
/// Header: the request proof (standard base64).
pub const HEADER_PROOF: &str = "x-agentnest-proof";
/// Header: the response signature (standard base64).
pub const HEADER_SIG: &str = "x-agentnest-sig";

/// How far the relay's clock may be from the daemon's (both run on the same machine).
pub const MAX_SKEW_MS: i64 = 120_000;

const KEY_LABEL: &[u8] = b"agentnest-hook-hmac-v1\0";
const REQ_LABEL: &[u8] = b"agentnest-hook-req-v1\0";
const RESP_LABEL: &[u8] = b"agentnest-hook-resp-v1\0";

/// The HMAC key for a hook token: `SHA-256("agentnest-hook-hmac-v1\0" || token)`. Domain separated from the token hash
/// the database stores (`SHA-256(token)`), so a copy of the database does not hand out the key.
pub fn derive_key(token: &str) -> [u8; 32] {
    let mut m = Vec::with_capacity(KEY_LABEL.len() + token.len());
    m.extend_from_slice(KEY_LABEL);
    m.extend_from_slice(token.as_bytes());
    sha256(&m)
}

fn request_message(method: &str, path: &str, ts: &str, nonce: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(REQ_LABEL);
    for part in [method, path, ts, nonce] {
        m.extend_from_slice(part.as_bytes());
        m.push(0);
    }
    m
}

/// The proof the relay sends instead of the token.
pub fn request_proof(key: &[u8; 32], method: &str, path: &str, ts: &str, nonce: &str) -> String {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    b64_encode(hmac::sign(&k, &request_message(method, path, ts, nonce)).as_ref())
}

/// Verifies a request proof (constant time). Malformed input simply fails.
pub fn verify_request_proof(
    key: &[u8; 32],
    method: &str,
    path: &str,
    ts: &str,
    nonce: &str,
    proof_b64: &str,
) -> bool {
    let Ok(tag) = b64_decode(proof_b64) else {
        return false;
    };
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&k, &request_message(method, path, ts, nonce), &tag).is_ok()
}

fn response_message(nonce: &str, status: u16, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(RESP_LABEL.len() + nonce.len() + body.len() + 16);
    m.extend_from_slice(RESP_LABEL);
    m.extend_from_slice(nonce.as_bytes());
    m.push(0);
    m.extend_from_slice(status.to_string().as_bytes());
    m.push(0);
    m.extend_from_slice(body);
    m
}

/// The signature the daemon puts on its answer to a proven request.
pub fn response_sig(key: &[u8; 32], nonce: &str, status: u16, body: &[u8]) -> String {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    b64_encode(hmac::sign(&k, &response_message(nonce, status, body)).as_ref())
}

/// Verifies the signature of an answer (constant time). Malformed input simply fails.
pub fn verify_response_sig(
    key: &[u8; 32],
    nonce: &str,
    status: u16,
    body: &[u8],
    sig_b64: &str,
) -> bool {
    let Ok(tag) = b64_decode(sig_b64) else {
        return false;
    };
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&k, &response_message(nonce, status, body), &tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_and_signatures_verify_only_for_the_exact_inputs() {
        let key = derive_key("an_hk_token");
        assert_ne!(key, sha256(b"an_hk_token"), "not the stored hash");
        let proof = request_proof(
            &key,
            "POST",
            "/v1/hooks/claude-code",
            "1700000000000",
            "nonce-0123456789ab",
        );
        assert!(verify_request_proof(
            &key,
            "POST",
            "/v1/hooks/claude-code",
            "1700000000000",
            "nonce-0123456789ab",
            &proof
        ));
        for (m, p, t, n) in [
            (
                "GET",
                "/v1/hooks/claude-code",
                "1700000000000",
                "nonce-0123456789ab",
            ),
            (
                "POST",
                "/v1/hooks/codex",
                "1700000000000",
                "nonce-0123456789ab",
            ),
            (
                "POST",
                "/v1/hooks/claude-code",
                "1700000000001",
                "nonce-0123456789ab",
            ),
            (
                "POST",
                "/v1/hooks/claude-code",
                "1700000000000",
                "nonce-0123456789ac",
            ),
        ] {
            assert!(
                !verify_request_proof(&key, m, p, t, n, &proof),
                "{m} {p} {t} {n}"
            );
        }
        assert!(!verify_request_proof(
            &derive_key("other"),
            "POST",
            "/v1/hooks/claude-code",
            "1700000000000",
            "nonce-0123456789ab",
            &proof
        ));
        assert!(!verify_request_proof(
            &key,
            "POST",
            "/x",
            "1",
            "n",
            "not base64!"
        ));

        let sig = response_sig(&key, "n1", 200, b"{\"a\":1}");
        assert!(verify_response_sig(&key, "n1", 200, b"{\"a\":1}", &sig));
        assert!(
            !verify_response_sig(&key, "n2", 200, b"{\"a\":1}", &sig),
            "another request's answer"
        );
        assert!(
            !verify_response_sig(&key, "n1", 204, b"{\"a\":1}", &sig),
            "status is signed"
        );
        assert!(
            !verify_response_sig(&key, "n1", 200, b"{\"a\":2}", &sig),
            "body is signed"
        );
        assert!(
            !verify_response_sig(&derive_key("other"), "n1", 200, b"{\"a\":1}", &sig),
            "needs the token"
        );
        assert!(!verify_response_sig(&key, "n1", 200, b"", ""));
    }
}
