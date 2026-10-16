//! Authentication of the loopback hook channel between `agentnest-hook` (the command-hook relay) and the daemon
//! (docs/security.md 1.2, docs/integrations/claude-code.md 3/4).
//!
//! Claude Code's own `type: "http"` hooks send the token in a literal header and cannot verify the answer: whoever
//! listens on the port can answer. The relay CLI can do better, and these helpers are its protocol:
//!
//! * The relay **never sends the hook token**. It derives a key from it ([`derive_key`]) and sends only a one-time proof
//!   ([`request_proof`]) over `(method, path, timestamp, nonce, via, SHA-256(request body))`. The body hash is part of the
//!   proof, so a process that squats the port cannot attach a different body to a proof it saw: the daemon recomputes the
//!   hash over the body it received and the proof no longer verifies. The daemon also remembers nonces, so the proof
//!   cannot be replayed either.
//! * The daemon answers with `X-AgentNest-Sig = base64(HMAC-SHA256(key, "resp" || nonce || SHA-256(request body) ||
//!   status || body))` ([`response_sig`]). The signature names the request it answers (nonce **and** the hash of the
//!   body the daemon saw), so a squatter cannot relay a signed answer to a different question: the relay recomputes the
//!   hash over the body **it sent** and prints nothing (= "no decision") for any answer that does not verify.
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
const REQ_LABEL: &[u8] = b"agentnest-hook-req-v2\0";
const RESP_LABEL: &[u8] = b"agentnest-hook-resp-v2\0";

/// The HMAC key for a hook token: `SHA-256("agentnest-hook-hmac-v1\0" || token)`. Domain separated from the token hash
/// the database stores (`SHA-256(token)`), so a copy of the database does not hand out the key.
pub fn derive_key(token: &str) -> [u8; 32] {
    let mut m = Vec::with_capacity(KEY_LABEL.len() + token.len());
    m.extend_from_slice(KEY_LABEL);
    m.extend_from_slice(token.as_bytes());
    sha256(&m)
}

/// SHA-256 of a request body: the value both sides bind into the proof and the signature.
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    sha256(body)
}

/// Everything a request proof covers. The body is bound by its digest ([`body_digest`]).
#[derive(Clone, Copy, Debug)]
pub struct RequestBinding<'a> {
    /// HTTP method (`POST`).
    pub method: &'a str,
    /// Request path without the query (`/v1/hooks/claude-code`).
    pub path: &'a str,
    /// The `X-AgentNest-Ts` header value.
    pub ts: &'a str,
    /// The `X-AgentNest-Nonce` header value.
    pub nonce: &'a str,
    /// The `X-AgentNest-Via` header value (empty when the header is absent).
    pub via: &'a str,
    /// `SHA-256` of the request body as sent (empty body: the digest of nothing).
    pub body_sha256: [u8; 32],
}

fn request_message(b: &RequestBinding<'_>) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(REQ_LABEL);
    for part in [b.method, b.path, b.ts, b.nonce, b.via] {
        m.extend_from_slice(part.as_bytes());
        m.push(0);
    }
    // fixed length and last: no ambiguity with the NUL-terminated parts before it
    m.extend_from_slice(&b.body_sha256);
    m
}

/// The proof the relay sends instead of the token.
pub fn request_proof(key: &[u8; 32], binding: &RequestBinding<'_>) -> String {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    b64_encode(hmac::sign(&k, &request_message(binding)).as_ref())
}

/// Verifies a request proof (constant time). Malformed input simply fails.
pub fn verify_request_proof(key: &[u8; 32], binding: &RequestBinding<'_>, proof_b64: &str) -> bool {
    let Ok(tag) = b64_decode(proof_b64) else {
        return false;
    };
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&k, &request_message(binding), &tag).is_ok()
}

fn response_message(
    nonce: &str,
    request_body_sha256: &[u8; 32],
    status: u16,
    body: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(RESP_LABEL.len() + nonce.len() + body.len() + 48);
    m.extend_from_slice(RESP_LABEL);
    m.extend_from_slice(nonce.as_bytes());
    m.push(0);
    m.extend_from_slice(request_body_sha256);
    m.extend_from_slice(status.to_string().as_bytes());
    m.push(0);
    m.extend_from_slice(body);
    m
}

/// The signature the daemon puts on its answer to a proven request. `request_body_sha256` is the digest of the request
/// body the daemon received (the one the proof was verified against).
pub fn response_sig(
    key: &[u8; 32],
    nonce: &str,
    request_body_sha256: &[u8; 32],
    status: u16,
    body: &[u8],
) -> String {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    b64_encode(
        hmac::sign(
            &k,
            &response_message(nonce, request_body_sha256, status, body),
        )
        .as_ref(),
    )
}

/// Verifies the signature of an answer (constant time). `request_body_sha256` is the digest of the body the **relay
/// sent**: an answer the daemon gave to a different body does not verify. Malformed input simply fails.
pub fn verify_response_sig(
    key: &[u8; 32],
    nonce: &str,
    request_body_sha256: &[u8; 32],
    status: u16,
    body: &[u8],
    sig_b64: &str,
) -> bool {
    let Ok(tag) = b64_decode(sig_b64) else {
        return false;
    };
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(
        &k,
        &response_message(nonce, request_body_sha256, status, body),
        &tag,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding<'a>(body: &[u8]) -> RequestBinding<'a> {
        RequestBinding {
            method: "POST",
            path: "/v1/hooks/claude-code",
            ts: "1700000000000",
            nonce: "nonce-0123456789ab",
            via: "cli",
            body_sha256: body_digest(body),
        }
    }

    #[test]
    fn proofs_and_signatures_verify_only_for_the_exact_inputs() {
        let key = derive_key("an_hk_token");
        assert_ne!(key, sha256(b"an_hk_token"), "not the stored hash");
        let good = binding(b"{\"cmd\":\"ls\"}");
        let proof = request_proof(&key, &good);
        assert!(verify_request_proof(&key, &good, &proof));
        let variants = [
            RequestBinding {
                method: "GET",
                ..good
            },
            RequestBinding {
                path: "/v1/hooks/codex",
                ..good
            },
            RequestBinding {
                ts: "1700000000001",
                ..good
            },
            RequestBinding {
                nonce: "nonce-0123456789ac",
                ..good
            },
            RequestBinding { via: "", ..good },
            RequestBinding {
                via: "cli2",
                ..good
            },
            RequestBinding {
                body_sha256: body_digest(b"{\"cmd\":\"rm -rf /\"}"),
                ..good
            },
            RequestBinding {
                body_sha256: body_digest(b""),
                ..good
            },
        ];
        for (i, v) in variants.iter().enumerate() {
            assert!(!verify_request_proof(&key, v, &proof), "variant {i}");
        }
        assert!(!verify_request_proof(&derive_key("other"), &good, &proof));
        assert!(!verify_request_proof(&key, &good, "not base64!"));

        let req = body_digest(b"request");
        let sig = response_sig(&key, "n1", &req, 200, b"{\"a\":1}");
        assert!(verify_response_sig(
            &key,
            "n1",
            &req,
            200,
            b"{\"a\":1}",
            &sig
        ));
        assert!(
            !verify_response_sig(&key, "n2", &req, 200, b"{\"a\":1}", &sig),
            "another request's answer (nonce)"
        );
        assert!(
            !verify_response_sig(
                &key,
                "n1",
                &body_digest(b"other request"),
                200,
                b"{\"a\":1}",
                &sig
            ),
            "the same nonce answered for a different request body"
        );
        assert!(
            !verify_response_sig(&key, "n1", &req, 204, b"{\"a\":1}", &sig),
            "status is signed"
        );
        assert!(
            !verify_response_sig(&key, "n1", &req, 200, b"{\"a\":2}", &sig),
            "body is signed"
        );
        assert!(
            !verify_response_sig(&derive_key("other"), "n1", &req, 200, b"{\"a\":1}", &sig),
            "needs the token"
        );
        assert!(!verify_response_sig(&key, "n1", &req, 200, b"", ""));
    }
}
