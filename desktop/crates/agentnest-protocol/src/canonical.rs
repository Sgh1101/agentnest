//! Canonical encodings and pairing crypto (protocol.md 4.2/4.3/6.1, security.md 4.2/6.1).
//!
//! Everything here is backed by `ring` only. The byte-exact behaviour is pinned by `protocol/vectors/*.json`, which the
//! Kotlin implementation (`android/core`) reads as well.
//!
//! * [`canonical_json`]: RFC 8785 (JCS): object keys sorted by UTF-16 code units, no whitespace, minimal string escaping
//!   (only `"` `\` and control characters below U+0020; everything else raw UTF-8), every number is the ECMAScript
//!   `Number::toString` of its IEEE-754 double. Duplicate object keys: the last one wins (serde_json semantics).
//! * [`tool_input_sha256`]: lowercase hex SHA-256 of the canonical JSON of `tool_input`. Computed by the PC only.
//! * [`canonical_pair_bytes`], [`pair_proof`], [`sas`]: the pairing possession proof and the short authentication string.

use ring::{digest, hmac};
use serde_json::Value;
use subtle::ConstantTimeEq;

use crate::error::CanonicalError;
use crate::limits::{CHALLENGE_LEN, DEVICE_NAME_MAX_BYTES};

/// Label that starts `canonical_pair_bytes`.
pub const PAIR_LABEL: &[u8] = b"agentnest-pair-v1";
/// Label that starts the SAS HMAC input.
pub const SAS_LABEL: &[u8] = b"sas";

/// Constant-time equality of two byte strings (length differences are not hidden).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Lowercase hex SHA-256 digest.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

// ------------------------------------------------------------------ canonical JSON

/// ECMAScript `Number::toString(x)` for a finite double (RFC 8785 section 3.2.2.3). `-0` becomes `0`.
pub fn es6_number(x: f64) -> String {
    if x == 0.0 {
        return "0".to_owned();
    }
    let (sign, abs) = if x < 0.0 { ("-", -x) } else { ("", x) };
    // `{:e}` yields the shortest round-trip digits, e.g. "1.2345e-7".
    let sci = format!("{abs:e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp10: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp10 + 1; // position of the decimal point relative to the digit string
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let es = if e >= 0 {
            format!("+{e}")
        } else {
            format!("-{}", -e)
        };
        if k == 1 {
            format!("{digits}e{es}")
        } else {
            format!("{}.{}e{es}", &digits[..1], &digits[1..])
        }
    };
    format!("{sign}{body}")
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&es6_number(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                if let Some(v) = map.get(key.as_str()) {
                    write_value(out, v);
                }
            }
            out.push('}');
        }
    }
}

/// RFC 8785 canonical JSON text of `value`.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// `tool_input_sha256`: lowercase hex SHA-256 over the UTF-8 canonical JSON of `tool_input`.
pub fn tool_input_sha256(tool_input: &Value) -> String {
    sha256_hex(canonical_json(tool_input).as_bytes())
}

// ------------------------------------------------------------------ pairing

fn push_prefixed(out: &mut Vec<u8>, field: &[u8]) -> Result<(), CanonicalError> {
    let len = u16::try_from(field.len()).map_err(|_| CanonicalError::FieldTooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Builds `canonical_pair_bytes` (protocol.md 4.2):
///
/// ```text
/// "agentnest-pair-v1" || L(pc_id) pc_id || L(pairing_id) pairing_id || L(challenge) challenge(16B)
///   || L(device_name) device_name(UTF-8, <=64B) || L(spki) spki(DER, empty => L=0)
/// ```
///
/// `L(x)` is the u16 big-endian byte length. `device_name` must already be NFC-normalised by the phone; it is used
/// exactly as received.
pub fn canonical_pair_bytes(
    pc_id: &str,
    pairing_id: &str,
    challenge: &[u8],
    device_name: &str,
    spki_der: &[u8],
) -> Result<Vec<u8>, CanonicalError> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(CanonicalError::BadChallengeLength);
    }
    if device_name.len() > DEVICE_NAME_MAX_BYTES {
        return Err(CanonicalError::DeviceNameTooLong);
    }
    let mut out = Vec::with_capacity(
        PAIR_LABEL.len()
            + 10
            + pc_id.len()
            + pairing_id.len()
            + 16
            + device_name.len()
            + spki_der.len(),
    );
    out.extend_from_slice(PAIR_LABEL);
    push_prefixed(&mut out, pc_id.as_bytes())?;
    push_prefixed(&mut out, pairing_id.as_bytes())?;
    push_prefixed(&mut out, challenge)?;
    push_prefixed(&mut out, device_name.as_bytes())?;
    push_prefixed(&mut out, spki_der)?;
    Ok(out)
}

/// `HMAC-SHA256(key = pairing_secret, msg)`.
pub fn hmac_sha256(pairing_secret: &[u8], msg: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, pairing_secret);
    let tag = hmac::sign(&key, msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// The pairing proof: `HMAC-SHA256(pairing_secret, canonical_pair_bytes)`.
pub fn pair_proof(pairing_secret: &[u8], canonical_pair_bytes: &[u8]) -> [u8; 32] {
    hmac_sha256(pairing_secret, canonical_pair_bytes)
}

/// Verifies a pairing proof in constant time (`ring::hmac::verify`). Wrong lengths simply fail.
pub fn verify_pair_proof(pairing_secret: &[u8], canonical_pair_bytes: &[u8], proof: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, pairing_secret);
    hmac::verify(&key, canonical_pair_bytes, proof).is_ok()
}

/// The 6-digit short authentication string (protocol.md 4.3):
/// first 4 bytes (big-endian u32) of `HMAC-SHA256(pairing_secret, "sas" || challenge || spki)` modulo 1,000,000,
/// zero padded. `challenge` is the 16 raw bytes, `spki_der` may be empty.
pub fn sas(
    pairing_secret: &[u8],
    challenge: &[u8],
    spki_der: &[u8],
) -> Result<String, CanonicalError> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(CanonicalError::BadChallengeLength);
    }
    let mut msg = Vec::with_capacity(SAS_LABEL.len() + challenge.len() + spki_der.len());
    msg.extend_from_slice(SAS_LABEL);
    msg.extend_from_slice(challenge);
    msg.extend_from_slice(spki_der);
    let mac = hmac_sha256(pairing_secret, &msg);
    let n = u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]) % 1_000_000;
    Ok(format!("{n:06}"))
}

/// Constant-time comparison of two SAS strings.
pub fn sas_matches(a: &str, b: &str) -> bool {
    ct_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn es6_numbers() {
        assert_eq!(es6_number(0.0), "0");
        assert_eq!(es6_number(-0.0), "0");
        assert_eq!(es6_number(1.0), "1");
        assert_eq!(es6_number(1.5), "1.5");
        assert_eq!(es6_number(-2.25), "-2.25");
        assert_eq!(es6_number(0.000001), "0.000001");
        assert_eq!(es6_number(1e-7), "1e-7");
        assert_eq!(es6_number(1e21), "1e+21");
        assert_eq!(es6_number(1e20), "100000000000000000000");
        assert_eq!(es6_number(123456789012345680000.0), "123456789012345680000");
        assert_eq!(es6_number(5e-324), "5e-324");
        assert_eq!(
            es6_number(1.7976931348623157e308),
            "1.7976931348623157e+308"
        );
    }

    #[test]
    fn canonical_basics() {
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": [true, null, "x"]})),
            r#"{"a":[true,null,"x"],"b":1}"#
        );
        assert_eq!(
            canonical_json(&json!("a\u{1}\n\"\\é")),
            "\"a\\u0001\\n\\\"\\\\é\""
        );
    }

    #[test]
    fn pair_bytes_reject_bad_inputs() {
        let c = [0u8; 16];
        assert_eq!(
            canonical_pair_bytes("pc", "p", &c[..15], "n", &[]),
            Err(CanonicalError::BadChallengeLength)
        );
        assert_eq!(
            canonical_pair_bytes("pc", "p", &c, &"n".repeat(65), &[]),
            Err(CanonicalError::DeviceNameTooLong)
        );
        assert!(canonical_pair_bytes("pc", "p", &c, &"n".repeat(64), &[]).is_ok());
    }
}
