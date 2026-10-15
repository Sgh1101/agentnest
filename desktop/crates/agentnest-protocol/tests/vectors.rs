//! Byte-exact vector tests. The same files are read by `android/core` (Kotlin).

mod common;

use agentnest_protocol::canonical::*;
use agentnest_protocol::qr::{
    b64_decode, b64_encode, b64url_decode, b64url_encode, pc_id_from_spki, spki_pin,
};
use agentnest_protocol::CanonicalError;
use common::{protocol_dir, read_json, unhex};
use serde_json::Value;

#[test]
fn pair_vectors() {
    let vec = read_json(&protocol_dir().join("vectors/pair.json"));
    let cases = vec["cases"].as_array().unwrap();
    assert!(cases.len() >= 5);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let secret = unhex(c["pairing_secret_hex"].as_str().unwrap());
        assert_eq!(
            b64url_decode(c["pairing_secret_b64url"].as_str().unwrap()).unwrap(),
            secret,
            "{name}: secret encodings"
        );
        assert_eq!(
            b64url_encode(&secret),
            c["pairing_secret_b64url"].as_str().unwrap(),
            "{name}"
        );
        let challenge = unhex(c["challenge_hex"].as_str().unwrap());
        assert_eq!(
            b64_decode(c["challenge_b64"].as_str().unwrap()).unwrap(),
            challenge,
            "{name}"
        );
        let spki = unhex(c["spki_hex"].as_str().unwrap());
        let device_name = c["device_name"].as_str().unwrap();
        assert_eq!(
            device_name.len() as u64,
            c["device_name_utf8_len"].as_u64().unwrap(),
            "{name}"
        );

        let cpb = canonical_pair_bytes(
            c["pc_id"].as_str().unwrap(),
            c["pairing_id"].as_str().unwrap(),
            &challenge,
            device_name,
            &spki,
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            hex::encode(&cpb),
            c["canonical_pair_bytes_hex"].as_str().unwrap(),
            "{name}: canonical bytes"
        );

        let proof = pair_proof(&secret, &cpb);
        assert_eq!(
            hex::encode(proof),
            c["proof_hmac_sha256_hex"].as_str().unwrap(),
            "{name}: proof"
        );
        assert_eq!(
            b64_encode(&proof),
            c["proof_b64"].as_str().unwrap(),
            "{name}: proof b64"
        );
        assert!(verify_pair_proof(&secret, &cpb, &proof), "{name}");

        assert_eq!(
            sas(&secret, &challenge, &spki).unwrap(),
            c["sas"].as_str().unwrap(),
            "{name}: sas"
        );
    }
    // SAS zero padding is exercised by at least one case
    assert!(cases
        .iter()
        .any(|c| c["sas"].as_str().unwrap().starts_with('0')));
    // the spec's literal prefix
    let first = unhex(cases[0]["canonical_pair_bytes_hex"].as_str().unwrap());
    assert!(first.starts_with(b"agentnest-pair-v1\x00\x13pc_"));
}

#[test]
fn pair_verify_cases() {
    let vec = read_json(&protocol_dir().join("vectors/pair.json"));
    for vc in vec["verify_cases"].as_array().unwrap() {
        let case = vec["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == vc["case"])
            .unwrap();
        let secret = unhex(case["pairing_secret_hex"].as_str().unwrap());
        let cpb = unhex(case["canonical_pair_bytes_hex"].as_str().unwrap());
        let proof = b64_decode(vc["proof_b64"].as_str().unwrap()).unwrap();
        assert_eq!(
            verify_pair_proof(&secret, &cpb, &proof),
            vc["expect_valid"].as_bool().unwrap(),
            "{}",
            vc["name"]
        );
    }
}

#[test]
fn pair_invalid_inputs() {
    let vec = read_json(&protocol_dir().join("vectors/pair.json"));
    for c in vec["invalid_inputs"].as_array().unwrap() {
        let r = canonical_pair_bytes(
            c["pc_id"].as_str().unwrap(),
            c["pairing_id"].as_str().unwrap(),
            &unhex(c["challenge_hex"].as_str().unwrap()),
            c["device_name"].as_str().unwrap(),
            &unhex(c["spki_hex"].as_str().unwrap()),
        );
        let expected = match c["error"].as_str().unwrap() {
            "device_name_too_long" => CanonicalError::DeviceNameTooLong,
            "bad_challenge_length" => CanonicalError::BadChallengeLength,
            other => panic!("unknown error kind {other}"),
        };
        assert_eq!(r, Err(expected), "{}", c["name"]);
    }
}

#[test]
fn pin_vectors() {
    let vec = read_json(&protocol_dir().join("vectors/pin.json"));
    for c in vec["cases"].as_array().unwrap() {
        let spki = unhex(c["spki_hex"].as_str().unwrap());
        assert_eq!(
            hex::encode(sha256(&spki)),
            c["sha256_hex"].as_str().unwrap()
        );
        assert_eq!(spki_pin(&spki), c["spki_pin"].as_str().unwrap());
        assert_eq!(pc_id_from_spki(&spki), c["pc_id"].as_str().unwrap());
    }
}

#[test]
fn tool_input_sha256_vectors() {
    let vec = read_json(&protocol_dir().join("vectors/tool_input_sha256.json"));
    let cases = vec["cases"].as_array().unwrap();
    assert!(cases.len() >= 25);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let input: Value = serde_json::from_str(c["input_json"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let canon = canonical_json(&input);
        assert_eq!(
            canon,
            c["canonical_json"].as_str().unwrap(),
            "{name}: canonical json"
        );
        assert_eq!(
            tool_input_sha256(&input),
            c["sha256_hex"].as_str().unwrap(),
            "{name}: sha256"
        );
        assert_eq!(
            sha256_hex(canon.as_bytes()),
            c["sha256_hex"].as_str().unwrap(),
            "{name}"
        );
        // canonical form is a fixed point
        let again: Value = serde_json::from_str(&canon).unwrap();
        assert_eq!(canonical_json(&again), canon, "{name}: idempotent");
    }
}

#[test]
fn sha256_known_answers() {
    assert_eq!(
        sha256_hex(b"test"),
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn hmac_rfc4231_case_2() {
    // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        hex::encode(mac),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}
