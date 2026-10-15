//! Round-trip (deserialize -> serialize -> same JSON), rejection, forward-compat and cross-file consistency tests.

mod common;

use agentnest_protocol::*;
use common::{json_files, protocol_dir, read_json, read_text, unhex};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

fn examples_dir() -> std::path::PathBuf {
    protocol_dir().join("examples")
}

fn round_trip<T: Serialize + DeserializeOwned>(name: &str, value: &Value) {
    let typed: T = serde_json::from_value(value.clone())
        .unwrap_or_else(|e| panic!("{name}: deserialize: {e}"));
    let back = serde_json::to_value(&typed).unwrap();
    assert_eq!(&back, value, "{name}: round trip changed the JSON");
}

#[test]
fn every_envelope_example_round_trips_through_frame() {
    let dir = examples_dir();
    let mut count = 0;
    for rel in json_files(&dir) {
        if rel.components().count() != 1 {
            continue;
        }
        let text = read_text(&dir.join(&rel));
        let original: Value = serde_json::from_str(&text).unwrap();
        let frame = Frame::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", rel.display()));
        assert_eq!(
            frame.message.type_name(),
            original["type"].as_str().unwrap()
        );
        assert_eq!(
            frame.to_value().unwrap(),
            original,
            "{}: round trip changed the JSON",
            rel.display()
        );
        // and through text
        let again = Frame::parse(&frame.to_json().unwrap()).unwrap();
        assert_eq!(again, frame, "{}", rel.display());
        count += 1;
    }
    assert!(count >= 45, "only {count} envelope examples");
}

#[test]
fn message_directions_are_consistent() {
    let dir = examples_dir();
    let c2s = [
        "pair",
        "hello",
        "ack",
        "ping",
        "snapshot_request",
        "events_request",
        "decision",
        "approval_seen",
        "unpair",
    ];
    for rel in json_files(&dir) {
        if rel.components().count() != 1 {
            continue;
        }
        let frame = Frame::parse(&read_text(&dir.join(&rel))).unwrap();
        let name = frame.message.type_name().to_owned();
        let expected = if name == "future_message_type" {
            Direction::Unknown
        } else if c2s.contains(&name.as_str()) {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        assert_eq!(frame.message.direction(), expected, "{name}");
        assert_eq!(
            frame.message.is_replayable(),
            is_replayable_type(&name),
            "{name}"
        );
        if frame.message.is_replayable() {
            assert!(frame.seq.is_some(), "{name} must carry seq");
        }
    }
}

#[test]
fn model_examples_round_trip() {
    let dir = examples_dir().join("model");
    for rel in json_files(&dir) {
        let name = rel.to_string_lossy().into_owned();
        let value = read_json(&dir.join(&rel));
        let stem = name.split('.').next().unwrap();
        match stem {
            "agent_event" => {
                round_trip::<AgentEvent>(&name, &value);
                let ev: AgentEvent = serde_json::from_value(value).unwrap();
                assert_eq!(
                    ev.kind.category().as_ref(),
                    Some(&ev.category),
                    "{name}: category must match kind"
                );
            }
            "session_state" => round_trip::<SessionState>(&name, &value),
            "approval_request" => round_trip::<ApprovalRequest>(&name, &value),
            "risk" => round_trip::<Risk>(&name, &value),
            "project_ref" => round_trip::<ProjectRef>(&name, &value),
            "agent_state" => round_trip::<AgentState>(&name, &value),
            other => panic!("unexpected model example {other}"),
        }
    }
}

#[test]
fn qr_example_round_trips_and_uri_works() {
    let value = read_json(&examples_dir().join("qr/pairing_payload.1.json"));
    round_trip::<qr::PairingPayload>("qr", &value);
    let payload: qr::PairingPayload = serde_json::from_value(value).unwrap();
    let uri = payload.to_uri().unwrap();
    assert!(uri.starts_with("agentnest://pair?d="));
    assert!(
        !uri["agentnest://pair?d=".len()..].contains('='),
        "base64url without padding"
    );
    assert_eq!(qr::PairingPayload::from_uri(&uri).unwrap(), payload);
    assert_eq!(payload.pairing_secret_bytes().unwrap().len(), 32);
    assert!(payload.pc_id_matches_pin());
    let mut tampered = payload.clone();
    tampered.pc_id = "pc_0000000000000000".into();
    assert!(!tampered.pc_id_matches_pin());
    assert!(qr::PairingPayload::from_uri("agentnest://pair?d=!!!").is_err());
    assert!(qr::PairingPayload::from_uri("https://pair?d=abc").is_err());
}

#[test]
fn invalid_examples_marked_rust_rejects_are_rejected() {
    let dir = examples_dir().join("invalid");
    let index = read_json(&dir.join("_index.json"));
    let mut checked = 0;
    for (name, meta) in index["files"].as_object().unwrap() {
        if meta["rust_rejects"] != Value::Bool(true) {
            continue;
        }
        let text = read_text(&dir.join(name));
        let value: Value = serde_json::from_str(&text).unwrap();
        let rejected = match meta.get("schema").and_then(Value::as_str) {
            None => Frame::parse(&text).is_err(),
            Some("model/risk.schema.json") => serde_json::from_value::<Risk>(value).is_err(),
            Some(other) => panic!("{name}: no typed check for {other}"),
        };
        assert!(
            rejected,
            "invalid/{name} must be rejected by the Rust types: {}",
            meta["reason"]
        );
        checked += 1;
    }
    assert!(
        checked >= 30,
        "only {checked} rust-rejected invalid examples"
    );
}

#[test]
fn forward_compat_examples_are_read_tolerantly() {
    let dir = examples_dir().join("forward_compat");

    let f = Frame::parse(&read_text(&dir.join("session_state.unknown_enums.json"))).unwrap();
    let Message::SessionState(s) = &f.message else {
        panic!("type")
    };
    assert_eq!(s.state, AgentState::Unknown("hyperdrive".into()));
    assert_eq!(s.state.effective(), AgentState::Working);
    assert_eq!(s.remote_approval, RemoteApproval::Unknown("quantum".into()));
    assert_eq!(
        s.meta.review.as_ref().unwrap().state,
        ReviewState::Unknown("rewinding".into())
    );
    // unknown values are written back unchanged; unknown fields are dropped
    let back = f.to_value().unwrap();
    assert_eq!(back["payload"]["state"], "hyperdrive");
    assert!(back["payload"].get("future_field").is_none());

    let f = Frame::parse(&read_text(&dir.join("approval_request.unknown_enums.json"))).unwrap();
    let Message::ApprovalRequest(a) = &f.message else {
        panic!("type")
    };
    assert_eq!(a.risk.level, RiskLevel::Unknown("extreme".into()));
    assert_eq!(
        a.risk.level.effective(),
        RiskLevel::High,
        "unknown risk must never be lowered"
    );
    assert_eq!(a.details.kind, DetailsKind::Unknown("teleport".into()));
    assert_eq!(a.local_prompt, LocalPrompt::Unknown("maybe".into()));

    let f = Frame::parse(&read_text(
        &dir.join("approval_resolved.unknown_enums.json"),
    ))
    .unwrap();
    let Message::ApprovalResolved(r) = &f.message else {
        panic!("type")
    };
    assert!(r.outcome.is_unknown() && r.resolved_by.is_unknown());

    let f = Frame::parse(&read_text(&dir.join("event.unknown_enums.json"))).unwrap();
    let Message::Event(e) = &f.message else {
        panic!("type")
    };
    assert_eq!(e.kind, EventKind::Unknown("future_kind".into()));
    assert!(e.kind.category().is_none());
    assert_eq!(e.agent_kind, AgentKind::Other);
    assert!(!e.kind.is_timeline_only());
}

#[test]
fn unknown_payload_fields_are_ignored() {
    let mut v = read_json(&examples_dir().join("hello.1.json"));
    v["payload"]["brand_new_field"] = Value::from(42);
    let f = Frame::parse(&v.to_string()).unwrap();
    assert!(matches!(f.message, Message::Hello(_)));
}

#[test]
fn null_is_accepted_for_optional_fields_but_never_written() {
    let mut v = read_json(&examples_dir().join("decision.1.json"));
    v["payload"]["reason"] = Value::Null;
    v["payload"]["signature_b64"] = Value::Null;
    let f = Frame::parse(&v.to_string()).unwrap();
    let out = f.to_value().unwrap();
    assert!(out["payload"].get("reason").is_none());
    assert!(out["payload"].get("signature_b64").is_none());
}

#[test]
fn approval_request_examples_match_the_tool_input_vectors() {
    let vecs = read_json(&protocol_dir().join("vectors/tool_input_sha256.json"));
    let find = |name: &str| -> String {
        vecs["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap()["sha256_hex"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    for (file, case) in [
        ("approval_request.1.json", "approval_request_example_1"),
        ("approval_request.2.json", "approval_request_example_2"),
    ] {
        let f = Frame::parse(&read_text(&examples_dir().join(file))).unwrap();
        let Message::ApprovalRequest(a) = f.message else {
            panic!()
        };
        assert_eq!(a.tool_input_sha256, find(case), "{file}");
    }
}

#[test]
fn pair_related_examples_agree_with_the_pair_vectors() {
    let vec = read_json(&protocol_dir().join("vectors/pair.json"));
    let t = &vec["cases"][0];
    let secret = unhex(t["pairing_secret_hex"].as_str().unwrap());

    let f = Frame::parse(&read_text(&examples_dir().join("pair.1.json"))).unwrap();
    let Message::Pair(p) = f.message else {
        panic!()
    };
    let challenge = qr::b64_decode(&p.challenge_b64).unwrap();
    let spki = qr::b64_decode(p.device_pubkey_spki_b64.as_deref().unwrap()).unwrap();
    let cpb = canonical::canonical_pair_bytes(
        t["pc_id"].as_str().unwrap(),
        &p.pairing_id,
        &challenge,
        &p.device.name,
        &spki,
    )
    .unwrap();
    let proof = qr::b64_decode(p.proof_b64.expose()).unwrap();
    assert!(
        canonical::verify_pair_proof(&secret, &cpb, &proof),
        "pair.1.json proof must verify"
    );

    let f = Frame::parse(&read_text(&examples_dir().join("pair_pending.1.json"))).unwrap();
    let Message::PairPending(pp) = f.message else {
        panic!()
    };
    assert!(canonical::sas_matches(
        &pp.sas,
        &canonical::sas(&secret, &challenge, &spki).unwrap()
    ));

    let f = Frame::parse(&read_text(&examples_dir().join("challenge.1.json"))).unwrap();
    let Message::Challenge(c) = f.message else {
        panic!()
    };
    assert_eq!(c.challenge_b64, p.challenge_b64);
    assert_eq!(c.pc_id, t["pc_id"].as_str().unwrap());

    let qr_ex: qr::PairingPayload =
        serde_json::from_value(read_json(&examples_dir().join("qr/pairing_payload.1.json")))
            .unwrap();
    assert_eq!(qr_ex.pairing_secret_bytes().unwrap(), secret);
    assert_eq!(qr_ex.pairing_id, p.pairing_id);
    assert_eq!(qr_ex.pc_id, c.pc_id);
}

#[test]
fn secrets_never_show_up_in_debug_output() {
    let hello = read_text(&examples_dir().join("hello.1.json"));
    let token = read_json(&examples_dir().join("hello.1.json"))["payload"]["device_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let dbg = format!("{:?}", Frame::parse(&hello).unwrap());
    assert!(!dbg.contains(&token));
    assert!(dbg.contains("<redacted>"));

    let decision = read_text(&examples_dir().join("decision.1.json"));
    let nonce = read_json(&examples_dir().join("decision.1.json"))["payload"]["nonce_b64"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!format!("{:?}", Frame::parse(&decision).unwrap()).contains(&nonce));

    let req = read_text(&examples_dir().join("approval_request.1.json"));
    let nonce = read_json(&examples_dir().join("approval_request.1.json"))["payload"]["nonce_b64"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!format!("{:?}", Frame::parse(&req).unwrap()).contains(&nonce));

    let pr = read_text(&examples_dir().join("pair_result.1.json"));
    let tok = read_json(&examples_dir().join("pair_result.1.json"))["payload"]["device_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!format!("{:?}", Frame::parse(&pr).unwrap()).contains(&tok));

    let qr_ex: qr::PairingPayload =
        serde_json::from_value(read_json(&examples_dir().join("qr/pairing_payload.1.json")))
            .unwrap();
    assert!(!format!("{qr_ex:?}").contains(qr_ex.pairing_secret.expose()));
}

#[test]
fn decision_enum_has_no_scope_expanding_variant() {
    // Exhaustive match: adding a variant breaks compilation here and forces a security review (I11).
    fn name(d: Decision) -> &'static str {
        match d {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::DenyAndStop => "deny_and_stop",
        }
    }
    for d in [Decision::Allow, Decision::Deny, Decision::DenyAndStop] {
        assert_eq!(name(d), d.as_str());
        assert_eq!(serde_json::to_value(d).unwrap(), d.as_str());
    }
}
