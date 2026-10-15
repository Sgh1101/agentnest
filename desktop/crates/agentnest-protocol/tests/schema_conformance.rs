//! Validates every `protocol/examples/**` file against `protocol/schema/**` and checks that every
//! `protocol/examples/invalid/**` file is rejected, for the intended reason.

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::{json_files, protocol_dir, read_json};
use jsonschema::{Registry, Validator};
use serde_json::Value;

struct Schemas {
    registry: &'static Registry<'static>,
    docs: BTreeMap<String, &'static Value>,
}

fn load_schemas() -> Schemas {
    let dir = protocol_dir().join("schema");
    let mut docs = BTreeMap::new();
    let mut builder = Registry::new();
    for rel in json_files(&dir) {
        let value: &'static Value = Box::leak(Box::new(read_json(&dir.join(&rel))));
        let id = value["$id"]
            .as_str()
            .unwrap_or_else(|| panic!("{} has no $id", rel.display()))
            .to_owned();
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        assert!(
            id.ends_with(&rel_s),
            "$id {id} must end with its path {rel_s}"
        );
        builder = builder.add(id.as_str(), value).unwrap();
        docs.insert(rel_s, value);
    }
    let registry: &'static Registry<'static> = Box::leak(Box::new(builder.prepare().unwrap()));
    Schemas { registry, docs }
}

fn validator(s: &Schemas, rel: &str) -> Validator {
    let schema = s.docs.get(rel).unwrap_or_else(|| panic!("no schema {rel}"));
    jsonschema::options()
        .with_registry(s.registry)
        .build(schema)
        .unwrap_or_else(|e| panic!("build {rel}: {e}"))
}

fn errors(v: &Validator, instance: &Value) -> Vec<(String, String)> {
    v.iter_errors(instance)
        .map(|e| (e.instance_path().to_string(), e.to_string()))
        .collect()
}

#[test]
fn every_schema_is_a_valid_draft_2020_12_schema() {
    let s = load_schemas();
    assert!(
        s.docs.len() >= 34,
        "expected the full schema set, got {}",
        s.docs.len()
    );
    for (rel, doc) in &s.docs {
        assert_eq!(
            doc["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{rel}"
        );
        jsonschema::meta::validate(doc)
            .unwrap_or_else(|e| panic!("{rel} is not a valid 2020-12 schema: {e}"));
        // every schema must also compile with the shared registry (all $refs resolve)
        let _ = validator(&s, rel);
    }
}

#[test]
fn schema_layout_matches_architecture_doc() {
    let s = load_schemas();
    let must = [
        "envelope.schema.json",
        "c2s/pair.schema.json",
        "c2s/hello.schema.json",
        "c2s/ack.schema.json",
        "c2s/ping.schema.json",
        "c2s/snapshot_request.schema.json",
        "c2s/events_request.schema.json",
        "c2s/decision.schema.json",
        "c2s/approval_seen.schema.json",
        "c2s/unpair.schema.json",
        "s2c/challenge.schema.json",
        "s2c/pair_pending.schema.json",
        "s2c/pair_result.schema.json",
        "s2c/welcome.schema.json",
        "s2c/snapshot.schema.json",
        "s2c/event.schema.json",
        "s2c/session_state.schema.json",
        "s2c/approval_request.schema.json",
        "s2c/approval_resolved.schema.json",
        "s2c/decision_result.schema.json",
        "s2c/events_page.schema.json",
        "s2c/hosts_update.schema.json",
        "s2c/adapter_status.schema.json",
        "s2c/pong.schema.json",
        "s2c/error.schema.json",
        "s2c/bye.schema.json",
        "model/agent_event.schema.json",
        "model/agent_state.schema.json",
        "model/approval_request.schema.json",
        "model/session_state.schema.json",
        "model/project_ref.schema.json",
        "model/risk.schema.json",
        "model/common.schema.json",
        "qr/pairing_payload.schema.json",
    ];
    for m in must {
        assert!(s.docs.contains_key(m), "missing schema {m}");
    }
}

/// Maps an example path (relative to `protocol/examples`) to the schema that must accept it.
fn schema_for_example(rel: &Path) -> String {
    let comps: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let file = comps.last().unwrap().clone();
    let stem = file.split('.').next().unwrap().to_owned();
    match comps.first().map(String::as_str) {
        Some("model") => format!("model/{stem}.schema.json"),
        Some("qr") => format!("qr/{stem}.schema.json"),
        _ => "envelope.schema.json".to_owned(),
    }
}

#[test]
fn all_valid_examples_conform() {
    let s = load_schemas();
    let dir = protocol_dir().join("examples");
    let mut checked = 0;
    for rel in json_files(&dir) {
        let first = rel
            .components()
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        if first == "invalid" || first == "forward_compat" {
            continue;
        }
        let instance = read_json(&dir.join(&rel));
        let schema = schema_for_example(&rel);
        let v = validator(&s, &schema);
        let errs = errors(&v, &instance);
        assert!(
            errs.is_empty(),
            "{} must conform to {schema}: {errs:?}",
            rel.display()
        );
        checked += 1;
    }
    assert!(checked >= 90, "only {checked} valid examples found");
}

#[test]
fn envelope_examples_also_conform_to_their_payload_schema_alone() {
    let s = load_schemas();
    let dir = protocol_dir().join("examples");
    for rel in json_files(&dir) {
        let comps: Vec<_> = rel.components().collect();
        if comps.len() != 1 {
            continue;
        }
        let env = read_json(&dir.join(&rel));
        let ty = env["type"].as_str().unwrap();
        let schema_rel = ["c2s", "s2c"]
            .iter()
            .map(|d| format!("{d}/{ty}.schema.json"))
            .find(|p| s.docs.contains_key(p));
        let Some(schema_rel) = schema_rel else {
            assert_eq!(
                ty,
                "future_message_type",
                "{} has a type without a payload schema",
                rel.display()
            );
            continue;
        };
        let v = validator(&s, &schema_rel);
        let errs = errors(&v, &env["payload"]);
        assert!(
            errs.is_empty(),
            "{}: payload vs {schema_rel}: {errs:?}",
            rel.display()
        );
    }
}

#[test]
fn every_message_type_has_a_valid_example() {
    let dir = protocol_dir().join("examples");
    let mut seen = std::collections::BTreeSet::new();
    for rel in json_files(&dir) {
        if rel.components().count() == 1 {
            seen.insert(
                read_json(&dir.join(&rel))["type"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
    }
    let types = [
        "pair",
        "hello",
        "ack",
        "ping",
        "snapshot_request",
        "events_request",
        "decision",
        "approval_seen",
        "unpair",
        "challenge",
        "pair_pending",
        "pair_result",
        "welcome",
        "snapshot",
        "event",
        "session_state",
        "approval_request",
        "approval_resolved",
        "decision_result",
        "events_page",
        "hosts_update",
        "adapter_status",
        "pong",
        "error",
        "bye",
    ];
    for t in types {
        assert!(seen.contains(t), "no valid example for message type {t}");
    }
}

#[test]
fn every_agent_event_kind_has_a_model_example() {
    let dir = protocol_dir().join("examples/model");
    for kind in agentnest_protocol::EventKind::KNOWN {
        assert!(
            dir.join(format!("agent_event.{kind}.json")).exists(),
            "no model example for kind {kind}"
        );
    }
}

#[test]
fn all_invalid_examples_are_rejected_for_the_intended_reason() {
    let s = load_schemas();
    let dir = protocol_dir().join("examples/invalid");
    let index = read_json(&dir.join("_index.json"));
    let files = index["files"].as_object().expect("files map");
    let mut seen = 0;
    for rel in json_files(&dir) {
        let name = rel.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with('_') {
            continue;
        }
        let meta = files
            .get(&name)
            .unwrap_or_else(|| panic!("invalid/{name} is not listed in _index.json"));
        let instance = read_json(&dir.join(&rel));
        let schema = meta
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or("envelope.schema.json");
        let v = validator(&s, schema);
        let errs = errors(&v, &instance);
        assert!(
            !errs.is_empty(),
            "invalid/{name} must be rejected ({})",
            meta["reason"]
        );
        let pointer = meta["error_pointer"].as_str().unwrap();
        assert!(
            // Optional fields are nullable (`anyOf`), so the error may be reported at the nearest enclosing property.
            errs.iter().any(|(path, _)| path == pointer
                || (!path.is_empty() && pointer.starts_with(&format!("{path}/")))),
            "invalid/{name}: no error at {pointer:?}; errors: {errs:?}"
        );
        seen += 1;
    }
    assert_eq!(
        seen,
        files.len(),
        "_index.json lists files that do not exist"
    );
    assert!(seen >= 80, "expected a broad invalid corpus, got {seen}");
}

#[test]
fn scope_expanding_decisions_are_rejected_everywhere() {
    let s = load_schemas();
    let dir = protocol_dir().join("examples");
    let v = validator(&s, "envelope.schema.json");
    let mut base = read_json(&dir.join("decision.1.json"));
    for bad in [
        "allow_for_session",
        "allow_always",
        "acceptForSession",
        "acceptWithExecpolicyAmendment",
        "applyNetworkPolicyAmendment",
        "allow_always_for_project",
        "updatedPermissions",
        "allow_once",
    ] {
        base["payload"]["decision"] = Value::from(bad);
        assert!(!errors(&v, &base).is_empty(), "{bad} must be rejected");
    }
    for ok in ["allow", "deny", "deny_and_stop"] {
        base["payload"]["decision"] = Value::from(ok);
        assert!(errors(&v, &base).is_empty(), "{ok} must be accepted");
    }
    // The decision enum must be exactly the three values in the shared definition.
    let common = read_json(&protocol_dir().join("schema/model/common.schema.json"));
    assert_eq!(
        common["$defs"]["Decision"]["enum"],
        serde_json::json!(["allow", "deny", "deny_and_stop"])
    );
}

#[test]
fn unknown_message_types_pass_the_envelope_untyped() {
    let s = load_schemas();
    let v = validator(&s, "envelope.schema.json");
    let inst = read_json(&protocol_dir().join("examples/unknown_type.1.json"));
    assert!(errors(&v, &inst).is_empty());
}
