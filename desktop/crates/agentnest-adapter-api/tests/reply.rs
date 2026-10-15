//! Behaviour of the opaque reply types. (Calls `ApplyProof::mint` directly: allowed in tests, see desktop/clippy.toml.)
#![allow(clippy::disallowed_methods)]

use agentnest_adapter_api::{ApplyProof, ApprovalReply, ReplyKind};

#[test]
fn deny_is_always_available_and_visible_through_the_wire_view() {
    let r = ApprovalReply::deny("AgentNest: denied".to_owned(), false);
    assert_eq!(
        r.as_wire(),
        ReplyKind::Deny {
            message: "AgentNest: denied",
            interrupt: false
        }
    );
    let r = ApprovalReply::deny(String::new(), true);
    assert_eq!(
        r.as_wire(),
        ReplyKind::Deny {
            message: "",
            interrupt: true
        }
    );
}

#[test]
fn allow_needs_a_proof_and_shows_as_allow() {
    let r = ApprovalReply::allow(ApplyProof::mint());
    assert_eq!(r.as_wire(), ReplyKind::Allow);
}

#[test]
fn replies_compare_by_value_and_clone() {
    let a = ApprovalReply::deny("x".into(), false);
    assert_eq!(a.clone(), a);
    assert_ne!(a, ApprovalReply::deny("x".into(), true));
    assert_ne!(ApprovalReply::allow(ApplyProof::mint()), a);
}

#[test]
fn debug_output_of_a_proof_carries_no_data() {
    assert_eq!(format!("{:?}", ApplyProof::mint()), "ApplyProof(())");
}
