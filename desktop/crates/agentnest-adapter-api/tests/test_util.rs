//! Only compiled with `--features test-util` (CI runs this crate once with the feature on).
#![cfg(feature = "test-util")]

use agentnest_adapter_api::{ApplyProof, ApprovalReply, ReplyKind};

#[test]
fn test_constructors_exist_behind_the_feature() {
    assert_eq!(ApprovalReply::allow_for_test().as_wire(), ReplyKind::Allow);
    assert_eq!(
        ApprovalReply::allow(ApplyProof::mint_for_test()).as_wire(),
        ReplyKind::Allow
    );
}
