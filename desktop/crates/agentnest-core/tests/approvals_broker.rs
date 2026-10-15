//! Broker behaviour (docs/security.md 6, I4-I6; docs/testing-and-ci.md approvals row): opening, the single decision
//! transition, idempotency, replays, binding, expiry, merge rules, desktop decisions, correlation, recovery.

mod common;

use agentnest_adapter_api::{AbandonReason, AgentCloseReason};
use agentnest_core::approvals::broker::{OpenOutcome, ToolObservation};
use agentnest_core::approvals::correlator::HookPhase;
use agentnest_core::events::{ApprovalChannel, ApprovalUiEvent, DaemonEvent};
use agentnest_protocol::canonical::tool_input_sha256;
use agentnest_protocol::{
    AgentState, Decision, DecisionResultReason, ExtraConfirmation, ObservedResult, Secret,
};
use common::harness::*;
use serde_json::json;

#[tokio::test]
async fn opening_publishes_the_card_the_timeline_event_and_the_awaiting_state() {
    let h = Harness::new();
    let _phone = h.add_phone("Galaxy");
    let mut stream = h.registry.subscribe();
    let mut ui = h.bus.subscribe();
    let (card, _rx) = h.open_low().await;
    assert!(card.request_id.starts_with("ar_"));
    assert_eq!(card.ttl_seconds, 120);
    assert_eq!(
        card.tool_input_sha256,
        tool_input_sha256(&json!({"command": "cargo test -p agentnest-core"}))
    );
    assert_eq!(card.title, "테스트를 실행하려고 해요");
    assert_eq!(
        card.auth_required_for,
        vec![Decision::Allow, Decision::DenyAndStop]
    );
    assert_eq!(
        card.allowed_decisions,
        vec![Decision::Allow, Decision::Deny, Decision::DenyAndStop]
    );
    assert_eq!(card.purpose.as_deref(), Some("Run the tests"));
    assert_eq!(card.permission_mode.as_deref(), Some("default"));
    assert_eq!(
        agentnest_protocol::qr::b64_decode(card.nonce_b64.expose())
            .unwrap()
            .len(),
        16
    );
    // stream: event(approval_requested) + session_state + approval_request, seq strictly increasing
    let msgs = Harness::drain(&mut stream);
    let types: Vec<&str> = msgs.iter().map(|m| m.1.as_str()).collect();
    assert!(types.contains(&"approval_request"), "{types:?}");
    assert!(types.contains(&"event"));
    assert!(types.contains(&"session_state"));
    let seqs: Vec<i64> = msgs.iter().map(|m| m.0).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted, "broadcast order equals seq order");
    let req = msgs.iter().find(|m| m.1 == "approval_request").unwrap();
    assert_eq!(req.2["request_id"], card.request_id);
    // session state
    let s = h.pipeline.session(&card.session_key).await.unwrap();
    assert_eq!(s.state, AgentState::AwaitingApproval);
    assert_eq!(s.pending_approval_ids, vec![card.request_id.clone()]);
    // desktop event
    let mut opened = false;
    while let Ok(ev) = ui.try_recv() {
        if let DaemonEvent::Approval(ApprovalUiEvent::Opened { request, channel }) = ev {
            assert_eq!(request.request_id, card.request_id);
            assert_eq!(channel, ApprovalChannel::Remote);
            opened = true;
        }
    }
    assert!(opened);
    // database
    let row = h.row(&card.request_id);
    assert_eq!(row.status, "pending");
    assert_eq!(row.risk_level, "low");
    assert!(h
        .audit_actions(&card.request_id)
        .contains(&"opened".to_owned()));
    // raw tool input is nowhere in the row
    let dump = format!("{row:?}");
    assert!(!dump.contains("agentnest-core") || row.details_json.is_some());
}

#[tokio::test]
async fn a_valid_allow_is_committed_then_delivered_exactly_once() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let mut stream = h.registry.subscribe();
    let (card, mut rx) = h.open_low().await;
    Harness::drain(&mut stream);
    assert_eq!(
        try_seen(&mut rx),
        None,
        "nothing is answered before a decision"
    );
    let out = h
        .broker
        .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
        .await;
    assert!(out.accepted);
    assert_eq!(out.reason, DecisionResultReason::Applied);
    assert!(out.message_ko.starts_with("허용했어요"));
    assert_eq!(rx.await.unwrap(), Seen::Allow);
    let row = h.row(&card.request_id);
    assert_eq!(row.status, "resolved");
    assert_eq!(row.outcome.as_deref(), Some("allowed"));
    assert_eq!(row.resolved_by.as_deref(), Some("phone"));
    assert_eq!(
        row.resolved_device_id.as_deref(),
        Some(phone.device_id.as_str())
    );
    assert_eq!(row.delivery.as_deref(), Some("delivered"));
    assert!(row.decision_msg_id.is_some());
    let decisions = h.store.list_decisions(&card.request_id).unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].verify_result, "APPLIED");
    assert_eq!(decisions[0].actor, format!("device:{}", phone.device_id));
    let audit = h.audit_actions(&card.request_id);
    assert!(audit.contains(&"decision_received".to_owned()));
    assert!(audit.contains(&"delivered".to_owned()));
    // resolved message with delivery + the session leaves awaiting_approval
    let msgs = Harness::drain(&mut stream);
    let resolved = msgs
        .iter()
        .find(|m| m.1 == "approval_resolved")
        .expect("approval_resolved published");
    assert_eq!(resolved.2["outcome"], "allowed");
    assert_eq!(resolved.2["resolved_by"], "phone");
    assert_eq!(resolved.2["delivery"], "delivered");
    assert_eq!(resolved.2["observed_result"], "unknown");
    assert_eq!(
        h.pipeline
            .session(&card.session_key)
            .await
            .unwrap()
            .pending_approval_ids
            .len(),
        0
    );
    assert_eq!(h.broker.pending_count().await, 0);
}

#[tokio::test]
async fn deny_and_deny_and_stop_produce_deny_replies_with_a_sanitised_message() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (card, rx) = h.open_low().await;
    let mut d = h.phone_decision(&card, &phone.device_id, Decision::Deny);
    d.reason = Some("너무 위험\n\u{202e}해요".into());
    d.auth = None; // a plain deny needs no authentication under the default policy
    let out = h.broker.apply_decision(d).await;
    assert!(out.accepted, "{out:?}");
    match rx.await.unwrap() {
        Seen::Deny { message, interrupt } => {
            assert!(!interrupt);
            assert!(message.starts_with("AgentNest: 사용자가 휴대폰에서 거부했습니다."));
            assert!(message.contains("너무 위험 해요"));
            assert!(!message.contains('\n') && !message.contains('\u{202e}'));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(h.row(&card.request_id).outcome.as_deref(), Some("denied"));

    let (card, rx) = h.open_low().await;
    let out = h
        .broker
        .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::DenyAndStop))
        .await;
    assert!(out.accepted);
    assert_eq!(
        rx.await.unwrap(),
        Seen::Deny {
            message: "AgentNest: 사용자가 휴대폰에서 거부했습니다. 사유(사용자 입력): 사유 없음"
                .into(),
            interrupt: true
        }
    );
    assert_eq!(
        h.row(&card.request_id).outcome.as_deref(),
        Some("denied_and_stopped")
    );
}

#[tokio::test]
async fn a_resent_decision_is_idempotent_and_a_new_decision_after_resolution_is_refused() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (card, rx) = h.open_low().await;
    let d = h.phone_decision(&card, &phone.device_id, Decision::Allow);
    let again = d.clone();
    assert!(h.broker.apply_decision(d).await.accepted);
    assert_eq!(rx.await.unwrap(), Seen::Allow);
    // same decision id: stored result, nothing re-applied
    let out = h.broker.apply_decision(again.clone()).await;
    assert!(out.accepted);
    assert_eq!(out.reason, DecisionResultReason::Applied);
    assert_eq!(h.store.list_decisions(&card.request_id).unwrap().len(), 1);
    // a different decision id for the same request: ALREADY_RESOLVED, recorded as an attempt
    let mut second = again;
    second.decision_id = uuid::Uuid::now_v7().to_string();
    let out = h.broker.apply_decision(second).await;
    assert!(!out.accepted);
    assert_eq!(out.reason, DecisionResultReason::AlreadyResolved);
    let decisions = h.store.list_decisions(&card.request_id).unwrap();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[1].verify_result, "ALREADY_RESOLVED");
    assert_eq!(h.row(&card.request_id).outcome.as_deref(), Some("allowed"));
}

#[tokio::test]
async fn binding_mismatches_change_nothing_and_leave_the_request_pending() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (a, mut rx_a) = h.open_low().await;
    let (out_b, _rx_b) = h
        .open(h.draft("Bash", json!({"command": "cargo build"})))
        .await;
    let OpenOutcome::Opened { request_id: id_b } = out_b else {
        panic!()
    };
    let b = h.broker.pending_card(&id_b).await.unwrap();
    // B's nonce on A's request
    let mut d = h.phone_decision(&a, &phone.device_id, Decision::Allow);
    d.nonce_b64 = Some(Secret::new(b.nonce_b64.expose()));
    let out = h.broker.apply_decision(d).await;
    assert_eq!(out.reason, DecisionResultReason::BindingMismatch);
    // B's hash on A's request
    let mut d = h.phone_decision(&a, &phone.device_id, Decision::Allow);
    d.tool_input_sha256 = b.tool_input_sha256.clone();
    assert_eq!(
        h.broker.apply_decision(d).await.reason,
        DecisionResultReason::InputHashMismatch
    );
    // another session key
    let mut d = h.phone_decision(&a, &phone.device_id, Decision::Allow);
    d.session_key = Some("claude_code:other".into());
    assert_eq!(
        h.broker.apply_decision(d).await.reason,
        DecisionResultReason::BindingMismatch
    );
    // A is untouched
    assert_eq!(h.row(&a.request_id).status, "pending");
    assert_eq!(try_seen(&mut rx_a), None);
    assert_eq!(h.broker.pending_count().await, 2);
    // every attempt is evidence
    let decisions = h.store.list_decisions(&a.request_id).unwrap();
    assert_eq!(decisions.len(), 3);
    assert!(decisions.iter().all(|d| d.verify_result != "APPLIED"));
    // and the valid decision still works afterwards (TTL permitting)
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&a, &phone.device_id, Decision::Allow))
            .await
            .accepted
    );
    assert_eq!(rx_a.await.unwrap(), Seen::Allow);
}

#[tokio::test]
async fn an_expired_decision_is_refused_and_the_request_expires_without_a_reply_of_substance() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (card, rx) = h.open_low().await;
    // the decision arrives 1 ms after expires_at (the timer has not run yet)
    h.clock.advance(120_000);
    let mut d = h.phone_decision(&card, &phone.device_id, Decision::Allow);
    d.decided_at = Some(agentnest_core::state::timers::format_ms(h.now_ms() - 1));
    let out = h.broker.apply_decision(d).await;
    assert!(!out.accepted);
    assert_eq!(out.reason, DecisionResultReason::Expired);
    assert_eq!(rx.await.unwrap(), Seen::Abandoned(AbandonReason::Expired));
    let row = h.row(&card.request_id);
    assert_eq!(row.status, "expired");
    assert_eq!(row.resolved_by.as_deref(), Some("timeout"));
}

#[tokio::test]
async fn the_tick_expires_at_the_ttl_and_not_before() {
    let h = Harness::new();
    let _phone = h.add_phone("Galaxy");
    let (card, mut rx) = h.open_low().await;
    h.advance(119_999).await;
    assert_eq!(try_seen(&mut rx), None);
    assert_eq!(h.row(&card.request_id).status, "pending");
    h.advance(1).await;
    assert_eq!(rx.await.unwrap(), Seen::Abandoned(AbandonReason::Expired));
    assert_eq!(h.row(&card.request_id).status, "expired");
    assert!(h
        .audit_actions(&card.request_id)
        .contains(&"expired".to_owned()));
    assert_eq!(
        h.pipeline
            .session(&card.session_key)
            .await
            .unwrap()
            .pending_approval_ids
            .len(),
        0
    );
}

#[tokio::test]
async fn two_devices_racing_exactly_one_decision_wins() {
    let h = Harness::new();
    let a = h.add_phone("A");
    let b = h.add_phone("B");
    let (card, rx) = h.open_low().await;
    let da = h.phone_decision(&card, &a.device_id, Decision::Allow);
    let db = h.phone_decision(&card, &b.device_id, Decision::Deny);
    let (ra, rb) = tokio::join!(h.broker.apply_decision(da), h.broker.apply_decision(db));
    let winners = [&ra, &rb].iter().filter(|o| o.accepted).count();
    assert_eq!(winners, 1, "{ra:?} {rb:?}");
    let loser = if ra.accepted { &rb } else { &ra };
    assert_eq!(loser.reason, DecisionResultReason::AlreadyResolved);
    let seen = rx.await.unwrap();
    assert!(matches!(seen, Seen::Allow | Seen::Deny { .. }));
    let row = h.row(&card.request_id);
    assert_eq!(row.status, "resolved");
    // the reply matches the winning decision
    match (row.outcome.as_deref(), &seen) {
        (Some("allowed"), Seen::Allow) | (Some("denied"), Seen::Deny { .. }) => {}
        other => panic!("reply does not match the stored outcome: {other:?}"),
    }
}

#[tokio::test]
async fn high_and_critical_allow_need_the_extra_confirmation_but_deny_never_does() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (card, rx) = h.open_critical().await;
    assert_eq!(
        card.risk.extra_confirmation,
        ExtraConfirmation::HoldAndReconfirm
    );
    let mut d = h.phone_decision(&card, &phone.device_id, Decision::Allow);
    d.extra_confirmation = None;
    assert_eq!(
        h.broker.apply_decision(d).await.reason,
        DecisionResultReason::ExtraConfirmationRequired
    );
    let mut d = h.phone_decision(&card, &phone.device_id, Decision::Allow);
    d.extra_confirmation = Some(agentnest_protocol::ExtraConfirmationProof {
        method: agentnest_protocol::ExtraConfirmationMethod::Hold,
        completed: true,
    });
    assert_eq!(
        h.broker.apply_decision(d).await.reason,
        DecisionResultReason::ExtraConfirmationRequired,
        "hold is weaker than hold_and_reconfirm"
    );
    // a plain deny passes on a critical card without any extra confirmation (lead decision)
    let mut d = h.phone_decision(&card, &phone.device_id, Decision::Deny);
    d.extra_confirmation = None;
    d.auth = None;
    assert!(h.broker.apply_decision(d).await.accepted);
    assert!(matches!(rx.await.unwrap(), Seen::Deny { .. }));
    // and the fully confirmed allow works on a fresh critical card
    let (card, rx) = h.open_critical().await;
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
            .await
            .accepted
    );
    assert_eq!(rx.await.unwrap(), Seen::Allow);
}

#[tokio::test]
async fn deny_requires_auth_policy_is_part_of_the_card() {
    let h = Harness::with(
        agentnest_core::approvals::broker::default_classifier(),
        120,
        10,
        false,
        true,
    );
    let phone = h.add_phone("Galaxy");
    let (card, _rx) = h.open_low().await;
    assert!(card.auth_required_for.contains(&Decision::Deny));
    let mut d = h.phone_decision(&card, &phone.device_id, Decision::Deny);
    d.auth = None;
    assert_eq!(
        h.broker.apply_decision(d).await.reason,
        DecisionResultReason::AuthRequired
    );
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Deny))
            .await
            .accepted
    );
}

#[tokio::test]
async fn identical_hooks_within_two_seconds_share_one_card_and_one_decision_answers_both() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let input = json!({"command": "cargo test"});
    let (o1, rx1) = h.open(h.draft("Bash", input.clone())).await;
    h.clock.advance(1_000);
    let (o2, rx2) = h.open(h.draft("Bash", input.clone())).await;
    let OpenOutcome::Opened { request_id } = o1 else {
        panic!("{o1:?}")
    };
    assert_eq!(
        o2,
        OpenOutcome::Merged {
            request_id: request_id.clone()
        }
    );
    assert_eq!(h.broker.pending_count().await, 1, "one card");
    let card = h.broker.pending_card(&request_id).await.unwrap();
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
            .await
            .accepted
    );
    assert_eq!(rx1.await.unwrap(), Seen::Allow);
    assert_eq!(rx2.await.unwrap(), Seen::Allow);
}

#[tokio::test]
async fn different_agents_or_a_longer_gap_get_separate_cards_each_answered_by_its_own_decision() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let input = json!({"command": "cargo test"});
    // different agent_id: two cards (parallel sub-agents must not share one approval)
    let (o1, rx1) = h
        .open(h.draft_for(SESSION, Some("agent-a"), "Bash", input.clone()))
        .await;
    let (o2, rx2) = h
        .open(h.draft_for(SESSION, Some("agent-b"), "Bash", input.clone()))
        .await;
    let (OpenOutcome::Opened { request_id: id1 }, OpenOutcome::Opened { request_id: id2 }) =
        (o1, o2)
    else {
        panic!("two cards expected")
    };
    assert_ne!(id1, id2);
    let c1 = h.broker.pending_card(&id1).await.unwrap();
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&c1, &phone.device_id, Decision::Allow))
            .await
            .accepted
    );
    assert_eq!(rx1.await.unwrap(), Seen::Allow);
    let mut rx2 = rx2;
    assert_eq!(
        try_seen(&mut rx2),
        None,
        "the approval of one sub-agent never answers the other"
    );
    let c2 = h.broker.pending_card(&id2).await.unwrap();
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&c2, &phone.device_id, Decision::Deny))
            .await
            .accepted
    );
    assert!(matches!(rx2.await.unwrap(), Seen::Deny { .. }));
    // the same call 3 s later: a new card
    let (o3, _rx3) = h.open(h.draft("Bash", input.clone())).await;
    h.clock.advance(3_000);
    let (o4, _rx4) = h.open(h.draft("Bash", input)).await;
    assert!(matches!(o3, OpenOutcome::Opened { .. }));
    assert!(matches!(o4, OpenOutcome::Opened { .. }));
    assert_eq!(h.broker.pending_count().await, 2);
}

#[tokio::test]
async fn desktop_decisions_use_the_same_transition_with_their_own_gates() {
    let h = Harness::new();
    let _phone = h.add_phone("Galaxy");
    let (card, rx) = h.open_critical().await;
    // missing confirm_ack on an allow
    let out = h
        .broker
        .decide_local(
            &card.request_id,
            Decision::Allow,
            &card.tool_input_sha256,
            false,
            None,
        )
        .await;
    assert_eq!(out.reason, DecisionResultReason::ExtraConfirmationRequired);
    // hash of another card
    let out = h
        .broker
        .decide_local(
            &card.request_id,
            Decision::Allow,
            &"0".repeat(64),
            true,
            None,
        )
        .await;
    assert_eq!(out.reason, DecisionResultReason::InputHashMismatch);
    // unknown request
    let out = h
        .broker
        .decide_local(
            "ar_nope",
            Decision::Allow,
            &card.tool_input_sha256,
            true,
            None,
        )
        .await;
    assert_eq!(out.reason, DecisionResultReason::UnknownRequest);
    // paused: the desktop still decides
    h.broker.set_paused(true).await;
    let out = h
        .broker
        .decide_local(
            &card.request_id,
            Decision::Allow,
            &card.tool_input_sha256,
            true,
            None,
        )
        .await;
    assert!(out.accepted, "{out:?}");
    assert_eq!(rx.await.unwrap(), Seen::Allow);
    let row = h.row(&card.request_id);
    assert_eq!(row.resolved_by.as_deref(), Some("desktop"));
    assert_eq!(row.resolved_device_id, None);
    let decisions = h.store.list_decisions(&card.request_id).unwrap();
    assert!(decisions
        .iter()
        .any(|d| d.actor == "desktop" && d.verify_result == "APPLIED"));
    // a desktop deny needs no ack even on a critical card
    h.broker.set_paused(false).await;
    let (card, rx) = h.open_critical().await;
    let out = h
        .broker
        .decide_local(
            &card.request_id,
            Decision::Deny,
            &card.tool_input_sha256,
            false,
            Some("no".into()),
        )
        .await;
    assert!(out.accepted);
    match rx.await.unwrap() {
        Seen::Deny { message, .. } => assert!(message.contains("PC에서 거부했습니다")),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn pause_hands_new_requests_to_the_local_prompt_and_refuses_phone_decisions() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (card, mut rx) = h.open_low().await;
    h.broker.set_paused(true).await;
    // a pending decision is refused with PAUSED and the request stays pending
    let out = h
        .broker
        .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
        .await;
    assert_eq!(out.reason, DecisionResultReason::Paused);
    assert_eq!(try_seen(&mut rx), None);
    // a new request is handed off at once
    let (o, rx2) = h
        .open(h.draft("Bash", json!({"command": "cargo build"})))
        .await;
    assert!(
        matches!(
            o,
            OpenOutcome::HandedOff {
                channel: ApprovalChannel::LocalOnly,
                ..
            }
        ),
        "{o:?}"
    );
    assert_eq!(
        rx2.await.unwrap(),
        Seen::Abandoned(AbandonReason::RemoteApprovalPaused)
    );
    // the sessions show "paused"
    assert_eq!(
        h.pipeline
            .session(&card.session_key)
            .await
            .unwrap()
            .remote_approval,
        agentnest_protocol::RemoteApproval::Paused
    );
    // resuming works again
    h.broker.set_paused(false).await;
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
            .await
            .accepted
    );
}

#[tokio::test]
async fn no_online_device_means_an_immediate_hand_off_with_no_card() {
    let h = Harness::new();
    let mut stream = h.registry.subscribe();
    let (o, rx) = h
        .open(h.draft("Bash", json!({"command": "cargo test"})))
        .await;
    let OpenOutcome::HandedOff {
        request_id,
        channel,
    } = o
    else {
        panic!("{o:?}")
    };
    assert_eq!(channel, ApprovalChannel::NoDevice);
    assert_eq!(
        rx.await.unwrap(),
        Seen::Abandoned(AbandonReason::NoOnlineDevice)
    );
    let row = h.row(&request_id);
    assert_eq!(row.status, "handed_off_local");
    assert_eq!(row.resolved_by.as_deref(), Some("system"));
    let msgs = Harness::drain(&mut stream);
    assert!(
        msgs.iter().all(|m| m.1 != "approval_request"),
        "no card for a hand-off"
    );
    assert_eq!(h.broker.pending_count().await, 0);
    assert_eq!(
        h.pipeline
            .session("claude_code:s-1")
            .await
            .unwrap()
            .pending_approval_ids
            .len(),
        0
    );
}

#[tokio::test]
async fn critical_local_only_never_reaches_the_phone() {
    let h = Harness::with(
        agentnest_core::approvals::broker::default_classifier(),
        120,
        10,
        true,
        false,
    );
    let _phone = h.add_phone("Galaxy");
    let (o, rx) = h
        .open(h.draft("Bash", json!({"command": "rm -rf /"})))
        .await;
    assert!(
        matches!(
            o,
            OpenOutcome::HandedOff {
                channel: ApprovalChannel::LocalOnly,
                ..
            }
        ),
        "{o:?}"
    );
    assert_eq!(
        rx.await.unwrap(),
        Seen::Abandoned(AbandonReason::HandedOffToDesktop)
    );
    // a non-critical request still goes to the phone
    let (card, _rx) = h.open_low().await;
    assert_eq!(h.row(&card.request_id).status, "pending");
}

#[tokio::test]
async fn reconnect_grace_hands_off_after_ten_seconds_unless_a_phone_returns() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (card, mut rx) = h.open_low().await;
    h.disconnect(&phone).await;
    h.advance(9_999).await;
    assert_eq!(try_seen(&mut rx), None, "still inside the grace period");
    assert_eq!(h.row(&card.request_id).status, "pending");
    h.advance(1).await;
    assert_eq!(
        rx.await.unwrap(),
        Seen::Abandoned(AbandonReason::PhoneDisconnected)
    );
    assert_eq!(h.row(&card.request_id).status, "handed_off_local");

    // a phone that comes back in time keeps the request alive
    let phone = h.add_phone("Galaxy 2");
    let (card, mut rx) = h.open_low().await;
    h.disconnect(&phone).await;
    h.advance(5_000).await;
    let (tx, _crx) = tokio::sync::mpsc::unbounded_channel();
    h.registry.register("dev_back", tx);
    h.broker.device_connected().await;
    h.advance(20_000).await;
    assert_eq!(try_seen(&mut rx), None);
    assert_eq!(h.row(&card.request_id).status, "pending");
}

#[tokio::test]
async fn a_second_phone_keeps_the_request_alive_when_the_first_disconnects() {
    let h = Harness::new();
    let a = h.add_phone("A");
    let _b = h.add_phone("B");
    let (card, mut rx) = h.open_low().await;
    h.disconnect(&a).await;
    h.advance(30_000).await;
    assert_eq!(try_seen(&mut rx), None);
    assert_eq!(h.row(&card.request_id).status, "pending");
}

#[tokio::test]
async fn zero_grace_hands_off_immediately() {
    let h = Harness::with(
        agentnest_core::approvals::broker::default_classifier(),
        120,
        0,
        false,
        false,
    );
    let phone = h.add_phone("Galaxy");
    let (_card, rx) = h.open_low().await;
    h.disconnect(&phone).await;
    assert_eq!(
        rx.await.unwrap(),
        Seen::Abandoned(AbandonReason::PhoneDisconnected)
    );
}

#[tokio::test]
async fn revoking_a_device_voids_its_decisions_and_hands_off_when_nobody_else_is_online() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (card, rx) = h.open_low().await;
    let d = h.phone_decision(&card, &phone.device_id, Decision::Allow);
    h.devices.revoke(&phone.device_id, "user_desktop").unwrap();
    // the decision of the revoked device is void even before the connection is kicked
    let out = h.broker.apply_decision(d).await;
    assert_eq!(out.reason, DecisionResultReason::DeviceRevoked);
    assert_eq!(h.row(&card.request_id).status, "pending");
    // kick + broker notification: nobody else online -> hand-off
    h.registry.kick_revoked(&phone.device_id);
    h.broker.device_revoked().await;
    assert_eq!(
        rx.await.unwrap(),
        Seen::Abandoned(AbandonReason::DeviceRevoked)
    );
    assert_eq!(h.row(&card.request_id).status, "handed_off_local");
}

#[tokio::test]
async fn revoking_one_of_two_devices_keeps_the_request_for_the_other() {
    let h = Harness::new();
    let a = h.add_phone("A");
    let b = h.add_phone("B");
    let (card, mut rx) = h.open_low().await;
    h.devices.revoke(&a.device_id, "user_desktop").unwrap();
    h.registry.kick_revoked(&a.device_id);
    h.broker.device_revoked().await;
    assert_eq!(try_seen(&mut rx), None);
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&card, &b.device_id, Decision::Allow))
            .await
            .accepted
    );
}

#[tokio::test]
async fn when_the_agent_closes_first_the_request_is_superseded_and_a_late_decision_is_logged() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let draft = h.draft("Bash", json!({"command": "cargo test"}));
    let binding = draft.binding.clone();
    let (o, mut rx) = h.open(draft).await;
    let OpenOutcome::Opened { request_id } = o else {
        panic!()
    };
    let card = h.broker.pending_card(&request_id).await.unwrap();
    h.broker
        .agent_closed(&binding, AgentCloseReason::ConnectionClosed)
        .await;
    let row = h.row(&request_id);
    assert_eq!(row.status, "superseded");
    assert_eq!(row.resolved_by.as_deref(), Some("agent"));
    assert_eq!(
        try_seen(&mut rx),
        Some(Seen::Abandoned(AbandonReason::Superseded))
    );
    // the phone decides late: refused, never answered, audited
    let out = h
        .broker
        .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
        .await;
    assert!(!out.accepted);
    assert_eq!(out.reason, DecisionResultReason::AlreadyResolved);
    assert!(h
        .audit_actions(&request_id)
        .contains(&"late_decision".to_owned()));
    assert_eq!(h.row(&request_id).status, "superseded");
}

#[tokio::test]
async fn closing_one_of_two_merged_handles_keeps_the_request_until_the_last_one_goes() {
    let h = Harness::new();
    let _phone = h.add_phone("Galaxy");
    let input = json!({"command": "cargo test"});
    let d1 = h.draft("Bash", input.clone());
    let d2 = h.draft("Bash", input);
    let (b1, b2) = (d1.binding.clone(), d2.binding.clone());
    let (o1, _rx1) = h.open(d1).await;
    let (o2, _rx2) = h.open(d2).await;
    let OpenOutcome::Opened { request_id } = o1 else {
        panic!()
    };
    assert!(matches!(o2, OpenOutcome::Merged { .. }));
    h.broker
        .agent_closed(&b1, AgentCloseReason::ConnectionClosed)
        .await;
    assert_eq!(
        h.row(&request_id).status,
        "pending",
        "the second handle still waits"
    );
    h.broker
        .agent_closed(&b2, AgentCloseReason::ConnectionClosed)
        .await;
    assert_eq!(h.row(&request_id).status, "superseded");
    // an unknown binding is ignored
    h.broker
        .agent_closed(&b2, AgentCloseReason::ConnectionClosed)
        .await;
}

#[tokio::test]
async fn handoff_local_ends_the_request_without_a_decision_whatever_the_risk() {
    let h = Harness::new();
    let _phone = h.add_phone("Galaxy");
    let (card, rx) = h.open_critical().await;
    assert!(h.broker.handoff_local(&card.request_id).await);
    assert!(!h.broker.handoff_local(&card.request_id).await);
    assert_eq!(
        rx.await.unwrap(),
        Seen::Abandoned(AbandonReason::HandedOffToDesktop)
    );
    let row = h.row(&card.request_id);
    assert_eq!(row.status, "handed_off_local");
    assert_eq!(row.resolved_by.as_deref(), Some("desktop"));
}

#[tokio::test]
async fn link_disable_and_shutdown_hand_off_everything() {
    let h = Harness::new();
    let _phone = h.add_phone("Galaxy");
    let (c1, rx1) = h.open_low().await;
    let (o2, rx2) = h
        .open(h.draft("Bash", json!({"command": "cargo build"})))
        .await;
    let OpenOutcome::Opened { request_id: id2 } = o2 else {
        panic!()
    };
    assert_eq!(h.broker.link_disabled().await, 2);
    assert_eq!(
        rx1.await.unwrap(),
        Seen::Abandoned(AbandonReason::LinkDisabled)
    );
    assert_eq!(
        rx2.await.unwrap(),
        Seen::Abandoned(AbandonReason::LinkDisabled)
    );
    assert_eq!(
        h.row(&c1.request_id).resolved_by.as_deref(),
        Some("desktop")
    );
    assert_eq!(h.row(&id2).status, "handed_off_local");
    let (_c3, rx3) = h.open_low().await;
    assert_eq!(h.broker.shutdown().await, 1);
    assert_eq!(
        rx3.await.unwrap(),
        Seen::Abandoned(AbandonReason::DaemonShutdown)
    );
}

#[tokio::test]
async fn observed_result_is_correlated_and_re_published_with_the_same_request_id() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let input = json!({"command": "cargo test -p agentnest-core"});
    let (card, rx) = h.open_low().await;
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
            .await
            .accepted
    );
    assert_eq!(rx.await.unwrap(), Seen::Allow);
    let mut stream = h.registry.subscribe();
    h.clock.advance(3_000);
    h.broker
        .observe_tool(ToolObservation {
            session_key: card.session_key.clone(),
            tool_name: "Bash".into(),
            input_sha256: tool_input_sha256(&input),
            phase: HookPhase::Post,
            evidence_event_id: "01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f".into(),
        })
        .await;
    let row = h.row(&card.request_id);
    assert_eq!(row.observed_result, "executed");
    assert_eq!(
        row.observed_event_id.as_deref(),
        Some("01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e5f")
    );
    let msgs = Harness::drain(&mut stream);
    let r = msgs
        .iter()
        .find(|m| m.1 == "approval_resolved")
        .expect("re-sent");
    assert_eq!(r.2["request_id"], card.request_id);
    assert_eq!(r.2["observed_result"], "executed");
    assert!(h
        .audit_actions(&card.request_id)
        .contains(&"observed".to_owned()));
    let _ = ObservedResult::Executed;
}

#[tokio::test]
async fn a_denied_call_that_fails_is_observed_as_declined() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (card, _rx) = h.open_low().await;
    assert!(
        h.broker
            .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::DenyAndStop))
            .await
            .accepted
    );
    h.broker
        .observe_tool(ToolObservation {
            session_key: card.session_key.clone(),
            tool_name: "Bash".into(),
            input_sha256: card.tool_input_sha256.clone(),
            phase: HookPhase::PostFailure,
            evidence_event_id: "01929f1a-6c2e-7b3c-9e4d-2a7b1c3d4e60".into(),
        })
        .await;
    assert_eq!(h.row(&card.request_id).observed_result, "declined");
}

#[tokio::test]
async fn startup_recovery_expires_every_pending_row_and_tells_the_phones() {
    let h = Harness::new();
    let _phone = h.add_phone("Galaxy");
    let (card, _rx) = h.open_low().await;
    assert_eq!(h.row(&card.request_id).status, "pending");
    // a "restarted" broker on the same database
    let registry = std::sync::Arc::new(agentnest_core::link::registry::Registry::new());
    let mut stream = registry.subscribe();
    let bus = agentnest_core::events::EventBus::new(16);
    let pipeline = std::sync::Arc::new(agentnest_core::pipeline::Pipeline::new(
        h.store.clone(),
        h.clock.clone(),
        registry.clone(),
        bus.clone(),
    ));
    let broker = agentnest_core::approvals::broker::Broker::new(
        agentnest_core::approvals::broker::BrokerDeps {
            store: h.store.clone(),
            clock: h.clock.clone(),
            pipeline,
            registry,
            bus,
            audit: h.audit.clone(),
            devices: h.devices.clone(),
            env: h.env.clone(),
            settings: h.settings.clone(),
            classifier: agentnest_core::approvals::broker::default_classifier(),
        },
    );
    assert_eq!(broker.recover_on_startup().await, 1);
    let row = h.row(&card.request_id);
    assert_eq!(row.status, "expired");
    assert_eq!(row.resolved_by.as_deref(), Some("system"));
    let msgs = Harness::drain(&mut stream);
    let r = msgs
        .iter()
        .find(|m| m.1 == "approval_resolved")
        .expect("phones are told");
    assert_eq!(r.2["outcome"], "expired");
    // a decision for it now is refused: the old HTTP handle is gone
    let phone2 = h.add_phone("P2");
    let out = broker
        .apply_decision(h.phone_decision(&card, &phone2.device_id, Decision::Allow))
        .await;
    assert_eq!(out.reason, DecisionResultReason::AlreadyResolved);
}

#[tokio::test]
async fn an_unreachable_agent_is_recorded_as_not_delivered_but_the_decision_stands() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (r, rx) = failing_responder();
    let o = h
        .broker
        .open(h.draft("Bash", json!({"command": "cargo test"})), r)
        .await;
    let OpenOutcome::Opened { request_id } = o else {
        panic!()
    };
    let card = h.broker.pending_card(&request_id).await.unwrap();
    let out = h
        .broker
        .apply_decision(h.phone_decision(&card, &phone.device_id, Decision::Allow))
        .await;
    assert!(out.accepted);
    drop(rx);
    assert_eq!(
        h.row(&request_id).delivery.as_deref(),
        Some("not_delivered")
    );
    assert_eq!(h.row(&request_id).outcome.as_deref(), Some("allowed"));
}

#[tokio::test]
async fn delivery_bookkeeping_is_stored_and_audited() {
    let h = Harness::new();
    let phone = h.add_phone("Galaxy");
    let (card, _rx) = h.open_low().await;
    h.broker.mark_sent(&card.request_id, &phone.device_id).await;
    h.broker.mark_sent(&card.request_id, &phone.device_id).await;
    h.broker
        .mark_acked(std::slice::from_ref(&card.request_id), &phone.device_id)
        .await;
    h.broker.mark_seen(&card.request_id, &phone.device_id).await;
    let overview = h.broker.pending_overview().await;
    assert_eq!(overview.len(), 1);
    assert_eq!(overview[0].sent_to, vec![phone.device_id.clone()]);
    assert!(overview[0].acked && overview[0].seen);
    let actions = h.audit_actions(&card.request_id);
    for a in ["sent_to_phone", "acked", "seen"] {
        assert_eq!(
            actions.iter().filter(|x| x.as_str() == a).count(),
            1,
            "{a} once: {actions:?}"
        );
    }
    let row = h.row(&card.request_id);
    let delivered: serde_json::Value = serde_json::from_str(&row.delivered_to_json).unwrap();
    assert!(delivered[&phone.device_id]["acked_at"].is_string());
}

#[tokio::test]
async fn a_failing_store_never_answers_a_request() {
    let h = Harness::new();
    let _phone = h.add_phone("Galaxy");
    // break the approvals table: the insert fails, the request must be abandoned (empty reply), not answered
    h.store
        .run(|c| Ok(c.execute_batch("DROP TABLE approvals")?))
        .unwrap();
    let (o, rx) = h
        .open(h.draft("Bash", json!({"command": "cargo test"})))
        .await;
    assert_eq!(o, OpenOutcome::Failed);
    assert_eq!(
        rx.await.unwrap(),
        Seen::Abandoned(AbandonReason::InternalError)
    );
    assert_eq!(h.broker.pending_count().await, 0);
}
