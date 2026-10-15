//! First-run checklist state (docs/desktop.md 6.1) and the start-up window decision.
//!
//! The front end renders its own onboarding; this module is the single place that says which step is done, which is
//! blocking, and when the window must open even though the app was started with `--minimized`.

/// State of one checklist step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepState {
    /// Measured and fine.
    Done,
    /// Not done yet.
    Pending,
    /// Measured and not fine (for example a `Public` network profile).
    Attention,
    /// Does not apply (Codex is switched off).
    NotApplicable,
}

/// The checklist steps in display order.
pub const STEP_IDS: [&str; 5] = [
    "risk_r1",
    "network_firewall",
    "claude_hooks",
    "codex_hooks",
    "add_device",
];

/// What the checklist is computed from. Every field is a measurement, not a stored claim.
#[derive(Clone, Debug, Default)]
pub struct ChecklistInput {
    /// R1 accepted (`risk_accept`).
    pub risk_accepted: bool,
    /// A connection diagnostics run exists.
    pub diagnostics_run: bool,
    /// The network profile is `private`.
    pub profile_private: bool,
    /// The firewall rule exists with the documented scope.
    pub firewall_scoped_ok: bool,
    /// Claude Code hooks installed.
    pub claude_hooks_installed: bool,
    /// A Claude Code event has been received.
    pub claude_event_seen: bool,
    /// `codex.mode == off`.
    pub codex_off: bool,
    /// Finished Codex steps (`hooks_json`, `trust`, `doctor`).
    pub codex_steps_done: Vec<String>,
    /// A Codex event has been received.
    pub codex_event_seen: bool,
    /// Paired (not revoked) devices.
    pub devices_paired: usize,
}

/// One checklist row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    /// One of [`STEP_IDS`].
    pub id: &'static str,
    /// Its state.
    pub state: StepState,
}

/// Computes the checklist. Step 5 can only be `Pending` or `Done`; whether it may *start* is [`can_start_pairing`].
pub fn checklist(i: &ChecklistInput) -> Vec<Step> {
    let risk = if i.risk_accepted {
        StepState::Done
    } else {
        StepState::Pending
    };
    let network = if !i.diagnostics_run {
        StepState::Pending
    } else if i.profile_private && i.firewall_scoped_ok {
        StepState::Done
    } else {
        StepState::Attention
    };
    let claude = if i.claude_hooks_installed && i.claude_event_seen {
        StepState::Done
    } else {
        StepState::Pending
    };
    let codex = if i.codex_off {
        StepState::NotApplicable
    } else if ["hooks_json", "trust", "doctor"]
        .iter()
        .all(|s| i.codex_steps_done.iter().any(|d| d == s))
        && i.codex_event_seen
    {
        StepState::Done
    } else {
        StepState::Pending
    };
    let device = if i.devices_paired > 0 {
        StepState::Done
    } else {
        StepState::Pending
    };
    vec![
        Step {
            id: "risk_r1",
            state: risk,
        },
        Step {
            id: "network_firewall",
            state: network,
        },
        Step {
            id: "claude_hooks",
            state: claude,
        },
        Step {
            id: "codex_hooks",
            state: codex,
        },
        Step {
            id: "add_device",
            state: device,
        },
    ]
}

/// "기기 추가" may start only when steps 1 and 2 pass (docs/desktop.md 6.1 row 5).
pub fn can_start_pairing(i: &ChecklistInput) -> bool {
    let steps = checklist(i);
    steps[0].state == StepState::Done && steps[1].state == StepState::Done
}

/// Whether the main window is shown at start-up. `--minimized` (autostart) keeps it hidden **unless** the first-run
/// checklist has not been completed: a new user must see the app.
pub fn show_window_at_start(minimized_flag: bool, onboarding_completed: bool) -> bool {
    !minimized_flag || !onboarding_completed
}

/// `true` if the process arguments ask for a tray-only start.
pub fn has_minimized_flag<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter().any(|a| a.as_ref() == "--minimized")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> ChecklistInput {
        ChecklistInput {
            risk_accepted: true,
            diagnostics_run: true,
            profile_private: true,
            firewall_scoped_ok: true,
            claude_hooks_installed: true,
            claude_event_seen: true,
            codex_off: false,
            codex_steps_done: vec!["hooks_json".into(), "trust".into(), "doctor".into()],
            codex_event_seen: true,
            devices_paired: 1,
        }
    }

    fn states(i: &ChecklistInput) -> Vec<StepState> {
        checklist(i).iter().map(|s| s.state).collect()
    }

    #[test]
    fn a_fresh_install_has_everything_pending() {
        let i = ChecklistInput {
            codex_off: false,
            ..ChecklistInput::default()
        };
        assert_eq!(states(&i), vec![StepState::Pending; 5]);
        assert!(!can_start_pairing(&i));
        let ids: Vec<&str> = checklist(&i).iter().map(|s| s.id).collect();
        assert_eq!(ids, STEP_IDS);
    }

    #[test]
    fn everything_done() {
        assert_eq!(states(&ready()), vec![StepState::Done; 5]);
        assert!(can_start_pairing(&ready()));
    }

    #[test]
    fn a_public_network_or_a_missing_rule_needs_attention_and_blocks_pairing() {
        let mut i = ready();
        i.profile_private = false;
        assert_eq!(checklist(&i)[1].state, StepState::Attention);
        assert!(!can_start_pairing(&i));
        let mut i = ready();
        i.firewall_scoped_ok = false;
        assert_eq!(checklist(&i)[1].state, StepState::Attention);
        assert!(!can_start_pairing(&i));
    }

    #[test]
    fn pairing_needs_the_risk_acceptance() {
        let mut i = ready();
        i.risk_accepted = false;
        assert!(!can_start_pairing(&i));
    }

    #[test]
    fn claude_needs_the_hooks_and_a_first_event() {
        let mut i = ready();
        i.claude_event_seen = false;
        assert_eq!(checklist(&i)[2].state, StepState::Pending);
        let mut i = ready();
        i.claude_hooks_installed = false;
        assert_eq!(checklist(&i)[2].state, StepState::Pending);
    }

    #[test]
    fn codex_is_not_applicable_when_off_and_needs_every_step_otherwise() {
        let mut i = ready();
        i.codex_off = true;
        assert_eq!(checklist(&i)[3].state, StepState::NotApplicable);
        let mut i = ready();
        i.codex_steps_done = vec!["hooks_json".into(), "trust".into()];
        assert_eq!(checklist(&i)[3].state, StepState::Pending);
        let mut i = ready();
        i.codex_event_seen = false;
        assert_eq!(checklist(&i)[3].state, StepState::Pending);
    }

    #[test]
    fn minimized_start_still_shows_the_window_until_onboarding_is_done() {
        assert!(show_window_at_start(false, true));
        assert!(show_window_at_start(false, false));
        assert!(!show_window_at_start(true, true));
        assert!(show_window_at_start(true, false));
    }

    #[test]
    fn the_minimized_flag_is_recognised() {
        assert!(has_minimized_flag(["agentnest.exe", "--minimized"]));
        assert!(!has_minimized_flag(["agentnest.exe"]));
        assert!(!has_minimized_flag(Vec::<String>::new()));
    }
}
