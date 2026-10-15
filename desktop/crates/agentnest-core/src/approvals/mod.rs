//! Approval broker (single transition path), 9-step validator, outcome correlator, drop guard.
//!
//! Layout:
//!
//! * [`validator`]: the pure, ordered checks of docs/security.md 6.2 / 6.2.1;
//! * [`broker`]: the only code that changes the state of an approval and the **only** place that can produce an allow
//!   reply (`apply_decision`);
//! * [`card`]: the bounded, masked card shown to the user;
//! * [`correlator`]: later observation of what happened to an approved / denied tool call;
//! * [`drop_guard`]: "the agent's connection went away" -> `superseded`.

pub mod broker;
pub mod card;
pub mod correlator;
pub mod drop_guard;
pub mod validator;
