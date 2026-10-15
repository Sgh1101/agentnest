//! AgentNest daemon core: collectors, normalisation, summaries, risk classification, state derivation, the approval
//! broker, storage, pairing and the WSS link. It knows nothing about Tauri.
//!
//! This crate is a skeleton: every module below is declared here once so that implementers fill them in without
//! touching `lib.rs`. Module responsibilities: docs/architecture.md 3.3. Protocol types live in
//! `agentnest-protocol`, the adapter plugin API in `agentnest-adapter-api`.
//!
//! Hard rules for the code that goes into these modules (docs/security.md): an allow reply is minted only in
//! `approvals::broker` (`ApplyProof`), every failure path is "no decision", secrets use the `redact` newtypes and never
//! reach logs, and `// UNVERIFIED (Phase 0)` code sits behind its feature flag.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// No `unwrap()` / `expect()` outside tests (CLAUDE.md). Test code is exempt through `cfg(test)`.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod adapters;
pub mod approvals;
pub mod audit;
pub mod auth;
pub mod config;
pub mod daemon;
pub mod http;
pub mod identity;
pub mod link;
pub mod normalize;
pub mod redact;
pub mod risk;
pub mod state;
pub mod store;
pub mod summarize;
