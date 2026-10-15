//! RawObservation -> AgentEvent post-processing: path normalisation, project resolution, masking, bounds, dedupe_key.
//!
//! * [`path`]: lexical Windows/POSIX path helpers (total, no panics).
//! * [`project`]: project resolution by walking up for `.git` (no `git` process).
//! * [`hook`]: field extraction shared by the hook normalisers.
//! * [`dedupe`]: the `dedupe_key` formula and the 2 second duplicate window.
//! * [`post`]: [`post::EventDraft`] -> [`agentnest_protocol::AgentEvent`] with masking, bounds, summary clipping, ids
//!   and timestamps; every adapter ends with [`post::build_event`].
//!
//! [`NormalizeEnv`] bundles the things that make normalisation non-deterministic (clock, id generator, file system) so
//! that golden tests can pin them.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::state::timers::{Clock, SystemClock};

pub mod dedupe;
pub mod hook;
pub mod path;
pub mod post;
pub mod project;

pub use dedupe::{dedupe_key, DedupeKey, DedupeWindow, DEDUPE_WINDOW_MS};
pub use post::{build_event, default_severity, EventDraft};
pub use project::{FsProbe, ProjectResolver, RealFs};

/// Generates event ids (UUIDv7, protocol.md 5.1).
pub trait IdGen: Send + Sync {
    /// The next event id.
    fn next_event_id(&self) -> String;
}

/// Real UUIDv7 ids.
#[derive(Clone, Copy, Debug, Default)]
pub struct UuidV7Gen;

impl IdGen for UuidV7Gen {
    fn next_event_id(&self) -> String {
        uuid::Uuid::now_v7().to_string()
    }
}

/// Deterministic UUIDv7-shaped ids `01929f1a-7a00-7b3c-9e4d-<counter>` for golden tests.
#[derive(Debug, Default)]
pub struct SequentialIdGen(AtomicU64);

impl IdGen for SequentialIdGen {
    fn next_event_id(&self) -> String {
        let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        format!("01929f1a-7a00-7b3c-9e4d-{n:012x}")
    }
}

/// Clock, id generator and project resolver used while normalising.
#[derive(Clone)]
pub struct NormalizeEnv {
    /// Source of `ts`.
    pub clock: Arc<dyn Clock>,
    /// Source of `event_id`.
    pub ids: Arc<dyn IdGen>,
    /// Project resolution.
    pub projects: Arc<ProjectResolver>,
}

impl std::fmt::Debug for NormalizeEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NormalizeEnv").finish_non_exhaustive()
    }
}

impl NormalizeEnv {
    /// Wall clock, UUIDv7 ids and the real file system.
    pub fn system() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            ids: Arc::new(UuidV7Gen),
            projects: Arc::new(ProjectResolver::new()),
        }
    }

    /// An environment from explicit parts.
    pub fn new(clock: Arc<dyn Clock>, ids: Arc<dyn IdGen>, projects: Arc<ProjectResolver>) -> Self {
        Self {
            clock,
            ids,
            projects,
        }
    }

    /// Fixed time `2026-10-15T09:12:33.120Z`, sequential ids and an empty in-memory file system.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        use crate::state::timers::ManualClock;
        let clock = Arc::new(ManualClock::new(1_792_055_553_120));
        Self {
            clock: clock.clone(),
            ids: Arc::new(SequentialIdGen::default()),
            projects: Arc::new(ProjectResolver::with_probe(
                Box::new(project::testing::FakeFs::default()),
                clock,
            )),
        }
    }
}
