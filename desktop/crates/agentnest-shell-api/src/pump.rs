//! The forwarding task: daemon events to the webview, the window, toasts and the tray.
//!
//! High-frequency `event` messages are batched into one array per [`BATCH_WINDOW`] (the Tauri event system is not built
//! for throughput, docs/desktop.md 3); every other kind is forwarded at once, after the pending batch, so the order the
//! daemon produced is the order the UI sees. [`UiSink`] is the only place that touches Tauri.

use std::sync::Arc;
use std::time::Duration;

use agentnest_core::events::DaemonEvent;
use serde_json::Value;
use tokio::sync::broadcast::{self, error::RecvError};

use crate::api::ShellApi;
use crate::events::{Envelope, Notification, ShellAction};

/// Batching window of `event` messages.
pub const BATCH_WINDOW: Duration = Duration::from_millis(100);
/// A batch is flushed early when it holds this many events.
pub const BATCH_MAX: usize = 50;

/// What the pump needs from the host (implemented by the Tauri glue; a recorder in tests).
pub trait UiSink: Send + Sync + 'static {
    /// Emit a `daemon-event` to the webview.
    fn emit(&self, envelope: &Envelope);
    /// `show()` + `set_focus()` the main window.
    fn show_window(&self);
    /// Show a toast (already filtered by `app.notifications`).
    fn notify(&self, notification: &Notification);
    /// The tray may have changed; recompute it (called at most once per batch window).
    fn tray_changed(&self);
}

/// Collects `event` payload arrays and releases them as one envelope.
#[derive(Debug, Default)]
pub struct EventBatcher {
    pending: Vec<Value>,
}

impl EventBatcher {
    /// Adds the events of an `event` envelope. Returns a full batch when [`BATCH_MAX`] is reached.
    pub fn push(&mut self, payload: Value) -> Option<Envelope> {
        match payload {
            Value::Array(items) => self.pending.extend(items),
            other => self.pending.push(other),
        }
        (self.pending.len() >= BATCH_MAX).then(|| self.take()).flatten()
    }

    /// Releases everything collected so far.
    pub fn take(&mut self) -> Option<Envelope> {
        if self.pending.is_empty() {
            return None;
        }
        Some(Envelope::new(
            "event",
            Value::Array(std::mem::take(&mut self.pending)),
        ))
    }

    /// Number of events waiting.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// `true` if nothing waits.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

struct Pump {
    api: Arc<ShellApi>,
    sink: Arc<dyn UiSink>,
    batcher: EventBatcher,
    tray_dirty: bool,
}

impl Pump {
    fn flush(&mut self) {
        if let Some(env) = self.batcher.take() {
            self.sink.emit(&env);
        }
    }

    async fn handle(&mut self, ev: DaemonEvent) {
        for action in self.api.process(ev).await {
            match action {
                ShellAction::Emit(env) if env.kind == "event" => {
                    if let Some(full) = self.batcher.push(env.payload) {
                        self.sink.emit(&full);
                    }
                }
                ShellAction::Emit(env) => {
                    // keep the daemon's order: batched events first
                    self.flush();
                    self.sink.emit(&env);
                }
                ShellAction::ShowWindow => {
                    self.flush();
                    self.sink.show_window();
                }
                ShellAction::Notify(n) => {
                    if self.api.notifications_enabled() {
                        self.sink.notify(&n);
                    }
                }
                ShellAction::RefreshTray => self.tray_dirty = true,
            }
        }
    }

    fn tick(&mut self) {
        self.flush();
        if self.tray_dirty {
            self.tray_dirty = false;
            self.sink.tray_changed();
        }
    }
}

/// Runs until the daemon's event channel closes. Spawn it on the daemon's runtime
/// (`DaemonHandle::runtime().spawn(..)`) or any tokio runtime.
pub async fn run_event_pump(
    api: Arc<ShellApi>,
    mut rx: broadcast::Receiver<DaemonEvent>,
    sink: Arc<dyn UiSink>,
) {
    run_event_pump_with(api, &mut rx, sink, BATCH_WINDOW).await;
}

/// [`run_event_pump`] with an explicit batch window (tests).
pub async fn run_event_pump_with(
    api: Arc<ShellApi>,
    rx: &mut broadcast::Receiver<DaemonEvent>,
    sink: Arc<dyn UiSink>,
    window: Duration,
) {
    let mut pump = Pump {
        api,
        sink,
        batcher: EventBatcher::default(),
        tray_dirty: true, // build the tray once at start
    };
    let mut ticker = tokio::time::interval(window);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Ok(ev) => pump.handle(ev).await,
                Err(RecvError::Lagged(missed)) => {
                    // the UI missed `missed` events; it re-reads state on the next user action
                    tracing::warn!(missed, "the event pump lagged behind the daemon");
                    pump.tray_dirty = true;
                }
                Err(RecvError::Closed) => {
                    pump.tick();
                    return;
                }
            },
            _ = ticker.tick() => pump.tick(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_batcher_merges_arrays_and_releases_them_once() {
        let mut b = EventBatcher::default();
        assert!(b.is_empty());
        assert!(b.push(json!([{"seq": 1}, {"seq": 2}])).is_none());
        assert!(b.push(json!({"seq": 3})).is_none());
        assert_eq!(b.len(), 3);
        let env = b.take().unwrap();
        assert_eq!(env.kind, "event");
        assert_eq!(env.payload, json!([{"seq": 1}, {"seq": 2}, {"seq": 3}]));
        assert!(b.take().is_none());
    }

    #[test]
    fn a_full_batch_is_released_early() {
        let mut b = EventBatcher::default();
        let mut released = None;
        for i in 0..BATCH_MAX {
            released = b.push(json!([{"seq": i}]));
        }
        let env = released.unwrap();
        assert_eq!(env.payload.as_array().unwrap().len(), BATCH_MAX);
        assert!(b.is_empty());
    }
}
