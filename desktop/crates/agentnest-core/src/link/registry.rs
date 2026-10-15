//! Connection registry: one authenticated connection per device, the live fan-out of replayable messages and the
//! "kick" used by revocation (docs/protocol.md 8.2, docs/security.md I6).
//!
//! The registry knows nothing about sockets. A connection task registers an `mpsc` sender; everything the daemon wants
//! to tell a specific phone goes through [`ConnCommand`]s, everything replayable (`event`, `session_state`,
//! `approval_request`, `approval_resolved`, `adapter_status`) goes through the [`Published`] broadcast that every
//! authenticated connection follows.
//!
//! Presence (how many authenticated phones are online) is a `watch` value; the approval broker uses it for the "no
//! online device -> hand off locally" rule and the 10 s reconnect grace.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agentnest_protocol::{ByeReason, Message};
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, watch};

/// A replayable message that was appended to the stream and is now being broadcast.
#[derive(Clone, Debug)]
pub struct Published {
    /// PC-global sequence number.
    pub seq: i64,
    /// `event`, `session_state`, `approval_request`, `approval_resolved` or `adapter_status`.
    pub msg_type: String,
    /// The wire payload.
    pub payload: Value,
    /// `approval_request` only.
    pub expires_at: Option<String>,
}

/// What the daemon asks a connection task to do.
#[derive(Debug)]
pub enum ConnCommand {
    /// Send a non-replayable message (`decision_result`, `hosts_update`, `error`, ...).
    Send(Message),
    /// Send `bye` and close with `close_code`.
    Bye {
        /// Reason.
        reason: ByeReason,
        /// Whether the phone should reconnect.
        reconnect: bool,
        /// Korean text.
        message_ko: String,
        /// WebSocket close code.
        close_code: u16,
    },
    /// Close the socket silently with this code.
    Close {
        /// WebSocket close code.
        code: u16,
    },
}

struct ConnEntry {
    conn_id: u64,
    tx: mpsc::UnboundedSender<ConnCommand>,
}

/// The registry. Share it as `Arc<Registry>`.
pub struct Registry {
    stream_tx: broadcast::Sender<Arc<Published>>,
    conns: Mutex<HashMap<String, ConnEntry>>,
    online_tx: watch::Sender<usize>,
    next_conn_id: AtomicU64,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("online", &self.online_count())
            .finish_non_exhaustive()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        let (stream_tx, _) = broadcast::channel(4096);
        let (online_tx, _) = watch::channel(0usize);
        Self {
            stream_tx,
            conns: Mutex::new(HashMap::new()),
            online_tx,
            next_conn_id: AtomicU64::new(1),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ConnEntry>> {
        self.conns.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A receiver of the live replayable stream. Subscribe **before** computing a replay so nothing is missed.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Published>> {
        self.stream_tx.subscribe()
    }

    /// Broadcasts a message that was just appended to the stream.
    pub fn broadcast(&self, published: Published) {
        let _ = self.stream_tx.send(Arc::new(published));
    }

    /// A receiver of the number of online authenticated devices.
    pub fn presence(&self) -> watch::Receiver<usize> {
        self.online_tx.subscribe()
    }

    /// Registers the authenticated connection of `device_id`. An earlier connection of the same device is told to go
    /// away (`bye{superseded_connection}`, 4009). Returns the connection id for [`Registry::unregister`].
    pub fn register(&self, device_id: &str, tx: mpsc::UnboundedSender<ConnCommand>) -> u64 {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (previous, count) = {
            let mut g = self.lock();
            let previous = g.insert(device_id.to_owned(), ConnEntry { conn_id, tx });
            (previous, g.len())
        };
        if let Some(prev) = previous {
            let _ = prev.tx.send(ConnCommand::Bye {
                reason: ByeReason::SupersededConnection,
                reconnect: true,
                message_ko: "다른 연결로 대체되었어요.".to_owned(),
                close_code: 4009,
            });
        }
        self.online_tx.send_replace(count);
        conn_id
    }

    /// Removes the connection, but only if it is still the registered one (a superseded connection must not remove its
    /// replacement). Returns `true` if the device went offline.
    pub fn unregister(&self, device_id: &str, conn_id: u64) -> bool {
        let (removed, count) = {
            let mut g = self.lock();
            let is_current = g.get(device_id).is_some_and(|e| e.conn_id == conn_id);
            if is_current {
                g.remove(device_id);
            }
            (is_current, g.len())
        };
        if removed {
            self.online_tx.send_replace(count);
        }
        removed
    }

    /// Number of online authenticated devices.
    pub fn online_count(&self) -> usize {
        self.lock().len()
    }

    /// Ids of the online devices.
    pub fn online_devices(&self) -> Vec<String> {
        let mut v: Vec<String> = self.lock().keys().cloned().collect();
        v.sort();
        v
    }

    /// `true` if `device_id` has an authenticated connection.
    pub fn is_online(&self, device_id: &str) -> bool {
        self.lock().contains_key(device_id)
    }

    /// Sends a command to one device. Returns `false` if it is not online.
    pub fn send_to(&self, device_id: &str, cmd: ConnCommand) -> bool {
        let g = self.lock();
        match g.get(device_id) {
            Some(e) => e.tx.send(cmd).is_ok(),
            None => false,
        }
    }

    /// Sends a command to every online device built by `make`. Returns how many devices were reached.
    pub fn send_all(&self, make: impl Fn() -> ConnCommand) -> usize {
        let g = self.lock();
        g.values().filter(|e| e.tx.send(make()).is_ok()).count()
    }

    /// Kicks a revoked device: `bye{device_revoked}` and close 4003, and removes it from the registry immediately
    /// (so it counts as offline from this moment on, I6). Returns `true` if it was online.
    pub fn kick_revoked(&self, device_id: &str) -> bool {
        let (entry, count) = {
            let mut g = self.lock();
            let e = g.remove(device_id);
            (e, g.len())
        };
        match entry {
            Some(e) => {
                let _ = e.tx.send(ConnCommand::Bye {
                    reason: ByeReason::DeviceRevoked,
                    reconnect: false,
                    message_ko: "PC에서 이 기기의 연결을 해제했어요.".to_owned(),
                    close_code: 4003,
                });
                self.online_tx.send_replace(count);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_unregister_and_presence() {
        let reg = Registry::new();
        let presence = reg.presence();
        assert_eq!(reg.online_count(), 0);
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let c1 = reg.register("dev_a", tx1);
        assert_eq!(*presence.borrow(), 1);
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let c2 = reg.register("dev_b", tx2);
        assert_eq!(*presence.borrow(), 2);
        assert_eq!(reg.online_devices(), vec!["dev_a", "dev_b"]);
        assert!(reg.is_online("dev_a"));
        assert!(reg.unregister("dev_a", c1));
        assert!(!reg.unregister("dev_a", c1), "second removal is a no-op");
        assert_eq!(*presence.borrow(), 1);
        assert!(reg.unregister("dev_b", c2));
        assert_eq!(*presence.borrow(), 0);
    }

    #[test]
    fn a_new_connection_of_the_same_device_supersedes_the_old_one() {
        let reg = Registry::new();
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let c1 = reg.register("dev_a", tx1);
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let c2 = reg.register("dev_a", tx2);
        assert_ne!(c1, c2);
        assert_eq!(reg.online_count(), 1);
        match rx1.try_recv().unwrap() {
            ConnCommand::Bye {
                reason,
                close_code,
                reconnect,
                ..
            } => {
                assert_eq!(reason, ByeReason::SupersededConnection);
                assert_eq!(close_code, 4009);
                assert!(reconnect);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(rx2.try_recv().is_err());
        // the old connection ending must not remove the new one
        assert!(!reg.unregister("dev_a", c1));
        assert!(reg.is_online("dev_a"));
        assert!(reg.unregister("dev_a", c2));
    }

    #[test]
    fn kick_revoked_sends_bye_4003_and_goes_offline_at_once() {
        let reg = Registry::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let c = reg.register("dev_a", tx);
        assert!(reg.kick_revoked("dev_a"));
        assert!(!reg.is_online("dev_a"));
        assert_eq!(*reg.presence().borrow(), 0);
        match rx.try_recv().unwrap() {
            ConnCommand::Bye {
                reason,
                close_code,
                reconnect,
                ..
            } => {
                assert_eq!(reason, ByeReason::DeviceRevoked);
                assert_eq!(close_code, 4003);
                assert!(!reconnect);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(!reg.kick_revoked("dev_a"));
        assert!(!reg.unregister("dev_a", c));
    }

    #[test]
    fn send_to_and_send_all_reach_only_online_devices() {
        let reg = Registry::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        reg.register("dev_a", tx);
        assert!(reg.send_to("dev_a", ConnCommand::Close { code: 1000 }));
        assert!(!reg.send_to("dev_x", ConnCommand::Close { code: 1000 }));
        assert!(matches!(
            rx.try_recv().unwrap(),
            ConnCommand::Close { code: 1000 }
        ));
        assert_eq!(reg.send_all(|| ConnCommand::Close { code: 1001 }), 1);
    }

    #[tokio::test]
    async fn broadcast_reaches_every_subscriber() {
        let reg = Registry::new();
        let mut a = reg.subscribe();
        let mut b = reg.subscribe();
        reg.broadcast(Published {
            seq: 7,
            msg_type: "event".into(),
            payload: serde_json::json!({"x": 1}),
            expires_at: None,
        });
        assert_eq!(a.recv().await.unwrap().seq, 7);
        assert_eq!(b.recv().await.unwrap().seq, 7);
    }
}
