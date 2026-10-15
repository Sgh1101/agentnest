//! rusqlite single-writer worker, migrations, retention.
//!
//! # Shape
//!
//! [`Store`] is a cheap `Clone + Send + Sync` handle. All writes go through one writer thread ([`worker`]); reads use up
//! to two read-only connections (file databases) so snapshot queries do not queue behind writes. Every method is
//! synchronous: from async code call it inside `tokio::task::spawn_blocking`, or use [`Store::run_blocking`].
//!
//! # Durability and the approval transitions (docs/storage.md header and section 2)
//!
//! Connections use `journal_mode=WAL; synchronous=NORMAL; foreign_keys=ON; busy_timeout=5000`. Every transaction that
//! changes an approval, inserts a decision, an approval audit row or an audit log row runs with
//! `synchronous=FULL`: the pragma is raised **before** `BEGIN` (it has no effect inside a transaction), the
//! transaction commits, then the pragma returns to `NORMAL` ([`with_full_sync`]). The adapter reply goes out only
//! after that commit, so "the reply was sent but no decision was recorded" cannot happen.
//!
//! # What is here
//!
//! * [`approvals`]: `insert_approval` (with the 2 s duplicate merge), `resolve_approval_conditional` (the single
//!   conditional `UPDATE ... WHERE status='pending' AND expires_at > ?`), `expire_due`,
//!   `expire_all_pending_on_startup`, `close_approval`, decisions, approval audit, audit log.
//! * [`stream`]: `append_event`, `stream_append`, `stream_replay_since`, `plan_resync`, `events_page`, snapshot helpers.
//! * [`sessions`]: projects, sessions, adapter state, review findings, settings.
//! * [`retention`]: the retention job (storage.md 3).
//!
//! Tables of other modules (`pc_identity`, `devices`, `pairings`) are reached with [`Store::run`] / [`Store::read`].

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags, Transaction};
use thiserror::Error;

pub mod approvals;
pub mod migrations;
pub mod retention;
pub mod sessions;
pub mod stream;
pub mod worker;

pub use approvals::*;
pub use retention::{RetentionConfig, RetentionReport};
pub use sessions::*;
pub use stream::*;

use worker::Worker;

/// Errors of the store. Messages never contain row values.
#[derive(Debug, Error)]
pub enum StoreError {
    /// SQLite reported an error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A migration failed.
    #[error("migration error: {0}")]
    Migration(#[from] rusqlite_migration::Error),
    /// JSON (de)serialisation failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// File system error while opening the database.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The writer thread has stopped.
    #[error("the store worker is gone")]
    WorkerGone,
    /// A job panicked (its transaction was rolled back).
    #[error("a store job panicked: {0}")]
    Panicked(String),
    /// The caller passed something that cannot be stored.
    #[error("invalid input: {0}")]
    Invalid(String),
}

/// `true` if the error is a SQLite constraint violation (unique, primary key, check, foreign key).
pub fn is_constraint_violation(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

/// Options for [`Store::open_with`].
#[derive(Clone, Copy, Debug)]
pub struct StoreOptions {
    /// Number of read-only connections (file databases only). `0` routes reads through the writer.
    pub readers: usize,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self { readers: 2 }
    }
}

struct Inner {
    worker: Worker,
    readers: Vec<Mutex<Connection>>,
    next_reader: AtomicUsize,
    path: Option<PathBuf>,
}

/// Handle to the database. Clone it freely.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.inner.path)
            .finish_non_exhaustive()
    }
}

fn apply_pragmas(conn: &Connection) -> Result<(), StoreError> {
    // `journal_mode` returns a row, so it cannot go through `pragma_update`.
    let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    Ok(())
}

impl Store {
    /// Opens (and migrates) the database file with two read connections.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with(path, StoreOptions::default())
    }

    /// Opens (and migrates) the database file.
    pub fn open_with(path: &Path, options: StoreOptions) -> Result<Self, StoreError> {
        restrict_db_file(path)?;
        let mut conn = Connection::open(path)?;
        apply_pragmas(&conn)?;
        migrations::migrate(&mut conn)?;
        // SQLite gives `-wal` / `-shm` the mode of the main file, so they are user-only too
        let mut readers = Vec::new();
        for _ in 0..options.readers {
            let r = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            r.pragma_update(None, "busy_timeout", 5000)?;
            readers.push(Mutex::new(r));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                worker: Worker::spawn(conn)?,
                readers,
                next_reader: AtomicUsize::new(0),
                path: Some(path.to_owned()),
            }),
        })
    }

    /// An in-memory database (tests, dry runs). Reads go through the writer.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let mut conn = Connection::open_in_memory()?;
        apply_pragmas(&conn)?;
        migrations::migrate(&mut conn)?;
        Ok(Self {
            inner: Arc::new(Inner {
                worker: Worker::spawn(conn)?,
                readers: Vec::new(),
                next_reader: AtomicUsize::new(0),
                path: None,
            }),
        })
    }

    /// The database file, if any.
    pub fn path(&self) -> Option<&Path> {
        self.inner.path.as_deref()
    }

    /// Runs `f` on the writer thread. Use it for anything the typed methods do not cover (`devices`, `pairings`,
    /// `pc_identity`). A panic in `f` rolls back its transaction and returns [`StoreError::Panicked`].
    pub fn run<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        self.inner.worker.run(f)
    }

    /// Runs a read-only closure on a read connection (or on the writer for in-memory databases).
    pub fn read<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    {
        if self.inner.readers.is_empty() {
            return self.inner.worker.run(move |c| f(c));
        }
        let idx = self.inner.next_reader.fetch_add(1, Ordering::Relaxed) % self.inner.readers.len();
        let guard = self.inner.readers[idx]
            .lock()
            .map_err(|_| StoreError::Panicked("a read connection was poisoned".to_owned()))?;
        // Reads are small; a panic would poison the mutex, which is reported above on the next call.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&guard)))
            .unwrap_or_else(|_| Err(StoreError::Panicked("a read job panicked".to_owned())))
    }

    /// [`Store::run`] from async code.
    pub async fn run_blocking<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.run(f))
            .await
            .map_err(|e| StoreError::Panicked(e.to_string()))?
    }

    /// The current `PRAGMA synchronous` of the writer (0 OFF, 1 NORMAL, 2 FULL).
    pub fn pragma_synchronous(&self) -> Result<i64, StoreError> {
        self.run(|c| Ok(c.query_row("PRAGMA synchronous", [], |r| r.get(0))?))
    }

    /// Forces a WAL checkpoint (`TRUNCATE`); the weekly maintenance step of storage.md 3.
    pub fn wal_checkpoint(&self) -> Result<(), StoreError> {
        self.run(|c| {
            c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
            Ok(())
        })
    }

    /// `VACUUM`; the monthly maintenance step of storage.md 3 (call when idle).
    pub fn vacuum(&self) -> Result<(), StoreError> {
        self.run(|c| Ok(c.execute_batch("VACUUM")?))
    }
}

/// On Unix the database (decision evidence, device hashes, approval details) is readable by the owner only: the file is
/// created with `0600` before SQLite opens it (SQLite would use the umask, usually `0644`) and an existing file is
/// tightened. On Windows the per-user data directory ACL applies (docs/security.md R1).
fn restrict_db_file(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Err(e) => return Err(StoreError::Io(e)),
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Runs `f` inside a transaction that commits with `synchronous=FULL`, then restores `NORMAL`.
///
/// The pragma is set before `BEGIN`: SQLite ignores `PRAGMA synchronous` inside a transaction.
///
/// **What the return value says.** `Ok` means exactly "the transaction committed". Failing to put `synchronous` back to
/// `NORMAL` afterwards does *not* turn a committed transaction into an error (the caller would report "not applied"
/// for a decision that is durably recorded): the failure is logged and the connection simply stays on `FULL`, which is
/// slower but never less durable.
pub fn with_full_sync<T>(
    conn: &mut Connection,
    f: impl FnOnce(&Transaction<'_>) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    with_full_sync_restoring(conn, f, |c| c.pragma_update(None, "synchronous", "NORMAL"))
}

fn with_full_sync_restoring<T>(
    conn: &mut Connection,
    f: impl FnOnce(&Transaction<'_>) -> Result<T, StoreError>,
    restore: impl FnOnce(&Connection) -> rusqlite::Result<()>,
) -> Result<T, StoreError> {
    conn.pragma_update(None, "synchronous", "FULL")?;
    let result = (|| {
        let tx = conn.transaction()?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok::<T, StoreError>(value)
    })();
    if let Err(e) = restore(conn) {
        tracing::warn!(
            error = %e,
            committed = result.is_ok(),
            "could not restore synchronous=NORMAL; the connection stays on FULL"
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_sync_is_raised_inside_and_restored_after() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_pragmas(&conn).unwrap();
        let before: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, 1);
        let inside = with_full_sync(&mut conn, |tx| {
            Ok(tx.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))?)
        })
        .unwrap();
        assert_eq!(inside, 2, "FULL while the transaction runs");
        let after: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, 1, "NORMAL again after the commit");
        // also after a failing transaction
        let r: Result<(), _> = with_full_sync(&mut conn, |_| Err(StoreError::Invalid("x".into())));
        assert!(r.is_err());
        let after: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, 1);
    }

    #[test]
    fn a_failed_pragma_restore_does_not_undo_a_committed_transaction() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_pragmas(&conn).unwrap();
        conn.execute_batch("CREATE TABLE t(x INTEGER)").unwrap();
        let committed = with_full_sync_restoring(
            &mut conn,
            |tx| {
                tx.execute("INSERT INTO t VALUES (1)", [])?;
                Ok("done")
            },
            |_| Err(rusqlite::Error::InvalidQuery),
        );
        assert_eq!(committed.unwrap(), "done", "the commit is what is reported");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "and it is really there");
        // a failing transaction is still an error, restore failure or not
        let failed: Result<(), _> = with_full_sync_restoring(
            &mut conn,
            |_| Err(StoreError::Invalid("x".into())),
            |_| Err(rusqlite::Error::InvalidQuery),
        );
        assert!(failed.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn database_files_are_user_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agentnest.db");
        let store = Store::open(&path).unwrap();
        store
            .run(|c| {
                c.execute_batch(
                    "CREATE TABLE IF NOT EXISTS probe(x); INSERT INTO probe VALUES (1);",
                )?;
                Ok(())
            })
            .unwrap();
        for name in ["agentnest.db", "agentnest.db-wal", "agentnest.db-shm"] {
            let p = dir.path().join(name);
            if let Ok(m) = std::fs::metadata(&p) {
                assert_eq!(m.permissions().mode() & 0o777, 0o600, "{name}");
            }
        }
        assert!(
            dir.path().join("agentnest.db-wal").exists(),
            "WAL mode is on"
        );
        drop(store);
        // an existing, world readable file is tightened on the next open
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _again = Store::open(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn pragmas_are_applied_to_file_databases() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("agentnest.db")).unwrap();
        let (journal, fk, busy, sync) = store
            .run(|c| {
                Ok((
                    c.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))?,
                    c.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))?,
                    c.query_row("PRAGMA busy_timeout", [], |r| r.get::<_, i64>(0))?,
                    c.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))?,
                ))
            })
            .unwrap();
        assert_eq!(journal, "wal");
        assert_eq!(fk, 1);
        assert_eq!(busy, 5000);
        assert_eq!(sync, 1);
        // reads work through the read connections and see committed writes
        store
            .run(|c| {
                Ok(c.execute(
                    "INSERT INTO settings(key,value_json,updated_at) VALUES ('k','1','t')",
                    [],
                )?)
            })
            .unwrap();
        let n: i64 = store
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM settings", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(n, 1);
        // a read connection cannot write
        let w = store.read(|c| Ok(c.execute("DELETE FROM settings", [])?));
        assert!(w.is_err(), "read connections are read-only");
    }

    #[test]
    fn in_memory_store_works_and_clones_share_state() {
        let s = Store::open_in_memory().unwrap();
        let s2 = s.clone();
        s.run(|c| {
            Ok(c.execute(
                "INSERT INTO settings(key,value_json,updated_at) VALUES ('a','1','t')",
                [],
            )?)
        })
        .unwrap();
        let n: i64 = s2
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM settings", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(n, 1);
        assert!(s.path().is_none());
    }

    #[tokio::test]
    async fn run_blocking_works_from_async_code() {
        let s = Store::open_in_memory().unwrap();
        let n: i64 = s
            .run_blocking(|c| Ok(c.query_row("SELECT 41 + 1", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(n, 42);
    }

    #[test]
    fn maintenance_calls_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("m.db")).unwrap();
        s.wal_checkpoint().unwrap();
        s.vacuum().unwrap();
    }
}
