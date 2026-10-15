//! Single writer task around rusqlite.
//!
//! All writes run on **one** dedicated thread that owns the writer [`Connection`]; callers send closures and wait for the
//! result. That serialises every transition (the approval "conditional UPDATE" included) without a lock around the
//! connection, and a panic inside a job is caught at the job boundary: the open transaction is rolled back when its
//! [`rusqlite::Transaction`] is dropped during unwinding, the caller gets [`StoreError::Panicked`] and the worker keeps
//! serving.
//!
//! The thread exits when the last [`Worker`] handle is dropped.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::thread::JoinHandle;

use rusqlite::Connection;

use super::StoreError;

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// Handle to the writer thread.
pub(crate) struct Worker {
    tx: Option<mpsc::Sender<Job>>,
    handle: Option<JoinHandle<()>>,
}

impl Worker {
    /// Starts the writer thread with `conn`.
    pub(crate) fn spawn(mut conn: Connection) -> Result<Self, StoreError> {
        let (tx, rx) = mpsc::channel::<Job>();
        let handle = std::thread::Builder::new()
            .name("agentnest-store-writer".to_owned())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    job(&mut conn);
                }
            })?;
        Ok(Self {
            tx: Some(tx),
            handle: Some(handle),
        })
    }

    /// Runs `f` on the writer thread and returns its result.
    pub(crate) fn run<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let (rtx, rrx) = mpsc::sync_channel::<Result<T, StoreError>>(1);
        let job: Job = Box::new(move |conn: &mut Connection| {
            let outcome = match catch_unwind(AssertUnwindSafe(|| f(conn))) {
                Ok(r) => r,
                Err(payload) => {
                    // A transaction that was open during the panic has been rolled back by its Drop. A synchronous=FULL
                    // transaction may have left the pragma raised; put it back.
                    let _ = conn.pragma_update(None, "synchronous", "NORMAL");
                    Err(StoreError::Panicked(panic_message(payload.as_ref())))
                }
            };
            let _ = rtx.send(outcome);
        });
        let tx = self.tx.as_ref().ok_or(StoreError::WorkerGone)?;
        tx.send(job).map_err(|_| StoreError::WorkerGone)?;
        rrx.recv().map_err(|_| StoreError::WorkerGone)?
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Closing the channel ends the loop; joining makes sure the connection is closed before the handle disappears
        // (important for temp-file databases in tests).
        self.tx.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_run_in_order_on_one_thread() {
        let w = Worker::spawn(Connection::open_in_memory().unwrap()).unwrap();
        w.run(|c| Ok(c.execute_batch("CREATE TABLE t(x INTEGER)")?))
            .unwrap();
        for i in 0..50 {
            w.run(move |c| Ok(c.execute("INSERT INTO t VALUES (?1)", [i])?))
                .unwrap();
        }
        let sum: i64 = w
            .run(|c| Ok(c.query_row("SELECT SUM(x) FROM t", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(sum, (0..50).sum::<i64>());
    }

    #[test]
    fn a_panicking_job_rolls_back_and_the_worker_survives() {
        let w = Worker::spawn(Connection::open_in_memory().unwrap()).unwrap();
        w.run(|c| Ok(c.execute_batch("CREATE TABLE t(x INTEGER)")?))
            .unwrap();
        let r: Result<(), _> = w.run(|c| {
            let tx = c.transaction()?;
            tx.execute("INSERT INTO t VALUES (1)", [])?;
            panic!("boom in the middle of a transaction");
        });
        assert!(
            matches!(r, Err(StoreError::Panicked(ref m)) if m.contains("boom")),
            "{r:?}"
        );
        let n: i64 = w
            .run(|c| Ok(c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(n, 0, "the panic must roll the transaction back");
        let sync: i64 = w
            .run(|c| Ok(c.query_row("PRAGMA synchronous", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(sync, 1, "synchronous is back to NORMAL after a panic");
    }

    #[test]
    fn errors_are_returned_not_swallowed() {
        let w = Worker::spawn(Connection::open_in_memory().unwrap()).unwrap();
        let r: Result<(), _> = w.run(|c| Ok(c.execute_batch("THIS IS NOT SQL")?));
        assert!(matches!(r, Err(StoreError::Sqlite(_))));
    }
}
