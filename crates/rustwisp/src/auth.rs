//! Password hashing off the worker threads. A bcrypt check takes tens to hundreds of milliseconds,
//! which would stall every connection on the worker that ran it, so hashed secrets are checked by a
//! small pool and the answer comes back through the worker's mailbox.
//!
//! The queue is bounded. When it is full, new checks are refused instead of piling up.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};

use crate::dns::Mailbox;
use crate::password;

/// Checks waiting for a thread before new ones are refused.
const QUEUE: usize = 64;

/// The outcome of one check.
#[derive(Debug)]
pub(crate) struct AuthDone {
    pub conn: u64,
    /// Matches the id `submit` returned, so a late answer for a recycled connection is ignored.
    pub id: u64,
    pub ok: bool,
}

struct Job {
    mailbox: Arc<Mailbox>,
    conn: u64,
    id: u64,
    secret: String,
    pass: Vec<u8>,
    /// The name was unknown: do the work anyway so the answer takes as long as a real one, then say no.
    force_fail: bool,
}

#[derive(Debug)]
pub(crate) struct AuthPool {
    tx: SyncSender<Job>,
    /// Keeps the queue open even when no thread drains it.
    _rx: Arc<Mutex<Receiver<Job>>>,
    next_id: AtomicU64,
}

fn worker_loop(rx: Arc<Mutex<Receiver<Job>>>) {
    loop {
        let job = {
            let Ok(guard) = rx.lock() else { return };
            match guard.recv() {
                Ok(j) => j,
                Err(_) => return,
            }
        };
        let matched = password::verify_hash(&job.secret, &job.pass);
        job.mailbox.post_auth(AuthDone {
            conn: job.conn,
            id: job.id,
            ok: matched && !job.force_fail,
        });
    }
}

impl AuthPool {
    /// `threads` of 0 starts no threads; use that when no hashed secrets are configured.
    pub(crate) fn new(threads: usize) -> AuthPool {
        let (tx, rx) = sync_channel::<Job>(QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..threads {
            let rx = Arc::clone(&rx);
            let _ = std::thread::Builder::new()
                .name(format!("hw-auth-{i}"))
                .spawn(move || worker_loop(rx));
        }
        AuthPool {
            tx,
            _rx: rx,
            next_id: AtomicU64::new(1),
        }
    }

    /// Queue a check. `None` means the queue is full (or the pool is gone) and the caller should
    /// treat the login as failed.
    pub(crate) fn submit(
        &self,
        mailbox: &Arc<Mailbox>,
        conn: u64,
        secret: &str,
        pass: &[u8],
        force_fail: bool,
    ) -> Option<u64> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let job = Job {
            mailbox: Arc::clone(mailbox),
            conn,
            id,
            secret: secret.to_string(),
            pass: pass.to_vec(),
            force_fail,
        };
        match self.tx.try_send(job) {
            Ok(()) => Some(id),
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const SHA512: &str = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";

    fn wait_for(mb: &Mailbox, want: usize) -> Vec<AuthDone> {
        let mut got = Vec::new();
        for _ in 0..500 {
            got.extend(mb.take_auth());
            if got.len() >= want {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        got
    }

    #[test]
    fn answers_come_back_through_the_mailbox() {
        let mb = Mailbox::new().unwrap();
        let pool = AuthPool::new(2);
        let good = pool.submit(&mb, 7, SHA512, b"Hello world!", false).unwrap();
        let bad = pool.submit(&mb, 7, SHA512, b"nope", false).unwrap();
        let unknown = pool.submit(&mb, 7, SHA512, b"Hello world!", true).unwrap();
        let mut got = wait_for(&mb, 3);
        got.sort_by_key(|d| d.id);
        assert_eq!(got.len(), 3);
        assert_eq!((got[0].id, got[0].ok), (good, true));
        assert_eq!((got[1].id, got[1].ok), (bad, false));
        assert_eq!(
            (got[2].id, got[2].ok),
            (unknown, false),
            "unknown names always fail"
        );
        assert!(got.iter().all(|d| d.conn == 7));
    }

    #[test]
    fn a_full_queue_refuses_instead_of_growing() {
        let mb = Mailbox::new().unwrap();
        let pool = AuthPool::new(0); // nothing drains the queue
        let accepted = (0..QUEUE + 10)
            .filter(|_| pool.submit(&mb, 1, SHA512, b"x", false).is_some())
            .count();
        assert_eq!(accepted, QUEUE);
    }
}
