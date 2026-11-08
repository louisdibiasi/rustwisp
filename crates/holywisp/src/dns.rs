//! Name resolution off the worker threads: a small pool runs the system resolver and hands the
//! answer back through the worker's mailbox. Answers are cached for `dns-ttl-s` (failures for
//! `dns-negative-ttl-s`). Policy is never applied here: the worker checks the resolved addresses
//! and connects to the very same ones.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use holywisp_config::DnsOrder;

use crate::auth::AuthDone;
use crate::sys;

#[derive(Debug)]
pub(crate) struct DnsDone {
    pub conn: u64,
    pub sid: u32,
    pub serial: u32,
    /// `Err(())` is "does not resolve".
    pub addrs: Result<Vec<IpAddr>, ()>,
}

/// Where a worker receives finished lookups.
#[derive(Debug)]
pub(crate) struct Mailbox {
    queue: Mutex<Vec<DnsDone>>,
    auth: Mutex<Vec<AuthDone>>,
    wake: OwnedFd,
}

impl Mailbox {
    pub(crate) fn new() -> std::io::Result<Arc<Mailbox>> {
        Ok(Arc::new(Mailbox {
            queue: Mutex::new(Vec::new()),
            auth: Mutex::new(Vec::new()),
            wake: sys::wake_fd()?,
        }))
    }

    pub(crate) fn wake_fd_clone(&self) -> std::io::Result<OwnedFd> {
        self.wake.try_clone()
    }

    pub(crate) fn post(&self, done: DnsDone) {
        if let Ok(mut q) = self.queue.lock() {
            q.push(done);
        }
        sys::wake(&self.wake);
    }

    pub(crate) fn take(&self) -> Vec<DnsDone> {
        self.queue
            .lock()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default()
    }

    pub(crate) fn post_auth(&self, done: AuthDone) {
        if let Ok(mut q) = self.auth.lock() {
            q.push(done);
        }
        sys::wake(&self.wake);
    }

    pub(crate) fn take_auth(&self) -> Vec<AuthDone> {
        self.auth
            .lock()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default()
    }

    /// Wake the worker (used to stop it).
    pub(crate) fn poke(&self) {
        sys::wake(&self.wake);
    }
}

struct Job {
    host: String,
    mailbox: Arc<Mailbox>,
    conn: u64,
    sid: u32,
    serial: u32,
}

type CacheMap = HashMap<String, (Instant, Result<Vec<IpAddr>, ()>)>;

#[derive(Debug)]
struct Cache {
    map: Mutex<CacheMap>,
    ttl: Duration,
    negative_ttl: Duration,
    entries: AtomicU64,
}

#[derive(Debug)]
pub(crate) struct Resolver {
    tx: Mutex<Sender<Job>>,
    cache: Arc<Cache>,
}

fn order_addrs(mut addrs: Vec<IpAddr>, order: DnsOrder) -> Vec<IpAddr> {
    match order {
        DnsOrder::Ipv4First => addrs.sort_by_key(IpAddr::is_ipv6),
        DnsOrder::Ipv6First => addrs.sort_by_key(IpAddr::is_ipv4),
        DnsOrder::Verbatim => {}
    }
    addrs.dedup();
    addrs
}

fn lookup(host: &str, order: DnsOrder) -> Result<Vec<IpAddr>, ()> {
    let found: Vec<IpAddr> = (host, 0u16)
        .to_socket_addrs()
        .map_err(|_| ())?
        .map(|a| a.ip())
        .collect();
    if found.is_empty() {
        Err(())
    } else {
        Ok(order_addrs(found, order))
    }
}

fn worker_loop(rx: Arc<Mutex<Receiver<Job>>>, cache: Arc<Cache>, order: DnsOrder) {
    loop {
        let job = {
            let Ok(guard) = rx.lock() else { return };
            match guard.recv() {
                Ok(j) => j,
                Err(_) => return,
            }
        };
        let answer = lookup(&job.host, order);
        let ttl = if answer.is_ok() {
            cache.ttl
        } else {
            cache.negative_ttl
        };
        if !ttl.is_zero()
            && let Ok(mut map) = cache.map.lock()
        {
            map.insert(job.host.clone(), (Instant::now() + ttl, answer.clone()));
            cache.entries.store(map.len() as u64, Ordering::Relaxed);
        }
        job.mailbox.post(DnsDone {
            conn: job.conn,
            sid: job.sid,
            serial: job.serial,
            addrs: answer,
        });
    }
}

impl Resolver {
    pub(crate) fn new(threads: u32, ttl_s: u32, negative_ttl_s: u32, order: DnsOrder) -> Resolver {
        let (tx, rx) = channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        let cache = Arc::new(Cache {
            map: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(u64::from(ttl_s)),
            negative_ttl: Duration::from_secs(u64::from(negative_ttl_s)),
            entries: AtomicU64::new(0),
        });
        for i in 0..threads.max(1) {
            let rx = Arc::clone(&rx);
            let cache = Arc::clone(&cache);
            let _ = std::thread::Builder::new()
                .name(format!("hw-dns-{i}"))
                .spawn(move || worker_loop(rx, cache, order));
        }
        Resolver {
            tx: Mutex::new(tx),
            cache,
        }
    }

    pub(crate) fn cache_entries(&self) -> u64 {
        self.cache.entries.load(Ordering::Relaxed)
    }

    /// Drop expired cache entries. Called now and then by worker 0.
    pub(crate) fn expire(&self) {
        if let Ok(mut map) = self.cache.map.lock() {
            let now = Instant::now();
            map.retain(|_, (until, _)| *until > now);
            self.cache
                .entries
                .store(map.len() as u64, Ordering::Relaxed);
        }
    }

    /// Resolve `host`. A cached answer is posted straight away; otherwise a pool thread does it.
    pub(crate) fn submit(
        &self,
        host: &str,
        mailbox: &Arc<Mailbox>,
        conn: u64,
        sid: u32,
        serial: u32,
    ) {
        let key = holywisp_config::normalize_hostname(host);
        let hit = self.cache.map.lock().ok().and_then(|m| {
            m.get(&key)
                .filter(|(until, _)| *until > Instant::now())
                .map(|(_, a)| a.clone())
        });
        if let Some(addrs) = hit {
            mailbox.post(DnsDone {
                conn,
                sid,
                serial,
                addrs,
            });
            return;
        }
        let job = Job {
            host: key,
            mailbox: Arc::clone(mailbox),
            conn,
            sid,
            serial,
        };
        let sent = self
            .tx
            .lock()
            .map(|tx| tx.send(job).is_ok())
            .unwrap_or(false);
        if !sent {
            mailbox.post(DnsDone {
                conn,
                sid,
                serial,
                addrs: Err(()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_puts_the_preferred_family_first() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v6: IpAddr = "2001::1".parse().unwrap();
        assert_eq!(order_addrs(vec![v6, v4], DnsOrder::Ipv4First), vec![v4, v6]);
        assert_eq!(order_addrs(vec![v4, v6], DnsOrder::Ipv6First), vec![v6, v4]);
        assert_eq!(order_addrs(vec![v6, v4], DnsOrder::Verbatim), vec![v6, v4]);
    }

    #[test]
    fn localhost_resolves_and_is_cached() {
        let mb = Mailbox::new().unwrap();
        let r = Resolver::new(1, 60, 5, DnsOrder::Ipv4First);
        r.submit("localhost", &mb, 1, 2, 3);
        for _ in 0..200 {
            let got = mb.take();
            if let Some(d) = got.into_iter().next() {
                assert_eq!((d.conn, d.sid, d.serial), (1, 2, 3));
                assert!(d.addrs.unwrap().iter().any(|a| a.is_loopback()));
                r.submit("localhost", &mb, 1, 2, 4);
                let again = mb.take();
                assert_eq!(again.len(), 1, "second lookup answers from the cache");
                assert_eq!(again[0].serial, 4);
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no answer");
    }
}
