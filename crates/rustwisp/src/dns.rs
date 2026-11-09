//! Name resolution off the worker threads: a small pool runs the system resolver and hands the
//! answer back through the worker's mailbox. Answers are cached for `dns-ttl-s` (failures for
//! `dns-negative-ttl-s`). Policy is never applied here: the worker checks the resolved addresses
//! and connects to the very same ones.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustwisp_config::DnsOrder;

use crate::auth::AuthDone;
use crate::sys;

#[derive(Debug)]
pub(crate) struct DnsDone {
    pub conn: u64,
    pub sid: u32,
    pub serial: u64,
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
    serial: u64,
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
    tx: Mutex<SyncSender<Job>>,
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

fn worker_loop(
    rx: Arc<Mutex<Receiver<Job>>>,
    cache: Arc<Cache>,
    order: DnsOrder,
    servers: Arc<Vec<SocketAddr>>,
    timeout: Duration,
) {
    loop {
        let job = {
            let Ok(guard) = rx.lock() else { return };
            match guard.recv() {
                Ok(j) => j,
                Err(_) => return,
            }
        };
        let (answer, ttl) = if servers.is_empty() {
            let answer = lookup(&job.host, order);
            let ttl = if answer.is_ok() {
                cache.ttl
            } else {
                cache.negative_ttl
            };
            (answer, ttl)
        } else {
            match crate::dns_client::lookup(&servers, &job.host, timeout) {
                Ok(found) => {
                    let ttl = if found.ttl == 0 {
                        cache.ttl
                    } else {
                        cache.ttl.min(Duration::from_secs(u64::from(found.ttl)))
                    };
                    (Ok(order_addrs(found.addrs, order)), ttl)
                }
                Err(crate::dns_client::Error::Retry) => (Err(()), Duration::ZERO),
                Err(_) => (Err(()), cache.negative_ttl),
            }
        };
        if !ttl.is_zero()
            && let Ok(mut map) = cache.map.lock()
        {
            if map.len() < 4096 || map.contains_key(&job.host) {
                map.insert(job.host.clone(), (Instant::now() + ttl, answer.clone()));
            }
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
    pub(crate) fn new(
        threads: u32,
        ttl_s: u32,
        negative_ttl_s: u32,
        order: DnsOrder,
        servers: Vec<SocketAddr>,
        timeout: Duration,
    ) -> Resolver {
        let servers = Arc::new(servers);
        let (tx, rx) = sync_channel::<Job>(256);
        let rx = Arc::new(Mutex::new(rx));
        let cache = Arc::new(Cache {
            map: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(u64::from(ttl_s)),
            negative_ttl: Duration::from_secs(u64::from(negative_ttl_s)),
            entries: AtomicU64::new(0),
        });
        for i in 0..threads.max(1) {
            let servers = Arc::clone(&servers);
            let rx = Arc::clone(&rx);
            let cache = Arc::clone(&cache);
            let _ = std::thread::Builder::new()
                .name(format!("hw-dns-{i}"))
                .spawn(move || worker_loop(rx, cache, order, servers, timeout));
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
        serial: u64,
    ) {
        let key = rustwisp_config::normalize_hostname(host);
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
            .map(|tx| tx.try_send(job).is_ok())
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
    fn busy_resolver_refuses_excess_waiting_jobs() {
        let dns = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        dns.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mb = Mailbox::new().unwrap();
        let resolver = Resolver::new(
            1,
            60,
            60,
            DnsOrder::Ipv4First,
            vec![dns.local_addr().unwrap()],
            Duration::from_secs(1),
        );
        resolver.submit("held.test", &mb, 1, 1, 1);
        dns.recv_from(&mut [0; 512]).unwrap();
        for i in 0..512 {
            resolver.submit(&format!("queued{i}.test"), &mb, 1, i, 1);
        }
        let refused = mb.take();
        assert!(!refused.is_empty(), "all jobs entered an unbounded queue");
        assert!(refused.iter().all(|done| done.addrs.is_err()));
    }

    #[test]
    fn distinct_names_cannot_grow_the_cache_without_bound() {
        let dns = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        dns.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let endpoint = dns.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            for _ in 0..4097 * 2 {
                let mut buf = [0; 512];
                let (n, peer) = dns.recv_from(&mut buf).unwrap();
                buf[2] = 0x81;
                buf[3] = 0x83;
                dns.send_to(&buf[..n], peer).unwrap();
            }
        });
        let mb = Mailbox::new().unwrap();
        let resolver = Resolver::new(
            1,
            60,
            60,
            DnsOrder::Ipv4First,
            vec![endpoint],
            Duration::from_secs(1),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        for i in 0..4097 {
            resolver.submit(&format!("unique{i}.test"), &mb, 1, i, 1);
            while mb.take().is_empty() {
                assert!(Instant::now() < deadline);
                std::thread::yield_now();
            }
        }
        responder.join().unwrap();
        assert!(resolver.cache_entries() <= 4096, "cache has no entry cap");
    }

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
        let r = Resolver::new(
            1,
            60,
            5,
            DnsOrder::Ipv4First,
            Vec::new(),
            Duration::from_secs(1),
        );
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
