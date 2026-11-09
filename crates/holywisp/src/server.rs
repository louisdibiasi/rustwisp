//! Server setup: validate the config, bind one SO_REUSEPORT listener per worker, start the worker
//! threads, and stop them again.

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::log;
use holywisp_config::Config;
use holywisp_proto::wisp::HEADER_LEN;

use crate::auth::AuthPool;
use crate::dns::{Mailbox, Resolver};
use crate::limits::{Bandwidth, Semaphore, Window};
use crate::pages;
use crate::password::{self, Scheme};
use crate::proxy::Upstream;
use crate::reputation::Reputation;
use crate::stats::Stats;
use crate::worker::{Shared, SpliceMode, Worker};

/// Reject configurations the individual keys cannot catch on their own.
pub fn validate(cfg: &Config) -> Result<(), String> {
    if cfg.max_message_size < 5 {
        return Err("max-message-size must be at least 5".into());
    }
    for u in &cfg.users {
        if let Err(why) = password::scheme(&u.secret) {
            return Err(format!("password-user '{}': {why}", u.name));
        }
    }
    if cfg.password_required && cfg.users.is_empty() {
        return Err("password-required needs at least one password-user".into());
    }
    if cfg.enable_twisp && cfg.users.is_empty() {
        return Err("enable-twisp needs password auth: add a password-user".into());
    }
    if cfg.enable_twisp && !cfg.enable_v2 {
        return Err("enable-twisp needs enable-v2".into());
    }
    if (cfg.connections_limit_per_ip == 0) != (cfg.connection_window_s == 0) {
        return Err(
            "connections-limit-per-ip and connection-window-s must both be set or both be zero"
                .into(),
        );
    }
    if !(0.0..=1.0).contains(&cfg.flood.syn_signature_failed_ratio) {
        return Err("syn-signature-failed-ratio must be between 0 and 1".into());
    }
    pages::check_wisp_url(&cfg.webclient_wisp_url)
}

/// The CONTINUE window actually advertised: `buffer-remaining`, capped so a whole window of
/// maximum-size DATA packets fits in half of `stream-queue-max`.
pub fn ingress_window(cfg: &Config) -> u32 {
    let payload = (cfg.max_message_size as usize)
        .saturating_sub(HEADER_LEN)
        .max(1);
    let by_memory = (cfg.stream_queue_max as usize / 2 / payload).max(1);
    u32::try_from(by_memory)
        .unwrap_or(u32::MAX)
        .min(cfg.buffer_remaining)
}

fn flood_window(cfg: &Config, limit: u32, window_ms: u64) -> Option<Window> {
    (cfg.flood.enabled && limit > 0).then(|| Window::new(limit, window_ms))
}

fn splice_mode() -> SpliceMode {
    match std::env::var("HOLYWISP_SPLICE").as_deref() {
        Ok("off") => SpliceMode::Off,
        Ok("always") => SpliceMode::Always,
        _ => SpliceMode::Auto,
    }
}

/// Slow housekeeping: limiter eviction, DNS cache expiry, reputation decay and saves.
fn maintenance(sh: &Shared) {
    let mut last_slow = 0u64;
    let mut last_save = 0u64;
    loop {
        std::thread::park_timeout(Duration::from_secs(1));
        let stopping = sh.stop.load(Ordering::Acquire);
        let now = sh.now_ms();
        if now.saturating_sub(last_slow) >= 60_000 || stopping {
            last_slow = now;
            let window_ms = u64::from(sh.cfg.connection_window_s) * 1000;
            if let Some(w) = sh.conn_rate.as_ref() {
                w.evict(2 * window_ms + 120_000, now);
            }
            for (w, idle) in [
                (sh.per_source.as_ref(), 120_000),
                (sh.per_dest_sec.as_ref(), 120_000),
                (sh.per_dest_min.as_ref(), 7_200_000),
            ] {
                if let Some(w) = w {
                    w.evict(idle, now);
                }
            }
            if let Some(b) = sh.bandwidth.as_ref() {
                b.evict(600_000, now);
            }
            sh.resolver.expire();
            sh.stats
                .dns_cache_entries
                .store(sh.resolver.cache_entries(), Ordering::Relaxed);
            if let Some(r) = sh.reputation.as_ref() {
                r.decay(now);
                r.evict();
            }
        }
        if let Some(r) = sh.reputation.as_ref() {
            let (sources, dests) = r.counts();
            sh.stats
                .reputation_sources
                .store(sources as u64, Ordering::Relaxed);
            sh.stats
                .reputation_dests
                .store(dests as u64, Ordering::Relaxed);
            let every = u64::from(sh.cfg.reputation.save_interval_s) * 1000;
            if every > 0 && (now.saturating_sub(last_save) >= every || stopping) {
                last_save = now;
                if let Err(e) = r.save() {
                    log::warn(
                        "reputation",
                        format_args!("save to {}: {e}", sh.cfg.reputation.store_path),
                    );
                }
            }
        }
        if stopping {
            return;
        }
    }
}

/// A bound but not yet running server.
#[derive(Debug)]
pub struct Server {
    shared: Arc<Shared>,
    workers: Vec<Worker>,
    mailboxes: Vec<Arc<Mailbox>>,
    port: u16,
}

impl Server {
    /// Bind with the splice mode from `HOLYWISP_SPLICE` (`off`, `always`, default adaptive).
    pub fn bind(cfg: Config) -> io::Result<Server> {
        Server::bind_with(cfg, splice_mode())
    }

    pub fn bind_with(cfg: Config, splice: SpliceMode) -> io::Result<Server> {
        log::set_level(cfg.log_level);
        validate(&cfg).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let count = if cfg.workers > 0 {
            cfg.workers as usize
        } else {
            std::thread::available_parallelism().map_or(1, usize::from)
        };
        let webclient = pages::webclient_page(&cfg.webclient_wisp_url)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let servers = cfg
            .dns_servers
            .iter()
            .filter_map(|value| {
                let parsed = crate::dns_client::server(value);
                if parsed.is_none() {
                    log::warn(
                        "dns",
                        format_args!("ignoring malformed dns-server '{value}'"),
                    );
                }
                parsed
            })
            .take(8)
            .collect();
        let resolver = Resolver::new(
            cfg.resolver_threads,
            cfg.dns_ttl_s,
            cfg.dns_negative_ttl_s,
            cfg.dns_order,
            servers,
            Duration::from_millis(u64::from(cfg.dns_timeout_ms.max(1))),
        );
        let upstream = cfg
            .proxy
            .as_ref()
            .map(Upstream::resolve)
            .transpose()
            .map_err(|e| io::Error::new(e.kind(), format!("cannot resolve the proxy host: {e}")))?;
        let hashed = cfg
            .users
            .iter()
            .any(|u| password::scheme(&u.secret) != Ok(Scheme::Plain));
        let shared = Arc::new(Shared {
            window: ingress_window(&cfg),
            stats: Stats::new(),
            webclient,
            splice,
            resolver,
            auth: AuthPool::new(if hashed { 2 } else { 0 }),
            upstream,
            started: std::time::Instant::now(),
            conn_rate: (cfg.connections_limit_per_ip > 0 && cfg.connection_window_s > 0).then(
                || {
                    Window::new(
                        cfg.connections_limit_per_ip,
                        u64::from(cfg.connection_window_s) * 1000,
                    )
                },
            ),
            per_source: flood_window(&cfg, cfg.flood.max_connects_per_source_per_second, 1000),
            per_dest_sec: flood_window(&cfg, cfg.flood.max_connects_per_dest_per_second, 1000),
            per_dest_min: flood_window(&cfg, cfg.flood.max_connects_per_dest_per_minute, 60_000),
            in_flight_syns: Semaphore::new(if cfg.flood.enabled {
                cfg.flood.max_in_flight_syns
            } else {
                0
            }),
            connections: Semaphore::new(if cfg.flood.enabled {
                cfg.flood.max_concurrent_connections
            } else {
                0
            }),
            reputation: cfg
                .reputation_enabled
                .then(|| Reputation::new(&cfg.reputation)),
            bandwidth: Bandwidth::new(u64::from(cfg.bandwidth_limit_kbps) * 1000 / 8),
            stop: std::sync::atomic::AtomicBool::new(false),
            cfg,
        });
        if let Some(r) = shared.reputation.as_ref()
            && let Err(e) = r.load()
        {
            log::warn(
                "reputation",
                format_args!("load from {}: {e}", shared.cfg.reputation.store_path),
            );
        }
        let mut port = shared.cfg.port;
        let mut workers = Vec::with_capacity(count);
        let mut mailboxes = Vec::with_capacity(count);
        for i in 0..count {
            // The first worker may pick an ephemeral port; the rest join it.
            let (listener, bound) =
                crate::sys::listen_tcp(&shared.cfg.host, port, shared.cfg.listen_backlog)?;
            port = bound;
            let mailbox = Mailbox::new()?;
            workers.push(Worker::new(
                Arc::clone(&shared),
                i,
                listener,
                Arc::clone(&mailbox),
            )?);
            mailboxes.push(mailbox);
        }
        Ok(Server {
            shared,
            workers,
            mailboxes,
            port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Start the worker threads.
    pub fn start(self) -> io::Result<ServerHandle> {
        let Server {
            shared,
            workers,
            mailboxes,
            port,
        } = self;
        log::info(
            "server",
            format_args!(
                "listening on {}:{} with {} workers",
                shared.cfg.host,
                port,
                workers.len()
            ),
        );
        let mut threads = Vec::with_capacity(workers.len() + 1);
        for w in workers {
            threads.push(
                std::thread::Builder::new()
                    .name("hw-worker".into())
                    .spawn(move || w.run())?,
            );
        }
        let maint_shared = Arc::clone(&shared);
        let maint = std::thread::Builder::new()
            .name("hw-maint".into())
            .spawn(move || maintenance(&maint_shared))?;
        let maint_thread = maint.thread().clone();
        threads.push(maint);
        Ok(ServerHandle {
            shared,
            mailboxes,
            threads,
            maint_thread,
            port,
        })
    }
}

/// A running server.
#[derive(Debug)]
pub struct ServerHandle {
    shared: Arc<Shared>,
    mailboxes: Vec<Arc<Mailbox>>,
    threads: Vec<JoinHandle<()>>,
    maint_thread: std::thread::Thread,
    port: u16,
}

impl ServerHandle {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Ask every worker to stop.
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::Release);
        for m in &self.mailboxes {
            m.poke();
        }
        self.maint_thread.unpark();
    }

    /// Wait for the threads to exit.
    pub fn join(self) {
        for t in self.threads {
            let _ = t.join();
        }
    }

    pub fn stop_and_join(self) {
        self.stop();
        self.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_is_capped_by_the_queue_budget() {
        let mut c = Config::default();
        assert_eq!(ingress_window(&c), 8, "16 MiB queue / 2 / 1 MiB packets");
        c.max_message_size = 65_541;
        assert_eq!(ingress_window(&c), 128);
        c.buffer_remaining = 4;
        assert_eq!(ingress_window(&c), 4);
    }

    #[test]
    fn validation_catches_cross_key_mistakes() {
        let mut c = Config::default();
        assert!(validate(&c).is_ok());
        c.password_required = true;
        assert!(validate(&c).unwrap_err().contains("password-user"));
        let c = Config {
            connections_limit_per_ip: 0,
            ..Config::default()
        };
        assert!(validate(&c).is_err());
    }
}
