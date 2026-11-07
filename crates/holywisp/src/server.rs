//! Server setup: validate the config, bind one SO_REUSEPORT listener per worker, start the worker
//! threads, and stop them again.

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Duration;

use holywisp_config::{Config, LogLevel};
use holywisp_proto::wisp::HEADER_LEN;

use crate::dns::{Mailbox, Resolver};
use crate::pages;
use crate::stats::Stats;
use crate::worker::{Shared, SpliceMode, Worker};

/// Reject configurations the individual keys cannot catch on their own.
pub fn validate(cfg: &Config) -> Result<(), String> {
    if cfg.max_message_size < 5 {
        return Err("max-message-size must be at least 5".into());
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

fn splice_mode() -> SpliceMode {
    match std::env::var("HOLYWISP_SPLICE").as_deref() {
        Ok("off") => SpliceMode::Off,
        Ok("always") => SpliceMode::Always,
        _ => SpliceMode::Auto,
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
        validate(&cfg).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let count = if cfg.workers > 0 {
            cfg.workers as usize
        } else {
            std::thread::available_parallelism().map_or(1, usize::from)
        };
        let webclient = pages::webclient_page(&cfg.webclient_wisp_url)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let resolver = Resolver::new(
            cfg.resolver_threads,
            cfg.dns_ttl_s,
            cfg.dns_negative_ttl_s,
            cfg.dns_order,
        );
        let shared = Arc::new(Shared {
            window: ingress_window(&cfg),
            stats: Stats::new(),
            webclient,
            splice,
            resolver,
            stop: std::sync::atomic::AtomicBool::new(false),
            cfg,
        });
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
        if shared.cfg.log_level != LogLevel::None && shared.cfg.log_level != LogLevel::Error {
            eprintln!(
                "holywisp: listening on {}:{} with {} worker{}",
                if shared.cfg.host.is_empty() {
                    "*"
                } else {
                    &shared.cfg.host
                },
                port,
                workers.len(),
                if workers.len() == 1 { "" } else { "s" },
            );
        }
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
            .spawn(move || {
                while !maint_shared.stop.load(Ordering::Acquire) {
                    std::thread::park_timeout(Duration::from_secs(30));
                    maint_shared.resolver.expire();
                    maint_shared
                        .stats
                        .dns_cache_entries
                        .store(maint_shared.resolver.cache_entries(), Ordering::Relaxed);
                }
            })?;
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
