//! One worker thread: an epoll loop that owns every connection it accepted. Level-triggered, like
//! the C server; a connection never leaves the thread that accepted it.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rustix::event::epoll::Event;
use rustwisp_config::Config;

use crate::auth::AuthPool;
use crate::conn::Conn;
use crate::dns::{DnsDone, Mailbox, Resolver};
use crate::limits::{Bandwidth, Semaphore, Window};
use crate::proxy::Upstream;
use crate::reputation::Reputation;
use crate::slab::Slab;
use crate::stats::Stats;
use crate::stream::SState;
use crate::sys::{self, EventFlags};

/// Bytes read from a client in one go.
pub(crate) const RX_SIZE: usize = 256 * 1024;
/// Largest remote read, chosen to stay inside one loopback MSS-sized segment run.
pub(crate) const REMOTE_CHUNK: usize = 65_472;
/// Largest piece moved by one splice once a stream is in bulk mode. Measured on loopback with ten
/// streams: 64 KiB 2.5 GiB/s, 256 KiB 2.8, 512 KiB 3.3, 1 MiB 3.4-3.6. 512 KiB keeps one frame
/// well under the pipe size and bounds how long a frame can hold up the others.
pub(crate) const SPLICE_CHUNK: usize = 512 * 1024;
const PIPE_SIZE: usize = 1 << 20;
const MAX_EVENTS: usize = 1024;
const MAX_TIMERS: usize = 262_144;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceMode {
    Off,
    Auto,
    Always,
}

/// What every worker shares.
#[derive(Debug)]
pub(crate) struct Shared {
    pub cfg: Config,
    /// The CONTINUE window actually advertised (`buffer-remaining`, capped by `stream-queue-max`).
    pub window: u32,
    pub client_rcvbuf: usize,
    pub stats: Stats,
    pub webclient: Vec<u8>,
    pub splice: SpliceMode,
    pub resolver: Resolver,
    #[cfg(feature = "twisp")]
    pub terminals: Arc<crate::twisp::Terminals>,
    pub auth: AuthPool,
    /// The upstream proxy for outbound TCP, when one is configured.
    pub upstream: Option<Upstream>,
    pub started: Instant,
    pub conn_rate: Option<Window>,
    pub per_source: Option<Window>,
    pub per_dest_sec: Option<Window>,
    pub per_dest_min: Option<Window>,
    pub in_flight_syns: Semaphore,
    pub connections: Semaphore,
    pub rejections: Semaphore,
    pub bandwidth: Option<Bandwidth>,
    pub reputation: Option<Reputation>,
    pub stop: std::sync::atomic::AtomicBool,
}

impl Shared {
    /// Milliseconds since the server started; the clock every limiter uses.
    pub(crate) fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

#[derive(Debug)]
pub(crate) enum Entry {
    Listener,
    Wake,
    Conn(Box<Conn>),
    /// A stream's remote socket: which connection and stream it belongs to.
    Stream {
        conn: u64,
        sid: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimerKind {
    Handshake,
    Connect,
    Throttle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Timer {
    pub at: Instant,
    pub conn: u64,
    pub sid: u32,
    pub serial: u64,
    pub kind: u8,
}

impl TimerKind {
    fn code(self) -> u8 {
        match self {
            TimerKind::Handshake => 0,
            TimerKind::Connect => 1,
            TimerKind::Throttle => 2,
        }
    }
    pub(crate) fn from_code(c: u8) -> TimerKind {
        match c {
            0 => TimerKind::Handshake,
            1 => TimerKind::Connect,
            _ => TimerKind::Throttle,
        }
    }
}

/// Everything a connection needs from its worker while it handles an event. It does not contain
/// the connection itself, which is taken out of the slab while it runs.
#[derive(Debug)]
pub(crate) struct Ctx {
    pub sh: Arc<Shared>,
    pub ep: OwnedFd,
    pub slab: Slab<Entry>,
    /// Client reads land here and complete frames are processed in place.
    pub rx: Vec<u8>,
    /// Remote reads (the copy path) land here.
    pub rd: Vec<u8>,
    pub pipe: Option<(OwnedFd, OwnedFd)>,
    pub timers: BinaryHeap<Reverse<Timer>>,
    last_timer_purge: Option<Instant>,
    next_serial: u64,
    pub mailbox: Arc<Mailbox>,
    pub index: usize,
}

impl Ctx {
    pub(crate) fn next_serial(&mut self) -> u64 {
        self.next_serial = self.next_serial.wrapping_add(1);
        self.next_serial
    }

    pub(crate) fn cfg(&self) -> &Config {
        &self.sh.cfg
    }

    pub(crate) fn add_timer(
        &mut self,
        after: Duration,
        conn: u64,
        sid: u32,
        serial: u64,
        kind: TimerKind,
    ) -> bool {
        if self.timers.len() >= MAX_TIMERS {
            let now = Instant::now();
            if self
                .last_timer_purge
                .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1))
            {
                self.last_timer_purge = Some(now);
                let slab = &self.slab;
                self.timers.retain(|Reverse(t)| match slab.get(t.conn) {
                    Some(Entry::Conn(c)) if !c.link.closing => match TimerKind::from_code(t.kind) {
                        TimerKind::Handshake => !c.link.handshake_done,
                        TimerKind::Throttle => c.link.throttled,
                        TimerKind::Connect => c.streams.get(&t.sid).is_some_and(|s| {
                            s.serial == t.serial
                                && matches!(
                                    s.state,
                                    SState::Resolving | SState::Connecting | SState::ProxyHandshake
                                )
                        }),
                    },
                    // A connection handling an event is temporarily absent from its reserved slot.
                    None => slab.contains(t.conn),
                    _ => false,
                });
            }
            if self.timers.len() >= MAX_TIMERS {
                return false;
            }
        }
        self.timers.push(Reverse(Timer {
            at: Instant::now() + after,
            conn,
            sid,
            serial,
            kind: kind.code(),
        }));
        true
    }
}

pub(crate) struct Worker {
    cx: Ctx,
    listener: OwnedFd,
    wake: OwnedFd,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("index", &self.cx.index)
            .finish()
    }
}

impl Worker {
    pub(crate) fn new(
        sh: Arc<Shared>,
        index: usize,
        listener: OwnedFd,
        mailbox: Arc<Mailbox>,
    ) -> std::io::Result<Worker> {
        let ep = sys::epoll_new()?;
        let wake = mailbox.wake_fd_clone()?;
        let pipe = if sh.splice == SpliceMode::Off {
            None
        } else {
            sys::pipe_pair(PIPE_SIZE).ok()
        };
        let mut cx = Ctx {
            sh,
            ep,
            slab: Slab::new(),
            rx: vec![0u8; RX_SIZE],
            rd: vec![0u8; 65_536],
            pipe,
            timers: BinaryHeap::new(),
            last_timer_purge: None,
            next_serial: 0,
            mailbox,
            index,
        };
        let lt = cx.slab.insert(Entry::Listener);
        sys::epoll_add(&cx.ep, &listener, lt, sys::IN)?;
        let wt = cx.slab.insert(Entry::Wake);
        sys::epoll_add(&cx.ep, &wake, wt, sys::IN)?;
        Ok(Worker { cx, listener, wake })
    }

    pub(crate) fn run(mut self) {
        #[cfg(feature = "worker-panic-test")]
        if self.cx.index == 0 && std::env::var_os("RUSTWISP_TEST_WORKER_PANIC").is_some() {
            panic!("worker panic fixture");
        }
        let mut scratch: Vec<Event> = Vec::with_capacity(MAX_EVENTS);
        let mut events: Vec<(u64, EventFlags)> = Vec::with_capacity(MAX_EVENTS);
        while !self.cx.sh.stop.load(Ordering::Acquire) {
            let timeout = self.next_timeout();
            if let Err(e) = sys::epoll_wait(&self.cx.ep, &mut scratch, &mut events, timeout) {
                crate::log::error(
                    "worker",
                    format_args!("worker {}: epoll_wait: {e}", self.cx.index),
                );
                break;
            }
            for &(token, flags) in &events {
                self.dispatch(token, flags);
            }
            self.fire_timers();
        }
    }

    fn next_timeout(&self) -> Option<Duration> {
        let next = self.cx.timers.peek()?.0.at;
        let now = Instant::now();
        // Round up to a whole millisecond so a timer due in 200 us does not spin.
        Some(next.saturating_duration_since(now) + Duration::from_micros(500))
    }

    fn dispatch(&mut self, token: u64, flags: EventFlags) {
        let (conn_tok, sid) = match self.cx.slab.get(token) {
            Some(Entry::Conn(_)) => (token, None),
            Some(Entry::Stream { conn, sid }) => (*conn, Some(*sid)),
            Some(Entry::Listener) => return self.accept_all(),
            Some(Entry::Wake) => return self.on_wake(),
            None => return,
        };
        self.with_conn(conn_tok, |c, cx| match sid {
            None => c.on_event(cx, flags),
            Some(sid) => c.on_stream_event(cx, sid, flags),
        });
    }

    /// Run `f` on a connection taken out of the slab; put it back or tear it down afterwards.
    fn with_conn(&mut self, tok: u64, f: impl FnOnce(&mut Conn, &mut Ctx)) {
        let Some(Entry::Conn(mut c)) = self.cx.slab.take(tok) else {
            return;
        };
        f(&mut c, &mut self.cx);
        c.settle(&mut self.cx);
        if c.is_closing() {
            c.teardown(&mut self.cx);
            self.cx.slab.release(tok);
        } else {
            self.cx.slab.put(tok, Entry::Conn(c));
        }
    }

    fn accept_all(&mut self) {
        loop {
            match sys::accept(&self.listener) {
                Ok((fd, peer)) => Conn::accept(&mut self.cx, fd, peer),
                Err(e) if sys::is_would_block(e) || e == sys::Errno::INTR => return,
                Err(e) if e == sys::Errno::CONNABORTED => {}
                Err(e) => {
                    if e == sys::Errno::MFILE || e == sys::Errno::NFILE {
                        crate::log::warn(
                            "accept",
                            format_args!("worker {}: out of file descriptors", self.cx.index),
                        );
                    } else {
                        crate::log::warn(
                            "accept",
                            format_args!("worker {}: accept: {e}", self.cx.index),
                        );
                    }
                    return;
                }
            }
        }
    }

    fn on_wake(&mut self) {
        sys::drain_wake(&self.wake);
        let done: Vec<DnsDone> = self.cx.mailbox.take();
        for d in done {
            self.with_conn(d.conn, |c, cx| c.on_resolved(cx, d));
        }
        for a in self.cx.mailbox.take_auth() {
            self.with_conn(a.conn, |c, cx| c.on_auth(cx, a));
        }
    }

    fn fire_timers(&mut self) {
        let now = Instant::now();
        while let Some(Reverse(t)) = self.cx.timers.peek().copied() {
            if t.at > now {
                break;
            }
            self.cx.timers.pop();
            let kind = TimerKind::from_code(t.kind);
            self.with_conn(t.conn, |c, cx| c.on_timer(cx, kind, t.sid, t.serial));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker() -> Worker {
        configured_worker(None)
    }

    fn configured_worker(proxy: Option<rustwisp_config::ProxyUrl>) -> Worker {
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 0,
            workers: 1,
            reputation_enabled: false,
            allow_loopback: true,
            allow_direct_ip: true,
            connections_limit_per_ip: 0,
            connection_window_s: 0,
            proxy,
            flood: rustwisp_config::FloodConfig {
                max_concurrent_connections: 1,
                ..Config::default().flood
            },
            ..Config::default()
        };
        crate::Server::bind(cfg).unwrap().take_test_worker()
    }

    fn socket_pair() -> (OwnedFd, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();
        (server.into(), client)
    }

    fn connection(cx: &mut Ctx) -> (u64, std::net::TcpStream) {
        let (fd, client) = socket_pair();
        Conn::accept(cx, fd, Some(client.local_addr().unwrap()));
        (cx.timers.peek().unwrap().0.conn, client)
    }

    fn fill(cx: &mut Ctx, conn: u64) {
        while cx.timers.len() < MAX_TIMERS {
            assert!(cx.add_timer(
                Duration::from_secs(3600),
                conn,
                cx.timers.len() as u32,
                1,
                TimerKind::Connect
            ));
        }
    }

    fn expect_throttled(client: &mut std::net::TcpStream, sid: u32) {
        use std::io::Read;
        let mut frame = [0u8; 8];
        client.read_exact(&mut frame).unwrap();
        assert_eq!(&frame[..2], &[0x82, 6]);
        let packet = rustwisp_proto::wisp::parse(&frame[2..]).unwrap();
        assert_eq!(packet.ptype, rustwisp_proto::wisp::ptype::CLOSE);
        assert_eq!(packet.stream_id, sid);
        assert_eq!(packet.payload, &[rustwisp_proto::wisp::close::THROTTLED]);
    }

    #[test]
    fn a_short_vectored_upload_queues_only_the_unsent_suffix() {
        use std::io::Read;
        let mut worker = worker();
        let cx = &mut worker.cx;
        let (token, _client) = connection(cx);
        let Some(Entry::Conn(mut c)) = cx.slab.take(token) else {
            panic!("missing connection")
        };
        let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        rustix::net::sockopt::set_socket_recv_buffer_size(&target, 4096).unwrap();
        crate::stream::open(
            &mut c,
            cx,
            7,
            1,
            "127.0.0.1",
            target.local_addr().unwrap().port(),
        );
        let (mut peer, _) = target.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.on_stream_event(cx, 7, sys::OUT);
        let s = c.streams.get_mut(&7).unwrap();
        assert_eq!(s.state, SState::Open);
        rustix::net::sockopt::set_socket_send_buffer_size(s.fd.as_ref().unwrap(), 4096).unwrap();
        let data: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 65_536]).collect();
        let parts: Vec<_> = data.iter().map(|p| std::io::IoSlice::new(p)).collect();
        let remaining = s.remaining;
        crate::stream::on_data_batch(&mut c.link, cx, s, &parts);
        assert!(!s.out.is_empty() && s.out.len() < 4 * 65_536);
        assert_eq!(c.link.queued_out, s.out.len());
        assert_eq!(s.remaining, remaining - 4);
        let reader = std::thread::spawn(move || {
            let mut got = vec![0; 4 * 65_536];
            peer.read_exact(&mut got).unwrap();
            got
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while c.link.queued_out != 0 {
            assert!(Instant::now() < deadline);
            c.on_stream_event(cx, 7, sys::OUT);
            std::thread::yield_now();
        }
        assert_eq!(reader.join().unwrap(), data.concat());
        c.teardown(cx);
    }

    #[test]
    fn upload_budget_counts_pending_streams_and_releases_on_close() {
        let mut worker = worker();
        let cfg = &mut Arc::get_mut(&mut worker.cx.sh).unwrap().cfg;
        cfg.stream_queue_max = 1 << 20;
        cfg.conn_queue_max = 2 << 20;
        let cx = &mut worker.cx;
        let (token, _client) = connection(cx);
        let Some(Entry::Conn(mut c)) = cx.slab.take(token) else {
            panic!("missing connection")
        };
        for sid in [1, 2, 3] {
            crate::stream::open(&mut c, cx, sid, 1, "waiting.invalid", 80);
            let s = c.streams.get_mut(&sid).unwrap();
            crate::stream::on_data(&mut c.link, cx, s, &vec![1; 768 << 10]);
        }
        assert_eq!(c.link.queued_out, 2304 << 10);
        assert!(c.link.read_paused);
        assert!(c.link.want().contains(EventFlags::RDHUP));
        assert!(!c.link.want().contains(EventFlags::IN));
        assert_eq!(c.link.live_streams, 3);
        for sid in [1, 2] {
            let s = c.streams.get_mut(&sid).unwrap();
            crate::stream::close_stream(&mut c.link, cx, s, 1, false);
        }
        assert_eq!(c.link.queued_out, 768 << 10);
        assert!(!c.link.read_paused);
        assert!(c.link.read_resumed);
        c.teardown(cx);
        assert_eq!(c.link.queued_out, 0);
        assert_eq!(c.link.live_streams, 0);
    }

    #[test]
    fn refill_credit_never_exceeds_the_advertised_window() {
        let mut worker = worker();
        let cx = &mut worker.cx;
        let (token, _client) = connection(cx);
        let Some(Entry::Conn(mut c)) = cx.slab.take(token) else {
            panic!("missing connection")
        };
        c.link.live_streams = 1;
        c.link.packet_average = 65_536;
        assert_eq!(c.link.refill_window(cx), 128);
        c.link.live_streams = 4;
        assert_eq!(c.link.refill_window(cx), 32);
        c.link.live_streams = 1000;
        assert_eq!(c.link.refill_window(cx), 4);
        c.link.live_streams = 0;
        c.teardown(cx);
    }

    #[test]
    fn long_deadlines_cannot_grow_the_timer_heap_without_bound() {
        let mut worker = worker();
        let cx = &mut worker.cx;
        let conn = cx.slab.reserve();
        for sid in 0..262_144 + 32 {
            cx.add_timer(Duration::from_secs(3600), conn, sid, 1, TimerKind::Connect);
        }
        println!("long-deadline timers: {}", cx.timers.len());
        assert!(cx.timers.len() <= 262_144);
    }

    #[test]
    fn timer_capacity_preserves_taken_connections_and_limits_purging() {
        let mut worker = worker();
        let cx = &mut worker.cx;
        let conn = cx.slab.reserve();
        fill(cx, conn);
        assert!(!cx.add_timer(Duration::from_secs(1), conn, 0, 1, TimerKind::Connect));
        assert_eq!(cx.timers.len(), MAX_TIMERS);
        let last = cx.last_timer_purge;
        cx.slab.release(conn);
        assert!(!cx.add_timer(Duration::from_secs(1), conn, 0, 1, TimerKind::Connect));
        assert_eq!(cx.last_timer_purge, last);
        cx.last_timer_purge = Some(Instant::now() - Duration::from_secs(1));
        let replacement = cx.slab.reserve();
        assert_ne!(conn, replacement);
        assert!(cx.add_timer(
            Duration::from_secs(1),
            replacement,
            0,
            1,
            TimerKind::Connect
        ));
        assert_eq!(cx.timers.len(), 1);
    }

    #[test]
    fn stale_stream_and_finished_handshake_timers_are_pruned() {
        let mut worker = worker();
        let cx = &mut worker.cx;
        let (token, _client) = connection(cx);
        let Some(Entry::Conn(mut c)) = cx.slab.take(token) else {
            panic!("connection missing")
        };
        c.link.handshake_done = true;
        crate::stream::open(&mut c, cx, 7, 1, "waiting.invalid", 80);
        let stream = c.streams.get_mut(&7).unwrap();
        stream.serial = cx.next_serial();
        let serial = stream.serial;
        assert!(cx.add_timer(
            Duration::from_secs(3600),
            token,
            7,
            serial,
            TimerKind::Connect
        ));
        crate::stream::open(&mut c, cx, 8, 1, "closed.invalid", 80);
        let stream = c.streams.get_mut(&8).unwrap();
        crate::stream::close_stream(&mut c.link, cx, stream, 1, false);
        c.link.throttled = false;
        assert!(cx.add_timer(Duration::from_secs(3600), token, 0, 0, TimerKind::Throttle));
        cx.slab.put(token, Entry::Conn(c));
        let dead = cx.slab.reserve();
        fill(cx, dead);
        cx.slab.release(dead);
        assert!(cx.add_timer(Duration::from_secs(3600), token, 9, 1, TimerKind::Connect));
        assert_eq!(cx.timers.len(), 2);
        assert!(
            cx.timers
                .iter()
                .any(|t| t.0.sid == 7 && t.0.serial == serial)
        );
        worker.with_conn(token, |c, _| c.link.close());
        assert!(!worker.cx.slab.contains(token));
    }

    #[test]
    fn timer_capacity_rejection_releases_connection_admission() {
        let mut worker = worker();
        let cx = &mut worker.cx;
        let reserved = cx.slab.reserve();
        fill(cx, reserved);
        let before = cx.slab.len();
        let (fd, client) = socket_pair();
        Conn::accept(cx, fd, Some(client.local_addr().unwrap()));
        assert_eq!(cx.slab.len(), before);
        assert_eq!(cx.sh.connections.value(), 0);
        assert_eq!(cx.sh.stats.connections_active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn timer_capacity_refuses_resolves_connects_and_throttle_waits() {
        let mut worker = worker();
        let cx = &mut worker.cx;
        let (token, mut client) = connection(cx);
        let Some(Entry::Conn(mut c)) = cx.slab.take(token) else {
            panic!("connection missing")
        };
        fill(cx, token);
        crate::stream::open(&mut c, cx, 7, 1, "waiting.invalid", 80);
        assert!(!c.streams.contains_key(&7));
        expect_throttled(&mut client, 7);
        let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        crate::stream::open(
            &mut c,
            cx,
            8,
            1,
            "127.0.0.1",
            target.local_addr().unwrap().port(),
        );
        assert!(!c.streams.contains_key(&8));
        expect_throttled(&mut client, 8);
        assert_eq!(cx.sh.in_flight_syns.value(), 0);
        assert_eq!(cx.sh.stats.streams_active.load(Ordering::Relaxed), 0);
        c.link.pending_throttle_ms = 1000;
        c.settle(cx);
        assert!(c.is_closing());
        c.teardown(cx);
        assert_eq!(cx.sh.connections.value(), 0);
    }

    #[test]
    fn timer_capacity_refuses_a_proxy_handshake_without_leaking_its_socket() {
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("socks5://127.0.0.1:{}", proxy.local_addr().unwrap().port());
        let mut worker = configured_worker(Some(url.parse().unwrap()));
        let cx = &mut worker.cx;
        let (token, mut client) = connection(cx);
        let Some(Entry::Conn(mut c)) = cx.slab.take(token) else {
            panic!("connection missing")
        };
        crate::stream::open(&mut c, cx, 7, 1, "127.0.0.1", 80);
        assert_eq!(c.streams[&7].state, SState::Connecting);
        let (_socket, _) = proxy.accept().unwrap();
        fill(cx, token);
        c.on_stream_event(cx, 7, sys::OUT);
        assert!(!c.streams.contains_key(&7));
        expect_throttled(&mut client, 7);
        assert_eq!(cx.sh.in_flight_syns.value(), 0);
        assert_eq!(cx.sh.stats.streams_active.load(Ordering::Relaxed), 0);
        c.teardown(cx);
    }
}
