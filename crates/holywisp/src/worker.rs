//! One worker thread: an epoll loop that owns every connection it accepted. Level-triggered, like
//! the C server; a connection never leaves the thread that accepted it.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use holywisp_config::Config;
use rustix::event::epoll::Event;

use crate::auth::AuthPool;
use crate::conn::Conn;
use crate::dns::{DnsDone, Mailbox, Resolver};
use crate::limits::{Bandwidth, Semaphore, Window};
use crate::proxy::Upstream;
use crate::reputation::Reputation;
use crate::slab::Slab;
use crate::stats::Stats;
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
    pub serial: u32,
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
    pub mailbox: Arc<Mailbox>,
    pub index: usize,
}

impl Ctx {
    pub(crate) fn cfg(&self) -> &Config {
        &self.sh.cfg
    }

    pub(crate) fn add_timer(
        &mut self,
        after: Duration,
        conn: u64,
        sid: u32,
        serial: u32,
        kind: TimerKind,
    ) {
        self.timers.push(Reverse(Timer {
            at: Instant::now() + after,
            conn,
            sid,
            serial,
            kind: kind.code(),
        }));
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
